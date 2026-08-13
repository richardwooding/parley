// Package session is the client-side engine: it dials the relay, runs the
// create/join handshake, performs the PAKE + group-key exchange, and moves
// encrypted service envelopes. It compiles natively (tests, headless tools)
// and to WASM (the browser core) — no syscall/js here, ever.
package session

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/richardwooding/parley/crypto"
	"github.com/richardwooding/parley/phrase"
	"github.com/richardwooding/parley/wire"
)

// Role is assigned by the host when it wraps the group key for a joiner.
// The zero value means "not keyed yet". The byte value rides inside the
// encrypted handshake, so it is application protocol: every end and every
// version of an application must agree on the numbering. RoleNone and
// RoleHost are reserved by the library; values 2..255 belong to the
// application's RolePolicy (RoleMember and RoleObserver are the built-in
// default vocabulary).
type Role uint8

const (
	RoleNone     Role = 0 // not keyed yet; in a rekey wrap: "keep your existing role"
	RoleHost     Role = 1 // reserved: the key authority
	RoleMember   Role = 2 // default policy: an ordinary joiner
	RoleObserver Role = 3 // default policy: a joiner that asked to observe
)

// Event is anything the session surfaces to the layer above (a service mux
// or UI bridge): MemberJoined, MemberKeyed, MemberLeft, Frame, Closed.
type Event any

type (
	// MemberJoined fires when the relay announces a new participant. For the
	// host it fires before that member is keyed.
	MemberJoined struct{ ID wire.ParticipantID }
	// MemberKeyed fires on the host once a joiner completes the handshake.
	MemberKeyed struct {
		ID   wire.ParticipantID
		Role Role
	}
	// MemberLeft fires when a participant disconnects.
	MemberLeft struct{ ID wire.ParticipantID }
	// Frame is one decrypted service envelope from a peer.
	Frame struct {
		From     wire.ParticipantID
		Envelope wire.Envelope
	}
	// Closed fires last: the session is over.
	Closed struct{ Reason string }
)

// Client is one end of a live session.
type Client struct {
	conn     *websocket.Conn
	relayURL string // kept so Reconnect can re-dial the same relay
	proto    string // application domain-separation label (see WithProtocol)
	sid      wire.SessionID
	phraseC  string // canonical phrase — the PAKE secret
	self     wire.ParticipantID
	hostID   wire.ParticipantID
	role     Role

	resumeToken []byte // opaque relay-issued secret to reclaim this slot after a drop
	observer    bool   // joiner intent, sent as wire.Pake.Spectate (the field name is deployed wire vocabulary)

	// rolePolicy assigns roles to joiners when this end is — or is promoted
	// to be — the session host. Immutable after dial.
	rolePolicy RolePolicy

	groupKey crypto.Key
	keyed    bool

	// Forward secrecy on member-leave: the (original) host rotates the group key
	// when a non-host member leaves, re-wrapping a fresh key to each survivor
	// under its retained pairwise key. prevKeys is a short ring of superseded
	// keys kept only to Open frames still in flight across the swap (survivors
	// are trusted; the departed member never receives the new key).
	prevKeys         []crypto.Key                      // superseded group keys, newest first
	pairwise         map[wire.ParticipantID]crypto.Key // host: per-member pairwise keys, for re-wrapping
	hostPairwise     crypto.Key                        // joiner: pairwise key with the host, for unwrapping a rekey
	haveHostPairwise bool
	rekeyJoiner      *crypto.Joiner // survivor: in-flight re-PAKE with a newly-promoted host

	events chan Event

	writeMu sync.Mutex // coder/websocket allows one concurrent writer

	mu      sync.Mutex
	seqs    map[string]uint64 // per-service send sequence
	joiners map[wire.ParticipantID]Role
}

// prevKeyRing bounds how many superseded group keys we retain to decrypt frames
// in flight across a rekey. Eight is far more than any realistic burst of leaves
// within a single frame's flight window.
const prevKeyRing = 8

const (
	eventBuffer = 256
	// pingInterval elicits a pong that keeps both the relay's idle timeout from
	// firing and the read deadline below refreshed. readTimeout is how long the
	// read loop waits for ANY frame before declaring the connection dead — this
	// is what catches a half-open drop (offline, NAT eviction) where reads would
	// otherwise block forever. readTimeout > pingInterval so a healthy quiet
	// connection (pongs every pingInterval) never times out.
	pingInterval = 8 * time.Second
	readTimeout  = 20 * time.Second
)

// DefaultProtocol is the domain-separation label used when no WithProtocol
// option is given. Applications with their own deployed protocol pass their
// label instead; the label feeds both session-ID derivation and the PAKE key
// schedule, so all ends of a session must agree on it.
const DefaultProtocol = "parley/v1"

type config struct {
	protocol   string
	rolePolicy RolePolicy
	observer   bool
}

// RolePolicy decides the role for a newly keyed joiner. The host calls it
// once per completed handshake, on the session's read goroutine, with the
// joiner's participant ID, whether the joiner asked to observe (see
// WithObserver), and a snapshot of the roles this host has already assigned
// to its joiners (the host itself is not in the map). Implementations must
// be fast, must not block, and must not call back into the Client — a
// stalled policy stalls the whole session end. RoleNone and RoleHost are
// reserved: a policy returning either is clamped to RoleMember. Any other
// value (2..255) is delivered verbatim, so applications may define their
// own role vocabulary on top of Role.
type RolePolicy func(joiner wire.ParticipantID, observer bool, assigned map[wire.ParticipantID]Role) Role

// DefaultRolePolicy seats observers as RoleObserver and everyone else as
// RoleMember.
func DefaultRolePolicy(_ wire.ParticipantID, observer bool, _ map[wire.ParticipantID]Role) Role {
	if observer {
		return RoleObserver
	}
	return RoleMember
}

// Option configures Host and Join.
type Option func(*config)

// WithProtocol sets the application's domain-separation label (for example
// "myapp/v1"). Changing an application's label is a protocol version bump:
// clients with different labels derive different session IDs and keys and
// cannot talk to each other.
func WithProtocol(label string) Option {
	return func(c *config) { c.protocol = label }
}

// WithRolePolicy installs the policy used to assign roles to joiners when
// this end is the session host. Pass it to Join as well as Host: after a
// host migration the promoted joiner becomes the role assigner.
func WithRolePolicy(p RolePolicy) Option {
	return func(c *config) { c.rolePolicy = p }
}

// WithObserver marks a Join as an observer: the joiner asks the host to
// seat it with an observer role rather than a member seat. The intent rides
// the first handshake flight; the host's RolePolicy decides what to do with
// it. No effect on Host.
func WithObserver() Option {
	return func(c *config) { c.observer = true }
}

func buildConfig(opts []Option) config {
	cfg := config{protocol: DefaultProtocol, rolePolicy: DefaultRolePolicy}
	for _, o := range opts {
		o(&cfg)
	}
	return cfg
}

// Host creates a new session on the relay and returns a keyed client plus
// the freshly generated code phrase. Joiner roles are assigned by the
// configured RolePolicy (see WithRolePolicy); the default seats observers
// as RoleObserver and everyone else as RoleMember.
func Host(ctx context.Context, relayURL string, opts ...Option) (*Client, string, error) {
	p := phrase.New()
	c, err := dial(ctx, relayURL, p, buildConfig(opts))
	if err != nil {
		return nil, "", err
	}
	if err := c.hostHello(ctx); err != nil {
		_ = c.conn.CloseNow()
		return nil, "", err
	}
	go c.readLoop(c.conn)
	go c.pingLoop(c.conn)
	return c, p, nil
}

// Join connects to an existing session with its phrase. It returns once the
// handshake completes and the client is keyed; a wrong phrase surfaces as
// crypto.ErrUnwrap. A joiner that wants to watch rather than participate
// passes WithObserver.
func Join(ctx context.Context, relayURL, phraseText string, opts ...Option) (*Client, error) {
	cfg := buildConfig(opts)
	c, err := dial(ctx, relayURL, phraseText, cfg)
	if err != nil {
		return nil, err
	}
	c.observer = cfg.observer
	if err := c.joinHello(ctx); err != nil {
		_ = c.conn.CloseNow()
		return nil, err
	}
	go c.readLoop(c.conn)
	go c.pingLoop(c.conn)
	return c, nil
}

// Reconnect re-dials the relay and reclaims this client's slot after an
// unexpected drop, preserving the participant id, role, group key, and per-
// service send sequence — so peers see an uninterrupted sender and no re-key is
// needed. It returns once keyed traffic can flow again; the caller then rebinds
// its routing layer onto the client. A rejected reclaim (grace expired, relay
// restarted, bad token) returns an error the caller should treat as terminal.
//
// Precondition: the previous readLoop has ended (the events channel closed),
// which is exactly the state after a Closed event — so no goroutine is touching
// the client when Reconnect runs.
func (c *Client) Reconnect(ctx context.Context) error {
	dialURL, err := sessionURL(c.relayURL, c.sid)
	if err != nil {
		return err
	}
	conn, _, err := websocket.Dial(ctx, dialURL, nil)
	if err != nil {
		return fmt.Errorf("session: redial relay: %w", err)
	}
	conn.SetReadLimit(wire.MaxFrame + 16)
	c.conn = conn
	if err := c.writeFrame(wire.MsgResumeSession, wire.ResumeSession{
		SessionID: c.sid, ParticipantID: c.self, Token: c.resumeToken,
	}); err != nil {
		_ = conn.CloseNow()
		return err
	}
	raw, err := c.awaitReply(ctx, wire.MsgJoinResult)
	if err != nil {
		_ = conn.CloseNow()
		return err
	}
	jr, err := wire.Body[wire.JoinResult](raw)
	if err != nil {
		_ = conn.CloseNow()
		return err
	}
	if !jr.OK {
		_ = conn.CloseNow()
		return fmt.Errorf("session: resume refused: %s", jr.Err)
	}
	if len(jr.ResumeToken) > 0 {
		c.resumeToken = jr.ResumeToken
	}
	// Fresh event stream for the new connection; the routing layer picks it
	// up when it rebinds.
	c.events = make(chan Event, eventBuffer)
	go c.readLoop(c.conn)
	go c.pingLoop(c.conn)
	return nil
}

// pingLoop heartbeats every pingInterval so the relay's idle timeout never
// fires, NAT mappings stay warm, and — most importantly — the read loop's
// deadline keeps getting refreshed by the returning pongs on a healthy but
// quiet connection. It writes to its own conn so a later Reconnect swapping
// c.conn never makes a stale loop touch the new connection; a write failure
// (dead socket) force-closes conn to unblock the read loop.
func (c *Client) pingLoop(conn *websocket.Conn) {
	t := time.NewTicker(pingInterval)
	defer t.Stop()
	var nonce uint32
	for range t.C {
		nonce++
		frame, err := wire.Encode(wire.MsgPing, wire.Ping{Nonce: nonce})
		if err != nil {
			continue
		}
		c.writeMu.Lock()
		err = conn.Write(context.Background(), websocket.MessageBinary, frame)
		c.writeMu.Unlock()
		if err != nil {
			_ = conn.CloseNow()
			return
		}
	}
}

// sessionURL appends the SessionID routing hint (wire.SessionParam) to a relay
// URL, preserving its scheme, path, and any existing query. Multi-node relays
// use the hint to route every connection for a session to one node; a
// single-node relay ignores it.
func sessionURL(relayURL string, sid wire.SessionID) (string, error) {
	u, err := url.Parse(relayURL)
	if err != nil {
		return "", fmt.Errorf("session: parse relay url: %w", err)
	}
	q := u.Query()
	q.Set(wire.SessionParam, sid.Hex())
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func dial(ctx context.Context, relayURL, phraseText string, cfg config) (*Client, error) {
	canonical := phrase.Canonical(phraseText)
	sid := phrase.SessionID(cfg.protocol, canonical)
	dialURL, err := sessionURL(relayURL, sid)
	if err != nil {
		return nil, err
	}
	conn, _, err := websocket.Dial(ctx, dialURL, nil)
	if err != nil {
		return nil, fmt.Errorf("session: dial relay: %w", err)
	}
	conn.SetReadLimit(wire.MaxFrame + 16)
	return &Client{
		conn:       conn,
		relayURL:   relayURL, // param-free base; Reconnect re-derives the ?s= hint
		proto:      cfg.protocol,
		rolePolicy: cfg.rolePolicy,
		sid:        sid,
		phraseC:    canonical,
		events:     make(chan Event, eventBuffer),
		seqs:       map[string]uint64{},
		joiners:    map[wire.ParticipantID]Role{},
		pairwise:   map[wire.ParticipantID]crypto.Key{},
	}, nil
}

// Events delivers session events. The channel closes after Closed.
func (c *Client) Events() <-chan Event { return c.events }

// Self returns this client's participant ID (valid after construction).
func (c *Client) Self() wire.ParticipantID { return c.self }

// HostID returns the session host's participant ID. Locked because host
// migration can reassign it from another goroutine (see SetHostID/BecomeHost).
func (c *Client) HostID() wire.ParticipantID {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hostID
}

// Role returns this client's role (RoleHost, or as assigned by the host).
func (c *Client) Role() Role {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.role
}

// BecomeHost promotes this client to session host in place after a host
// migration: role→RoleHost, hostID→self. The group key and keyed flag are
// untouched — the successor already holds the key and wraps that same key to
// future joiners (no re-key). Called on the routing goroutine during
// promotion.
func (c *Client) BecomeHost() {
	c.mu.Lock()
	c.role = RoleHost
	c.hostID = c.self
	c.mu.Unlock()
}

// SetHostID re-points a non-host survivor at the newly elected host so its ctl
// accepts the new host's announces and its services address the right authority.
func (c *Client) SetHostID(id wire.ParticipantID) {
	c.mu.Lock()
	c.hostID = id
	c.mu.Unlock()
}

// ClaimHost tells the relay this client is the new host, so it routes future
// joiners' handshake here. Safe from any goroutine (writeFrame holds writeMu).
func (c *Client) ClaimHost() error {
	return c.writeFrame(wire.MsgClaimHost, wire.ClaimHost{})
}

// RotateForMigration is called on the promoted host immediately after
// BecomeHost: it mints a fresh group key the departed host does NOT hold, so
// once survivors re-fetch it (see RekeyWithNewHost) the departed host is locked
// out of subsequent traffic. The old key is retained in the ring so in-flight
// frames still open, and the pairwise map is reset (a promoted host holds none)
// to refill as survivors re-PAKE. Runs on the routing goroutine, before any
// survivor's re-PAKE can traverse the network, so the fresh key is in place
// when the re-PAKE responder wraps it.
func (c *Client) RotateForMigration() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.role != RoleHost || c.hostID != c.self {
		return
	}
	newKey, err := crypto.NewGroupKey()
	if err != nil {
		return
	}
	c.pushPrevKeyLocked(c.groupKey)
	c.groupKey = newKey
	c.pairwise = map[wire.ParticipantID]crypto.Key{}
}

// RekeyWithNewHost is called on a surviving non-host member after a host
// migration: the promoted host shares no pairwise key with it, so it re-runs
// the PAKE (over the phrase everyone still holds) to establish one; the host
// replies (KindRekeyPake2) and then delivers the rotated group key (KindRekey).
// No-op if we are the host or not keyed.
func (c *Client) RekeyWithNewHost() error {
	c.mu.Lock()
	if c.role == RoleHost || c.hostID == c.self || !c.keyed {
		c.mu.Unlock()
		return nil
	}
	host := c.hostID
	j, err := crypto.NewJoiner(c.proto, c.phraseC)
	if err != nil {
		c.mu.Unlock()
		return err
	}
	c.rekeyJoiner = j
	c.mu.Unlock()
	payload, err := wire.EncodePayload(wire.KindRekeyPake1, wire.Pake{Data: j.Flight1})
	if err != nil {
		return err
	}
	return c.writeFrame(wire.MsgDirect, wire.Direct{To: host, Payload: payload})
}

// Close tears the connection down gracefully (a normal-closure "bye"); the
// relay treats this as leaving for good — no grace, no reconnect.
func (c *Client) Close() error {
	return c.conn.Close(websocket.StatusNormalClosure, "bye")
}

// CloseNow drops the connection abruptly, with no close handshake — as a real
// network loss does. The relay classifies this as unexpected and holds the slot
// for its grace window, so a subsequent Reconnect can reclaim it. The read loop
// emits Closed("connection lost") and exits.
func (c *Client) CloseNow() error {
	return c.conn.CloseNow()
}

// Broadcast seals one service message to every other participant.
func (c *Client) Broadcast(serviceID string, body []byte) error {
	payload, err := c.seal(serviceID, body)
	if err != nil {
		return err
	}
	return c.writeFrame(wire.MsgBroadcast, wire.Broadcast{Payload: payload})
}

// SendTo seals one service message to a single participant.
func (c *Client) SendTo(to wire.ParticipantID, serviceID string, body []byte) error {
	payload, err := c.seal(serviceID, body)
	if err != nil {
		return err
	}
	return c.writeFrame(wire.MsgDirect, wire.Direct{To: to, Payload: payload})
}

func (c *Client) seal(serviceID string, body []byte) ([]byte, error) {
	c.mu.Lock()
	if !c.keyed {
		c.mu.Unlock()
		return nil, errors.New("session: not keyed yet")
	}
	c.seqs[serviceID]++
	env := wire.Envelope{ServiceID: serviceID, Seq: c.seqs[serviceID], Body: body}
	key := c.groupKey
	c.mu.Unlock()

	plain, err := wire.Marshal(env)
	if err != nil {
		return nil, err
	}
	sf, err := crypto.Seal(key, plain, c.sid, c.self)
	if err != nil {
		return nil, err
	}
	return wire.EncodePayload(wire.KindSealed, sf)
}

// openFrame decrypts a received SealedFrame, trying the current group key first
// and then any recently-superseded key (a frame may have been sealed under the
// old key and still be in flight when a rekey lands). Returns ok=false if not
// keyed or no key opens it (tampered / foreign / too-old).
func (c *Client) openFrame(sf wire.SealedFrame, sender wire.ParticipantID) ([]byte, bool) {
	c.mu.Lock()
	if !c.keyed {
		c.mu.Unlock()
		return nil, false
	}
	keys := make([]crypto.Key, 0, 1+len(c.prevKeys))
	keys = append(keys, c.groupKey)
	keys = append(keys, c.prevKeys...)
	c.mu.Unlock()
	for _, k := range keys {
		if plain, err := crypto.Open(k, sf, c.sid, sender); err == nil {
			return plain, true
		}
	}
	return nil, false
}

// pushPrevKeyLocked records a superseded group key at the front of the ring,
// dropping the oldest past prevKeyRing. Caller holds c.mu.
func (c *Client) pushPrevKeyLocked(old crypto.Key) {
	c.prevKeys = append([]crypto.Key{old}, c.prevKeys...)
	if len(c.prevKeys) > prevKeyRing {
		c.prevKeys = c.prevKeys[:prevKeyRing]
	}
}

// rekeyAfterLeave rotates the group key when a member leaves so the departed
// participant can no longer decrypt new traffic. It re-wraps a fresh key to
// every member this host holds a pairwise key for (c.pairwise) — populated at
// join by the original host and by the re-PAKE for a promoted host, so this
// works in both cases. No-op unless we are the host with at least one such
// member. Runs on the readLoop goroutine, the same one that keys new joiners
// and handles re-PAKEs, so it never races those. Role is RoleNone: a member's
// role never changes on a leave, so survivors keep their existing one.
func (c *Client) rekeyAfterLeave() {
	c.mu.Lock()
	if c.role != RoleHost || c.hostID != c.self || len(c.pairwise) == 0 {
		c.mu.Unlock()
		return
	}
	newKey, err := crypto.NewGroupKey()
	if err != nil {
		c.mu.Unlock()
		return
	}
	type rekeyTo struct {
		to wire.ParticipantID
		gk wire.GroupKey
	}
	outs := make([]rekeyTo, 0, len(c.pairwise))
	for id, pw := range c.pairwise {
		wrapped, werr := crypto.WrapGroupKey(pw, newKey, byte(RoleNone), c.sid, id)
		if werr != nil {
			c.mu.Unlock()
			return
		}
		outs = append(outs, rekeyTo{to: id, gk: wrapped})
	}
	c.mu.Unlock()

	// Send every rekey (wrapped under pairwise keys, independent of the group
	// key) BEFORE swapping our own key. Per-sender ordering then guarantees each
	// survivor installs the new key before any new-key group frame from us.
	for _, o := range outs {
		payload, perr := wire.EncodePayload(wire.KindRekey, o.gk)
		if perr != nil {
			continue
		}
		_ = c.writeFrame(wire.MsgDirect, wire.Direct{To: o.to, Payload: payload})
	}
	c.mu.Lock()
	c.pushPrevKeyLocked(c.groupKey)
	c.groupKey = newKey
	c.mu.Unlock()
}

// handleRekey installs a fresh group key a member received from the host after
// another member left. Verified to come from the host and unwrapped under the
// retained pairwise key; the old key is kept briefly (prev-key ring) so frames
// in flight still open.
func (c *Client) handleRekey(from wire.ParticipantID, praw []byte) {
	c.mu.Lock()
	ok := c.haveHostPairwise && from == c.hostID
	pw := c.hostPairwise
	c.mu.Unlock()
	if !ok {
		return
	}
	gk, err := wire.Body[wire.GroupKey](praw)
	if err != nil {
		return
	}
	key, role, err := crypto.UnwrapGroupKey(pw, gk, c.sid, c.self)
	if err != nil {
		return
	}
	c.mu.Lock()
	c.pushPrevKeyLocked(c.groupKey)
	c.groupKey = key
	if Role(role) != RoleNone { // a migration rekey wraps RoleNone: keep our existing role
		c.role = Role(role)
	}
	c.mu.Unlock()
}

func (c *Client) writeFrame(t wire.MsgType, body any) error {
	frame, err := wire.Encode(t, body)
	if err != nil {
		return err
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.conn.Write(context.Background(), websocket.MessageBinary, frame)
}

func (c *Client) readFrame(ctx context.Context) (wire.MsgType, []byte, error) {
	return c.readFrameConn(ctx, c.conn)
}

// readFrameConn reads one frame from a specific connection. The read loop
// passes its own conn so a later Reconnect swapping c.conn never races it.
func (c *Client) readFrameConn(ctx context.Context, conn *websocket.Conn) (wire.MsgType, []byte, error) {
	_, data, err := conn.Read(ctx)
	if err != nil {
		return 0, nil, err
	}
	return wire.Decode(data)
}

func (c *Client) emit(e Event) {
	c.events <- e
}
