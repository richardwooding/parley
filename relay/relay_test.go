package relay

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/time/rate"

	"github.com/richardwooding/parley/wire"
)

// testClient is a raw wire-protocol client for exercising the relay.
type testClient struct {
	t    *testing.T
	conn *websocket.Conn
	ctx  context.Context
}

func newServer(t *testing.T, opts Options) *httptest.Server {
	t.Helper()
	s := New(opts)
	t.Cleanup(s.Close)
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	return srv
}

func dial(t *testing.T, srv *httptest.Server) *testClient {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.CloseNow() })
	return &testClient{t: t, conn: conn, ctx: ctx}
}

func (c *testClient) write(t wire.MsgType, body any) {
	c.t.Helper()
	frame, err := wire.Encode(t, body)
	if err != nil {
		c.t.Fatalf("encode: %v", err)
	}
	if err := c.conn.Write(c.ctx, websocket.MessageBinary, frame); err != nil {
		c.t.Fatalf("write: %v", err)
	}
}

func (c *testClient) read() (wire.MsgType, []byte) {
	c.t.Helper()
	_, data, err := c.conn.Read(c.ctx)
	if err != nil {
		c.t.Fatalf("read: %v", err)
	}
	typ, raw, err := wire.Decode(data)
	if err != nil {
		c.t.Fatalf("decode: %v", err)
	}
	return typ, raw
}

// expect reads frames until one of type want arrives, failing on anything
// unexpected other than membership notifications, which tests often ignore.
func expect[T any](c *testClient, want wire.MsgType) T {
	c.t.Helper()
	for range 10 {
		typ, raw := c.read()
		if typ == want {
			v, err := wire.Body[T](raw)
			if err != nil {
				c.t.Fatalf("body: %v", err)
			}
			return v
		}
		if typ == wire.MsgParticipantJoined || typ == wire.MsgParticipantLeft {
			continue
		}
		c.t.Fatalf("got message type %v, want %v", typ, want)
	}
	c.t.Fatalf("no %v frame in 10 messages", want)
	panic("unreachable")
}

var sid = wire.SessionID{0xaa, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

func createSession(t *testing.T, srv *httptest.Server) *testClient {
	t.Helper()
	host := dial(t, srv)
	host.write(wire.MsgCreateSession, wire.CreateSession{SessionID: sid, MaxParticipants: 4})
	created := expect[wire.SessionCreated](host, wire.MsgSessionCreated)
	if created.ParticipantID != 1 {
		t.Fatalf("host ID = %d, want 1", created.ParticipantID)
	}
	return host
}

func TestCreateAndJoin(t *testing.T) {
	srv := newServer(t, Options{})
	host := createSession(t, srv)

	joiner := dial(t, srv)
	joiner.write(wire.MsgJoinSession, wire.JoinSession{SessionID: sid})
	jr := expect[wire.JoinResult](joiner, wire.MsgJoinResult)
	if !jr.OK || jr.ParticipantID != 2 || jr.HostID != 1 {
		t.Fatalf("join result %+v", jr)
	}
	if len(jr.Peers) != 1 || jr.Peers[0] != 1 {
		t.Fatalf("peers %v, want [1]", jr.Peers)
	}

	pj := expect[wire.ParticipantJoined](host, wire.MsgParticipantJoined)
	if pj.ParticipantID != 2 {
		t.Fatalf("host notified of %d, want 2", pj.ParticipantID)
	}
}

func TestDirectStampsFrom(t *testing.T) {
	srv := newServer(t, Options{})
	host := createSession(t, srv)
	joiner := dial(t, srv)
	joiner.write(wire.MsgJoinSession, wire.JoinSession{SessionID: sid})
	expect[wire.JoinResult](joiner, wire.MsgJoinResult)

	// Joiner lies about From — the relay must overwrite it.
	joiner.write(wire.MsgDirect, wire.Direct{To: 1, From: 99, Payload: []byte("hello")})
	d := expect[wire.Direct](host, wire.MsgDirect)
	if d.From != 2 {
		t.Fatalf("From = %d, want relay-stamped 2", d.From)
	}
	if string(d.Payload) != "hello" {
		t.Fatalf("payload %q", d.Payload)
	}
}

func TestBroadcastExcludesSender(t *testing.T) {
	srv := newServer(t, Options{})
	host := createSession(t, srv)
	j2 := dial(t, srv)
	j2.write(wire.MsgJoinSession, wire.JoinSession{SessionID: sid})
	expect[wire.JoinResult](j2, wire.MsgJoinResult)
	j3 := dial(t, srv)
	j3.write(wire.MsgJoinSession, wire.JoinSession{SessionID: sid})
	expect[wire.JoinResult](j3, wire.MsgJoinResult)

	j2.write(wire.MsgBroadcast, wire.Broadcast{Payload: []byte("all")})
	for _, c := range []*testClient{host, j3} {
		b := expect[wire.Broadcast](c, wire.MsgBroadcast)
		if b.From != 2 || string(b.Payload) != "all" {
			t.Fatalf("broadcast %+v", b)
		}
	}
	// Sender must NOT receive its own broadcast: send a ping and ensure the
	// next frame is the pong, not an echoed broadcast.
	j2.write(wire.MsgPing, wire.Ping{Nonce: 7})
	if p := expect[wire.Pong](j2, wire.MsgPong); p.Nonce != 7 {
		t.Fatalf("pong nonce %d", p.Nonce)
	}
}

func TestJoinMissingSession(t *testing.T) {
	srv := newServer(t, Options{})
	c := dial(t, srv)
	c.write(wire.MsgJoinSession, wire.JoinSession{SessionID: wire.SessionID{0xff}})
	e := expect[wire.Error](c, wire.MsgError)
	if e.Code != wire.ErrCodeSessionNotFound {
		t.Fatalf("error code %d", e.Code)
	}
}

func TestSessionFull(t *testing.T) {
	srv := newServer(t, Options{MaxParticipants: 2})
	createSession(t, srv)
	j2 := dial(t, srv)
	j2.write(wire.MsgJoinSession, wire.JoinSession{SessionID: sid})
	expect[wire.JoinResult](j2, wire.MsgJoinResult)

	j3 := dial(t, srv)
	j3.write(wire.MsgJoinSession, wire.JoinSession{SessionID: sid})
	e := expect[wire.Error](j3, wire.MsgError)
	if e.Code != wire.ErrCodeSessionFull {
		t.Fatalf("error code %d", e.Code)
	}
}

func TestDuplicateCreate(t *testing.T) {
	srv := newServer(t, Options{})
	createSession(t, srv)
	c := dial(t, srv)
	c.write(wire.MsgCreateSession, wire.CreateSession{SessionID: sid, MaxParticipants: 4})
	e := expect[wire.Error](c, wire.MsgError)
	if e.Code != wire.ErrCodeSessionExists {
		t.Fatalf("error code %d", e.Code)
	}
}

// TestHostLeaveMigratesNotCloses: the host is no longer special — a host leave
// with survivors broadcasts ParticipantLeft (not SessionClosed), the session
// stays open, and the survivor can claim host so a new joiner is routed to it.
func TestHostLeaveMigratesNotCloses(t *testing.T) {
	srv := newServer(t, Options{})
	host := createSession(t, srv)
	joiner := dial(t, srv)
	joiner.write(wire.MsgJoinSession, wire.JoinSession{SessionID: sid})
	expect[wire.JoinResult](joiner, wire.MsgJoinResult)

	_ = host.conn.Close(websocket.StatusNormalClosure, "bye")
	pl := expect[wire.ParticipantLeft](joiner, wire.MsgParticipantLeft)
	if pl.ParticipantID != 1 {
		t.Fatalf("left ID %d, want the departed host (1)", pl.ParticipantID)
	}

	// The session lives on. The survivor claims host → a new joiner is routed to
	// it (JoinResult.HostID == the survivor, id 2).
	joiner.write(wire.MsgClaimHost, wire.ClaimHost{})
	c := dial(t, srv)
	c.write(wire.MsgJoinSession, wire.JoinSession{SessionID: sid})
	jr := expect[wire.JoinResult](c, wire.MsgJoinResult)
	if !jr.OK || jr.HostID != 2 {
		t.Fatalf("new joiner routed to host %d, want migrated host 2 (%+v)", jr.HostID, jr)
	}
}

// TestLastLeaveClosesSession: the hub closes only when the LAST participant is
// gone (empty), regardless of who it was.
func TestLastLeaveClosesSession(t *testing.T) {
	srv := newServer(t, Options{})
	host := createSession(t, srv)
	_ = host.conn.Close(websocket.StatusNormalClosure, "bye")
	// The now-empty session must be gone: a new join fails.
	c := dial(t, srv)
	c.write(wire.MsgJoinSession, wire.JoinSession{SessionID: sid})
	e := expect[wire.Error](c, wire.MsgError)
	if e.Code != wire.ErrCodeSessionNotFound {
		t.Fatalf("error code %d", e.Code)
	}
}

func TestPeerLeaveNotifies(t *testing.T) {
	srv := newServer(t, Options{})
	host := createSession(t, srv)
	joiner := dial(t, srv)
	joiner.write(wire.MsgJoinSession, wire.JoinSession{SessionID: sid})
	expect[wire.JoinResult](joiner, wire.MsgJoinResult)
	expect[wire.ParticipantJoined](host, wire.MsgParticipantJoined)

	_ = joiner.conn.Close(websocket.StatusNormalClosure, "bye")
	pl := expect[wire.ParticipantLeft](host, wire.MsgParticipantLeft)
	if pl.ParticipantID != 2 {
		t.Fatalf("left ID %d", pl.ParticipantID)
	}
}

func TestDirectToUnknownPeer(t *testing.T) {
	srv := newServer(t, Options{})
	host := createSession(t, srv)
	host.write(wire.MsgDirect, wire.Direct{To: 42, Payload: []byte("x")})
	e := expect[wire.Error](host, wire.MsgError)
	if e.Code != wire.ErrCodeUnknownPeer {
		t.Fatalf("error code %d", e.Code)
	}
}

func TestMaxAgeSweep(t *testing.T) {
	srv := newServer(t, Options{MaxAge: 50 * time.Millisecond, SweepEvery: 20 * time.Millisecond})
	host := createSession(t, srv)
	sc := expect[wire.SessionClosed](host, wire.MsgSessionClosed)
	if sc.Reason != "session expired" {
		t.Fatalf("reason %q", sc.Reason)
	}
}

func TestConnRateLimit(t *testing.T) {
	srv := newServer(t, Options{ConnRate: rate.Every(time.Hour), ConnBurst: 2})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	for i := range 2 {
		conn, _, err := websocket.Dial(ctx, url, nil)
		if err != nil {
			t.Fatalf("dial %d within burst: %v", i, err)
		}
		_ = conn.CloseNow()
	}
	if _, _, err := websocket.Dial(ctx, url, nil); err == nil {
		t.Fatal("third dial exceeded burst but was accepted")
	}
}

func TestSessionCapacity(t *testing.T) {
	srv := newServer(t, Options{MaxSessions: 1})
	createSession(t, srv)
	c := dial(t, srv)
	c.write(wire.MsgCreateSession, wire.CreateSession{SessionID: wire.SessionID{0xbb}, MaxParticipants: 2})
	e := expect[wire.Error](c, wire.MsgError)
	if e.Code != wire.ErrCodeRateLimited {
		t.Fatalf("error code %d", e.Code)
	}
}

// joinWithToken joins and returns the client plus its reclaim token.
func joinWithToken(t *testing.T, srv *httptest.Server) (*testClient, []byte) {
	t.Helper()
	j := dial(t, srv)
	j.write(wire.MsgJoinSession, wire.JoinSession{SessionID: sid})
	jr := expect[wire.JoinResult](j, wire.MsgJoinResult)
	if !jr.OK || len(jr.ResumeToken) == 0 {
		t.Fatalf("join result %+v (want OK + token)", jr)
	}
	return j, jr.ResumeToken
}

// TestResumeReclaimsSlot: an unexpected drop holds the slot; resuming with the
// token re-attaches to the SAME id, and frames buffered during the outage flush
// (JoinResult-first) to the resumed connection.
func TestResumeReclaimsSlot(t *testing.T) {
	srv := newServer(t, Options{Grace: 5 * time.Second})
	host := createSession(t, srv)
	joiner, token := joinWithToken(t, srv)
	expect[wire.ParticipantJoined](host, wire.MsgParticipantJoined)

	// Abrupt drop (no close frame) → the relay holds the slot for grace.
	_ = joiner.conn.CloseNow()
	time.Sleep(150 * time.Millisecond) // let the hold register

	// A broadcast during the outage buffers on the held slot.
	host.write(wire.MsgBroadcast, wire.Broadcast{Payload: []byte("during-outage")})
	time.Sleep(50 * time.Millisecond)

	resumed := dial(t, srv)
	resumed.write(wire.MsgResumeSession, wire.ResumeSession{SessionID: sid, ParticipantID: 2, Token: token})
	jr := expect[wire.JoinResult](resumed, wire.MsgJoinResult)
	if !jr.OK || jr.ParticipantID != 2 || jr.HostID != 1 {
		t.Fatalf("resume result %+v", jr)
	}
	// The buffered broadcast arrives after the JoinResult.
	b := expect[wire.Broadcast](resumed, wire.MsgBroadcast)
	if string(b.Payload) != "during-outage" {
		t.Fatalf("buffered payload %q", b.Payload)
	}
	// Live traffic resumes on the same id.
	host.write(wire.MsgBroadcast, wire.Broadcast{Payload: []byte("after")})
	if b := expect[wire.Broadcast](resumed, wire.MsgBroadcast); string(b.Payload) != "after" {
		t.Fatalf("post-resume payload %q", b.Payload)
	}
}

// TestResumeSupersedesLiveSlot: a half-open drop can leave the relay still
// believing the old connection is live (it hasn't read an error yet). A resume
// with the right token must still reclaim the id — kicking the stale connection
// — rather than reject because the slot isn't "held".
func TestResumeSupersedesLiveSlot(t *testing.T) {
	srv := newServer(t, Options{Grace: 5 * time.Second})
	host := createSession(t, srv)
	joiner, token := joinWithToken(t, srv)
	expect[wire.ParticipantJoined](host, wire.MsgParticipantJoined)

	// The joiner is still live from the relay's view. Reclaim from a new conn.
	resumed := dial(t, srv)
	resumed.write(wire.MsgResumeSession, wire.ResumeSession{SessionID: sid, ParticipantID: 2, Token: token})
	jr := expect[wire.JoinResult](resumed, wire.MsgJoinResult)
	if !jr.OK || jr.ParticipantID != 2 {
		t.Fatalf("supersede resume %+v", jr)
	}
	// The stale old connection is kicked; the new one carries traffic.
	host.write(wire.MsgBroadcast, wire.Broadcast{Payload: []byte("to-resumed")})
	if b := expect[wire.Broadcast](resumed, wire.MsgBroadcast); string(b.Payload) != "to-resumed" {
		t.Fatalf("resumed got %q", b.Payload)
	}
	// The old joiner connection must be closed now.
	joiner.conn.SetReadLimit(1 << 20)
	if _, _, err := joiner.conn.Read(joiner.ctx); err == nil {
		t.Fatal("stale connection was not kicked")
	}
}

// TestResumeBadToken: a wrong token is rejected.
func TestResumeBadToken(t *testing.T) {
	srv := newServer(t, Options{Grace: 5 * time.Second})
	createSession(t, srv)
	joiner, _ := joinWithToken(t, srv)
	_ = joiner.conn.CloseNow()
	time.Sleep(150 * time.Millisecond)

	c := dial(t, srv)
	c.write(wire.MsgResumeSession, wire.ResumeSession{SessionID: sid, ParticipantID: 2, Token: []byte("wrong-token-bytes-................")})
	e := expect[wire.Error](c, wire.MsgError)
	if e.Code != wire.ErrCodeResumeRejected {
		t.Fatalf("error code %d, want ResumeRejected", e.Code)
	}
}

// TestGraceExpiryNotifies: with no resume, the held slot expires and peers are
// finally told the participant left (which forfeits any live game).
func TestGraceExpiryNotifies(t *testing.T) {
	srv := newServer(t, Options{Grace: 80 * time.Millisecond})
	host := createSession(t, srv)
	joiner, _ := joinWithToken(t, srv)
	expect[wire.ParticipantJoined](host, wire.MsgParticipantJoined)

	_ = joiner.conn.CloseNow()
	pl := expect[wire.ParticipantLeft](host, wire.MsgParticipantLeft)
	if pl.ParticipantID != 2 {
		t.Fatalf("left ID %d", pl.ParticipantID)
	}
}

// TestHostResume: a host drop is held (no immediate SessionClosed); the host
// reclaims id=1 with its token and the session survives.
func TestHostResume(t *testing.T) {
	srv := newServer(t, Options{Grace: 5 * time.Second})
	host := dial(t, srv)
	host.write(wire.MsgCreateSession, wire.CreateSession{SessionID: sid, MaxParticipants: 4})
	created := expect[wire.SessionCreated](host, wire.MsgSessionCreated)
	hostTok := created.ResumeToken
	joiner, _ := joinWithToken(t, srv)

	_ = host.conn.CloseNow()
	time.Sleep(150 * time.Millisecond)

	// The joiner must NOT have received SessionClosed during grace: resume and
	// confirm the session is intact by round-tripping a broadcast.
	resumed := dial(t, srv)
	resumed.write(wire.MsgResumeSession, wire.ResumeSession{SessionID: sid, ParticipantID: 1, Token: hostTok})
	jr := expect[wire.JoinResult](resumed, wire.MsgJoinResult)
	if !jr.OK || jr.ParticipantID != 1 {
		t.Fatalf("host resume %+v", jr)
	}
	resumed.write(wire.MsgBroadcast, wire.Broadcast{Payload: []byte("host-back")})
	if b := expect[wire.Broadcast](joiner, wire.MsgBroadcast); string(b.Payload) != "host-back" {
		t.Fatalf("joiner got %q after host resume", b.Payload)
	}
}

// TestHostGraceExpiryMigrates: an abrupt host drop is held for grace (no
// ParticipantLeft yet); if the host never returns, grace expiry surfaces the
// departure as a normal ParticipantLeft — the survivor migrates, not closes.
func TestHostGraceExpiryMigrates(t *testing.T) {
	srv := newServer(t, Options{Grace: 80 * time.Millisecond})
	host := createSession(t, srv)
	joiner, _ := joinWithToken(t, srv)
	expect[wire.ParticipantJoined](host, wire.MsgParticipantJoined)

	_ = host.conn.CloseNow()
	pl := expect[wire.ParticipantLeft](joiner, wire.MsgParticipantLeft)
	if pl.ParticipantID != 1 {
		t.Fatalf("left ID %d, want the departed host (1)", pl.ParticipantID)
	}
}
