package relay

import (
	"crypto/rand"
	"crypto/subtle"
	"time"

	"github.com/richardwooding/parley/wire"
)

// hub owns one session. All session state is confined to the run goroutine;
// connection handlers talk to it exclusively through the inbox channel.
type hub struct {
	id      wire.SessionID
	max     int
	grace   time.Duration // how long a dropped slot is held for reconnect (0 = never)
	created time.Time
	inbox   chan any // joinCmd | leaveCmd | resumeCmd | graceExpiredCmd | frameCmd | closeCmd | statsCmd
	done    chan struct{}
	metrics *Metrics // cumulative relay counters (atomic; shared with the Server)

	// Owned by run() — never touched from outside.
	clients map[wire.ParticipantID]*client
	nextID  wire.ParticipantID
	// host is the current authority id used to route new joiners' handshake.
	// It starts as the creator (id 1) and moves on host migration via ClaimHost.
	host wire.ParticipantID
}

// client is the hub's view of one connected participant. out is drained by
// the connection's writer goroutine; if it fills up (slow reader), the hub
// drops the client rather than blocking the whole session.
//
// A client can be *held*: after an unexpected drop the hub keeps the slot
// (same id, same reclaim token) for the grace window so the participant can
// reconnect and resume. While held there is no live writer; frames routed to
// it buffer in out and flush, JoinResult-first, on resume.
type client struct {
	id    wire.ParticipantID
	out   chan []byte
	kick  func() // closes the underlying connection
	token []byte // opaque reclaim secret issued at join
	held  bool
	// gen is the connection generation: bumped on join, hold, and resume. It
	// guards both stale grace timers and stale teardown — a superseded
	// connection's leaveCmd carries an old gen and is ignored.
	gen   uint64
	timer *time.Timer // grace timer while held
}

// sendBuffer is the per-client fan-out buffer. A full buffer means a reader
// slower than the session's traffic — disconnecting it beats stalling everyone.
const sendBuffer = 64

// resumeTokenLen is the length of the opaque per-participant reclaim token.
const resumeTokenLen = 32

type joinCmd struct {
	out      chan []byte
	kick     func()
	isCreate bool // reply with SessionCreated instead of JoinResult
	reply    chan joinReply
}

type joinReply struct {
	ok   bool
	errC uint16
	errS string
	id   wire.ParticipantID
	gen  uint64 // connection generation, echoed on the eventual leaveCmd
}

// leaveCmd reports a connection ending. unexpected drops (network loss, idle
// timeout, abnormal close) hold the slot for grace; a clean close removes it.
// gen is the connection's generation; a mismatch means this connection was
// already superseded (e.g. a fast reconnect) and the leave is ignored.
type leaveCmd struct {
	id         wire.ParticipantID
	gen        uint64
	unexpected bool
}

// resumeCmd reclaims a slot. On a token match the hub re-attaches the new
// connection to the same id and returns its out channel — whether the slot was
// held (grace) or still "live" from the relay's view (a half-open old
// connection the relay hadn't noticed die yet, which is then kicked).
type resumeCmd struct {
	id    wire.ParticipantID
	token []byte
	kick  func()
	reply chan resumeReply
}

type resumeReply struct {
	ok   bool
	errC uint16
	errS string
	out  chan []byte // the slot's out channel, JoinResult already queued
	gen  uint64      // new connection generation, echoed on the eventual leaveCmd
}

// graceExpiredCmd fires when a held slot's grace window elapses. gen guards
// against a stale timer expiring a slot that was resumed (and maybe re-held).
type graceExpiredCmd struct {
	id  wire.ParticipantID
	gen uint64
}

type frameCmd struct {
	from wire.ParticipantID
	typ  wire.MsgType
	raw  []byte // CBOR body as received
}

type closeCmd struct{ reason string }

// claimHostCmd records a host migration: the sender is the new join authority.
type claimHostCmd struct{ id wire.ParticipantID }

const hostID wire.ParticipantID = 1

func newHub(id wire.SessionID, maxParticipants int, grace time.Duration, metrics *Metrics, onEmpty func()) *hub {
	if metrics == nil {
		metrics = &Metrics{}
	}
	h := &hub{
		id:      id,
		max:     maxParticipants,
		grace:   grace,
		created: time.Now(),
		inbox:   make(chan any, 16),
		done:    make(chan struct{}),
		metrics: metrics,
		clients: map[wire.ParticipantID]*client{},
		nextID:  hostID,
		host:    hostID,
	}
	go h.run(onEmpty)
	return h
}

func (h *hub) run(onEmpty func()) {
	defer h.shutdown(onEmpty)
	for cmd := range h.inbox {
		switch cmd := cmd.(type) {
		case joinCmd:
			h.handleJoin(cmd)
		case leaveCmd:
			if h.handleLeave(cmd) {
				return
			}
		case resumeCmd:
			h.handleResume(cmd)
		case graceExpiredCmd:
			if h.handleGraceExpired(cmd) {
				return
			}
		case claimHostCmd:
			h.handleClaimHost(cmd)
		case frameCmd:
			h.route(cmd)
		case statsCmd:
			h.handleStats(cmd)
		case closeCmd:
			h.handleClose(cmd)
			return
		}
	}
}

// shutdown is run's deferred teardown: stop any grace timers, kick every
// remaining connection, then close done and signal the empty callback. Ordering
// (kick all, close done, onEmpty) is unchanged from the inline defer.
func (h *hub) shutdown(onEmpty func()) {
	for _, c := range h.clients {
		if c.timer != nil {
			c.timer.Stop()
		}
		c.kick()
	}
	close(h.done)
	onEmpty()
}

// handleClaimHost records a host migration: a promoted successor becomes the
// join authority so new joiners route to it. Only a live participant can claim
// (the sender is stamped by the connection), and it's within the member trust
// boundary.
func (h *hub) handleClaimHost(cmd claimHostCmd) {
	if _, ok := h.clients[cmd.id]; ok {
		h.host = cmd.id
	}
}

// handleClose broadcasts the SessionClosed notice to all remaining clients;
// run returns immediately after, ending the session.
func (h *hub) handleClose(cmd closeCmd) {
	h.broadcastFrame(wire.MsgSessionClosed, wire.SessionClosed{Reason: cmd.reason}, 0)
}

func (h *hub) handleJoin(cmd joinCmd) {
	if len(h.clients) >= h.max {
		h.metrics.Errors.Add(1)
		cmd.reply <- joinReply{errC: wire.ErrCodeSessionFull, errS: "session full"}
		return
	}
	id := h.nextID
	h.nextID++
	token := newToken()

	// The hello reply MUST be queued here, atomically with registration:
	// once the client is in h.clients, the very next routed broadcast lands
	// in its out channel — if the connection handler queued the reply
	// instead, that broadcast could beat the JoinResult onto the wire.
	var frame []byte
	var err error
	if cmd.isCreate {
		frame, err = wire.Encode(wire.MsgSessionCreated, wire.SessionCreated{ParticipantID: id, ResumeToken: token})
	} else {
		frame, err = wire.Encode(wire.MsgJoinResult, wire.JoinResult{
			OK: true, ParticipantID: id, Peers: h.peersExcept(id), HostID: h.host, ResumeToken: token,
		})
	}
	if err != nil {
		cmd.reply <- joinReply{errC: wire.ErrCodeBadFrame, errS: "encode reply"}
		return
	}
	cmd.out <- frame // fresh buffered channel: never blocks

	h.clients[id] = &client{id: id, out: cmd.out, kick: cmd.kick, token: token, gen: 1}
	h.metrics.Joins.Add(1)
	cmd.reply <- joinReply{ok: true, id: id, gen: 1}
	h.broadcastFrame(wire.MsgParticipantJoined, wire.ParticipantJoined{ParticipantID: id}, id)
}

// handleLeave processes a connection ending. An unexpected drop holds the slot
// for grace (suppressing the ParticipantLeft/forfeit); a clean close removes
// it immediately. Returns true when the hub must shut down.
func (h *hub) handleLeave(cmd leaveCmd) bool {
	c, ok := h.clients[cmd.id]
	if !ok || c.held || c.gen != cmd.gen {
		// Already gone, already held, or this connection was superseded by a
		// faster reconnect (stale gen) — its teardown must not disturb the slot.
		return false
	}
	if cmd.unexpected && h.grace > 0 {
		h.holdSlot(c)
		return false
	}
	return h.removeParticipant(cmd.id)
}

// holdSlot detaches the dying writer and keeps the slot alive for grace. It
// swaps in a fresh out channel so the departing writer drains the old one while
// frames routed during the outage buffer on the new one for the resuming client.
func (h *hub) holdSlot(c *client) {
	c.held = true
	c.gen++
	c.out = make(chan []byte, sendBuffer)
	id, gen := c.id, c.gen
	c.timer = time.AfterFunc(h.grace, func() {
		h.send(graceExpiredCmd{id: id, gen: gen})
	})
}

// handleGraceExpired removes a held slot whose window elapsed. A stale timer
// (the slot was resumed, so gen advanced) is ignored.
func (h *hub) handleGraceExpired(cmd graceExpiredCmd) bool {
	c, ok := h.clients[cmd.id]
	if !ok || !c.held || c.gen != cmd.gen {
		return false
	}
	return h.removeParticipant(cmd.id)
}

// removeParticipant does the real teardown for one participant: the host
// leaving closes the session; the last participant leaving empties it;
// otherwise peers are told it left. The host is NOT special: its departure
// broadcasts ParticipantLeft like any other, and the survivors migrate the host
// role among themselves (see the client's promotion path). The session closes
// only when the last participant is gone.
func (h *hub) removeParticipant(id wire.ParticipantID) bool {
	c, ok := h.clients[id]
	if !ok {
		return false
	}
	if c.timer != nil {
		c.timer.Stop()
	}
	delete(h.clients, id)
	c.kick()
	if len(h.clients) == 0 {
		return true
	}
	h.broadcastFrame(wire.MsgParticipantLeft, wire.ParticipantLeft{ParticipantID: id}, 0)
	return false
}

// handleResume reclaims a held slot on a matching token, re-attaching the new
// connection to the same participant id. Frames buffered during the outage
// flush after the JoinResult, so the resumed client catches up in order.
func (h *hub) handleResume(cmd resumeCmd) {
	c, ok := h.clients[cmd.id]
	if !ok || subtle.ConstantTimeCompare(c.token, cmd.token) != 1 {
		h.metrics.Errors.Add(1)
		cmd.reply <- resumeReply{errC: wire.ErrCodeResumeRejected, errS: "cannot resume session"}
		return
	}
	jr, err := wire.Encode(wire.MsgJoinResult, wire.JoinResult{
		OK: true, ParticipantID: cmd.id, Peers: h.peersExcept(cmd.id), HostID: h.host, ResumeToken: c.token,
	})
	if err != nil {
		cmd.reply <- resumeReply{errC: wire.ErrCodeBadFrame, errS: "encode reply"}
		return
	}
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}

	// A held slot buffered frames on its out channel during the outage; preserve
	// them. A still-"live" slot means the relay hadn't yet noticed the old
	// connection die (a half-open drop) — kick that stale connection and start a
	// fresh out. Either way the new connection resumes the SAME participant id.
	var buffered [][]byte
	if c.held {
		buffered = drainChan(c.out)
	} else {
		c.kick() // supersede the stale/half-open old connection
		c.out = make(chan []byte, sendBuffer)
	}
	c.held = false
	c.gen++ // supersede the old connection: its later leaveCmd (old gen) is ignored
	c.kick = cmd.kick

	// JoinResult must lead: the resuming client's read loop skips session
	// traffic until it sees the reply, so queue it ahead of buffered frames.
	c.out <- jr
	for _, f := range buffered {
		select {
		case c.out <- f:
		default: // extreme backlog: drop the overflow rather than block the hub
		}
	}
	h.metrics.Resumes.Add(1)
	cmd.reply <- resumeReply{ok: true, out: c.out, gen: c.gen}
}

// route forwards Direct/Broadcast frames, re-encoding with From stamped by
// the relay so a client can never spoof its sender ID.
func (h *hub) route(cmd frameCmd) {
	h.metrics.FramesForwarded.Add(1)
	h.metrics.BytesForwarded.Add(uint64(len(cmd.raw)))
	switch cmd.typ {
	case wire.MsgDirect:
		d, err := wire.Body[wire.Direct](cmd.raw)
		if err != nil {
			h.metrics.Errors.Add(1)
			h.sendTo(cmd.from, wire.MsgError, wire.Error{Code: wire.ErrCodeBadFrame, Msg: "bad direct frame"})
			return
		}
		d.From = cmd.from
		if _, ok := h.clients[d.To]; !ok {
			h.metrics.Errors.Add(1)
			h.sendTo(cmd.from, wire.MsgError, wire.Error{Code: wire.ErrCodeUnknownPeer, Msg: "unknown peer"})
			return
		}
		h.sendTo(d.To, wire.MsgDirect, d)
	case wire.MsgBroadcast:
		b, err := wire.Body[wire.Broadcast](cmd.raw)
		if err != nil {
			h.metrics.Errors.Add(1)
			h.sendTo(cmd.from, wire.MsgError, wire.Error{Code: wire.ErrCodeBadFrame, Msg: "bad broadcast frame"})
			return
		}
		b.From = cmd.from
		h.broadcastFrame(wire.MsgBroadcast, b, cmd.from)
	}
}

func (h *hub) sendTo(id wire.ParticipantID, t wire.MsgType, body any) {
	c, ok := h.clients[id]
	if !ok {
		return
	}
	frame, err := wire.Encode(t, body)
	if err != nil {
		return
	}
	h.queue(c, frame)
}

func (h *hub) broadcastFrame(t wire.MsgType, body any, except wire.ParticipantID) {
	frame, err := wire.Encode(t, body)
	if err != nil {
		return
	}
	for id, c := range h.clients {
		if id == except {
			continue
		}
		h.queue(c, frame)
	}
}

// queue enqueues a frame for one client. A held slot buffers (no live writer)
// until grace expires; a full buffer on a *live* client is a slow consumer, so
// drop it rather than stall the session — a full buffer on a held slot means
// the outage overran the buffer, so expire the slot (forfeit).
func (h *hub) queue(c *client, frame []byte) {
	select {
	case c.out <- frame:
	default:
		if c.held {
			h.removeParticipant(c.id)
			return
		}
		delete(h.clients, c.id)
		c.kick()
	}
}

func (h *hub) peersExcept(id wire.ParticipantID) []wire.ParticipantID {
	peers := make([]wire.ParticipantID, 0, len(h.clients))
	for pid := range h.clients {
		if pid != id {
			peers = append(peers, pid)
		}
	}
	return peers
}

// drainChan non-blockingly empties a channel. Safe on the hub goroutine: a held
// slot has no writer, so the hub is the only toucher of its out channel.
func drainChan(ch chan []byte) [][]byte {
	var out [][]byte
	for {
		select {
		case f := <-ch:
			out = append(out, f)
		default:
			return out
		}
	}
}

func newToken() []byte {
	b := make([]byte, resumeTokenLen)
	_, _ = rand.Read(b) // crypto/rand.Read never fails on supported platforms
	return b
}
