// Package relay implements the parley relay server: a blind frame forwarder.
// It manages sessions and participant membership, stamps sender IDs, and
// forwards opaque payloads — it never parses anything inside a Direct or
// Broadcast payload and never learns the code phrase (only its hash).
package relay

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/time/rate"

	"github.com/richardwooding/parley/wire"
)

type Options struct {
	MaxSessions     int           // relay-wide live session cap (default 1000)
	MaxParticipants int           // hard per-session cap; client requests are clamped to it (default 16)
	MaxAge          time.Duration // absolute session lifetime (default 24h)
	SweepEvery      time.Duration // sweeper interval (default 1m)
	IdleTimeout     time.Duration // per-connection read deadline; clients ping to stay alive (default 90s)
	Grace           time.Duration // how long a dropped slot is held for reconnect/resume (default 30s)
	ConnRate        rate.Limit    // per-IP connection attempts (default 5/min)
	ConnBurst       int           // per-IP burst (default 5)
	// Router, when non-nil, is consulted for every connection BEFORE the
	// WebSocket upgrade (and before rate limiting), enabling session-affinity
	// routing across multiple relay nodes. It receives the SessionID parsed
	// from the wire.SessionParam query value and the raw request. Return the
	// zero RouteResult to serve the connection here; return a Replay result to
	// hand the request off without upgrading (e.g. a Fly-Replay header naming
	// the owning node). Nil Router = single-node behavior: the query param is
	// ignored and the relay behaves exactly as it does with no router.
	Router func(sid wire.SessionID, r *http.Request) RouteResult
}

// RouteResult is a Router's decision. The zero value means "serve this
// connection here" — the upgrade proceeds normally. Set Replay to hand the
// request off WITHOUT upgrading: the relay copies Header onto the response and
// writes Status (0 → 503), then returns. All platform specifics (e.g. a
// Fly-Replay header) live in the Router; the relay only relays the directive.
type RouteResult struct {
	Replay bool
	Header http.Header
	Status int
}

func (o *Options) defaults() {
	if o.MaxSessions <= 0 {
		o.MaxSessions = 1000
	}
	if o.MaxParticipants <= 0 {
		o.MaxParticipants = 16
	}
	if o.MaxAge <= 0 {
		o.MaxAge = 24 * time.Hour
	}
	if o.SweepEvery <= 0 {
		o.SweepEvery = time.Minute
	}
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = 90 * time.Second
	}
	if o.Grace <= 0 {
		o.Grace = 30 * time.Second
	}
	if o.ConnRate <= 0 {
		o.ConnRate = rate.Every(12 * time.Second) // 5/min
	}
	if o.ConnBurst <= 0 {
		o.ConnBurst = 5
	}
}

// Server is an http.Handler that upgrades to WebSocket and speaks the wire
// protocol. Mount it at /ws.
type Server struct {
	opts    Options
	reg     *registry
	limiter *ipLimiter
	metrics *Metrics
	started time.Time
	stop    chan struct{}
}

func New(opts Options) *Server {
	opts.defaults()
	m := &Metrics{}
	s := &Server{
		opts:    opts,
		reg:     newRegistry(opts.MaxSessions, opts.MaxAge, opts.Grace, m),
		limiter: newIPLimiter(opts.ConnRate, opts.ConnBurst),
		metrics: m,
		started: time.Now(),
		stop:    make(chan struct{}),
	}
	go s.reg.sweepLoop(opts.SweepEvery, s.stop)
	return s
}

// Close stops the background sweeper. Live connections wind down with their
// own contexts.
func (s *Server) Close() { close(s.stop) }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Session-affinity routing runs before rate limiting and the upgrade: a
	// node that will only hand this connection off must not burn its own
	// rate-limit budget, and fly-replay must decide from the HTTP request
	// before Accept writes the 101.
	if s.opts.Router != nil {
		sid, ok := parseSessionParam(r)
		if !ok {
			http.Error(w, "missing or malformed session id", http.StatusBadRequest)
			return
		}
		if res := s.opts.Router(sid, r); res.Replay {
			for k, vs := range res.Header {
				for _, v := range vs {
					w.Header().Add(k, v)
				}
			}
			status := res.Status
			if status == 0 {
				status = http.StatusServiceUnavailable
			}
			w.WriteHeader(status)
			return
		}
	}
	if !s.limiter.allow(r.RemoteAddr) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// The web client may be served from a different origin than a
		// self-hosted relay; session security comes from PAKE, not Origin.
		OriginPatterns: []string{"*"},
	})
	if err != nil {
		return
	}
	conn.SetReadLimit(wire.MaxFrame + 16)
	s.handle(r.Context(), conn)
}

// parseSessionParam extracts and validates the routing-hint SessionID from the
// request's query string. Reports false for a missing or malformed value.
func parseSessionParam(r *http.Request) (wire.SessionID, bool) {
	h := r.URL.Query().Get(wire.SessionParam)
	if h == "" {
		return wire.SessionID{}, false
	}
	sid, err := wire.ParseSessionID(h)
	if err != nil {
		return wire.SessionID{}, false
	}
	return sid, true
}

// handle drives one connection: hello (create or join), the relay loop, then
// an explicit teardown that flushes queued frames (e.g. SessionClosed) before
// the socket closes.
func (s *Server) handle(ctx context.Context, conn *websocket.Conn) {
	ctx, cancel := context.WithCancel(ctx)
	defer func() { _ = conn.CloseNow() }()

	// kicked is the hub's way to shed this client. It must NOT cancel ctx
	// directly: coder/websocket tears down the whole connection the moment a
	// Read context dies, which would race ahead of queued frames like
	// SessionClosed. The writer drains first, then cancels.
	kicked := make(chan struct{})
	var kickOnce sync.Once
	kick := func() { kickOnce.Do(func() { close(kicked) }) }

	h, id, gen, out, ok := s.hello(ctx, conn, kick)
	if !ok {
		cancel()
		return
	}

	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		writer(ctx, cancel, kicked, conn, out)
	}()

	unexpected := s.readLoop(ctx, conn, h, id, out)

	// Teardown, in order: tell the hub we're gone (it may be gone already),
	// stop the writer — it drains anything the hub queued on the way out —
	// and only then close the socket. An unexpected drop holds the slot for
	// grace so the participant can reconnect; a clean close leaves for good.
	h.send(leaveCmd{id: id, gen: gen, unexpected: unexpected})
	kick()
	<-writerDone
	cancel()
	_ = conn.Close(websocket.StatusNormalClosure, "")
}

// readLoop pumps frames until the connection ends. It reports whether the end
// was unexpected (network loss, idle timeout, abnormal close) — which holds the
// slot for reconnect — versus a clean StatusNormalClosure, which leaves for good.
func (s *Server) readLoop(ctx context.Context, conn *websocket.Conn, h *hub, id wire.ParticipantID, out chan []byte) bool {
	for {
		// Idle disconnect: clients heartbeat with MsgPing well inside this
		// window; a silent connection is a dead one.
		rctx, rcancel := context.WithTimeout(ctx, s.opts.IdleTimeout)
		typ, raw, err := readFrame(rctx, conn)
		rcancel()
		if err != nil {
			return websocket.CloseStatus(err) != websocket.StatusNormalClosure
		}
		switch typ {
		case wire.MsgPing:
			p, err := wire.Body[wire.Ping](raw)
			if err == nil {
				queueFrame(out, wire.MsgPong, wire.Pong(p))
			}
		case wire.MsgDirect, wire.MsgBroadcast:
			h.send(frameCmd{from: id, typ: typ, raw: raw})
		case wire.MsgClaimHost:
			h.send(claimHostCmd{id: id})
		default:
			queueFrame(out, wire.MsgError, wire.Error{Code: wire.ErrCodeBadFrame, Msg: "unexpected message type"})
		}
	}
}

// helloTimeout bounds how long a fresh connection may dawdle before its
// create/join frame arrives.
const helloTimeout = 10 * time.Second

// hello performs the first exchange on a fresh connection and hooks it into
// a hub. On success it returns the client's out channel with the initial
// reply already queued; the caller starts the writer that drains it.
func (s *Server) hello(ctx context.Context, conn *websocket.Conn, cancel context.CancelFunc) (*hub, wire.ParticipantID, uint64, chan []byte, bool) {
	hctx, hcancel := context.WithTimeout(ctx, helloTimeout)
	typ, raw, err := readFrame(hctx, conn)
	hcancel()
	if err != nil {
		if errors.Is(err, wire.ErrUnsupportedVersion) {
			writeFrame(ctx, conn, wire.MsgError, wire.Error{Code: wire.ErrCodeUnsupportedVersion, Msg: "unsupported protocol version"})
		}
		return nil, 0, 0, nil, false
	}

	if typ == wire.MsgResumeSession {
		return s.resume(ctx, conn, cancel, raw)
	}

	var h *hub
	switch typ {
	case wire.MsgCreateSession:
		var ok bool
		if h, ok = s.helloCreate(ctx, conn, raw); !ok {
			return nil, 0, 0, nil, false
		}
	case wire.MsgJoinSession:
		var ok bool
		if h, ok = s.helloJoin(ctx, conn, raw); !ok {
			return nil, 0, 0, nil, false
		}
	default:
		writeFrame(ctx, conn, wire.MsgError, wire.Error{Code: wire.ErrCodeBadFrame, Msg: "expected create or join"})
		return nil, 0, 0, nil, false
	}

	out := make(chan []byte, sendBuffer)
	reply := make(chan joinReply, 1)
	if !h.send(joinCmd{out: out, kick: cancel, isCreate: typ == wire.MsgCreateSession, reply: reply}) {
		writeFrame(ctx, conn, wire.MsgError, wire.Error{Code: wire.ErrCodeSessionNotFound, Msg: "session closed"})
		return nil, 0, 0, nil, false
	}
	jr := <-reply
	if !jr.ok {
		writeFrame(ctx, conn, wire.MsgError, wire.Error{Code: jr.errC, Msg: jr.errS})
		return nil, 0, 0, nil, false
	}
	// The hub already queued SessionCreated/JoinResult into out (see
	// handleJoin — ordering against broadcasts demands it).
	return h, jr.id, jr.gen, out, true
}

// helloCreate handles a MsgCreateSession handshake: decode, clamp the
// participant cap, and register a fresh session. On any failure it writes the
// error frame and reports !ok.
func (s *Server) helloCreate(ctx context.Context, conn *websocket.Conn, raw []byte) (*hub, bool) {
	cs, err := wire.Body[wire.CreateSession](raw)
	if err != nil {
		writeFrame(ctx, conn, wire.MsgError, wire.Error{Code: wire.ErrCodeBadFrame, Msg: "bad create frame"})
		return nil, false
	}
	maxP := int(cs.MaxParticipants)
	if maxP <= 0 || maxP > s.opts.MaxParticipants {
		maxP = s.opts.MaxParticipants
	}
	h, code, msg := s.reg.create(cs.SessionID, maxP)
	if h == nil {
		writeFrame(ctx, conn, wire.MsgError, wire.Error{Code: code, Msg: msg})
		return nil, false
	}
	return h, true
}

// helloJoin handles a MsgJoinSession handshake: decode and look up the target
// session. On any failure it writes the error frame and reports !ok.
func (s *Server) helloJoin(ctx context.Context, conn *websocket.Conn, raw []byte) (*hub, bool) {
	js, err := wire.Body[wire.JoinSession](raw)
	if err != nil {
		writeFrame(ctx, conn, wire.MsgError, wire.Error{Code: wire.ErrCodeBadFrame, Msg: "bad join frame"})
		return nil, false
	}
	h, ok := s.reg.get(js.SessionID)
	if !ok {
		writeFrame(ctx, conn, wire.MsgError, wire.Error{Code: wire.ErrCodeSessionNotFound, Msg: "session not found"})
		return nil, false
	}
	return h, true
}

// resume reclaims a held slot after an unexpected drop: it looks up the hub,
// asks it to re-attach this connection to the prior participant id on a token
// match, and returns the slot's out channel (JoinResult already queued ahead of
// any frames buffered during the outage).
func (s *Server) resume(ctx context.Context, conn *websocket.Conn, kick context.CancelFunc, raw []byte) (*hub, wire.ParticipantID, uint64, chan []byte, bool) {
	rs, err := wire.Body[wire.ResumeSession](raw)
	if err != nil {
		writeFrame(ctx, conn, wire.MsgError, wire.Error{Code: wire.ErrCodeBadFrame, Msg: "bad resume frame"})
		return nil, 0, 0, nil, false
	}
	h, ok := s.reg.get(rs.SessionID)
	if !ok {
		writeFrame(ctx, conn, wire.MsgError, wire.Error{Code: wire.ErrCodeSessionNotFound, Msg: "session not found"})
		return nil, 0, 0, nil, false
	}
	reply := make(chan resumeReply, 1)
	if !h.send(resumeCmd{id: rs.ParticipantID, token: rs.Token, kick: kick, reply: reply}) {
		writeFrame(ctx, conn, wire.MsgError, wire.Error{Code: wire.ErrCodeSessionNotFound, Msg: "session closed"})
		return nil, 0, 0, nil, false
	}
	rr := <-reply
	if !rr.ok {
		writeFrame(ctx, conn, wire.MsgError, wire.Error{Code: rr.errC, Msg: rr.errS})
		return nil, 0, 0, nil, false
	}
	return h, rs.ParticipantID, rr.gen, rr.out, true
}

// send delivers a command to the hub unless it has already shut down.
// Reports whether the command was accepted.
func (h *hub) send(cmd any) bool {
	select {
	case h.inbox <- cmd:
		return true
	case <-h.done:
		return false
	}
}

// writer serializes all post-hello writes for one connection. On kick it
// flushes already-queued frames — e.g. the SessionClosed notice — before
// canceling the connection context; on ctx death (peer disconnect) it just
// exits.
func writer(ctx context.Context, cancel context.CancelFunc, kicked <-chan struct{}, conn *websocket.Conn, out <-chan []byte) {
	write := func(b []byte) bool {
		// Per-write deadline independent of ctx so a frame queued just
		// before a kick still goes out.
		wctx, wcancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer wcancel()
		return conn.Write(wctx, websocket.MessageBinary, b) == nil
	}
	for {
		select {
		case b := <-out:
			if !write(b) {
				cancel()
				return
			}
		case <-kicked:
			drainAndCancel(cancel, out, write)
			return
		case <-ctx.Done():
			return
		}
	}
}

// drainAndCancel flushes whatever is already queued in out — each frame with
// its own write deadline, exactly as the main pump — then cancels the
// connection context. It is the kick path: drain first, cancel last, so a
// frame the hub queued on the way out (e.g. SessionClosed) still reaches the
// wire. A failed write short-circuits: cancel and stop.
func drainAndCancel(cancel context.CancelFunc, out <-chan []byte, write func([]byte) bool) {
	for {
		select {
		case b := <-out:
			if !write(b) {
				cancel()
				return
			}
		default:
			cancel()
			return
		}
	}
}

func readFrame(ctx context.Context, conn *websocket.Conn) (wire.MsgType, []byte, error) {
	mt, data, err := conn.Read(ctx)
	if err != nil {
		return 0, nil, err
	}
	if mt != websocket.MessageBinary {
		return 0, nil, errors.New("relay: non-binary message")
	}
	return wire.Decode(data)
}

// writeFrame is for pre-hello replies only — once a writer goroutine owns
// the connection, use queueFrame.
func writeFrame(ctx context.Context, conn *websocket.Conn, t wire.MsgType, body any) {
	frame, err := wire.Encode(t, body)
	if err != nil {
		return
	}
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_ = conn.Write(wctx, websocket.MessageBinary, frame)
}

func queueFrame(out chan<- []byte, t wire.MsgType, body any) bool {
	frame, err := wire.Encode(t, body)
	if err != nil {
		return false
	}
	select {
	case out <- frame:
		return true
	default:
		return false
	}
}
