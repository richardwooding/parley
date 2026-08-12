package session

import (
	"context"
	"errors"
	"fmt"

	"github.com/coder/websocket"

	"github.com/richardwooding/parley/crypto"
	"github.com/richardwooding/parley/wire"
)

// hostHello creates the session on the relay and generates the group key.
func (c *Client) hostHello(ctx context.Context) error {
	if err := c.writeFrame(wire.MsgCreateSession, wire.CreateSession{SessionID: c.sid}); err != nil {
		return err
	}
	raw, err := c.awaitReply(ctx, wire.MsgSessionCreated)
	if err != nil {
		return err
	}
	sc, err := wire.Body[wire.SessionCreated](raw)
	if err != nil {
		return err
	}
	c.self = sc.ParticipantID
	c.hostID = sc.ParticipantID
	c.resumeToken = sc.ResumeToken

	key, err := crypto.NewGroupKey()
	if err != nil {
		return err
	}
	c.groupKey = key
	c.keyed = true
	c.role = RoleHost
	return nil
}

// joinHello joins the session and runs the PAKE + group-key handshake to
// completion, so Join returns a usable client or a clean error.
func (c *Client) joinHello(ctx context.Context) error {
	if err := c.joinRequest(ctx); err != nil {
		return err
	}
	j, err := c.sendPake1()
	if err != nil {
		return err
	}
	return c.joinDriveHandshake(ctx, j)
}

// joinRequest sends the join request and records the identity the relay
// assigns (self/host/resume token), returning a clean error if the join is
// refused.
func (c *Client) joinRequest(ctx context.Context) error {
	if err := c.writeFrame(wire.MsgJoinSession, wire.JoinSession{SessionID: c.sid}); err != nil {
		return err
	}
	raw, err := c.awaitReply(ctx, wire.MsgJoinResult)
	if err != nil {
		return err
	}
	jr, err := wire.Body[wire.JoinResult](raw)
	if err != nil {
		return err
	}
	if !jr.OK {
		return fmt.Errorf("session: join refused: %s", jr.Err)
	}
	c.self = jr.ParticipantID
	c.hostID = jr.HostID
	c.resumeToken = jr.ResumeToken
	return nil
}

// sendPake1 starts the joiner PAKE and sends its first flight to the host,
// returning the joiner state the read side needs to finish the exchange.
func (c *Client) sendPake1() (*crypto.Joiner, error) {
	j, err := crypto.NewJoiner(c.proto, c.phraseC)
	if err != nil {
		return nil, err
	}
	payload, err := wire.EncodePayload(wire.KindPake1, wire.Pake{Data: j.Flight1, Spectate: c.spectate})
	if err != nil {
		return nil, err
	}
	if err := c.writeFrame(wire.MsgDirect, wire.Direct{To: c.hostID, Payload: payload}); err != nil {
		return nil, err
	}
	return j, nil
}

// joinDriveHandshake drives the read side until keyed: Pake2 then GroupKey,
// both from the host. Anything else that arrives mid-handshake (membership
// notices, early broadcasts we can't decrypt yet) is skipped — the ctl
// snapshot catches joiners up once keyed.
func (c *Client) joinDriveHandshake(ctx context.Context, j *crypto.Joiner) error {
	var pairwise crypto.Key
	havePairwise := false
	for !c.keyed {
		typ, raw, err := c.readFrame(ctx)
		if err != nil {
			return err
		}
		if typ == wire.MsgSessionClosed {
			return errors.New("session: closed during handshake")
		}
		if typ != wire.MsgDirect {
			continue
		}
		d, err := wire.Body[wire.Direct](raw)
		if err != nil || d.From != c.hostID {
			continue
		}
		kind, praw, err := wire.DecodePayload(d.Payload)
		if err != nil {
			continue
		}
		if err := c.joinHandleDirect(j, kind, praw, &pairwise, &havePairwise); err != nil {
			return err
		}
	}
	return nil
}

// joinHandleDirect advances the joiner handshake for one Direct payload from
// the host: Pake2 finishes the PAKE into the pairwise key; GroupKey unwraps
// the group key (wrong phrase → crypto.ErrUnwrap) and marks the client keyed.
// It runs on the single Join goroutine before readLoop starts, so it touches
// client state without the lock, exactly as the inline loop did.
func (c *Client) joinHandleDirect(j *crypto.Joiner, kind wire.PayloadKind, praw []byte, pairwise *crypto.Key, havePairwise *bool) error {
	switch kind {
	case wire.KindPake2:
		p, err := wire.Body[wire.Pake](praw)
		if err != nil {
			return err
		}
		pw, err := j.Finish(p.Data, c.sid, c.self, c.hostID)
		if err != nil {
			return err
		}
		*pairwise = pw
		*havePairwise = true
	case wire.KindGroupKey:
		if !*havePairwise {
			return errors.New("session: group key arrived before pake reply")
		}
		gk, err := wire.Body[wire.GroupKey](praw)
		if err != nil {
			return err
		}
		key, role, err := crypto.UnwrapGroupKey(*pairwise, gk, c.sid, c.self)
		if err != nil {
			return err // crypto.ErrUnwrap: wrong phrase
		}
		c.groupKey = key
		c.role = Role(role)
		c.keyed = true
		c.hostPairwise = *pairwise // retained so a later host rekey can be unwrapped
		c.haveHostPairwise = true
	}
	return nil
}

// awaitReply reads until the wanted hello reply arrives, returning its raw
// body. Session traffic that races ahead of the reply (undecryptable this
// early; the application's snapshot mechanism catches us up) is skipped;
// relay errors surface.
func (c *Client) awaitReply(ctx context.Context, want wire.MsgType) ([]byte, error) {
	for {
		typ, raw, err := c.readFrame(ctx)
		if err != nil {
			return nil, err
		}
		switch typ {
		case want:
			return raw, nil
		case wire.MsgError:
			return nil, relayError(raw)
		case wire.MsgBroadcast, wire.MsgDirect, wire.MsgParticipantJoined, wire.MsgParticipantLeft:
			continue
		default:
			return nil, fmt.Errorf("session: unexpected reply %v awaiting %v", typ, want)
		}
	}
}

// handleHandshakeDirect is the host side: a Pake1 from a joiner triggers the
// stateless exchange — reply Pake2, then the wrapped group key with the
// joiner's assigned role.
func (c *Client) handleHandshakeDirect(from wire.ParticipantID, kind wire.PayloadKind, praw []byte) {
	// Read the role under the lock: host migration can flip it from the mux
	// goroutine (BecomeHost). Once promoted, this responder path serves new
	// joiners using c.phraseC + the already-held group key — no re-key.
	c.mu.Lock()
	isHost := c.role == RoleHost
	c.mu.Unlock()
	if !isHost || kind != wire.KindPake1 {
		return
	}
	p, err := wire.Body[wire.Pake](praw)
	if err != nil {
		return
	}
	pairwise, flight2, err := crypto.HostExchange(c.proto, c.phraseC, p.Data, c.sid, from, c.self)
	if err != nil {
		return
	}

	c.mu.Lock()
	role := c.assignJoinerRole(p.Spectate)
	c.joiners[from] = role
	c.pairwise[from] = pairwise // retained so we can re-wrap a fresh key on a later leave
	key := c.groupKey
	c.mu.Unlock()

	reply, err := wire.EncodePayload(wire.KindPake2, wire.Pake{Data: flight2})
	if err != nil {
		return
	}
	if c.writeFrame(wire.MsgDirect, wire.Direct{To: from, Payload: reply}) != nil {
		return
	}
	wrapped, err := crypto.WrapGroupKey(pairwise, key, byte(role), c.sid, from)
	if err != nil {
		return
	}
	gkPayload, err := wire.EncodePayload(wire.KindGroupKey, wrapped)
	if err != nil {
		return
	}
	if c.writeFrame(wire.MsgDirect, wire.Direct{To: from, Payload: gkPayload}) != nil {
		return
	}
	c.emit(MemberKeyed{ID: from, Role: role})
}

// handleRekeyPake1 is the promoted host's side of a survivor's re-PAKE after a
// migration: complete the exchange to a fresh pairwise key, retain it (so later
// member-leave rekeys can re-wrap), reply with the PAKE flight, then deliver the
// rotated group key wrapped under that pairwise. Role is RoleNone — the survivor
// keeps whatever role it already had.
func (c *Client) handleRekeyPake1(from wire.ParticipantID, praw []byte) {
	c.mu.Lock()
	isHost := c.role == RoleHost && c.hostID == c.self
	c.mu.Unlock()
	if !isHost {
		return
	}
	p, err := wire.Body[wire.Pake](praw)
	if err != nil {
		return
	}
	pairwise, flight2, err := crypto.HostExchange(c.proto, c.phraseC, p.Data, c.sid, from, c.self)
	if err != nil {
		return
	}
	c.mu.Lock()
	c.pairwise[from] = pairwise
	key := c.groupKey
	c.mu.Unlock()

	reply, err := wire.EncodePayload(wire.KindRekeyPake2, wire.Pake{Data: flight2})
	if err != nil {
		return
	}
	if c.writeFrame(wire.MsgDirect, wire.Direct{To: from, Payload: reply}) != nil {
		return
	}
	wrapped, err := crypto.WrapGroupKey(pairwise, key, byte(RoleNone), c.sid, from)
	if err != nil {
		return
	}
	gkPayload, err := wire.EncodePayload(wire.KindRekey, wrapped)
	if err != nil {
		return
	}
	_ = c.writeFrame(wire.MsgDirect, wire.Direct{To: from, Payload: gkPayload})
}

// handleRekeyPake2 is the survivor's side: finish the re-PAKE into the pairwise
// key it will use to unwrap the incoming rotated group key (KindRekey follows).
func (c *Client) handleRekeyPake2(from wire.ParticipantID, praw []byte) {
	c.mu.Lock()
	j := c.rekeyJoiner
	ok := j != nil && from == c.hostID
	c.mu.Unlock()
	if !ok {
		return
	}
	p, err := wire.Body[wire.Pake](praw)
	if err != nil {
		return
	}
	pairwise, err := j.Finish(p.Data, c.sid, c.self, c.hostID)
	if err != nil {
		return
	}
	c.mu.Lock()
	c.hostPairwise = pairwise
	c.haveHostPairwise = true
	c.rekeyJoiner = nil
	c.mu.Unlock()
}

// assignJoinerRole picks the role for a newly keyed joiner. The caller must
// hold c.mu: it reads c.joiners without re-locking. A joiner that asked to
// watch is always a spectator, so it never takes the open player seat.
// Otherwise the first non-watcher to key becomes the player.
func (c *Client) assignJoinerRole(spectate bool) Role {
	if spectate {
		return RoleSpectator
	}
	for _, r := range c.joiners {
		if r == RolePlayer {
			return RoleSpectator
		}
	}
	return RolePlayer
}

// readLoop pumps relay frames into events until the connection dies. It reads
// from the conn it was started with (not c.conn) so a Reconnect that swaps in a
// new connection never disturbs an already-exited loop. Each read carries a
// deadline: a healthy connection sees a pong every pingInterval, so exceeding
// readTimeout means the connection is dead (a half-open drop where reads would
// otherwise block forever) — surfaced as a Closed the caller can reconnect.
func (c *Client) readLoop(conn *websocket.Conn) {
	defer close(c.events)
	for {
		rctx, cancel := context.WithTimeout(context.Background(), readTimeout)
		typ, raw, err := c.readFrameConn(rctx, conn)
		cancel()
		if err != nil {
			c.emit(Closed{Reason: "connection lost"})
			return
		}
		if c.dispatchFrame(typ, raw) {
			return
		}
	}
}

// dispatchFrame turns one relay frame into events, mirroring the readLoop
// switch exactly. It returns true when the session closed and the loop should
// stop. The MsgParticipantLeft case takes c.mu only around the map delete,
// unchanged from the inline version.
func (c *Client) dispatchFrame(typ wire.MsgType, raw []byte) (stop bool) {
	switch typ {
	case wire.MsgParticipantJoined:
		if pj, err := wire.Body[wire.ParticipantJoined](raw); err == nil {
			c.emit(MemberJoined{ID: pj.ParticipantID})
		}
	case wire.MsgParticipantLeft:
		if pl, err := wire.Body[wire.ParticipantLeft](raw); err == nil {
			c.mu.Lock()
			delete(c.joiners, pl.ParticipantID)
			delete(c.pairwise, pl.ParticipantID)
			c.mu.Unlock()
			c.emit(MemberLeft{ID: pl.ParticipantID})
			c.rekeyAfterLeave() // host rotates the key so the departed member is locked out
		}
	case wire.MsgSessionClosed:
		reason := ""
		if sc, err := wire.Body[wire.SessionClosed](raw); err == nil {
			reason = sc.Reason
		}
		c.emit(Closed{Reason: reason})
		return true
	case wire.MsgDirect:
		if d, err := wire.Body[wire.Direct](raw); err == nil {
			c.handlePayload(d.From, d.Payload)
		}
	case wire.MsgBroadcast:
		if b, err := wire.Body[wire.Broadcast](raw); err == nil {
			c.handlePayload(b.From, b.Payload)
		}
	}
	return false
}

// handlePayload routes one inner payload: handshake kinds to the host
// responder, sealed frames through decryption to a Frame event.
func (c *Client) handlePayload(from wire.ParticipantID, payload []byte) {
	kind, praw, err := wire.DecodePayload(payload)
	if err != nil {
		return
	}
	switch kind {
	case wire.KindSealed:
		// fall through to decryption below
	case wire.KindRekey:
		c.handleRekey(from, praw)
		return
	case wire.KindRekeyPake1:
		c.handleRekeyPake1(from, praw)
		return
	case wire.KindRekeyPake2:
		c.handleRekeyPake2(from, praw)
		return
	default:
		c.handleHandshakeDirect(from, kind, praw)
		return
	}
	sf, err := wire.Body[wire.SealedFrame](praw)
	if err != nil {
		return
	}
	plain, ok := c.openFrame(sf, from)
	if !ok {
		return // not keyed, tampered, foreign, or too old; drop silently
	}
	env, err := wire.Body[wire.Envelope](plain)
	if err != nil {
		return
	}
	c.emit(Frame{From: from, Envelope: env})
}

func relayError(raw []byte) error {
	e, err := wire.Body[wire.Error](raw)
	if err != nil {
		return errors.New("session: relay error")
	}
	return fmt.Errorf("session: relay error %d: %s", e.Code, e.Msg)
}
