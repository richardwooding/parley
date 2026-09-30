package relay

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/richardwooding/parley/wire"
)

// A participant that stops reading is dropped once its send buffer fills. Its
// peers must still hear that it left: otherwise they keep addressing a member
// that no longer exists, and the host never rotates the group key away from it.
func TestSlowConsumerDropNotifiesPeers(t *testing.T) {
	srv := newServer(t, Options{})
	host := createSession(t, srv)

	slow := dial(t, srv) // joins, then never reads again
	slow.write(wire.MsgJoinSession, wire.JoinSession{SessionID: sid})
	jr := expect[wire.JoinResult](slow, wire.MsgJoinResult)

	watcher := dial(t, srv)
	watcher.write(wire.MsgJoinSession, wire.JoinSession{SessionID: sid})
	expect[wire.JoinResult](watcher, wire.MsgJoinResult)

	// The host drains its own socket so that it is never the slow one.
	ctx := t.Context()
	go func() {
		for {
			if _, _, err := host.conn.Read(ctx); err != nil {
				return
			}
		}
	}()

	// Flood the slow member with directed frames until the relay gives up on it.
	// Localhost socket buffers absorb several MiB before the relay's own
	// 64-frame buffer backs up, so send far more than that.
	payload := bytes.Repeat([]byte{0x5a}, 60*1024)
	flood, err := wire.Encode(wire.MsgDirect, wire.Direct{To: jr.ParticipantID, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for range 2000 {
			if host.conn.Write(ctx, websocket.MessageBinary, flood) != nil {
				return
			}
		}
	}()

	deadline, stop := context.WithTimeout(context.Background(), 20*time.Second)
	defer stop()
	for {
		_, data, err := watcher.conn.Read(deadline)
		if err != nil {
			t.Fatalf("watcher never saw the slow member leave: %v", err)
		}
		typ, raw, err := wire.Decode(data)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if typ != wire.MsgParticipantLeft {
			continue
		}
		pl, err := wire.Body[wire.ParticipantLeft](raw)
		if err != nil {
			t.Fatal(err)
		}
		if pl.ParticipantID == jr.ParticipantID {
			return
		}
	}
}
