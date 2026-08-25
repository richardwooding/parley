package service

import (
	"sync"
	"testing"
	"time"

	"github.com/richardwooding/parley/session"
	"github.com/richardwooding/parley/wire"
)

// fakeConn is a minimal Conn whose Events channel the test drives. Sender
// methods are no-ops — the mux only routes and emits; it never needs a real
// transport for this test.
type fakeConn struct {
	self, host wire.ParticipantID
	role       session.Role
	events     chan session.Event
}

func (f *fakeConn) Broadcast(string, []byte) error                  { return nil }
func (f *fakeConn) SendTo(wire.ParticipantID, string, []byte) error { return nil }
func (f *fakeConn) Self() wire.ParticipantID                        { return f.self }
func (f *fakeConn) HostID() wire.ParticipantID                      { return f.host }
func (f *fakeConn) Role() session.Role                              { return f.role }
func (f *fakeConn) Events() <-chan session.Event                    { return f.events }

// TestMuxCloseRaceWithConcurrentEmits reproduces parley#2: Close() closing the
// events channel while the run goroutine and off-goroutine callers (e.g.
// chat.Say) are still emitting → "panic: send on closed channel". On the unfixed
// code this panics (crashing the test, especially under -race); with the fix
// Close is safe against concurrent emits and Events() still closes exactly once.
func TestMuxCloseRaceWithConcurrentEmits(t *testing.T) {
	fc := &fakeConn{self: 1, host: 1, role: session.RoleHost, events: make(chan session.Event)}
	m := NewMux(fc)
	m.SetReconnectable() // terminal teardown goes through Close (the racy path)

	// Drain the merged stream until it closes.
	drained := make(chan struct{})
	go func() {
		for range m.Events() {
		}
		close(drained)
	}()

	// Hammer emit from several goroutines — models chat.Say emitting off the run
	// goroutine, concurrently with teardown.
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 500 {
				m.emit(Desync{})
			}
		})
	}

	// Deliver a final session.Closed via the client's stream (as a real teardown
	// does), then let the run goroutine exit — all racing Close below.
	go func() {
		fc.events <- session.Closed{Reason: "bye"}
		close(fc.events)
	}()

	time.Sleep(2 * time.Millisecond) // let emits and the Closed interleave
	m.Close()

	wg.Wait()

	select {
	case <-drained:
	case <-time.After(2 * time.Second):
		t.Fatal("Events() did not close after Close()")
	}

	// Emitting after shutdown is a safe no-op, and Close is idempotent.
	m.emit(Desync{})
	m.Close()
}
