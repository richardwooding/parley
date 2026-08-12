package service

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/richardwooding/parley/relay"
	"github.com/richardwooding/parley/session"
	"github.com/richardwooding/parley/wire"
)

// probe is a minimal Service: it re-emits each frame's body on the mux stream,
// so a test can observe routing without importing a concrete service (which
// would form an import cycle with this package).
type probe struct{ ctx Context }

type probeMsg struct{ text string }

func (p *probe) ID() string         { return "probe" }
func (p *probe) Version() int       { return 1 }
func (p *probe) Attach(ctx Context) { p.ctx = ctx }
func (p *probe) HandleFrame(_ wire.ParticipantID, b []byte) error {
	p.ctx.Emit(probeMsg{text: string(b)})
	return nil
}
func (p *probe) Snapshot() ([]byte, error) { return nil, nil }
func (p *probe) Restore([]byte) error      { return nil }

func rebindRelay(t *testing.T) string {
	t.Helper()
	s := relay.New(relay.Options{Grace: 5 * time.Second})
	t.Cleanup(s.Close)
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http")
}

func nextEvent[T any](t *testing.T, ev <-chan any) T {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case e, ok := <-ev:
			if !ok {
				t.Fatalf("mux stream closed while waiting for %T", *new(T))
			}
			if v, ok := e.(T); ok {
				return v
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %T", *new(T))
		}
	}
}

// TestMuxRebindResumesRouting: a reconnectable mux keeps its merged stream open
// across an abrupt drop; after Client.Reconnect + Mux.Rebind it routes frames to
// the same service instance again (no rebuild, no re-snapshot).
func TestMuxRebindResumesRouting(t *testing.T) {
	url := rebindRelay(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	host, phrase, err := session.Host(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = host.Close() }()

	joiner, err := session.Join(ctx, url, phrase)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = joiner.Close() }()
	joinerMux := NewMux(joiner, WithServices(&probe{}))
	joinerMux.SetReconnectable() // survive the drop

	// Baseline: host broadcasts, joiner's mux routes it to the probe service.
	if err := host.Broadcast("probe", []byte("before")); err != nil {
		t.Fatal(err)
	}
	if m := nextEvent[probeMsg](t, joinerMux.Events()); m.text != "before" {
		t.Fatalf("pre-drop message %q", m.text)
	}

	// Abrupt drop; the reconnectable mux must surface Closed but NOT close its
	// stream (a non-reconnectable mux would close it here).
	_ = joiner.CloseNow()
	se := nextEvent[SessionEvent](t, joinerMux.Events())
	if _, ok := se.Event.(session.Closed); !ok {
		t.Fatalf("expected a Closed session event, got %+v", se.Event)
	}
	time.Sleep(150 * time.Millisecond)

	if err := joiner.Reconnect(ctx); err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	joinerMux.Rebind(joiner)

	// Routing resumes on the same probe instance via the same stream.
	if err := host.Broadcast("probe", []byte("after")); err != nil {
		t.Fatal(err)
	}
	if m := nextEvent[probeMsg](t, joinerMux.Events()); m.text != "after" {
		t.Fatalf("post-rebind message %q", m.text)
	}
}
