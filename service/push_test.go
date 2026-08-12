package service

import (
	"context"
	"testing"
	"time"

	"github.com/richardwooding/parley/session"
)

func waitRoster(t *testing.T, ev <-chan any, pred func(Roster) bool) Roster {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case e, ok := <-ev:
			if !ok {
				t.Fatal("mux stream closed while waiting for roster")
			}
			if r, ok := e.(Roster); ok && pred(r) {
				return r
			}
		case <-deadline:
			t.Fatal("timed out waiting for matching roster")
		}
	}
}

// TestCtlPropagatesPushKeyAndEndpoint: the shared session VAPID keypair (host →
// all) and each participant's push endpoint (participant → host → all) travel
// over the encrypted ctl channel and surface in the Roster event.
func TestCtlPropagatesPushKeyAndEndpoint(t *testing.T) {
	url := rebindRelay(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	host, phrase, err := session.Host(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = host.Close() }()
	hostMux := NewMux(host, WithServices(&probe{}))

	joiner, err := session.Join(ctx, url, phrase)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = joiner.Close() }()
	joinerMux := NewMux(joiner, WithServices(&probe{}))

	// Host publishes the shared keypair → the joiner sees it in a roster.
	hostMux.SetPushKey("vapid-blob-123")
	waitRoster(t, joinerMux.Events(), func(r Roster) bool { return r.PushKey == "vapid-blob-123" })

	// Joiner shares its push endpoint → the host sees it keyed to the joiner id.
	joinerMux.SetEndpoint("https://push.example/ep-abc")
	got := waitRoster(t, hostMux.Events(), func(r Roster) bool {
		return r.Endpoints[joiner.Self()] == "https://push.example/ep-abc"
	})
	if got.PushKey != "vapid-blob-123" {
		t.Fatalf("host roster lost the push key: %q", got.PushKey)
	}
}
