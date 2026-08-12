package session

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/richardwooding/parley/relay"
)

func reconnectRelay(t *testing.T) string {
	t.Helper()
	s := relay.New(relay.Options{Grace: 5 * time.Second})
	t.Cleanup(s.Close)
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http")
}

func waitEvent[E any](t *testing.T, c *Client) E {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case ev, ok := <-c.Events():
			if !ok {
				t.Fatalf("events closed while waiting for %T", *new(E))
			}
			if e, ok := ev.(E); ok {
				return e
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %T", *new(E))
		}
	}
}

// TestReconnectPreservesIdentityKeyAndSeq: an abrupt drop is recoverable — the
// joiner reclaims the SAME participant id, keeps its group key (frames still
// decrypt) and its send-sequence counter (no gap), and receives the frame the
// host sent while it was away. The host is never told the joiner left.
func TestReconnectPreservesIdentityKeyAndSeq(t *testing.T) {
	url := reconnectRelay(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	host, phrase, err := Host(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = host.Close() }()
	joiner, err := Join(ctx, url, phrase, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = joiner.Close() }()
	waitEvent[MemberKeyed](t, host)

	id := joiner.Self()
	if err := joiner.Broadcast("echo", []byte("one")); err != nil {
		t.Fatal(err)
	}
	if f := waitEvent[Frame](t, host); f.Envelope.Seq != 1 || string(f.Envelope.Body) != "one" {
		t.Fatalf("first frame %+v", f)
	}

	// Abrupt drop → the joiner's stream reports "connection lost".
	_ = joiner.CloseNow()
	if closed := waitEvent[Closed](t, joiner); closed.Reason != "connection lost" {
		t.Fatalf("close reason %q", closed.Reason)
	}
	time.Sleep(150 * time.Millisecond) // let the relay register the hold

	// Host sends while the joiner is away; the relay buffers it on the slot.
	if err := host.Broadcast("echo", []byte("during")); err != nil {
		t.Fatal(err)
	}

	if err := joiner.Reconnect(ctx); err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	if joiner.Self() != id {
		t.Fatalf("participant id changed %d → %d", id, joiner.Self())
	}
	// The buffered frame flushes and decrypts with the preserved key.
	if f := waitEvent[Frame](t, joiner); string(f.Envelope.Body) != "during" {
		t.Fatalf("buffered frame %+v", f)
	}
	// Sequence continues (2, not reset to 1) → peers see no gap.
	if err := joiner.Broadcast("echo", []byte("two")); err != nil {
		t.Fatal(err)
	}
	f := hostFrameNoLeave(t, host)
	if f.From != id || f.Envelope.Seq != 2 || string(f.Envelope.Body) != "two" {
		t.Fatalf("post-reconnect frame %+v (want id %d seq 2)", f, id)
	}
}

// hostFrameNoLeave reads until a Frame arrives, failing if the host is told a
// member left first (which would forfeit the game) — the whole point is that a
// reclaimed drop never surfaces as a departure.
func hostFrameNoLeave(t *testing.T, host *Client) Frame {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case ev, ok := <-host.Events():
			if !ok {
				t.Fatal("host events closed")
			}
			switch e := ev.(type) {
			case Frame:
				return e
			case MemberLeft:
				t.Fatalf("host saw MemberLeft %d — reclaimed drop must not forfeit", e.ID)
			}
		case <-deadline:
			t.Fatal("timed out waiting for host frame")
		}
	}
}

// TestHostReconnect: the host itself can drop and reclaim id=1; the joiner never
// sees the session close, and traffic resumes.
func TestHostReconnect(t *testing.T) {
	url := reconnectRelay(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	host, phrase, err := Host(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = host.Close() }()
	joiner, err := Join(ctx, url, phrase, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = joiner.Close() }()
	waitEvent[MemberKeyed](t, host)

	_ = host.CloseNow()
	if closed := waitEvent[Closed](t, host); closed.Reason != "connection lost" {
		t.Fatalf("host close reason %q", closed.Reason)
	}
	time.Sleep(150 * time.Millisecond)

	if err := host.Reconnect(ctx); err != nil {
		t.Fatalf("host reconnect: %v", err)
	}
	if host.Self() != 1 {
		t.Fatalf("host id changed to %d", host.Self())
	}
	if err := host.Broadcast("echo", []byte("back")); err != nil {
		t.Fatal(err)
	}
	if f := waitEvent[Frame](t, joiner); string(f.Envelope.Body) != "back" {
		t.Fatalf("joiner frame after host resume %+v", f)
	}
}
