package relay

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/richardwooding/parley/wire"
)

func dialSID(t *testing.T, srv *httptest.Server, sid wire.SessionID, hdr http.Header) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "?" + wire.SessionParam + "=" + sid.Hex()
	var opts *websocket.DialOptions
	if hdr != nil {
		opts = &websocket.DialOptions{HTTPHeader: hdr}
	}
	return websocket.Dial(ctx, url, opts)
}

// A non-owned session gets the Router's replay response and is never upgraded.
func TestRouterReplaysNonOwned(t *testing.T) {
	owned := wire.SessionID{1}
	var routed wire.SessionID
	srv := newServer(t, Options{
		Router: func(sid wire.SessionID, _ *http.Request) RouteResult {
			routed = sid
			if sid == owned {
				return RouteResult{} // serve here
			}
			return RouteResult{Replay: true, Header: http.Header{"Fly-Replay": {"instance=other"}}, Status: http.StatusConflict}
		},
	})

	conn, resp, err := dialSID(t, srv, wire.SessionID{9}, nil)
	if err == nil {
		_ = conn.CloseNow()
		t.Fatal("expected the upgrade to fail (replayed), but it succeeded")
	}
	if resp == nil || resp.StatusCode != http.StatusConflict {
		t.Fatalf("replay status = %v, want 409", resp)
	}
	if resp.Header.Get("Fly-Replay") != "instance=other" {
		t.Fatalf("missing Fly-Replay header: %v", resp.Header)
	}
	if routed != (wire.SessionID{9}) {
		t.Fatalf("Router saw sid %x, want the dialed one", routed)
	}
	// No session was created (no upgrade).
	if n := srv.Config.Handler.(*Server).Stats().ActiveSessions; n != 0 {
		t.Fatalf("ActiveSessions = %d, want 0", n)
	}
}

// An owned session upgrades and speaks the protocol normally.
func TestRouterServesOwned(t *testing.T) {
	sid := wire.SessionID{7}
	srv := newServer(t, Options{
		Router: func(wire.SessionID, *http.Request) RouteResult { return RouteResult{} },
	})
	conn, _, err := dialSID(t, srv, sid, nil)
	if err != nil {
		t.Fatalf("owned dial failed: %v", err)
	}
	defer func() { _ = conn.CloseNow() }()
	// The connection is live: create a session over it.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c := &testClient{t: t, conn: conn, ctx: ctx}
	c.write(wire.MsgCreateSession, wire.CreateSession{SessionID: sid, MaxParticipants: 4})
	if typ, _ := c.read(); typ != wire.MsgSessionCreated {
		t.Fatalf("want SessionCreated, got %v", typ)
	}
}

// Missing/malformed ?s= with a Router is a 400 before the Router runs.
func TestRouterRejectsBadParam(t *testing.T) {
	called := false
	srv := newServer(t, Options{
		Router: func(wire.SessionID, *http.Request) RouteResult { called = true; return RouteResult{} },
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	base := "ws" + strings.TrimPrefix(srv.URL, "http")
	for _, u := range []string{base, base + "?" + wire.SessionParam + "=zzzz"} {
		if _, resp, err := websocket.Dial(ctx, u, nil); err == nil || resp == nil || resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("dial %q: want 400, got resp=%v err=%v", u, resp, err)
		}
	}
	if called {
		t.Fatal("Router was called for a malformed param")
	}
}

// The Router receives the raw request (headers stand in for FLY_* / Fly-Replay-Src).
func TestRouterSeesRequest(t *testing.T) {
	var seen string
	srv := newServer(t, Options{
		Router: func(_ wire.SessionID, r *http.Request) RouteResult {
			seen = r.Header.Get("X-Test")
			return RouteResult{}
		},
	})
	conn, _, err := dialSID(t, srv, wire.SessionID{3}, http.Header{"X-Test": {"hello"}})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.CloseNow()
	if seen != "hello" {
		t.Fatalf("Router saw header %q, want hello", seen)
	}
}
