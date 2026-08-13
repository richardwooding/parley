package dashboard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/richardwooding/parley/relay"
)

type fixedStats relay.Stats

func (f fixedStats) Stats() relay.Stats { return relay.Stats(f) }

func TestInternalStatsHandlerTokenGate(t *testing.T) {
	token := []byte("cluster-token-123")
	h := InternalStatsHandler(fixedStats{ActiveSessions: 2}, token)
	srv := httptest.NewServer(h)
	defer srv.Close()

	// No token → 403.
	resp, _ := http.Get(srv.URL)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unauthenticated = %d, want 403", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// Correct token → 200 + JSON.
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set(clusterAuthHeader, hexToken(token))
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated = %v %v", resp, err)
	}
	_ = resp.Body.Close()
}

func hexToken(b []byte) string {
	// mirror InternalStatsHandler's encoding
	const hexdigits = "0123456789abcdef"
	var sb strings.Builder
	for _, c := range b {
		sb.WriteByte(hexdigits[c>>4])
		sb.WriteByte(hexdigits[c&0xf])
	}
	return sb.String()
}

func TestAggregatorMergesPeers(t *testing.T) {
	token := []byte("tok")
	// A peer node serving its own shard's stats.
	peer := httptest.NewServer(InternalStatsHandler(
		fixedStats{ActiveSessions: 1, SessionsCreated: 3, Sessions: []relay.SessionStat{{ID: "peer1"}}}, token))
	defer peer.Close()
	// An unreachable peer (closed) to prove it's skipped.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	local := fixedStats{ActiveSessions: 2, SessionsCreated: 5, Sessions: []relay.SessionStat{{ID: "local1"}, {ID: "local2"}}}
	agg := NewAggregator(local, func(context.Context) ([]string, error) {
		return []string{peer.URL, deadURL}, nil
	}, token)

	got := agg.Stats()
	if got.ActiveSessions != 3 { // 2 local + 1 peer; dead skipped
		t.Fatalf("ActiveSessions = %d, want 3", got.ActiveSessions)
	}
	if got.SessionsCreated != 8 {
		t.Fatalf("SessionsCreated = %d, want 8", got.SessionsCreated)
	}
	if len(got.Sessions) != 3 {
		t.Fatalf("Sessions = %d, want 3 (2 local + 1 peer)", len(got.Sessions))
	}
}

func TestAggregatorEmptyPeersIsLocal(t *testing.T) {
	local := fixedStats{ActiveSessions: 4, Sessions: []relay.SessionStat{{ID: "only"}}}
	agg := NewAggregator(local, func(context.Context) ([]string, error) { return nil, nil }, []byte("t"))
	got := agg.Stats()
	if got.ActiveSessions != 4 || len(got.Sessions) != 1 {
		t.Fatalf("empty-peers merge = %+v, want local", got)
	}
}
