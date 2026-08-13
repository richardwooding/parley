package dashboard

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/richardwooding/parley/relay"
)

// internalStatsPath is where a node exposes its own raw Stats for peers to
// scrape. It is authenticated by a shared cluster token and meant to be
// reachable only on a private network (e.g. Fly 6PN) — never routed to the
// public edge.
const internalStatsPath = "/internal/stats"

// clusterAuthHeader carries the constant-time-checked cluster token on peer
// stats requests.
const clusterAuthHeader = "X-Parley-Cluster"

// PeerLister returns the base URLs (scheme://host[:port]) of the OTHER relay
// nodes in the cluster — this node excluded. NewAggregator queries each for
// its local stats and merges them with this node's. Returning an empty slice
// (single node, or discovery unavailable) yields local-only stats.
type PeerLister func(ctx context.Context) ([]string, error)

// InternalStatsPath is the path a cluster peer should be mounted at and
// scraped on. Exposed so callers keep the two ends in sync.
func InternalStatsPath() string { return internalStatsPath }

// InternalStatsHandler serves this node's raw relay.Stats as JSON, gated by a
// constant-time comparison against token. Mount it at InternalStatsPath() on a
// private interface only; the token authenticates peers, not end users.
func InternalStatsHandler(local StatsSource, token []byte) http.Handler {
	want := hex.EncodeToString(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get(clusterAuthHeader)
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(local.Stats())
	})
}

// aggregator is a StatsSource that fans out to peer nodes and merges their
// snapshots with the local one, so a dashboard on any node shows the whole
// cluster. At one node (empty peer list) it is exactly the local source.
type aggregator struct {
	local  StatsSource
	peers  PeerLister
	token  string // hex of the cluster token, sent to peers
	client *http.Client
}

// NewAggregator wraps a local StatsSource so Stats() returns the cluster-wide
// merge of this node and every node PeerLister reports. Unreachable or slow
// peers are skipped (each has a short timeout); the local snapshot is always
// included, so the dashboard degrades to local-only rather than failing.
func NewAggregator(local StatsSource, peers PeerLister, token []byte) StatsSource {
	return &aggregator{
		local:  local,
		peers:  peers,
		token:  hex.EncodeToString(token),
		client: &http.Client{Timeout: 2 * time.Second},
	}
}

func (a *aggregator) Stats() relay.Stats {
	local := a.local.Stats()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	peers, err := a.peers(ctx)
	if err != nil || len(peers) == 0 {
		return local
	}

	parts := make([]relay.Stats, len(peers))
	ok := make([]bool, len(peers))
	var wg sync.WaitGroup
	for i, base := range peers {
		wg.Add(1)
		go func(i int, base string) {
			defer wg.Done()
			if st, e := a.fetch(ctx, base); e == nil {
				parts[i], ok[i] = st, true
			}
		}(i, base)
	}
	wg.Wait()

	merged := []relay.Stats{local}
	for i := range peers {
		if ok[i] {
			merged = append(merged, parts[i])
		}
	}
	return relay.MergeStats(merged...)
}

func (a *aggregator) fetch(ctx context.Context, base string) (relay.Stats, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+internalStatsPath, nil)
	if err != nil {
		return relay.Stats{}, err
	}
	req.Header.Set(clusterAuthHeader, a.token)
	resp, err := a.client.Do(req)
	if err != nil {
		return relay.Stats{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return relay.Stats{}, errStatus(resp.StatusCode)
	}
	var st relay.Stats
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return relay.Stats{}, err
	}
	return st, nil
}

type errStatus int

func (e errStatus) Error() string { return "dashboard: peer stats status " + http.StatusText(int(e)) }
