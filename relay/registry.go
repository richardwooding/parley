package relay

import (
	"sync"
	"time"

	"github.com/richardwooding/parley/wire"
)

// registry tracks live sessions. Sessions are memory-only: a relay restart
// drops everything, and clients simply re-pair (reconnect = rejoin).
type registry struct {
	mu       sync.Mutex
	sessions map[wire.SessionID]*hub
	maxCount int
	maxAge   time.Duration
	grace    time.Duration
	metrics  *Metrics
}

func newRegistry(maxSessions int, maxAge, grace time.Duration, m *Metrics) *registry {
	if m == nil {
		m = &Metrics{}
	}
	return &registry{
		sessions: map[wire.SessionID]*hub{},
		maxCount: maxSessions,
		maxAge:   maxAge,
		grace:    grace,
		metrics:  m,
	}
}

// create registers a new hub for id. Fails when the id is taken (phrase
// collision or replayed create) or the relay is at capacity.
func (r *registry) create(id wire.SessionID, maxParticipants int) (*hub, uint16, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.sessions[id]; ok {
		return nil, wire.ErrCodeSessionExists, "session already exists"
	}
	if len(r.sessions) >= r.maxCount {
		return nil, wire.ErrCodeRateLimited, "relay at session capacity"
	}
	h := newHub(id, maxParticipants, r.grace, r.metrics, func() { r.remove(id) })
	r.sessions[id] = h
	r.metrics.SessionsCreated.Add(1)
	return h, 0, ""
}

func (r *registry) get(id wire.SessionID) (*hub, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	h, ok := r.sessions[id]
	return h, ok
}

// hubs returns a snapshot of the live hubs. Callers must query each hub's
// run-owned state via hub.snapshot() AFTER this returns (i.e. without holding
// r.mu) to avoid deadlocking against a hub shutting down through remove.
func (r *registry) hubs() []*hub {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*hub, 0, len(r.sessions))
	for _, h := range r.sessions {
		out = append(out, h)
	}
	return out
}

func (r *registry) remove(id wire.SessionID) {
	r.mu.Lock()
	delete(r.sessions, id)
	r.mu.Unlock()
}

// sweep closes sessions past the absolute age cap. A hub shuts down on its own
// the moment its LAST participant leaves (the host is not special — survivors
// migrate the host role among themselves), so age is the only other reaper.
func (r *registry) sweep() {
	r.mu.Lock()
	var expired []*hub
	now := time.Now()
	for _, h := range r.sessions {
		if now.Sub(h.created) > r.maxAge {
			expired = append(expired, h)
		}
	}
	r.mu.Unlock()
	for _, h := range expired {
		select {
		case h.inbox <- closeCmd{reason: "session expired"}:
		case <-h.done:
		}
	}
}

func (r *registry) sweepLoop(every time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			r.sweep()
		case <-stop:
			return
		}
	}
}
