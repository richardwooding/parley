package relay

import (
	"encoding/hex"
	"sync/atomic"
	"time"

	"github.com/richardwooding/parley/wire"
)

// Metrics holds cumulative relay counters. Every field is an atomic so any
// goroutine (hub run loops, the accept path) can bump it lock-free and the
// dashboard can read a snapshot without coordinating with them.
type Metrics struct {
	SessionsCreated atomic.Uint64
	FramesForwarded atomic.Uint64
	BytesForwarded  atomic.Uint64
	Joins           atomic.Uint64
	Resumes         atomic.Uint64
	Errors          atomic.Uint64
}

// Stats is an immutable, blind-safe snapshot of the relay's internal state for
// the admin dashboard: only metadata — session-id hashes, counts, ages, and
// aggregate counters — never payloads, reclaim tokens, phrases, or client IPs.
type Stats struct {
	Uptime          time.Duration
	ActiveSessions  int
	MaxSessions     int
	MaxParticipants int
	MaxAge          time.Duration
	Grace           time.Duration
	IdleTimeout     time.Duration
	TrackedIPs      int
	SessionsCreated uint64
	FramesForwarded uint64
	BytesForwarded  uint64
	Joins           uint64
	Resumes         uint64
	Errors          uint64
	Sessions        []SessionStat
}

// SessionStat is one live session's blind-safe metadata.
type SessionStat struct {
	ID              string // hex of the session-id hash (never the phrase)
	AgeSeconds      float64
	Participants    int
	MaxParticipants int
	Host            uint32
	IDsIssued       uint32 // nextID-1: participants admitted over the session's life
	Clients         []ClientStat
}

// ClientStat is one participant slot's metadata. Held marks a slot kept alive
// for grace after an unexpected drop (awaiting resume).
type ClientStat struct {
	ID   uint32
	Held bool
	Gen  uint64
}

// statsCmd asks a hub's run goroutine to snapshot its (otherwise
// goroutine-confined) state and reply.
type statsCmd struct{ reply chan hubStats }

type hubStats struct {
	participants int
	host         wire.ParticipantID
	nextID       wire.ParticipantID
	clients      []ClientStat
}

func (h *hub) handleStats(cmd statsCmd) {
	hs := hubStats{
		participants: len(h.clients),
		host:         h.host,
		nextID:       h.nextID,
		clients:      make([]ClientStat, 0, len(h.clients)),
	}
	for _, c := range h.clients {
		hs.clients = append(hs.clients, ClientStat{ID: uint32(c.id), Held: c.held, Gen: c.gen})
	}
	cmd.reply <- hs
}

// snapshot asks the hub for its run-owned state, returning ok=false if the hub
// has already shut down. MUST be called WITHOUT holding registry.mu: a
// shutting-down hub grabs that lock via onEmpty→registry.remove, so querying it
// while holding the lock could deadlock.
func (h *hub) snapshot() (hubStats, bool) {
	reply := make(chan hubStats, 1)
	if !h.send(statsCmd{reply: reply}) {
		return hubStats{}, false
	}
	select {
	case hs := <-reply:
		return hs, true
	case <-h.done:
		return hubStats{}, false
	}
}

// Stats returns a blind-safe snapshot of live relay state for the dashboard.
func (s *Server) Stats() Stats {
	st := Stats{
		Uptime:          time.Since(s.started),
		MaxSessions:     s.opts.MaxSessions,
		MaxParticipants: s.opts.MaxParticipants,
		MaxAge:          s.opts.MaxAge,
		Grace:           s.opts.Grace,
		IdleTimeout:     s.opts.IdleTimeout,
		TrackedIPs:      s.limiter.count(),
		SessionsCreated: s.metrics.SessionsCreated.Load(),
		FramesForwarded: s.metrics.FramesForwarded.Load(),
		BytesForwarded:  s.metrics.BytesForwarded.Load(),
		Joins:           s.metrics.Joins.Load(),
		Resumes:         s.metrics.Resumes.Load(),
		Errors:          s.metrics.Errors.Load(),
	}
	hubs := s.reg.hubs() // snapshot the *hub pointers under the lock, then release it
	st.ActiveSessions = len(hubs)
	for _, h := range hubs {
		hs, ok := h.snapshot()
		if !ok {
			continue // hub shut down between listing and querying
		}
		st.Sessions = append(st.Sessions, SessionStat{
			ID:              hex.EncodeToString(h.id[:]),
			AgeSeconds:      time.Since(h.created).Seconds(),
			Participants:    hs.participants,
			MaxParticipants: h.max,
			Host:            uint32(hs.host),
			IDsIssued:       uint32(hs.nextID) - 1,
			Clients:         hs.clients,
		})
	}
	return st
}
