package relay

import (
	"net"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// ipLimiter rate-limits connection attempts per client IP. Behind PAKE the
// phrase space (~2^27) is only attackable online, so throttling joins is the
// second half of the wrong-phrase defense.
type ipLimiter struct {
	mu    sync.Mutex
	m     map[string]*ipEntry
	limit rate.Limit
	burst int
	now   func() time.Time // injectable for tests
}

type ipEntry struct {
	lim  *rate.Limiter
	seen time.Time
}

// ipLimiterCap bounds the tracking map. When full we evict rather than grow
// without bound — see evictLocked.
const ipLimiterCap = 16384

// ipIdleTTL: an entry idle at least this long has a fully-refilled token bucket
// (limit 5/min, burst 5 → refills in ~1 min), so evicting it is
// indistinguishable from a fresh one. This lets us bound memory without ever
// forgiving an ACTIVE offender, unlike a blanket map reset.
const ipIdleTTL = 2 * time.Minute

func newIPLimiter(limit rate.Limit, burst int) *ipLimiter {
	return &ipLimiter{m: map[string]*ipEntry{}, limit: limit, burst: burst, now: time.Now}
}

// count returns how many client IPs are currently tracked (for the dashboard;
// the IPs themselves are never exposed).
func (l *ipLimiter) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.m)
}

func (l *ipLimiter) allow(remoteAddr string) bool {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ip = remoteAddr
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if e, ok := l.m[ip]; ok {
		e.seen = now
		return e.lim.AllowN(now, 1)
	}
	if len(l.m) >= ipLimiterCap {
		l.evictLocked(now)
	}
	lim := rate.NewLimiter(l.limit, l.burst)
	l.m[ip] = &ipEntry{lim: lim, seen: now}
	return lim.AllowN(now, 1)
}

// evictLocked frees space in a full map: it drops every entry idle past
// ipIdleTTL (their buckets are already refilled, so this is lossless), and only
// if none are stale falls back to dropping the single least-recently-seen entry
// — never a blanket reset, which would forgive currently-active offenders.
// Caller holds l.mu.
func (l *ipLimiter) evictLocked(now time.Time) {
	var oldestKey string
	var oldestSeen time.Time
	freed := false
	for k, e := range l.m {
		if now.Sub(e.seen) >= ipIdleTTL {
			delete(l.m, k)
			freed = true
			continue
		}
		if oldestKey == "" || e.seen.Before(oldestSeen) {
			oldestKey, oldestSeen = k, e.seen
		}
	}
	if !freed && oldestKey != "" {
		delete(l.m, oldestKey)
	}
}
