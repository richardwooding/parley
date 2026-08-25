package relay

import (
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// TestIPLimiterThrottlesPerIP: burst then deny for one IP, while a different IP
// is unaffected.
func TestIPLimiterThrottlesPerIP(t *testing.T) {
	now := time.Unix(0, 0)
	l := newIPLimiter(rate.Every(12*time.Second), 5)
	l.now = func() time.Time { return now }
	for i := range 5 {
		if !l.allow("1.2.3.4:1000") {
			t.Fatalf("attempt %d within burst was denied", i)
		}
	}
	if l.allow("1.2.3.4:1001") {
		t.Fatal("6th attempt from the same IP should be denied")
	}
	if !l.allow("9.9.9.9:2000") {
		t.Fatal("a different IP should not be throttled")
	}
}

// TestIPLimiterEvictionDoesNotForgiveActiveOffender: filling the map to its cap
// must never reset an actively-throttled IP's bucket (as a blanket map reset
// would). The most-recently-seen offender survives LRU eviction and stays
// denied, then is allowed again only once its bucket refills.
func TestIPLimiterEvictionDoesNotForgiveActiveOffender(t *testing.T) {
	now := time.Unix(0, 0)
	l := newIPLimiter(rate.Every(12*time.Second), 5)
	l.now = func() time.Time { return now }

	// Pre-fill the map to its cap with distinct IPs at t0.
	for i := range ipLimiterCap {
		l.allow(uniqueIP(i))
	}

	// A moment later, an active offender exhausts its burst — it is now the
	// most-recently-seen entry, so LRU eviction can never pick it.
	now = now.Add(time.Second)
	for range 5 {
		l.allow("6.6.6.6:80")
	}
	if l.allow("6.6.6.6:80") {
		t.Fatal("offender should be denied after burst")
	}

	// Insert more fresh IPs, forcing eviction. A blanket reset would forgive the
	// offender; LRU-of-oldest must keep it denied.
	for i := ipLimiterCap; i < ipLimiterCap+50; i++ {
		l.allow(uniqueIP(i))
	}
	if l.allow("6.6.6.6:80") {
		t.Fatal("eviction forgave an active offender (it should still be throttled)")
	}

	// Once enough time passes for its bucket to refill, it is allowed again.
	now = now.Add(60 * time.Second)
	if !l.allow("6.6.6.6:80") {
		t.Fatal("offender should be allowed again after its bucket refilled")
	}
}

func uniqueIP(i int) string {
	return net4(i) + ":80"
}

func net4(i int) string {
	a := 10 + (i>>24)&0xff
	b := (i >> 16) & 0xff
	c := (i >> 8) & 0xff
	d := i & 0xff
	return itoa(a) + "." + itoa(b) + "." + itoa(c) + "." + itoa(d)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [3]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
