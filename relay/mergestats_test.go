package relay

import (
	"testing"
	"time"
)

func TestMergeStats(t *testing.T) {
	a := Stats{
		Uptime: 10 * time.Second, ActiveSessions: 2, TrackedIPs: 3,
		MaxSessions: 1000, MaxParticipants: 6, Grace: 30 * time.Second,
		SessionsCreated: 5, FramesForwarded: 100, BytesForwarded: 4000,
		Joins: 7, Resumes: 1, Errors: 2,
		Sessions: []SessionStat{{ID: "aa"}, {ID: "bb"}},
	}
	b := Stats{
		Uptime: 25 * time.Second, ActiveSessions: 1, TrackedIPs: 4,
		MaxSessions: 1000, MaxParticipants: 6, Grace: 30 * time.Second,
		SessionsCreated: 3, FramesForwarded: 50, BytesForwarded: 1000,
		Joins: 4, Resumes: 2, Errors: 1,
		Sessions: []SessionStat{{ID: "cc"}},
	}
	m := MergeStats(a, b)

	if m.ActiveSessions != 3 || m.TrackedIPs != 7 {
		t.Fatalf("counts: active=%d ips=%d", m.ActiveSessions, m.TrackedIPs)
	}
	if m.SessionsCreated != 8 || m.FramesForwarded != 150 || m.BytesForwarded != 5000 ||
		m.Joins != 11 || m.Resumes != 3 || m.Errors != 3 {
		t.Fatalf("counter sums wrong: %+v", m)
	}
	if m.Uptime != 25*time.Second {
		t.Fatalf("uptime = %v, want max 25s", m.Uptime)
	}
	if m.MaxSessions != 1000 || m.MaxParticipants != 6 || m.Grace != 30*time.Second {
		t.Fatalf("config fields not carried: %+v", m)
	}
	if len(m.Sessions) != 3 {
		t.Fatalf("sessions = %d, want 3 (concatenated)", len(m.Sessions))
	}
	// The first snapshot's Sessions must not be mutated by the merge.
	if len(a.Sessions) != 2 {
		t.Fatal("MergeStats mutated the input's Sessions slice")
	}
}

func TestMergeStatsEdgeCases(t *testing.T) {
	if got := MergeStats(); got.ActiveSessions != 0 || got.Sessions != nil {
		t.Fatalf("zero-arg merge = %+v, want zero", got)
	}
	one := Stats{ActiveSessions: 4, Sessions: []SessionStat{{ID: "x"}}}
	if got := MergeStats(one); got.ActiveSessions != 4 || len(got.Sessions) != 1 {
		t.Fatalf("single merge = %+v", got)
	}
}
