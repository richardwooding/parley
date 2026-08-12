package relay

import (
	"testing"
	"time"

	"github.com/richardwooding/parley/wire"
)

// TestServerStatsSnapshot drives the registry + a hub directly (white-box) to
// confirm Stats() reflects live state and increments the cumulative counters
// without racing the hub's run goroutine.
func TestServerStatsSnapshot(t *testing.T) {
	s := New(Options{Grace: time.Second})
	defer s.Close()

	var sid wire.SessionID
	sid[0] = 0xab
	h, code, _ := s.reg.create(sid, 4)
	if h == nil {
		t.Fatalf("create failed, code %d", code)
	}

	// Admit one participant via a joinCmd; waiting on the reply guarantees the
	// client is registered before we snapshot.
	reply := make(chan joinReply, 1)
	if !h.send(joinCmd{out: make(chan []byte, 8), kick: func() {}, isCreate: true, reply: reply}) {
		t.Fatal("hub rejected join")
	}
	if jr := <-reply; !jr.ok {
		t.Fatalf("join not ok: %d", jr.errC)
	}

	st := s.Stats()
	if st.ActiveSessions != 1 {
		t.Fatalf("ActiveSessions = %d, want 1", st.ActiveSessions)
	}
	if st.SessionsCreated != 1 {
		t.Fatalf("SessionsCreated = %d, want 1", st.SessionsCreated)
	}
	if st.Joins != 1 {
		t.Fatalf("Joins = %d, want 1", st.Joins)
	}
	if len(st.Sessions) != 1 {
		t.Fatalf("Sessions len = %d, want 1", len(st.Sessions))
	}
	ss := st.Sessions[0]
	if ss.Participants != 1 || ss.MaxParticipants != 4 {
		t.Fatalf("participants %d/%d, want 1/4", ss.Participants, ss.MaxParticipants)
	}
	if len(ss.ID) != 32 { // 16-byte SessionID hex-encoded
		t.Fatalf("ID hex len = %d, want 32 (%q)", len(ss.ID), ss.ID)
	}
	if st.Uptime <= 0 {
		t.Fatal("Uptime should be positive")
	}
}

// TestStatsEmptyServer confirms a snapshot of an idle relay is well-formed.
func TestStatsEmptyServer(t *testing.T) {
	s := New(Options{})
	defer s.Close()
	st := s.Stats()
	if st.ActiveSessions != 0 || len(st.Sessions) != 0 {
		t.Fatalf("expected no sessions, got %d", st.ActiveSessions)
	}
	if st.MaxSessions != 1000 {
		t.Fatalf("MaxSessions = %d, want default 1000", st.MaxSessions)
	}
}
