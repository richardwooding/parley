package service

import (
	"context"
	"testing"
	"time"

	"github.com/richardwooding/parley/session"
	"github.com/richardwooding/parley/wire"
)

func TestDefaultSuccessorPolicy(t *testing.T) {
	r := func(pairs ...any) map[wire.ParticipantID]session.Role {
		m := map[wire.ParticipantID]session.Role{}
		for i := 0; i < len(pairs); i += 2 {
			m[wire.ParticipantID(pairs[i].(int))] = pairs[i+1].(session.Role)
		}
		return m
	}
	cases := []struct {
		name       string
		candidates map[wire.ParticipantID]session.Role
		want       wire.ParticipantID
	}{
		{"lowest member wins over lower observer", r(2, session.RoleObserver, 4, session.RoleMember, 5, session.RoleMember), 4},
		{"host role counts as member-tier", r(3, session.RoleHost, 5, session.RoleMember), 3},
		{"observer-only falls back to lowest id", r(6, session.RoleObserver, 4, session.RoleObserver), 4},
		{"empty roster elects nobody", r(), 0},
	}
	for _, tc := range cases {
		if got := DefaultSuccessorPolicy(tc.candidates); got != tc.want {
			t.Fatalf("%s: got %d want %d", tc.name, got, tc.want)
		}
	}
}

// A custom policy is consulted, and a result outside the candidate set is
// treated as "no successor" rather than trusted.
func TestSuccessorPolicyOverrideAndGuard(t *testing.T) {
	roster := map[wire.ParticipantID]session.Role{
		1: session.RoleHost, 2: session.RoleMember, 3: session.RoleMember,
	}
	pick3 := func(c map[wire.ParticipantID]session.Role) wire.ParticipantID { return 3 }
	rogue := func(c map[wire.ParticipantID]session.Role) wire.ParticipantID { return 99 }

	for _, tc := range []struct {
		policy SuccessorPolicy
		want   wire.ParticipantID
	}{{pick3, 3}, {rogue, 0}} {
		m := &Mux{successor: tc.policy}
		c := &ctlService{mux: m, roster: roster,
			names: map[wire.ParticipantID]string{}, endpoints: map[wire.ParticipantID]string{}}
		if got := c.electSuccessor(1); got != tc.want {
			t.Fatalf("policy result %d, want %d", got, tc.want)
		}
	}
}

// Names asserted by members flow through the host's announce to every end.
func TestCtlNameDistribution(t *testing.T) {
	url := rebindRelay(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	host, phrase, err := session.Host(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = host.Close() }()
	hostMux := NewMux(host, WithServices(&probe{}))
	hostMux.SetName("alice")

	joiner, err := session.Join(ctx, url, phrase)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = joiner.Close() }()
	joinerMux := NewMux(joiner, WithServices(&probe{}))
	joinerMux.SetName("bob")

	for _, mux := range []*Mux{hostMux, joinerMux} {
		got := waitRoster(t, mux.Events(), func(r Roster) bool {
			return r.Names[host.Self()] == "alice" && r.Names[joiner.Self()] == "bob"
		})
		if len(got.Members) != 2 {
			t.Fatalf("roster members = %d, want 2", len(got.Members))
		}
	}
}
