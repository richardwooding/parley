package session

import (
	"context"
	"testing"
	"time"

	"github.com/richardwooding/parley/wire"
)

func roleCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// The default policy seats plain joiners as members and observers as
// observers — with no single-seat demotion of later joiners.
func TestDefaultRolePolicy(t *testing.T) {
	url := reconnectRelay(t)
	ctx := roleCtx(t)
	host, phrase, err := Host(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = host.Close() }()

	j1, err := Join(ctx, url, phrase)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = j1.Close() }()
	if k := waitEvent[MemberKeyed](t, host); k.Role != RoleMember {
		t.Fatalf("first joiner keyed as %d, want RoleMember", k.Role)
	}

	j2, err := Join(ctx, url, phrase)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = j2.Close() }()
	if k := waitEvent[MemberKeyed](t, host); k.Role != RoleMember {
		t.Fatalf("second joiner keyed as %d, want RoleMember (no single-seat demotion)", k.Role)
	}

	obs, err := Join(ctx, url, phrase, WithObserver())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = obs.Close() }()
	if k := waitEvent[MemberKeyed](t, host); k.Role != RoleObserver {
		t.Fatalf("observer keyed as %d, want RoleObserver", k.Role)
	}
	if obs.Role() != RoleObserver || j1.Role() != RoleMember {
		t.Fatalf("joiner-side roles: obs=%d j1=%d", obs.Role(), j1.Role())
	}
}

// An application-defined role byte survives the wrap/unwrap verbatim.
func TestCustomRolePolicyVerbatimByte(t *testing.T) {
	url := reconnectRelay(t)
	ctx := roleCtx(t)
	custom := func(wire.ParticipantID, bool, map[wire.ParticipantID]Role) Role { return Role(7) }
	host, phrase, err := Host(ctx, url, WithRolePolicy(custom))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = host.Close() }()

	j, err := Join(ctx, url, phrase)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = j.Close() }()
	if k := waitEvent[MemberKeyed](t, host); k.Role != Role(7) {
		t.Fatalf("host keyed joiner as %d, want 7", k.Role)
	}
	if j.Role() != Role(7) {
		t.Fatalf("joiner unwrapped role %d, want 7", j.Role())
	}
}

// Reserved values from a misbehaving policy are clamped to RoleMember —
// RoleNone would collide with the rekey keep-role convention and RoleHost
// with the migration guards.
func TestRolePolicyReservedClamp(t *testing.T) {
	url := reconnectRelay(t)
	ctx := roleCtx(t)
	bad := func(wire.ParticipantID, bool, map[wire.ParticipantID]Role) Role { return RoleHost }
	host, phrase, err := Host(ctx, url, WithRolePolicy(bad))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = host.Close() }()

	j, err := Join(ctx, url, phrase)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = j.Close() }()
	if j2 := waitEvent[MemberKeyed](t, host); j2.Role != RoleMember {
		t.Fatalf("reserved role delivered as %d, want clamped RoleMember", j2.Role)
	}
	if j.Role() != RoleMember {
		t.Fatalf("joiner role %d, want clamped RoleMember", j.Role())
	}
}

// The policy sees the roles already assigned, so single-seat policies (like
// kibitz's player/spectator split) are expressible.
func TestRolePolicySeesAssigned(t *testing.T) {
	url := reconnectRelay(t)
	ctx := roleCtx(t)
	firstOnly := func(_ wire.ParticipantID, _ bool, assigned map[wire.ParticipantID]Role) Role {
		if len(assigned) > 0 {
			return RoleObserver
		}
		return RoleMember
	}
	host, phrase, err := Host(ctx, url, WithRolePolicy(firstOnly))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = host.Close() }()

	j1, err := Join(ctx, url, phrase)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = j1.Close() }()
	if k := waitEvent[MemberKeyed](t, host); k.Role != RoleMember {
		t.Fatalf("first joiner keyed as %d, want RoleMember", k.Role)
	}
	j2, err := Join(ctx, url, phrase)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = j2.Close() }()
	if k := waitEvent[MemberKeyed](t, host); k.Role != RoleObserver {
		t.Fatalf("second joiner keyed as %d, want RoleObserver (policy saw prior assignment)", k.Role)
	}
}
