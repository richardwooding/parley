package session

import "testing"

// HostWithPhrase creates a joinable session under a caller-chosen phrase — the
// primitive that lets an app reopen a persisted workspace by its known phrase.
func TestHostWithPhraseJoinable(t *testing.T) {
	url := reconnectRelay(t)
	ctx := roleCtx(t)
	const p = "lion-42-maple"

	host, err := HostWithPhrase(ctx, url, p)
	if err != nil {
		t.Fatalf("HostWithPhrase: %v", err)
	}
	defer func() { _ = host.Close() }()

	j, err := Join(ctx, url, p)
	if err != nil {
		t.Fatalf("Join chosen-phrase session: %v", err)
	}
	defer func() { _ = j.Close() }()

	if k := waitEvent[MemberKeyed](t, host); k.Role != RoleMember {
		t.Fatalf("joiner keyed as %d, want RoleMember", k.Role)
	}
}

// The phrase is canonicalized exactly like Join, so casing/whitespace variants
// land in the same session — essential so a re-host and a later join agree.
func TestHostWithPhraseCanonicalized(t *testing.T) {
	url := reconnectRelay(t)
	ctx := roleCtx(t)

	host, err := HostWithPhrase(ctx, url, "Lion-42-Maple")
	if err != nil {
		t.Fatalf("HostWithPhrase: %v", err)
	}
	defer func() { _ = host.Close() }()

	j, err := Join(ctx, url, "  lion-42-maple ")
	if err != nil {
		t.Fatalf("Join canonical variant: %v", err)
	}
	defer func() { _ = j.Close() }()

	_ = waitEvent[MemberKeyed](t, host)
}

// An empty/blank phrase is rejected before dialing.
func TestHostWithPhraseEmpty(t *testing.T) {
	url := reconnectRelay(t)
	ctx := roleCtx(t)
	if _, err := HostWithPhrase(ctx, url, "   "); err == nil {
		t.Fatal("expected an error for an empty phrase")
	}
}

// Hosting a phrase whose session is already live is refused by the relay, so a
// "join-or-host" caller knows to fall back to Join.
func TestHostWithPhraseAlreadyExists(t *testing.T) {
	url := reconnectRelay(t)
	ctx := roleCtx(t)
	const p = "otter-7-canyon"

	h1, err := HostWithPhrase(ctx, url, p)
	if err != nil {
		t.Fatalf("first HostWithPhrase: %v", err)
	}
	defer func() { _ = h1.Close() }()

	if _, err := HostWithPhrase(ctx, url, p); err == nil {
		t.Fatal("expected an error hosting an already-live phrase")
	}
}
