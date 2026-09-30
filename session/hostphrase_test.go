package session

import (
	"errors"
	"testing"
)

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

	_, err = HostWithPhrase(ctx, url, p)
	if !errors.Is(err, ErrSessionExists) {
		t.Fatalf("hosting an already-live phrase: got %v, want ErrSessionExists", err)
	}
	if errors.Is(err, ErrSessionNotFound) {
		t.Fatal("ErrSessionExists also matched ErrSessionNotFound")
	}
}

// Joining a phrase nobody hosts is distinguishable too, so join-or-host can
// branch on the error rather than on its text.
func TestJoinMissingIsSessionNotFound(t *testing.T) {
	url := reconnectRelay(t)
	ctx := roleCtx(t)
	if _, err := Join(ctx, url, "nobody-0-home"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("got %v, want ErrSessionNotFound", err)
	}
}
