package session

import (
	"context"
	"testing"
	"time"

	"github.com/richardwooding/parley/crypto"
	"github.com/richardwooding/parley/wire"
)

func groupKeyOf(c *Client) crypto.Key {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.groupKey
}

func waitKeyChange(t *testing.T, c *Client, was crypto.Key) crypto.Key {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		if k := groupKeyOf(c); k != was {
			return k
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for group key to rotate")
		case <-time.After(15 * time.Millisecond):
		}
	}
}

// TestRekeyOnLeaveLocksOutDepartedMember is the forward-secrecy proof: when a
// member leaves, the host rotates the group key and re-wraps it to every
// survivor. The departed member's retained key can no longer open new traffic,
// while survivors decrypt seamlessly — including a frame that was in flight
// under the old key across the rotation.
func TestRekeyOnLeaveLocksOutDepartedMember(t *testing.T) {
	ctx := context.Background()
	url := reconnectRelay(t)

	host, phrase, err := Host(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	player, err := Join(ctx, url, phrase, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = player.Close() })
	// The host keys each joiner on its read loop; wait until both are seated.
	waitEvent[MemberKeyed](t, host)
	spectator, err := Join(ctx, url, phrase, true)
	if err != nil {
		t.Fatal(err)
	}
	waitEvent[MemberKeyed](t, host)

	k0 := groupKeyOf(host)
	if groupKeyOf(player) != k0 || groupKeyOf(spectator) != k0 {
		t.Fatal("participants did not converge on the same group key at join")
	}
	departedKey := groupKeyOf(spectator) // what a colluding departed member would keep

	// The spectator leaves → the host must rotate the key and re-wrap to the
	// surviving player.
	if err := spectator.Close(); err != nil {
		t.Fatal(err)
	}
	k1 := waitKeyChange(t, host, k0)
	if got := waitKeyChange(t, player, k0); got != k1 {
		t.Fatalf("player installed a different key than the host: %x vs %x", got[:4], k1[:4])
	}

	// Forward secrecy: a frame sealed under the NEW key must NOT open under the
	// departed member's retained key, but must open under the new key.
	sf, err := crypto.Seal(k1, []byte("secret after you left"), host.sid, host.self)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.Open(departedKey, sf, host.sid, host.self); err == nil {
		t.Fatal("departed member's old key still decrypts NEW traffic — no forward secrecy")
	}
	if _, err := crypto.Open(k1, sf, host.sid, host.self); err != nil {
		t.Fatalf("survivor's new key failed to open new traffic: %v", err)
	}

	// Mixed-key window: a frame sealed under the OLD key, still in flight when
	// the rotation lands, must still open at the survivor via the prev-key ring.
	oldFrame, err := crypto.Seal(k0, wireEnvelope(t, "chat", 1, []byte("in flight")), host.sid, host.self)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := player.openFrame(oldFrame, host.self); !ok {
		t.Fatal("survivor could not open an in-flight old-key frame after rekey (prev-key ring failed)")
	}

	// And the survivor still receives real live traffic under the new key.
	if err := host.Broadcast("chat", []byte("still here")); err != nil {
		t.Fatal(err)
	}
	fr := waitEvent[Frame](t, player)
	if string(fr.Envelope.Body) != "still here" || fr.Envelope.ServiceID != "chat" {
		t.Fatalf("survivor got wrong frame after rekey: %+v", fr.Envelope)
	}
}

// TestHostDepartureRekeyLocksOutOldHost is the forward-secrecy proof for host
// migration: after the host leaves and a survivor is promoted, the promoted host
// rotates the group key and the other survivors re-PAKE to fetch it — so the
// DEPARTED host's key can no longer open new traffic, and survivors keep their
// roles. Drives the session-layer migration crypto directly (BecomeHost +
// RotateForMigration on the successor, RekeyWithNewHost on the survivor), the
// same calls the mux makes in maybeMigrate.
func TestHostDepartureRekeyLocksOutOldHost(t *testing.T) {
	ctx := context.Background()
	url := reconnectRelay(t)

	host, phrase, err := Host(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	player, err := Join(ctx, url, phrase, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = player.Close() })
	waitEvent[MemberKeyed](t, host)
	spectator, err := Join(ctx, url, phrase, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = spectator.Close() })
	waitEvent[MemberKeyed](t, host)

	hostKey := groupKeyOf(host) // what the departing host keeps a copy of
	if groupKeyOf(player) != hostKey || groupKeyOf(spectator) != hostKey {
		t.Fatal("participants did not converge on the group key at join")
	}

	// The host departs; the player is promoted (successor), the spectator is a
	// surviving non-host member. Mirror exactly what mux.maybeMigrate does.
	if err := host.Close(); err != nil {
		t.Fatal(err)
	}
	player.BecomeHost()
	player.RotateForMigration()
	spectator.SetHostID(player.Self())
	if err := spectator.RekeyWithNewHost(); err != nil {
		t.Fatal(err)
	}

	// The spectator fetches the rotated key via the re-PAKE; both survivors end
	// up on the same NEW key, different from what the host kept.
	newKey := waitKeyChange(t, spectator, hostKey)
	if got := groupKeyOf(player); got != newKey {
		t.Fatalf("promoted host and survivor disagree on the rotated key: %x vs %x", got[:4], newKey[:4])
	}
	if newKey == hostKey {
		t.Fatal("key did not rotate on host departure")
	}

	// Forward secrecy: the departed host's key must NOT open post-migration
	// traffic; the rotated key must.
	sf, err := crypto.Seal(newKey, []byte("after you left, old host"), player.sid, player.self)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.Open(hostKey, sf, player.sid, player.self); err == nil {
		t.Fatal("departed host's key still decrypts new traffic — no forward secrecy on host departure")
	}
	if _, err := crypto.Open(newKey, sf, player.sid, player.self); err != nil {
		t.Fatalf("survivor's rotated key failed to open new traffic: %v", err)
	}

	// The survivor keeps its role across the re-key (migration rekey wraps RoleNone).
	if spectator.Role() != RoleSpectator {
		t.Fatalf("spectator role not preserved across migration rekey: got %v", spectator.Role())
	}
}

func wireEnvelope(t *testing.T, service string, seq uint64, body []byte) []byte {
	t.Helper()
	b, err := wire.Marshal(wire.Envelope{ServiceID: service, Seq: seq, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
