package crypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/richardwooding/parley/wire"
)

var sid = wire.SessionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

const testProtocol = "parleytest/v1"

// handshake runs the full two-flight PAKE both ways and returns both keys.
func handshake(t *testing.T, joinerPhrase, hostPhrase string) (Key, Key, error) {
	t.Helper()
	j, err := NewJoiner(testProtocol, joinerPhrase)
	if err != nil {
		t.Fatal(err)
	}
	hostKey, flight2, err := HostExchange(testProtocol, hostPhrase, j.Flight1, sid, 2, 1)
	if err != nil {
		return Key{}, Key{}, err
	}
	joinerKey, err := j.Finish(flight2, sid, 2, 1)
	if err != nil {
		return Key{}, Key{}, err
	}
	return joinerKey, hostKey, nil
}

func TestPakeHandshakeAgrees(t *testing.T) {
	jk, hk, err := handshake(t, "lion-42-maple", "lion-42-maple")
	if err != nil {
		t.Fatal(err)
	}
	if jk != hk {
		t.Fatal("matching phrases produced different pairwise keys")
	}
	if jk == (Key{}) {
		t.Fatal("all-zero pairwise key")
	}
}

func TestWrongPhraseFailsCleanly(t *testing.T) {
	jk, hk, err := handshake(t, "lion-42-maple", "lion-42-eagle")
	if err != nil {
		// Some PAKE implementations error during the exchange on mismatch —
		// that's an acceptable clean failure too.
		return
	}
	if jk == hk {
		t.Fatal("different phrases agreed on a key")
	}
	// The definitive wrong-phrase signal: group key unwrap fails.
	group, err := NewGroupKey()
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := WrapGroupKey(hk, group, 1, sid, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := UnwrapGroupKey(jk, wrapped, sid, 2); !errors.Is(err, ErrUnwrap) {
		t.Fatalf("want ErrUnwrap, got %v", err)
	}
}

func TestGroupKeyWrapUnwrap(t *testing.T) {
	jk, hk, err := handshake(t, "p", "p")
	if err != nil {
		t.Fatal(err)
	}
	group, err := NewGroupKey()
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := WrapGroupKey(hk, group, 2, sid, 2)
	if err != nil {
		t.Fatal(err)
	}
	got, role, err := UnwrapGroupKey(jk, wrapped, sid, 2)
	if err != nil {
		t.Fatal(err)
	}
	if got != group || role != 2 {
		t.Fatalf("unwrapped key/role mismatch (role=%d)", role)
	}

	// Same wrap replayed for a different joiner ID must fail (AD binding).
	if _, _, err := UnwrapGroupKey(jk, wrapped, sid, 3); !errors.Is(err, ErrUnwrap) {
		t.Fatalf("cross-joiner replay: want ErrUnwrap, got %v", err)
	}
}

func TestSealOpen(t *testing.T) {
	key, err := NewGroupKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("kibitz says hi")
	sf, err := Seal(key, msg, sid, 2)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(key, sf, sid, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("round trip: %q", got)
	}
}

func TestOpenRejectsTampering(t *testing.T) {
	key, _ := NewGroupKey()
	sf, err := Seal(key, []byte("move e2e4"), sid, 2)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("flipped ciphertext bit", func(t *testing.T) {
		bad := sf
		bad.Ciphertext = append([]byte{}, sf.Ciphertext...)
		bad.Ciphertext[0] ^= 1
		if _, err := Open(key, bad, sid, 2); !errors.Is(err, ErrOpen) {
			t.Fatalf("want ErrOpen, got %v", err)
		}
	})
	t.Run("wrong sender", func(t *testing.T) {
		if _, err := Open(key, sf, sid, 3); !errors.Is(err, ErrOpen) {
			t.Fatalf("sender reflection: want ErrOpen, got %v", err)
		}
	})
	t.Run("wrong session", func(t *testing.T) {
		other := sid
		other[0] ^= 1
		if _, err := Open(key, sf, other, 2); !errors.Is(err, ErrOpen) {
			t.Fatalf("cross-session replay: want ErrOpen, got %v", err)
		}
	})
	t.Run("wrong key", func(t *testing.T) {
		otherKey, _ := NewGroupKey()
		if _, err := Open(otherKey, sf, sid, 2); !errors.Is(err, ErrOpen) {
			t.Fatalf("want ErrOpen, got %v", err)
		}
	})
}

func TestPairwiseKeyBindsPairSymmetrically(t *testing.T) {
	// Both orderings of (a, b) must derive the same key — the two ends pass
	// (joinerID, hostID) in whatever order they know them.
	raw := []byte("raw pake secret")
	k1, err := derivePairwise(testProtocol, raw, sid, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := derivePairwise(testProtocol, raw, sid, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if k1 != k2 {
		t.Fatal("pairwise derivation is order-sensitive")
	}
	k3, err := derivePairwise(testProtocol, raw, sid, 3, 1)
	if err != nil {
		t.Fatal(err)
	}
	if k1 == k3 {
		t.Fatal("different pairs derived the same key")
	}
}

// TestDerivePairwiseGolden pins the HKDF construction under two protocol
// labels. "kibitz/v1" is deployed by kibitz — independently built clients
// derive this exact key from the same PAKE secret, so an accidental change
// to the info string, salt, or hash breaks every mixed-version session.
// Changing either vector knowingly is a protocol version bump.
func TestDerivePairwiseGolden(t *testing.T) {
	raw := bytes.Repeat([]byte{0x42}, 32)
	var gsid wire.SessionID
	for i := range gsid {
		gsid[i] = 0x24
	}
	for _, tc := range []struct{ protocol, want string }{
		{"kibitz/v1", "d38d4db9216dab1928efb8fe1736962200a713c85319d2c8695a7d9d7172bfac"},
		{"parley/v1", "860611c5c96b01ea608c119b8e9e3512548b6c46ed12afca2f0f60e99c7f04ee"},
	} {
		// IDs passed high-first to assert order normalization too.
		k, err := derivePairwise(tc.protocol, raw, gsid, 2, 1)
		if err != nil {
			t.Fatal(err)
		}
		if h := hex.EncodeToString(k[:]); h != tc.want {
			t.Fatalf("%s: pairwise derivation changed: %s", tc.protocol, h)
		}
	}
}
