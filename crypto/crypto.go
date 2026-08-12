// Package crypto is parley's security boundary. The code phrase seeds a
// per-pair PAKE (schollz/pake/v3, curve "siec" — croc's default) between each
// joiner and the host; the host wraps a random 32-byte group key to each
// joiner under the PAKE-derived pairwise key; all service traffic is
// XChaCha20-Poly1305 under the group key. Every AEAD binds associated data to
// the session, protocol version, and sender so frames cannot be replayed
// across sessions or reflected as another participant.
//
// pake/v3 is wrapped completely here so it stays swappable
// (filippo.io/spake2 is the fallback if it bit-rots).
package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/schollz/pake/v3"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	"github.com/richardwooding/parley/wire"
)

const pakeCurve = "siec"

// KeySize is the size of pairwise and group keys.
const KeySize = 32

// Key is a symmetric key — pairwise (PAKE-derived) or the session group key.
type Key [KeySize]byte

var (
	ErrUnwrap = errors.New("crypto: group key unwrap failed (wrong phrase?)")
	ErrOpen   = errors.New("crypto: frame authentication failed")
)

// --- Pairwise PAKE handshake -----------------------------------------------

// Joiner is the joiner's half of the two-flight PAKE. Create with NewJoiner,
// send Flight1 to the host (KindPake1), feed the host's reply to Finish.
type Joiner struct {
	p        *pake.Pake
	protocol string
	Flight1  []byte
}

// NewJoiner starts a joiner-side PAKE. protocol is the application's
// domain-separation label (e.g. "myapp/v1"); both ends must use the same
// label or the derived keys diverge.
func NewJoiner(protocol, phrase string) (*Joiner, error) {
	p, err := pake.InitCurve([]byte(phrase), 0, pakeCurve)
	if err != nil {
		return nil, fmt.Errorf("crypto: pake init: %w", err)
	}
	return &Joiner{p: p, protocol: protocol, Flight1: p.Bytes()}, nil
}

// Finish consumes the host's flight (KindPake2) and derives the pairwise key.
func (j *Joiner) Finish(flight2 []byte, sid wire.SessionID, joinerID, hostID wire.ParticipantID) (Key, error) {
	if err := j.p.Update(flight2); err != nil {
		return Key{}, fmt.Errorf("crypto: pake update: %w", err)
	}
	raw, err := j.p.SessionKey()
	if err != nil {
		return Key{}, fmt.Errorf("crypto: pake session key: %w", err)
	}
	return derivePairwise(j.protocol, raw, sid, joinerID, hostID)
}

// HostExchange is the host's whole handshake in one call: consume the
// joiner's flight (KindPake1), produce the reply flight (KindPake2) and the
// pairwise key. The host retains no per-joiner handshake state. protocol is
// the application's domain-separation label and must match the joiner's.
func HostExchange(protocol, phrase string, flight1 []byte, sid wire.SessionID, joinerID, hostID wire.ParticipantID) (Key, []byte, error) {
	p, err := pake.InitCurve([]byte(phrase), 1, pakeCurve)
	if err != nil {
		return Key{}, nil, fmt.Errorf("crypto: pake init: %w", err)
	}
	if err := p.Update(flight1); err != nil {
		return Key{}, nil, fmt.Errorf("crypto: pake update: %w", err)
	}
	raw, err := p.SessionKey()
	if err != nil {
		return Key{}, nil, fmt.Errorf("crypto: pake session key: %w", err)
	}
	key, err := derivePairwise(protocol, raw, sid, joinerID, hostID)
	if err != nil {
		return Key{}, nil, err
	}
	return key, p.Bytes(), nil
}

// derivePairwise binds the raw PAKE secret to the application protocol, the
// session, and the pair of participant IDs (order-normalized) via HKDF-SHA256.
func derivePairwise(protocol string, raw []byte, sid wire.SessionID, a, b wire.ParticipantID) (Key, error) {
	lo, hi := a, b
	if lo > hi {
		lo, hi = hi, lo
	}
	info := protocol + fmt.Sprintf("/pairwise/%d/%d", lo, hi)
	r := hkdf.New(sha256.New, raw, sid[:], []byte(info))
	var key Key
	if _, err := io.ReadFull(r, key[:]); err != nil {
		return Key{}, fmt.Errorf("crypto: hkdf: %w", err)
	}
	return key, nil
}

// --- Group key --------------------------------------------------------------

// NewGroupKey generates the random session group key (host-side, at create).
func NewGroupKey() (Key, error) {
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		return Key{}, fmt.Errorf("crypto: rand: %w", err)
	}
	return k, nil
}

// WrapGroupKey seals groupKey∥role to one joiner under the pairwise key,
// AD-bound to the session and the joiner's identity.
func WrapGroupKey(pairwise, groupKey Key, role byte, sid wire.SessionID, joinerID wire.ParticipantID) (wire.GroupKey, error) {
	aead, err := chacha20poly1305.NewX(pairwise[:])
	if err != nil {
		return wire.GroupKey{}, err
	}
	var gk wire.GroupKey
	if _, err := rand.Read(gk.Nonce[:]); err != nil {
		return wire.GroupKey{}, fmt.Errorf("crypto: rand: %w", err)
	}
	plaintext := append(append([]byte{}, groupKey[:]...), role)
	gk.Ciphertext = aead.Seal(nil, gk.Nonce[:], plaintext, wrapAD(sid, joinerID))
	return gk, nil
}

// UnwrapGroupKey opens a wrapped group key. A failure almost always means the
// two sides typed different phrases — surface it as such.
func UnwrapGroupKey(pairwise Key, gk wire.GroupKey, sid wire.SessionID, joinerID wire.ParticipantID) (Key, byte, error) {
	aead, err := chacha20poly1305.NewX(pairwise[:])
	if err != nil {
		return Key{}, 0, err
	}
	plaintext, err := aead.Open(nil, gk.Nonce[:], gk.Ciphertext, wrapAD(sid, joinerID))
	if err != nil {
		return Key{}, 0, ErrUnwrap
	}
	if len(plaintext) != KeySize+1 {
		return Key{}, 0, ErrUnwrap
	}
	var key Key
	copy(key[:], plaintext[:KeySize])
	return key, plaintext[KeySize], nil
}

func wrapAD(sid wire.SessionID, joinerID wire.ParticipantID) []byte {
	ad := make([]byte, 0, len(sid)+1+4)
	ad = append(ad, sid[:]...)
	ad = append(ad, wire.Version)
	ad = binary.BigEndian.AppendUint32(ad, uint32(joinerID))
	return ad
}

// --- Service traffic --------------------------------------------------------

// Seal encrypts an encoded Envelope under the group key for broadcast or
// direct sending. AD binds session, protocol version, and sender.
func Seal(groupKey Key, plaintext []byte, sid wire.SessionID, sender wire.ParticipantID) (wire.SealedFrame, error) {
	aead, err := chacha20poly1305.NewX(groupKey[:])
	if err != nil {
		return wire.SealedFrame{}, err
	}
	var sf wire.SealedFrame
	if _, err := rand.Read(sf.Nonce[:]); err != nil {
		return wire.SealedFrame{}, fmt.Errorf("crypto: rand: %w", err)
	}
	sf.Ciphertext = aead.Seal(nil, sf.Nonce[:], plaintext, frameAD(sid, sender))
	return sf, nil
}

// Open decrypts a SealedFrame received from sender. The relay stamps sender
// IDs, so a mismatch between the stamped sender and the AD the peer sealed
// with fails authentication here.
func Open(groupKey Key, sf wire.SealedFrame, sid wire.SessionID, sender wire.ParticipantID) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(groupKey[:])
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, sf.Nonce[:], sf.Ciphertext, frameAD(sid, sender))
	if err != nil {
		return nil, ErrOpen
	}
	return plaintext, nil
}

func frameAD(sid wire.SessionID, sender wire.ParticipantID) []byte {
	ad := make([]byte, 0, len(sid)+1+4)
	ad = append(ad, sid[:]...)
	ad = append(ad, wire.Version)
	ad = binary.BigEndian.AppendUint32(ad, uint32(sender))
	return ad
}
