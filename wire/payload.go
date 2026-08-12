// The inner payload layer: what clients put inside Direct/Broadcast Payload
// fields. The relay never parses any of this. Pre-keying, payloads are
// plaintext PAKE handshake flights and the wrapped group key; post-keying,
// every payload is a SealedFrame whose plaintext is an Envelope.
//
// Format mirrors the outer frame: [PayloadKind][CBOR body], no version byte —
// the outer frame's version already gates the whole stack.
package wire

import (
	"errors"
	"fmt"
)

// PayloadKind is the first byte of every Direct/Broadcast payload.
type PayloadKind uint8

const (
	KindPake1    PayloadKind = 1 // joiner→host: first PAKE flight
	KindPake2    PayloadKind = 2 // host→joiner: second PAKE flight
	KindGroupKey PayloadKind = 3 // host→joiner: wrapped group key + role
	KindSealed   PayloadKind = 4 // any→any: encrypted Envelope
	KindRekey    PayloadKind = 5 // host→member: a fresh wrapped group key after a member leaves
	// After a host migration the promoted host shares no pairwise key with the
	// other survivors, so they re-run the PAKE to establish one and fetch the
	// rotated key (delivered as a KindRekey). These mirror KindPake1/KindPake2.
	KindRekeyPake1 PayloadKind = 6 // survivor→new host: re-PAKE first flight
	KindRekeyPake2 PayloadKind = 7 // new host→survivor: re-PAKE reply flight
)

// Pake carries one PAKE flight (schollz/pake/v3 serialized state; the
// exchange is two flights — joiner init, host reply — and both sides are
// keyed after it). Spectate (set on the joiner's first flight) asks the host to
// seat this participant as a spectator regardless of join order under
// session's default seat policy (one player seat; a watcher never consumes
// it). It rides the encrypted handshake — the relay never sees it.
type Pake struct {
	Data     []byte `cbor:"1,keyasint"`
	Spectate bool   `cbor:"2,keyasint,omitempty"`
}

// GroupKey is the host-wrapped session group key: XChaCha20-Poly1305 under
// the pairwise PAKE-derived key, AD = SessionID ∥ joinerID. Ciphertext
// plaintext is groupKey(32) ∥ role(1).
type GroupKey struct {
	Nonce      [24]byte `cbor:"1,keyasint"`
	Ciphertext []byte   `cbor:"2,keyasint"`
}

// SealedFrame is what the relay forwards after keying: an Envelope encrypted
// with the session group key, AD = SessionID ∥ version ∥ senderID.
type SealedFrame struct {
	Nonce      [24]byte `cbor:"1,keyasint"`
	Ciphertext []byte   `cbor:"2,keyasint"`
}

// Envelope is the decrypted content of a SealedFrame: one message for one
// service. Seq is per-sender-per-service monotonic; receivers use it for
// gap and replay detection.
type Envelope struct {
	ServiceID string `cbor:"1,keyasint"`
	Seq       uint64 `cbor:"2,keyasint"`
	Body      []byte `cbor:"3,keyasint"`
}

var ErrPayloadTooShort = errors.New("wire: payload shorter than 1-byte kind header")

// EncodePayload builds an inner payload: kind byte + CBOR body.
func EncodePayload(k PayloadKind, body any) ([]byte, error) {
	b, err := encMode.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("wire: encode payload kind %d: %w", k, err)
	}
	return append([]byte{byte(k)}, b...), nil
}

// DecodePayload splits an inner payload into its kind and raw CBOR body.
// Unmarshal the body with Body.
func DecodePayload(payload []byte) (PayloadKind, []byte, error) {
	if len(payload) < 1 {
		return 0, nil, ErrPayloadTooShort
	}
	return PayloadKind(payload[0]), payload[1:], nil
}
