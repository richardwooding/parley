// Package wire defines the relay protocol: every WebSocket binary message is
// [version 0x01][MsgType][CBOR body]. The relay understands ONLY this layer —
// everything interesting rides inside opaque Payload fields (see payload.go).
//
// CBOR structs use integer keys (`cbor:"N,keyasint"`) so fields can be added
// compatibly without bloating frames with string keys.
package wire

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// Version is the protocol version carried in byte 0 of every frame. The relay
// rejects unknown versions at connect time with ErrCodeUnsupportedVersion.
const Version byte = 0x01

// MaxFrame is the largest frame the relay accepts or forwards.
const MaxFrame = 64 * 1024

// MsgType is the relay-visible message type, carried in byte 1 of every frame.
type MsgType uint8

const (
	MsgCreateSession     MsgType = 1  // c→r CreateSession
	MsgSessionCreated    MsgType = 2  // r→c SessionCreated (host is always participant 1)
	MsgJoinSession       MsgType = 3  // c→r JoinSession
	MsgJoinResult        MsgType = 4  // r→c JoinResult
	MsgParticipantJoined MsgType = 5  // r→all ParticipantJoined
	MsgParticipantLeft   MsgType = 6  // r→all ParticipantLeft
	MsgDirect            MsgType = 7  // c→r→one Direct
	MsgBroadcast         MsgType = 8  // c→r→all-others Broadcast
	MsgPing              MsgType = 9  // either way Ping
	MsgPong              MsgType = 10 // either way Pong
	MsgError             MsgType = 11 // r→c Error
	MsgSessionClosed     MsgType = 12 // r→all SessionClosed
	MsgResumeSession     MsgType = 13 // c→r ResumeSession (reclaim a held slot after a drop)
	MsgClaimHost         MsgType = 14 // c→r ClaimHost (a promoted successor becomes the join authority)
)

// Relay error codes carried in Error.Code.
const (
	ErrCodeUnsupportedVersion uint16 = 1
	ErrCodeSessionNotFound    uint16 = 2
	ErrCodeSessionExists      uint16 = 3
	ErrCodeSessionFull        uint16 = 4
	ErrCodeRateLimited        uint16 = 5
	ErrCodeBadFrame           uint16 = 6
	ErrCodeUnknownPeer        uint16 = 7
	ErrCodeResumeRejected     uint16 = 8 // resume token mismatch, slot gone, or grace expired
)

// ParticipantID identifies a participant within one session. The relay
// assigns them; the host is always 1.
type ParticipantID uint32

// SessionID is derived client-side from the code phrase:
// SHA-256(protocol ∥ "/session-id" ∥ NUL ∥ phrase)[:16]. The relay never sees the
// phrase itself.
type SessionID [16]byte

// SessionParam is the query-string key that carries a SessionID's hex as a
// pre-upgrade routing hint (see relay.Options.Router). It is advisory: the
// authoritative SessionID is always the one inside the hello frame.
const SessionParam = "s"

// Hex is the lowercase-hex encoding of the SessionID. It leaks nothing the
// relay does not already learn from the hello frame; the phrase is never
// encoded.
func (s SessionID) Hex() string { return hex.EncodeToString(s[:]) }

// ParseSessionID decodes a lowercase-hex SessionID. It rejects any string
// that is not exactly 2*len(SessionID) hex characters.
func ParseSessionID(h string) (SessionID, error) {
	var id SessionID
	if len(h) != 2*len(id) {
		return id, fmt.Errorf("wire: session id must be %d hex chars", 2*len(id))
	}
	if _, err := hex.Decode(id[:], []byte(h)); err != nil {
		return id, fmt.Errorf("wire: session id: %w", err)
	}
	return id, nil
}

type CreateSession struct {
	SessionID       SessionID `cbor:"1,keyasint"`
	MaxParticipants uint8     `cbor:"2,keyasint"`
}

type SessionCreated struct {
	ParticipantID ParticipantID `cbor:"1,keyasint"`
	// ResumeToken authorizes reclaiming this slot after an unexpected drop.
	// Opaque random bytes; the relay only equality-compares it (stays blind).
	ResumeToken []byte `cbor:"2,keyasint,omitempty"`
}

type JoinSession struct {
	SessionID SessionID `cbor:"1,keyasint"`
}

type JoinResult struct {
	OK            bool            `cbor:"1,keyasint"`
	Err           string          `cbor:"2,keyasint,omitempty"`
	ParticipantID ParticipantID   `cbor:"3,keyasint"`
	Peers         []ParticipantID `cbor:"4,keyasint,omitempty"`
	HostID        ParticipantID   `cbor:"5,keyasint"`
	// ResumeToken authorizes reclaiming this slot after an unexpected drop
	// (also echoed on a successful ResumeSession). See SessionCreated.
	ResumeToken []byte `cbor:"6,keyasint,omitempty"`
}

// ResumeSession reclaims a participant slot the relay is holding after an
// unexpected drop: same SessionID, the ParticipantID the relay had assigned,
// and the ResumeToken it issued. The relay replies with JoinResult.
type ResumeSession struct {
	SessionID     SessionID     `cbor:"1,keyasint"`
	ParticipantID ParticipantID `cbor:"2,keyasint"`
	Token         []byte        `cbor:"3,keyasint"`
}

// ClaimHost asserts that the sender is the session's new host after a host
// migration, so the relay routes future joiners' handshake to it. The relay
// stamps the sender id from the connection; the body carries nothing.
type ClaimHost struct{}

type ParticipantJoined struct {
	ParticipantID ParticipantID `cbor:"1,keyasint"`
}

type ParticipantLeft struct {
	ParticipantID ParticipantID `cbor:"1,keyasint"`
}

// Direct is relayed to exactly one peer. From is stamped by the relay on
// forwarding (a client cannot spoof it).
type Direct struct {
	To      ParticipantID `cbor:"1,keyasint"`
	From    ParticipantID `cbor:"2,keyasint"`
	Payload []byte        `cbor:"3,keyasint"`
}

// Broadcast is relayed to every other participant. From is stamped by the
// relay on forwarding.
type Broadcast struct {
	From    ParticipantID `cbor:"1,keyasint"`
	Payload []byte        `cbor:"2,keyasint"`
}

type Ping struct {
	Nonce uint32 `cbor:"1,keyasint"`
}

type Pong struct {
	Nonce uint32 `cbor:"1,keyasint"`
}

type Error struct {
	Code uint16 `cbor:"1,keyasint"`
	Msg  string `cbor:"2,keyasint,omitempty"`
}

type SessionClosed struct {
	Reason string `cbor:"1,keyasint,omitempty"`
}

var (
	ErrFrameTooShort      = errors.New("wire: frame shorter than 2-byte header")
	ErrFrameTooLarge      = fmt.Errorf("wire: frame exceeds %d bytes", MaxFrame)
	ErrUnsupportedVersion = errors.New("wire: unsupported protocol version")
)

// encMode is deterministic CBOR — required by applications that hash
// encodings (commit-reveal schemes) and
// harmless everywhere else.
var encMode, decMode = func() (cbor.EncMode, cbor.DecMode) {
	em, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	dm, err := cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		MaxArrayElements: 4096,
		MaxMapPairs:      4096,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	return em, dm
}()

// Encode builds a complete frame: version byte, message type, CBOR body.
func Encode(t MsgType, body any) ([]byte, error) {
	b, err := encMode.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("wire: encode %v: %w", t, err)
	}
	frame := make([]byte, 0, 2+len(b))
	frame = append(frame, Version, byte(t))
	frame = append(frame, b...)
	if len(frame) > MaxFrame {
		return nil, ErrFrameTooLarge
	}
	return frame, nil
}

// Decode splits a frame into its message type and raw CBOR body, validating
// the version byte and size limits. Unmarshal the body with Body.
func Decode(frame []byte) (MsgType, []byte, error) {
	if len(frame) > MaxFrame {
		return 0, nil, ErrFrameTooLarge
	}
	if len(frame) < 2 {
		return 0, nil, ErrFrameTooShort
	}
	if frame[0] != Version {
		return 0, nil, fmt.Errorf("%w: 0x%02x", ErrUnsupportedVersion, frame[0])
	}
	return MsgType(frame[1]), frame[2:], nil
}

// Marshal encodes v as bare deterministic CBOR (no frame or payload header).
// Used for Envelope plaintexts and commit-reveal preimage hashing.
func Marshal(v any) ([]byte, error) {
	return encMode.Marshal(v)
}

// Body unmarshals a frame body produced by Decode into T.
func Body[T any](raw []byte) (T, error) {
	var v T
	if err := decMode.Unmarshal(raw, &v); err != nil {
		return v, fmt.Errorf("wire: decode body: %w", err)
	}
	return v, nil
}
