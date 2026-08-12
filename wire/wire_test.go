package wire

import (
	"bytes"
	"errors"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	sid := SessionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	cases := []struct {
		name string
		typ  MsgType
		body any
		echo func(t *testing.T, raw []byte)
	}{
		{"CreateSession", MsgCreateSession, CreateSession{SessionID: sid, MaxParticipants: 4}, func(t *testing.T, raw []byte) {
			got, err := Body[CreateSession](raw)
			if err != nil {
				t.Fatal(err)
			}
			if got.SessionID != sid || got.MaxParticipants != 4 {
				t.Fatalf("got %+v", got)
			}
		}},
		{"JoinResult", MsgJoinResult, JoinResult{OK: true, ParticipantID: 3, Peers: []ParticipantID{1, 2}, HostID: 1}, func(t *testing.T, raw []byte) {
			got, err := Body[JoinResult](raw)
			if err != nil {
				t.Fatal(err)
			}
			if !got.OK || got.ParticipantID != 3 || got.HostID != 1 || len(got.Peers) != 2 {
				t.Fatalf("got %+v", got)
			}
		}},
		{"Direct", MsgDirect, Direct{To: 2, From: 1, Payload: []byte{0xde, 0xad}}, func(t *testing.T, raw []byte) {
			got, err := Body[Direct](raw)
			if err != nil {
				t.Fatal(err)
			}
			if got.To != 2 || got.From != 1 || !bytes.Equal(got.Payload, []byte{0xde, 0xad}) {
				t.Fatalf("got %+v", got)
			}
		}},
		{"Error", MsgError, Error{Code: ErrCodeSessionFull, Msg: "session full"}, func(t *testing.T, raw []byte) {
			got, err := Body[Error](raw)
			if err != nil {
				t.Fatal(err)
			}
			if got.Code != ErrCodeSessionFull || got.Msg != "session full" {
				t.Fatalf("got %+v", got)
			}
		}},
		{"SessionCreated", MsgSessionCreated, SessionCreated{ParticipantID: 1, ResumeToken: []byte{0xaa, 0xbb}}, func(t *testing.T, raw []byte) {
			got, err := Body[SessionCreated](raw)
			if err != nil {
				t.Fatal(err)
			}
			if got.ParticipantID != 1 || !bytes.Equal(got.ResumeToken, []byte{0xaa, 0xbb}) {
				t.Fatalf("got %+v", got)
			}
		}},
		{"ResumeSession", MsgResumeSession, ResumeSession{SessionID: sid, ParticipantID: 2, Token: []byte{0x01, 0x02, 0x03}}, func(t *testing.T, raw []byte) {
			got, err := Body[ResumeSession](raw)
			if err != nil {
				t.Fatal(err)
			}
			if got.SessionID != sid || got.ParticipantID != 2 || !bytes.Equal(got.Token, []byte{0x01, 0x02, 0x03}) {
				t.Fatalf("got %+v", got)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			frame, err := Encode(tc.typ, tc.body)
			if err != nil {
				t.Fatal(err)
			}
			if frame[0] != Version {
				t.Fatalf("version byte = 0x%02x", frame[0])
			}
			typ, raw, err := Decode(frame)
			if err != nil {
				t.Fatal(err)
			}
			if typ != tc.typ {
				t.Fatalf("type = %v, want %v", typ, tc.typ)
			}
			tc.echo(t, raw)
		})
	}
}

func TestDecodeErrors(t *testing.T) {
	if _, _, err := Decode(nil); !errors.Is(err, ErrFrameTooShort) {
		t.Fatalf("nil frame: %v", err)
	}
	if _, _, err := Decode([]byte{Version}); !errors.Is(err, ErrFrameTooShort) {
		t.Fatalf("1-byte frame: %v", err)
	}
	if _, _, err := Decode([]byte{0x7f, byte(MsgPing)}); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("bad version: %v", err)
	}
	big := make([]byte, MaxFrame+1)
	big[0] = Version
	if _, _, err := Decode(big); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversized frame: %v", err)
	}
}

func TestEncodeRejectsOversize(t *testing.T) {
	if _, err := Encode(MsgBroadcast, Broadcast{From: 1, Payload: make([]byte, MaxFrame)}); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("want ErrFrameTooLarge, got %v", err)
	}
}

func TestPayloadRoundTrip(t *testing.T) {
	p, err := EncodePayload(KindSealed, SealedFrame{Nonce: [24]byte{9}, Ciphertext: []byte("ct")})
	if err != nil {
		t.Fatal(err)
	}
	kind, raw, err := DecodePayload(p)
	if err != nil {
		t.Fatal(err)
	}
	if kind != KindSealed {
		t.Fatalf("kind = %v", kind)
	}
	sf, err := Body[SealedFrame](raw)
	if err != nil {
		t.Fatal(err)
	}
	if sf.Nonce[0] != 9 || string(sf.Ciphertext) != "ct" {
		t.Fatalf("got %+v", sf)
	}

	if _, _, err := DecodePayload(nil); !errors.Is(err, ErrPayloadTooShort) {
		t.Fatalf("empty payload: %v", err)
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	p, err := EncodePayload(KindSealed, Envelope{ServiceID: "chat", Seq: 42, Body: []byte("hi")})
	if err != nil {
		t.Fatal(err)
	}
	_, raw, err := DecodePayload(p)
	if err != nil {
		t.Fatal(err)
	}
	env, err := Body[Envelope](raw)
	if err != nil {
		t.Fatal(err)
	}
	if env.ServiceID != "chat" || env.Seq != 42 || string(env.Body) != "hi" {
		t.Fatalf("got %+v", env)
	}
}

// Deterministic encoding is load-bearing for M2's commit-reveal hashing —
// pin it so a codec change can't silently break commitments.
func TestDeterministicEncoding(t *testing.T) {
	a, err := Encode(MsgJoinResult, JoinResult{OK: true, ParticipantID: 3, Peers: []ParticipantID{1, 2}, HostID: 1})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encode(MsgJoinResult, JoinResult{OK: true, ParticipantID: 3, Peers: []ParticipantID{1, 2}, HostID: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("same struct encoded to different bytes")
	}
}

// FuzzDecode ensures no input can panic the decoder stack (frame → body for
// every message type, payload → body for every kind).
func FuzzDecode(f *testing.F) {
	seed, _ := Encode(MsgDirect, Direct{To: 2, From: 1, Payload: []byte("x")})
	f.Add(seed)
	f.Add([]byte{Version, byte(MsgPing), 0xa1, 0x01, 0x00})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		typ, raw, err := Decode(data)
		if err != nil {
			return
		}
		switch typ {
		case MsgCreateSession:
			_, _ = Body[CreateSession](raw)
		case MsgJoinSession:
			_, _ = Body[JoinSession](raw)
		case MsgJoinResult:
			_, _ = Body[JoinResult](raw)
		case MsgDirect:
			d, err := Body[Direct](raw)
			if err == nil {
				if kind, praw, perr := DecodePayload(d.Payload); perr == nil {
					switch kind {
					case KindPake1, KindPake2:
						_, _ = Body[Pake](praw)
					case KindGroupKey:
						_, _ = Body[GroupKey](praw)
					case KindSealed:
						_, _ = Body[SealedFrame](praw)
					}
				}
			}
		case MsgBroadcast:
			_, _ = Body[Broadcast](raw)
		case MsgError:
			_, _ = Body[Error](raw)
		}
	})
}
