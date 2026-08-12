// Package chat is the simplest layered service: broadcast text messages with
// a bounded history that late joiners receive via the ctl snapshot.
package chat

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"

	"github.com/richardwooding/parley/service"
	"github.com/richardwooding/parley/wire"
)

const (
	ID = "chat"
	// historyCap bounds the snapshot for late joiners.
	historyCap = 200
	// maxText keeps one message well inside the 64KiB frame budget.
	maxText = 4096
)

// msg carries a random ID so a message seen both live and inside a late-join
// snapshot (the two paths race by design) is emitted exactly once.
type msg struct {
	ID   uint64 `cbor:"1,keyasint"`
	Text string `cbor:"2,keyasint"`
}

type snapshot struct {
	Messages []storedMsg `cbor:"1,keyasint"`
}

type storedMsg struct {
	ID   uint64             `cbor:"1,keyasint"`
	From wire.ParticipantID `cbor:"2,keyasint"`
	Text string             `cbor:"3,keyasint"`
}

// Message is the chat event emitted on the mux stream.
type Message struct {
	From wire.ParticipantID
	Text string
}

// Service implements service.Service. HandleFrame/Snapshot/Restore run on
// the mux goroutine; Say is called from the UI layer — the mutex covers the
// shared history.
type Service struct {
	service.Base

	mu      sync.Mutex
	history []storedMsg
}

func New() *Service { return &Service{} }

func (s *Service) ID() string   { return ID }
func (s *Service) Version() int { return 1 }

func (s *Service) Attach(ctx service.Context) { s.SetContext(ctx) }

// Say broadcasts a chat message. The sender's own message is emitted locally
// too (peers don't echo broadcasts back).
func (s *Service) Say(text string) error {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	if len(text) > maxText {
		return fmt.Errorf("chat: message exceeds %d bytes", maxText)
	}
	id, err := randomID()
	if err != nil {
		return err
	}
	body, err := wire.Marshal(msg{ID: id, Text: text})
	if err != nil {
		return err
	}
	if err := s.Ctx().Send.Broadcast(ID, body); err != nil {
		return err
	}
	s.record(id, s.Ctx().Self, text)
	s.Ctx().Emit(Message{From: s.Ctx().Self, Text: text})
	return nil
}

func (s *Service) HandleFrame(from wire.ParticipantID, body []byte) error {
	m, err := wire.Body[msg](body)
	if err != nil {
		return fmt.Errorf("chat: %w", err)
	}
	if len(m.Text) > maxText {
		return fmt.Errorf("chat: oversized message from %d", from)
	}
	if !s.record(m.ID, from, m.Text) {
		return nil // already seen via snapshot
	}
	s.Ctx().Emit(Message{From: from, Text: m.Text})
	return nil
}

func (s *Service) Snapshot() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.history) == 0 {
		return nil, nil
	}
	return wire.Marshal(snapshot{Messages: s.history})
}

func (s *Service) Restore(blob []byte) error {
	snap, err := wire.Body[snapshot](blob)
	if err != nil {
		return fmt.Errorf("chat: restore: %w", err)
	}
	for _, m := range snap.Messages {
		if s.record(m.ID, m.From, m.Text) {
			s.Ctx().Emit(Message{From: m.From, Text: m.Text})
		}
	}
	return nil
}

// record stores a message unless its ID is already in history; reports
// whether it was new. The linear scan is fine at historyCap scale.
func (s *Service) record(id uint64, from wire.ParticipantID, text string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range s.history {
		if m.ID == id {
			return false
		}
	}
	s.history = append(s.history, storedMsg{ID: id, From: from, Text: text})
	if len(s.history) > historyCap {
		s.history = s.history[len(s.history)-historyCap:]
	}
	return true
}

func randomID() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("chat: rand: %w", err)
	}
	return binary.BigEndian.Uint64(b[:]), nil
}
