// Package service defines the layered-service abstraction and the mux that
// routes decrypted envelopes to services. All services are client-side —
// the relay never sees plaintext, so there is nowhere else for them to live.
package service

import (
	"github.com/richardwooding/parley/session"
	"github.com/richardwooding/parley/wire"
)

// Sender is how services transmit. *session.Client satisfies it.
type Sender interface {
	Broadcast(serviceID string, body []byte) error
	SendTo(to wire.ParticipantID, serviceID string, body []byte) error
}

// Context is what a service gets at attach time.
type Context struct {
	Send   Sender
	Emit   func(any) // deliver an event to the merged mux stream
	Self   wire.ParticipantID
	HostID wire.ParticipantID
	Host   bool // this end is the session host
}

// Service is one layered capability (chat, chess, …) multiplexed over the
// session. HandleFrame is always called from the mux goroutine — services
// need no internal locking for state touched only there and in Snapshot/
// Restore (also mux-called).
type Service interface {
	ID() string
	Version() int
	Attach(ctx Context)
	HandleFrame(from wire.ParticipantID, body []byte) error
	// Snapshot captures state for late joiners (host side); Restore applies
	// it (joiner side). Nil/empty snapshots are fine for stateless services.
	Snapshot() ([]byte, error)
	Restore(snapshot []byte) error
}

// MemberObserver is implemented by services that care about membership
// (the ctl service tracks roles; applications may care about departures).
type MemberObserver interface {
	MemberKeyed(id wire.ParticipantID, role session.Role)
	MemberLeft(id wire.ParticipantID)
}

// Promotable is implemented by services whose host-only bookkeeping must reset
// when this end is promoted to host mid-session (host migration). Optional:
// asserted at runtime by the mux, so services that don't seat can skip it.
type Promotable interface {
	OnPromote()
}
