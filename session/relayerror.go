package session

import (
	"errors"
	"fmt"

	"github.com/richardwooding/parley/wire"
)

// Sentinels for the relay refusals a caller can act on. Match them with
// errors.Is; the underlying error is a *RelayError carrying the wire code.
var (
	ErrSessionNotFound = errors.New("session: session not found")
	ErrSessionExists   = errors.New("session: session already exists")
	ErrSessionFull     = errors.New("session: session full")
	ErrRateLimited     = errors.New("session: rate limited")
)

// RelayError is a refusal reported by the relay. Its text is unchanged from
// earlier releases, so callers that matched the string keep working.
type RelayError struct {
	Code uint16 // one of the wire.ErrCode* values
	Msg  string
}

func (e *RelayError) Error() string {
	return fmt.Sprintf("session: relay error %d: %s", e.Code, e.Msg)
}

// Is lets errors.Is(err, ErrSessionExists) and friends see through the code.
func (e *RelayError) Is(target error) bool {
	switch target {
	case ErrSessionNotFound:
		return e.Code == wire.ErrCodeSessionNotFound
	case ErrSessionExists:
		return e.Code == wire.ErrCodeSessionExists
	case ErrSessionFull:
		return e.Code == wire.ErrCodeSessionFull
	case ErrRateLimited:
		return e.Code == wire.ErrCodeRateLimited
	}
	return false
}
