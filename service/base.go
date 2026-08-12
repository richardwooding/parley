package service

import "sync/atomic"

// Base gives every service a data-race-safe Context accessor. The mux
// re-Attaches services from the mux goroutine on reconnect (Rebind) and host
// migration (maybeMigrate), while service methods read the Context from other
// goroutines (e.g. the WASM bridge invoking a move). A plain field would race;
// an atomic pointer makes reads lock-free and the re-Attach write safe. Embed
// Base and use Ctx()/SetContext instead of a bare ctx field.
//
// (The production client is single-threaded WASM, where this can't manifest;
// this keeps native builds and the -race test suite clean, and is correct for
// any future native client.)
type Base struct {
	cx atomic.Pointer[Context]
}

// SetContext installs the Context. Called from Attach on the mux goroutine.
func (b *Base) SetContext(c Context) { b.cx.Store(&c) }

// Ctx returns the current Context (by value); the zero Context before the first
// Attach. Safe to call from any goroutine.
func (b *Base) Ctx() Context {
	if p := b.cx.Load(); p != nil {
		return *p
	}
	return Context{}
}
