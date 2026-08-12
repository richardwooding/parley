// Package parley is a phrase-paired, end-to-end-encrypted group session
// library with a blind relay — croc-style pairing for long-lived sessions.
//
// A host gets a short code phrase (like "lion-42-maple"); others join with
// it. The phrase never leaves the clients: it seeds a PAKE handshake
// (schollz/pake/v3) between each joiner and the host, the host wraps a random
// group key to each joiner under the PAKE-derived pairwise key, and all
// application traffic is XChaCha20-Poly1305 under the group key. The relay
// forwards opaque frames it can never read; it sees only a hash of the phrase
// (the session ID) and participant counts. The group key rotates whenever a
// member leaves, and host departure triggers migration: a survivor is
// promoted and the others re-PAKE with it.
//
// Subpackages:
//
//   - phrase:  code-phrase generation (EFF short wordlist) and session-ID
//     derivation
//   - wire:    the framing protocol — versioned messages and encrypted
//     payload envelopes, deterministic CBOR
//   - crypto:  the security boundary — PAKE, HKDF pairwise keys, group-key
//     wrap/unwrap, AEAD sealing with session/sender-bound associated data
//   - session: the client engine — dial, handshake, events, rekey,
//     reconnect/resume, host migration (compiles to WASM)
//   - relay:   the server — a blind frame forwarder, one http.Handler
//   - service: the layered-service mux — routes decrypted envelopes to
//     application services, host-authoritative roster/names, snapshot
//     transfer for late joiners, host-migration election (compiles to WASM)
//   - service/chat: a ready-made text-chat service with late-join history
//   - dashboard: an optional GitHub-OAuth-gated admin dashboard over the
//     relay's blind Stats() snapshot (server-only)
//
// Every end of a session must agree on an application protocol label (see
// session.WithProtocol): it domain-separates session IDs and the key
// schedule, so two applications built on parley can never be cross-joined.
package parley
