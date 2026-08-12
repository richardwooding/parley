// Package phrase generates croc-style code phrases and derives session IDs
// from them. The phrase is the shared secret: it seeds the PAKE handshake and
// never leaves the clients — the relay only ever sees its hash (the session
// ID), so it cannot even attempt to join a session as a fake participant.
package phrase

import (
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"fmt"
	"math/big"
	"strings"

	"github.com/richardwooding/parley/wire"
)

// words.txt is the EFF short wordlist (1296 words): curated for typo
// distance, no profanity, all ≤5 letters. https://www.eff.org/dice
//
//go:embed words.txt
var wordsFile string

// words keeps only pure-[a-z] entries so a phrase is always cleanly
// word-NN-word. The EFF short list has one hyphenated entry ("yo-yo") that
// would otherwise produce phrases like "yo-yo-19-rival"; dropping it costs
// one word out of 1296 (negligible entropy).
var words = func() []string {
	out := make([]string, 0, 1296)
	for _, w := range strings.Fields(wordsFile) {
		alpha := w != ""
		for _, r := range w {
			if r < 'a' || r > 'z' {
				alpha = false
				break
			}
		}
		if alpha {
			out = append(out, w)
		}
	}
	return out
}()

// New generates a fresh code phrase of the form "lion-42-maple":
// 1296 × 100 × 1296 ≈ 2^27.3 combinations. That's plenty behind PAKE — every
// wrong guess costs an online round-trip and join attempts are rate-limited.
func New() string {
	return fmt.Sprintf("%s-%02d-%s", words[randInt(len(words))], randInt(100), words[randInt(len(words))])
}

// SessionID derives the relay-visible session identifier from a phrase as
// SHA-256(protocol ∥ "/session-id" ∥ NUL ∥ Canonical(phrase))[:16]. protocol
// is the application's domain-separation label (e.g. "myapp/v1"); it
// domain-separates the session-ID hash from any other use of the phrase, and
// both ends must use the same label or they land in different sessions.
// Phrases are canonicalized (trimmed, lowercased) so "Lion-42-Maple " and
// "lion-42-maple" land in the same session.
func SessionID(protocol, phrase string) wire.SessionID {
	sum := sha256.Sum256([]byte(protocol + "/session-id" + "\x00" + Canonical(phrase)))
	var id wire.SessionID
	copy(id[:], sum[:16])
	return id
}

// Canonical normalizes a phrase for hashing and comparison.
func Canonical(phrase string) string {
	return strings.ToLower(strings.TrimSpace(phrase))
}

func randInt(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		// crypto/rand failure is unrecoverable; generating a weak phrase
		// silently would be worse than crashing.
		panic(fmt.Sprintf("phrase: crypto/rand: %v", err))
	}
	return int(v.Int64())
}
