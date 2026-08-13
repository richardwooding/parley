package session

import (
	"strings"
	"testing"

	"github.com/richardwooding/parley/wire"
)

func TestSessionURL(t *testing.T) {
	sid := wire.SessionID{0xde, 0xad, 0xbe, 0xef}
	hex := sid.Hex()
	cases := []struct{ base, wantContains string }{
		{"wss://h/ws", "s=" + hex},
		{"ws://h:8080/ws", "s=" + hex},
		{"wss://h/ws?x=1", "x=1"},         // existing query preserved
		{"wss://h/relay/ws", "/relay/ws"}, // path preserved
	}
	for _, tc := range cases {
		got, err := sessionURL(tc.base, sid)
		if err != nil {
			t.Fatalf("%s: %v", tc.base, err)
		}
		if !strings.Contains(got, "s="+hex) {
			t.Fatalf("%s -> %s: missing session param", tc.base, got)
		}
		if !strings.Contains(got, tc.wantContains) {
			t.Fatalf("%s -> %s: want contains %q", tc.base, got, tc.wantContains)
		}
	}
	if _, err := sessionURL("://bad", sid); err == nil {
		t.Fatal("expected error on unparseable url")
	}
}
