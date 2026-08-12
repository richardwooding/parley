package chat_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/richardwooding/parley/relay"
	"github.com/richardwooding/parley/service"
	"github.com/richardwooding/parley/service/chat"
	"github.com/richardwooding/parley/session"
)

func chatRelay(t *testing.T) string {
	t.Helper()
	s := relay.New(relay.Options{})
	t.Cleanup(s.Close)
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http")
}

func waitMsg(t *testing.T, ev <-chan any, want string) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case e, ok := <-ev:
			if !ok {
				t.Fatal("event stream closed")
			}
			if m, isMsg := e.(chat.Message); isMsg && m.Text == want {
				return
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %q", want)
		}
	}
}

func TestSayRoundTripAndLateJoinHistory(t *testing.T) {
	url := chatRelay(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	host, phrase, err := session.Host(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = host.Close() }()
	hostChat := chat.New()
	hostMux := service.NewMux(host, service.WithServices(hostChat))

	joiner, err := session.Join(ctx, url, phrase)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = joiner.Close() }()
	joinerChat := chat.New()
	joinerMux := service.NewMux(joiner, service.WithServices(joinerChat))

	if err := hostChat.Say("hello"); err != nil {
		t.Fatal(err)
	}
	waitMsg(t, hostMux.Events(), "hello")   // local echo
	waitMsg(t, joinerMux.Events(), "hello") // peer delivery

	if err := joinerChat.Say("hi back"); err != nil {
		t.Fatal(err)
	}
	waitMsg(t, hostMux.Events(), "hi back")

	// A late joiner receives the history via the ctl snapshot, deduped
	// against anything that raced in live.
	late, err := session.Join(ctx, url, phrase)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = late.Close() }()
	lateChat := chat.New()
	lateMux := service.NewMux(late, service.WithServices(lateChat))
	waitMsg(t, lateMux.Events(), "hello")
	waitMsg(t, lateMux.Events(), "hi back")
}

func TestSayRejectsOversize(t *testing.T) {
	url := chatRelay(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	host, _, err := session.Host(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = host.Close() }()
	c := chat.New()
	service.NewMux(host, service.WithServices(c))
	if err := c.Say(strings.Repeat("x", 5000)); err == nil {
		t.Fatal("oversize message accepted")
	}
}
