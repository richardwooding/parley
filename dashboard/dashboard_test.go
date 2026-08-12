package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/richardwooding/parley/relay"
)

type fakeSrc struct{}

func (fakeSrc) Stats() relay.Stats {
	return relay.Stats{ActiveSessions: 2, Sessions: []relay.SessionStat{{ID: "abcd", Participants: 2}}}
}

// newTestDash returns a Dashboard whose GitHub endpoints point at a stub server
// that issues a fixed access token and reports login as *loginPtr.
func newTestDash(t *testing.T) (*Dashboard, *string) {
	t.Helper()
	login := new(string)
	*login = "richardwooding"
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/token"):
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		case strings.HasSuffix(r.URL.Path, "/user"):
			_ = json.NewEncoder(w).Encode(map[string]string{"login": *login})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(gh.Close)
	d := New(Config{
		ClientID: "cid", ClientSecret: "sec",
		CookieKey: []byte("0123456789abcdef0123456789abcdef"),
		Allow:     []string{"richardwooding"}, BaseURL: "https://example.test",
	}, fakeSrc{})
	d.authorizeURL = gh.URL + "/authorize"
	d.tokenURL = gh.URL + "/token"
	d.userURL = gh.URL + "/user"
	return d, login
}

func TestSignRoundTripAndTamper(t *testing.T) {
	d, _ := newTestDash(t)
	tok := d.sign("hello|123")
	if got, ok := d.unsign(tok); !ok || got != "hello|123" {
		t.Fatalf("round trip: %q ok=%v", got, ok)
	}
	if _, ok := d.unsign(tok + "x"); ok {
		t.Fatal("tampered token verified")
	}
	if _, ok := d.unsign("garbage"); ok {
		t.Fatal("garbage verified")
	}
}

func TestCurrentUserExpiry(t *testing.T) {
	d, _ := newTestDash(t)
	t0 := time.Unix(1_000_000, 0)
	d.now = func() time.Time { return t0 }
	rec := httptest.NewRecorder()
	d.setCookie(rec, "richardwooding")
	ck := rec.Result().Cookies()[0]

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(ck)
	if u, ok := d.currentUser(req); !ok || u != "richardwooding" {
		t.Fatalf("fresh cookie: %q ok=%v", u, ok)
	}
	d.now = func() time.Time { return t0.Add(sessionTTL + time.Hour) }
	if _, ok := d.currentUser(req); ok {
		t.Fatal("expired cookie accepted")
	}
}

func TestAllowed(t *testing.T) {
	d, _ := newTestDash(t)
	if !d.allowed("RichardWooding") {
		t.Fatal("case-insensitive allow failed")
	}
	if d.allowed("mallory") {
		t.Fatal("non-allowlisted accepted")
	}
}

func TestDashboardRedirectsWhenLoggedOut(t *testing.T) {
	d, _ := newTestDash(t)
	rec := httptest.NewRecorder()
	d.handleDashboard(rec, httptest.NewRequest(http.MethodGet, "/dashboard", nil))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/auth/login" {
		t.Fatalf("want 302 to /auth/login, got %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestDataUnauthorizedThenAuthorized(t *testing.T) {
	d, _ := newTestDash(t)
	rec := httptest.NewRecorder()
	d.handleData(rec, httptest.NewRequest(http.MethodGet, "/dashboard/data", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no cookie: want 401, got %d", rec.Code)
	}

	cookieRec := httptest.NewRecorder()
	d.setCookie(cookieRec, "richardwooding")
	req := httptest.NewRequest(http.MethodGet, "/dashboard/data", nil)
	req.AddCookie(cookieRec.Result().Cookies()[0])
	rec = httptest.NewRecorder()
	d.handleData(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid cookie: want 200, got %d", rec.Code)
	}
	var out relay.Stats
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if out.ActiveSessions != 2 {
		t.Fatalf("ActiveSessions = %d, want 2", out.ActiveSessions)
	}
}

func TestLoginRedirect(t *testing.T) {
	d, _ := newTestDash(t)
	rec := httptest.NewRecorder()
	d.handleLogin(rec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	loc := rec.Header().Get("Location")
	if rec.Code != http.StatusFound || !strings.Contains(loc, "client_id=cid") || !strings.Contains(loc, "state=") {
		t.Fatalf("bad login redirect: %d %q", rec.Code, loc)
	}
}

func TestCallbackHappyPath(t *testing.T) {
	d, _ := newTestDash(t)
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc&state="+d.newState(), nil)
	rec := httptest.NewRecorder()
	d.handleCallback(rec, req)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/dashboard" {
		t.Fatalf("want 302 to /dashboard, got %d %q", rec.Code, rec.Header().Get("Location"))
	}
	cks := rec.Result().Cookies()
	if len(cks) == 0 || cks[0].Name != d.cookieName || cks[0].Value == "" {
		t.Fatal("expected a session cookie to be set")
	}
	if u, ok := d.unsign(cks[0].Value); !ok || !strings.HasPrefix(u, "richardwooding|") {
		t.Fatalf("cookie payload = %q ok=%v", u, ok)
	}
}

func TestCallbackForbiddenUser(t *testing.T) {
	d, login := newTestDash(t)
	*login = "mallory" // GitHub reports a non-allowlisted user
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc&state="+d.newState(), nil)
	rec := httptest.NewRecorder()
	d.handleCallback(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403 for non-allowlisted user, got %d", rec.Code)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Fatal("no cookie should be set for a rejected user")
	}
}

func TestCallbackBadState(t *testing.T) {
	d, _ := newTestDash(t)
	rec := httptest.NewRecorder()
	d.handleCallback(rec, httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc&state=forged", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for forged state, got %d", rec.Code)
	}
}

func TestLogoutClearsCookie(t *testing.T) {
	d, _ := newTestDash(t)
	rec := httptest.NewRecorder()
	d.handleLogout(rec, httptest.NewRequest(http.MethodGet, "/auth/logout", nil))
	cks := rec.Result().Cookies()
	if len(cks) == 0 || cks[0].MaxAge >= 0 {
		t.Fatalf("logout should clear the cookie, got %+v", cks)
	}
}

// AppName brands both the session cookie and the served page; empty defaults
// to "parley".
func TestAppNameBranding(t *testing.T) {
	def := New(Config{}, fakeSrc{})
	if def.cookieName != "parley_admin" {
		t.Fatalf("default cookie name = %q, want parley_admin", def.cookieName)
	}
	d := New(Config{AppName: "confab"}, fakeSrc{})
	if d.cookieName != "confab_admin" {
		t.Fatalf("cookie name = %q, want confab_admin", d.cookieName)
	}
	if !strings.Contains(string(d.page), "confab relay") {
		t.Fatal("served page not branded with AppName")
	}
	if strings.Contains(string(d.page), "{{APP}}") {
		t.Fatal("branding placeholder left unsubstituted")
	}
}
