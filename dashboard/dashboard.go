// Package dashboard serves a read-only admin view of the relay's blind-safe
// internal state, gated by GitHub OAuth and restricted to an allowlisted set of
// usernames. It holds no game content — it only reads relay.Stats (session-id
// hashes, counts, ages, aggregate counters). All secrets come from the caller
// (env), and the whole feature is only wired up when configured, so nothing
// sensitive lives in the repo and local builds expose nothing.
package dashboard

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	_ "embed"

	"github.com/richardwooding/parley/relay"
)

var (
	errNoToken = errors.New("dashboard: github returned no access token")
	errNoLogin = errors.New("dashboard: github returned no login")
)

//go:embed dashboard.html
var pageHTML []byte

const (
	sessionTTL     = 7 * 24 * time.Hour
	stateTTL       = 10 * time.Minute
	defaultAppName = "parley"
)

// StatsSource yields a blind-safe relay snapshot; *relay.Server implements it.
type StatsSource interface{ Stats() relay.Stats }

// Config is the dashboard's runtime configuration — all from env secrets.
type Config struct {
	ClientID     string
	ClientSecret string
	CookieKey    []byte   // HMAC key for the session + OAuth-state signatures
	Allow        []string // allowed GitHub usernames (compared case-insensitively)
	BaseURL      string   // public origin for the OAuth callback, e.g. https://myapp.example.com
	// AppName brands the page (title/heading "<AppName> relay — admin") and
	// the session cookie ("<AppName>_admin"). Defaults to "parley".
	AppName string
}

// Dashboard serves the admin + auth routes.
type Dashboard struct {
	cfg    Config
	src    StatsSource
	client *http.Client
	// GitHub endpoints — fields so tests can point them at a stub server.
	authorizeURL string
	tokenURL     string
	userURL      string
	now          func() time.Time
	cookieName   string // "<AppName>_admin"
	page         []byte // dashboard.html with branding substituted
}

// New builds a Dashboard wired to production GitHub endpoints.
func New(cfg Config, src StatsSource) *Dashboard {
	app := cfg.AppName
	if app == "" {
		app = defaultAppName
	}
	brand := template.HTMLEscapeString(app + " relay")
	return &Dashboard{
		cfg:          cfg,
		src:          src,
		client:       &http.Client{Timeout: 10 * time.Second},
		authorizeURL: "https://github.com/login/oauth/authorize",
		tokenURL:     "https://github.com/login/oauth/access_token",
		userURL:      "https://api.github.com/user",
		now:          time.Now,
		cookieName:   app + "_admin",
		page:         bytes.ReplaceAll(pageHTML, []byte("{{APP}}"), []byte(brand)),
	}
}

// Register mounts the dashboard + auth routes on mux.
func (d *Dashboard) Register(mux *http.ServeMux) {
	mux.HandleFunc("/dashboard", d.handleDashboard)
	mux.HandleFunc("/dashboard/data", d.handleData)
	mux.HandleFunc("/auth/login", d.handleLogin)
	mux.HandleFunc("/auth/callback", d.handleCallback)
	mux.HandleFunc("/auth/logout", d.handleLogout)
}

// --- routes -----------------------------------------------------------------

func (d *Dashboard) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if _, ok := d.currentUser(r); !ok {
		http.Redirect(w, r, "/auth/login", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(d.page)
}

func (d *Dashboard) handleData(w http.ResponseWriter, r *http.Request) {
	if _, ok := d.currentUser(r); !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(d.src.Stats())
}

func (d *Dashboard) handleLogin(w http.ResponseWriter, r *http.Request) {
	q := url.Values{
		"client_id":    {d.cfg.ClientID},
		"redirect_uri": {d.redirectURI()},
		"scope":        {"read:user"},
		"state":        {d.newState()},
		"allow_signup": {"false"},
	}
	http.Redirect(w, r, d.authorizeURL+"?"+q.Encode(), http.StatusFound)
}

func (d *Dashboard) handleCallback(w http.ResponseWriter, r *http.Request) {
	if !d.checkState(r.URL.Query().Get("state")) {
		http.Error(w, "bad or expired state", http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}
	token, err := d.exchangeCode(r.Context(), code)
	if err != nil {
		http.Error(w, "oauth exchange failed", http.StatusBadGateway)
		return
	}
	login, err := d.fetchLogin(r.Context(), token)
	if err != nil {
		http.Error(w, "could not read GitHub user", http.StatusBadGateway)
		return
	}
	if !d.allowed(login) {
		http.Error(w, "not authorized", http.StatusForbidden)
		return
	}
	d.setCookie(w, login)
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func (d *Dashboard) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: d.cookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/auth/login", http.StatusFound)
}

// --- GitHub OAuth (hand-rolled; no external dependency) ---------------------

func (d *Dashboard) redirectURI() string {
	return strings.TrimRight(d.cfg.BaseURL, "/") + "/auth/callback"
}

// exchangeCode swaps an authorization code for an access token.
func (d *Dashboard) exchangeCode(ctx context.Context, code string) (string, error) {
	form := url.Values{
		"client_id":     {d.cfg.ClientID},
		"client_secret": {d.cfg.ClientSecret},
		"code":          {code},
		"redirect_uri":  {d.redirectURI()},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	if body.AccessToken == "" {
		return "", errNoToken
	}
	return body.AccessToken, nil
}

// fetchLogin returns the authenticated user's GitHub login.
func (d *Dashboard) fetchLogin(ctx context.Context, token string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.userURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := d.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	var body struct {
		Login string `json:"login"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	if body.Login == "" {
		return "", errNoLogin
	}
	return body.Login, nil
}

func (d *Dashboard) allowed(login string) bool {
	for _, a := range d.cfg.Allow {
		if strings.EqualFold(strings.TrimSpace(a), login) {
			return true
		}
	}
	return false
}

// --- signed cookie + OAuth state (stateless HMAC; no server session store) --

// sign returns base64url(msg).base64url(hmac(msg)).
func (d *Dashboard) sign(msg string) string {
	mac := hmac.New(sha256.New, d.cfg.CookieKey)
	mac.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString([]byte(msg)) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// unsign verifies a token from sign and returns the original message.
func (d *Dashboard) unsign(tok string) (string, bool) {
	msgB64, sigB64, ok := strings.Cut(tok, ".")
	if !ok {
		return "", false
	}
	msg, err := base64.RawURLEncoding.DecodeString(msgB64)
	if err != nil {
		return "", false
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return "", false
	}
	mac := hmac.New(sha256.New, d.cfg.CookieKey)
	mac.Write(msg)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return "", false
	}
	return string(msg), true
}

func (d *Dashboard) setCookie(w http.ResponseWriter, login string) {
	exp := d.now().Add(sessionTTL)
	val := d.sign(login + "|" + strconv.FormatInt(exp.Unix(), 10))
	http.SetCookie(w, &http.Cookie{
		Name: d.cookieName, Value: val, Path: "/", Expires: exp,
		MaxAge: int(sessionTTL.Seconds()), HttpOnly: true, Secure: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// currentUser returns the logged-in username if the request carries a valid,
// unexpired session cookie.
func (d *Dashboard) currentUser(r *http.Request) (string, bool) {
	ck, err := r.Cookie(d.cookieName)
	if err != nil {
		return "", false
	}
	msg, ok := d.unsign(ck.Value)
	if !ok {
		return "", false
	}
	login, expS, ok := strings.Cut(msg, "|")
	if !ok {
		return "", false
	}
	exp, err := strconv.ParseInt(expS, 10, 64)
	if err != nil || d.now().Unix() > exp {
		return "", false
	}
	return login, true
}

func (d *Dashboard) newState() string {
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	exp := d.now().Add(stateTTL).Unix()
	return d.sign(hex.EncodeToString(nonce) + "|" + strconv.FormatInt(exp, 10))
}

func (d *Dashboard) checkState(state string) bool {
	msg, ok := d.unsign(state)
	if !ok {
		return false
	}
	_, expS, ok := strings.Cut(msg, "|")
	if !ok {
		return false
	}
	exp, err := strconv.ParseInt(expS, 10, 64)
	return err == nil && d.now().Unix() <= exp
}
