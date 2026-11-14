// Package server is the Shipshape licence server. It turns Stripe
// subscription events into accounts, and account tokens into short-lived
// signed licences.
package server

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/20041540MichaelKelly/shipshape/internal/license"
)

// Account is one paying customer.
type Account struct {
	// Token is the plain token. It is kept only while the claim page may
	// still need to show it, then erased; TokenHash is what requests are
	// checked against, so a leaked accounts file does not leak usable tokens.
	Token          string    `json:"token,omitempty"`
	TokenHash      string    `json:"token_hash"`
	Email          string    `json:"email"`
	CustomerID     string    `json:"customer_id"`
	SubscriptionID string    `json:"subscription_id"`
	SessionID      string    `json:"session_id"`
	Active         bool      `json:"active"`
	CreatedAt      time.Time `json:"created_at"`
}

// Store keeps accounts in one JSON file. It suits the first few hundred
// customers on a single machine; move to a database before running two.
type Store struct {
	mu       sync.Mutex
	path     string
	Accounts []*Account `json:"accounts"`
}

// OpenStore loads the file at path, or starts empty when it does not exist.
func OpenStore(path string) (*Store, error) {
	s := &Store{path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, s); err != nil {
		return nil, err
	}
	for _, a := range s.Accounts {
		if a.TokenHash == "" && a.Token != "" {
			a.TokenHash = hashToken(a.Token) // file written by an older version
		}
	}
	return s, nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// limiter allows a fixed number of requests per key in each time window.
type limiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	start  time.Time
	hits   map[string]int
}

func (l *limiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.hits == nil || now.Sub(l.start) >= l.window {
		l.hits, l.start = map[string]int{}, now
	}
	l.hits[key]++
	return l.hits[key] <= l.limit
}

// save writes atomically: a crash never leaves a half-written file.
func (s *Store) save() error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) find(match func(*Account) bool) *Account {
	for _, a := range s.Accounts {
		if match(a) {
			return a
		}
	}
	return nil
}

// Server holds the configuration and the HTTP handlers.
type Server struct {
	Store         *Store
	WebhookSecret string             // Stripe signing secret, whsec_...
	Private       ed25519.PrivateKey // signs licences
	LicenseTTL    time.Duration      // how long each issued licence lasts
	ClaimWindow   time.Duration      // how long the claim page shows a new token
	RateLimit     int                // requests per minute per client on /v1/license and /claim
	// ClientIPHeader names the header your proxy sets to the caller's
	// address (Fly.io: "Fly-Client-IP"). Leave empty when clients connect
	// directly; a header is only trustworthy behind a proxy that sets it.
	ClientIPHeader string
	Now            func() time.Time

	limit limiter
}

// Handler returns the routes.
func (s *Server) Handler() http.Handler {
	if s.Now == nil {
		s.Now = time.Now
	}
	if s.LicenseTTL == 0 {
		s.LicenseTTL = 24 * time.Hour
	}
	if s.ClaimWindow == 0 {
		s.ClaimWindow = 24 * time.Hour
	}
	if s.RateLimit == 0 {
		s.RateLimit = 60
	}
	s.limit = limiter{limit: s.RateLimit, window: time.Minute}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok\n") })
	mux.HandleFunc("POST /stripe/webhook", s.handleWebhook)
	mux.HandleFunc("POST /v1/license", s.limited(s.handleLicense))
	mux.HandleFunc("GET /claim", s.limited(s.handleClaim))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Strict-Transport-Security", "max-age=31536000")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		mux.ServeHTTP(w, r)
	})
}

func (s *Server) clientIP(r *http.Request) string {
	if s.ClientIPHeader != "" {
		if v := strings.TrimSpace(r.Header.Get(s.ClientIPHeader)); v != "" {
			return v
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// limited slows down token guessing and scraping of the claim page.
func (s *Server) limited(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.limit.allow(s.clientIP(r), s.Now()) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// eraseClaimedTokens removes plain tokens whose claim window has passed.
// The caller holds the store lock.
func (s *Server) eraseClaimedTokens() (changed bool) {
	for _, a := range s.Store.Accounts {
		if a.Token != "" && s.Now().Sub(a.CreatedAt) > s.ClaimWindow {
			a.Token, changed = "", true
		}
	}
	return changed
}

// VerifyStripeSignature checks the Stripe-Signature header: the HMAC-SHA256
// of "<timestamp>.<body>" under the signing secret, with a replay window.
func VerifyStripeSignature(header string, body []byte, secret string, now time.Time, tolerance time.Duration) error {
	var ts string
	var sigs []string
	for _, part := range strings.Split(header, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch k {
		case "t":
			ts = v
		case "v1":
			sigs = append(sigs, v)
		}
	}
	if ts == "" || len(sigs) == 0 {
		return errors.New("signature header is missing t or v1")
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return errors.New("signature timestamp is not a number")
	}
	if age := now.Sub(time.Unix(sec, 0)); age > tolerance || age < -tolerance {
		return errors.New("signature timestamp is outside the allowed window")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	want := mac.Sum(nil)
	for _, s := range sigs {
		got, err := hex.DecodeString(s)
		if err == nil && hmac.Equal(got, want) {
			return nil
		}
	}
	return errors.New("signature does not match")
}

func newToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "shp_" + hex.EncodeToString(b), nil
}

func (s *Server) handleWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return
	}
	if err := VerifyStripeSignature(r.Header.Get("Stripe-Signature"), body, s.WebhookSecret, s.Now(), 5*time.Minute); err != nil {
		http.Error(w, "invalid signature", http.StatusBadRequest)
		return
	}
	var ev struct {
		Type string `json:"type"`
		Data struct {
			Object json.RawMessage `json:"object"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &ev); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	s.Store.mu.Lock()
	defer s.Store.mu.Unlock()
	changed := s.eraseClaimedTokens()

	switch ev.Type {
	case "checkout.session.completed":
		var o struct {
			ID           string `json:"id"`
			Customer     string `json:"customer"`
			Subscription string `json:"subscription"`
			Details      struct {
				Email string `json:"email"`
			} `json:"customer_details"`
		}
		if err := json.Unmarshal(ev.Data.Object, &o); err != nil || o.ID == "" || o.Subscription == "" {
			break // not a subscription checkout; nothing to do
		}
		if s.Store.find(func(a *Account) bool { return a.SessionID == o.ID }) != nil {
			break // Stripe retried an event we already handled
		}
		if a := s.Store.find(func(a *Account) bool { return a.SubscriptionID == o.Subscription }); a != nil {
			a.SessionID, a.Active, changed = o.ID, true, true
			break
		}
		token, err := newToken()
		if err != nil {
			http.Error(w, "could not create token", http.StatusInternalServerError)
			return
		}
		s.Store.Accounts = append(s.Store.Accounts, &Account{
			Token: token, TokenHash: hashToken(token), Email: o.Details.Email, CustomerID: o.Customer, SubscriptionID: o.Subscription,
			SessionID: o.ID, Active: true, CreatedAt: s.Now().UTC(),
		})
		changed = true
		log.Printf("new account for subscription %s", o.Subscription)

	case "customer.subscription.updated", "customer.subscription.deleted":
		var o struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		}
		if err := json.Unmarshal(ev.Data.Object, &o); err != nil {
			break
		}
		a := s.Store.find(func(a *Account) bool { return a.SubscriptionID == o.ID })
		if a == nil {
			break
		}
		// past_due stays active: Stripe is still retrying the card.
		active := ev.Type != "customer.subscription.deleted" &&
			(o.Status == "active" || o.Status == "trialing" || o.Status == "past_due")
		if a.Active != active {
			a.Active, changed = active, true
			log.Printf("subscription %s active=%v", o.ID, active)
		}
	}

	if changed {
		if err := s.Store.save(); err != nil {
			// A 500 makes Stripe retry the event later.
			log.Printf("save failed: %v", err)
			http.Error(w, "could not save", http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, `{"received":true}`)
}

func (s *Server) handleLicense(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	token = strings.TrimSpace(token)
	if !ok || token == "" {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}
	want := []byte(hashToken(token))
	s.Store.mu.Lock()
	a := s.Store.find(func(a *Account) bool { return hmac.Equal([]byte(a.TokenHash), want) })
	var active bool
	var customer string
	if a != nil {
		active, customer = a.Active, a.CustomerID
	}
	s.Store.mu.Unlock()

	if a == nil {
		http.Error(w, "unknown token", http.StatusUnauthorized)
		return
	}
	if !active {
		http.Error(w, "subscription is not active", http.StatusPaymentRequired)
		return
	}
	exp := s.Now().Add(s.LicenseTTL)
	lic, err := license.Sign(s.Private, license.Claims{Subject: customer, Plan: "team", Expires: exp.Unix()})
	if err != nil {
		http.Error(w, "could not sign licence", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"license": lic, "expires_at": exp.UTC().Format(time.RFC3339)})
}

var claimPage = template.Must(template.New("claim").Parse(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Shipshape Team</title>{{if .Wait}}<meta http-equiv="refresh" content="3">{{end}}
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:640px;margin:40px auto;padding:0 16px;color:#131b2c}
code,pre{font-family:ui-monospace,Menlo,monospace;background:#e9edf4;border-radius:6px}code{padding:2px 6px}
pre{padding:12px;overflow-x:auto}.tok{font-size:1.05rem;word-break:break-all;display:block;padding:12px}</style></head><body>
{{if .Wait}}<h1>Payment received</h1><p>Setting up your account. This page refreshes on its own.</p>
{{else if .Expired}}<h1>This link has expired</h1><p>For your security the token is shown only for a day after purchase. Reply to your receipt email and we will send a new one.</p>
{{else}}<h1>You are on Shipshape Team</h1>
<p>This is your Team token. Store it as a secret named <code>SHIPSHAPE_TOKEN</code> in your repository. Treat it like a password.</p>
<code class="tok">{{.Token}}</code>
<p>Then turn the Team features on in your workflow:</p>
<pre>- uses: 20041540MichaelKelly/shipshape@v1
  with:
    current: "1.24"
    target: "1.33"
    pr-comment: true
    team-token: ${{"{{"}} secrets.SHIPSHAPE_TOKEN {{"}}"}}</pre>
{{end}}</body></html>`))

func (s *Server) handleClaim(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("session_id")
	if id == "" {
		http.Error(w, "missing session_id", http.StatusBadRequest)
		return
	}
	s.Store.mu.Lock()
	a := s.Store.find(func(a *Account) bool { return a.SessionID == id })
	data := struct {
		Wait, Expired bool
		Token         string
	}{}
	switch {
	case a == nil:
		// The browser redirect can arrive before Stripe's webhook does.
		data.Wait = true
	case a.Token == "" || s.Now().Sub(a.CreatedAt) > s.ClaimWindow:
		data.Expired = true
	default:
		data.Token = a.Token
	}
	if s.eraseClaimedTokens() {
		if err := s.Store.save(); err != nil {
			log.Printf("save failed: %v", err)
		}
	}
	s.Store.mu.Unlock()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	claimPage.Execute(w, data)
}
