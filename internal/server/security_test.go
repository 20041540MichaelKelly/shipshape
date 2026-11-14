package server

import (
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/20041540MichaelKelly/shipshape/internal/license"
)

func TestTokensAreHashedAndErased(t *testing.T) {
	r := newRig(t)
	r.webhook(checkout, sign(checkout, r.now))
	a := r.srv.Store.Accounts[0]
	token := a.Token
	if a.TokenHash != hashToken(token) || a.TokenHash == token {
		t.Fatal("token hash missing or wrong")
	}
	// After the claim window the plain token is gone from memory and disk,
	// and the token still works because requests are checked by hash.
	r.now = r.now.Add(25 * time.Hour)
	r.get("/claim?session_id=cs_test_1")
	if a.Token != "" {
		t.Fatal("plain token still in memory after the claim window")
	}
	data, _ := os.ReadFile(r.dbPath)
	if strings.Contains(string(data), token) {
		t.Fatal("plain token still on disk after the claim window")
	}
	license.PublicKey = r.pub
	if err := license.Check(http.DefaultClient, r.ts.URL, token, r.now); err != nil {
		t.Fatalf("token stopped working after erasure: %v", err)
	}
}

func TestRateLimitAndHeaders(t *testing.T) {
	r := newRig(t)
	r.srv.RateLimit = 5
	r.ts.Config.Handler = r.srv.Handler()
	var last *http.Response
	for i := 0; i < 6; i++ {
		req, _ := http.NewRequest("POST", r.ts.URL+"/v1/license", nil)
		req.Header.Set("Authorization", "Bearer shp_guess")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if i < 5 && resp.StatusCode != 401 {
			t.Fatalf("request %d = %d, want 401", i, resp.StatusCode)
		}
		last = resp
	}
	if last.StatusCode != 429 || last.Header.Get("Retry-After") == "" {
		t.Fatalf("sixth request = %d, want 429 with Retry-After", last.StatusCode)
	}
	for _, h := range []string{"X-Content-Type-Options", "X-Frame-Options", "Strict-Transport-Security", "Content-Security-Policy"} {
		if last.Header.Get(h) == "" {
			t.Errorf("missing header %s", h)
		}
	}
	// The limit resets after the window, and Stripe's webhook is never limited.
	r.now = r.now.Add(61 * time.Second)
	if code, _ := r.get("/claim?session_id=x"); code != 200 {
		t.Fatalf("after window = %d", code)
	}
	for i := 0; i < 10; i++ {
		if code := r.webhook(checkout, sign(checkout, r.now)); code != 200 {
			t.Fatalf("webhook limited: %d", code)
		}
	}
}

func TestClientIPHeader(t *testing.T) {
	s := &Server{ClientIPHeader: "Fly-Client-IP"}
	req, _ := http.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	if got := s.clientIP(req); got != "10.0.0.1" {
		t.Fatalf("without header: %s", got)
	}
	req.Header.Set("Fly-Client-IP", "203.0.113.9")
	if got := s.clientIP(req); got != "203.0.113.9" {
		t.Fatalf("with header: %s", got)
	}
	if got := (&Server{}).clientIP(req); got != "10.0.0.1" {
		t.Fatalf("header must be ignored unless configured: %s", got)
	}
}
