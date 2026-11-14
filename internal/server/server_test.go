package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/20041540MichaelKelly/shipshape/internal/license"
)

const secret = "whsec_test"

func sign(body string, at time.Time) string {
	ts := fmt.Sprint(at.Unix())
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "." + body))
	return "t=" + ts + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

type rig struct {
	t      *testing.T
	ts     *httptest.Server
	srv    *Server
	now    time.Time
	pub    string
	dbPath string
}

func newRig(t *testing.T) *rig {
	t.Helper()
	pub, privSeed, err := license.Keygen()
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := license.ParsePrivate(privSeed)
	r := &rig{t: t, now: time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC), pub: pub, dbPath: filepath.Join(t.TempDir(), "db", "accounts.json")}
	store, err := OpenStore(r.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	r.srv = &Server{Store: store, WebhookSecret: secret, Private: priv, Now: func() time.Time { return r.now }}
	r.ts = httptest.NewServer(r.srv.Handler())
	t.Cleanup(r.ts.Close)
	return r
}

func (r *rig) webhook(body, sig string) int {
	req, _ := http.NewRequest("POST", r.ts.URL+"/stripe/webhook", strings.NewReader(body))
	req.Header.Set("Stripe-Signature", sig)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func (r *rig) get(path string) (int, string) {
	resp, err := http.Get(r.ts.URL + path)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return resp.StatusCode, b.String()
}

const checkout = `{"id":"evt_1","type":"checkout.session.completed","data":{"object":{"id":"cs_test_1","customer":"cus_1","subscription":"sub_1","customer_details":{"email":"ops@example.com"}}}}`

func subEvent(kind, status string) string {
	return fmt.Sprintf(`{"type":"customer.subscription.%s","data":{"object":{"id":"sub_1","status":%q}}}`, kind, status)
}

func TestPurchaseToLicenceToCancel(t *testing.T) {
	r := newRig(t)

	// Before the webhook lands, the claim page waits.
	if code, body := r.get("/claim?session_id=cs_test_1"); code != 200 || !strings.Contains(body, "Payment received") {
		t.Fatalf("claim before webhook: %d %s", code, body)
	}
	if code := r.webhook(checkout, sign(checkout, r.now)); code != 200 {
		t.Fatalf("webhook = %d", code)
	}
	// Stripe retries: no duplicate account.
	r.webhook(checkout, sign(checkout, r.now))
	if n := len(r.srv.Store.Accounts); n != 1 {
		t.Fatalf("accounts = %d, want 1", n)
	}
	token := r.srv.Store.Accounts[0].Token
	if !strings.HasPrefix(token, "shp_") || len(token) != 52 {
		t.Fatalf("unexpected token %q", token)
	}
	if _, body := r.get("/claim?session_id=cs_test_1"); !strings.Contains(body, token) {
		t.Fatal("claim page does not show the token")
	}

	// The CLI's full flow against the real handlers.
	license.PublicKey = r.pub
	if err := license.Check(http.DefaultClient, r.ts.URL, token, r.now); err != nil {
		t.Fatalf("licence check failed: %v", err)
	}
	if err := license.Check(http.DefaultClient, r.ts.URL, "shp_wrong", r.now); err == nil || !strings.Contains(err.Error(), "not recognised") {
		t.Fatalf("wrong token: %v", err)
	}
	// A licence is rejected once its 24 hours are up.
	lic, _ := license.Fetch(http.DefaultClient, r.ts.URL, token)
	if _, err := license.Verify(r.pub, lic, r.now.Add(25*time.Hour)); err == nil {
		t.Fatal("expired licence was accepted")
	}
	// A licence signed by someone else is rejected.
	otherPub, _, _ := license.Keygen()
	if _, err := license.Verify(otherPub, lic, r.now); err == nil {
		t.Fatal("licence verified against the wrong key")
	}

	// past_due keeps access while Stripe retries the card.
	body := subEvent("updated", "past_due")
	r.webhook(body, sign(body, r.now))
	if err := license.Check(http.DefaultClient, r.ts.URL, token, r.now); err != nil {
		t.Fatalf("past_due should stay active: %v", err)
	}
	// Cancellation ends access.
	body = subEvent("deleted", "canceled")
	r.webhook(body, sign(body, r.now))
	if err := license.Check(http.DefaultClient, r.ts.URL, token, r.now); err == nil || !strings.Contains(err.Error(), "not active") {
		t.Fatalf("after cancel: %v", err)
	}

	// State survives a restart.
	reopened, err := OpenStore(r.dbPath)
	if err != nil || len(reopened.Accounts) != 1 || reopened.Accounts[0].Active {
		t.Fatalf("reload: %v %+v", err, reopened.Accounts)
	}
	// The claim page stops showing the token after a day.
	r.now = r.now.Add(25 * time.Hour)
	if _, body := r.get("/claim?session_id=cs_test_1"); strings.Contains(body, token) || !strings.Contains(body, "expired") {
		t.Fatal("claim page still shows the token after the window")
	}
}

func TestWebhookRejectsBadSignatures(t *testing.T) {
	r := newRig(t)
	cases := map[string]string{
		"missing":   "",
		"wrong mac": "t=" + fmt.Sprint(r.now.Unix()) + ",v1=" + strings.Repeat("ab", 32),
		"replayed":  sign(checkout, r.now.Add(-10*time.Minute)),
		"tampered":  sign(checkout+" ", r.now),
	}
	for name, sig := range cases {
		if code := r.webhook(checkout, sig); code != 400 {
			t.Errorf("%s: status %d, want 400", name, code)
		}
	}
	if len(r.srv.Store.Accounts) != 0 {
		t.Fatal("an unsigned event created an account")
	}
	// One-off payments (no subscription) and unknown events are acknowledged and ignored.
	for _, body := range []string{
		`{"type":"checkout.session.completed","data":{"object":{"id":"cs_2","customer":"cus_2"}}}`,
		`{"type":"invoice.paid","data":{"object":{"id":"in_1"}}}`,
	} {
		if code := r.webhook(body, sign(body, r.now)); code != 200 {
			t.Errorf("ignored event returned %d", code)
		}
	}
	if len(r.srv.Store.Accounts) != 0 {
		t.Fatal("ignored events created an account")
	}
}

func TestLicenceEndpointShape(t *testing.T) {
	r := newRig(t)
	r.webhook(checkout, sign(checkout, r.now))
	req, _ := http.NewRequest("POST", r.ts.URL+"/v1/license", nil)
	req.Header.Set("Authorization", "Bearer "+r.srv.Store.Accounts[0].Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		License   string `json:"license"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.License == "" || out.ExpiresAt != "2026-11-15T12:00:00Z" {
		t.Fatalf("unexpected reply: %+v %v", out, err)
	}
	if code, _ := r.get("/healthz"); code != 200 {
		t.Fatal("healthz failed")
	}
	if code, _ := r.get("/v1/license"); code != 405 {
		t.Fatalf("GET /v1/license = %d, want 405", code)
	}
}
