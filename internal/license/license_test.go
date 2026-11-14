package license

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestTokenIsNeverSentOverPlainHTTP(t *testing.T) {
	for _, bad := range []string{"http://api.example.com", "ftp://x", "api.example.com", "http://10.0.0.5:8080", ""} {
		if err := checkServerURL(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	for _, ok := range []string{"https://api.example.com", "http://localhost:8080", "http://127.0.0.1:9", "http://[::1]:9"} {
		if err := checkServerURL(ok); err != nil {
			t.Errorf("%q was refused: %v", ok, err)
		}
	}
	_, err := Fetch(http.DefaultClient, "http://api.example.com", "shp_secret")
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("Fetch over http: %v", err)
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	pub, seed, _ := Keygen()
	priv, _ := ParsePrivate(seed)
	now := time.Unix(1_800_000_000, 0)
	lic, _ := Sign(priv, Claims{Subject: "cus_1", Plan: "team", Expires: now.Add(time.Hour).Unix()})
	if _, err := Verify(pub, lic, now); err != nil {
		t.Fatal(err)
	}
	// Swap the payload for one with a later expiry, keeping the signature.
	forged, _ := Sign(priv, Claims{Subject: "cus_1", Plan: "team", Expires: now.Add(9999 * time.Hour).Unix()})
	p, _, _ := strings.Cut(forged, ".")
	_, s, _ := strings.Cut(lic, ".")
	for _, bad := range []string{p + "." + s, lic + "x", "abc", "", "a.b.c"} {
		if _, err := Verify(pub, bad, now); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, err := Verify("", lic, now); err == nil {
		t.Error("accepted with no public key configured")
	}
}
