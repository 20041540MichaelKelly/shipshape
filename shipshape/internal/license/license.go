// Package license issues and verifies short-lived, signed licences.
//
// The server holds an Ed25519 private key and signs a small JSON claim. The
// CLI embeds the matching public key and verifies the signature offline, so
// a licence cannot be forged without the private key.
package license

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// PublicKey is the base64 Ed25519 public key that licences are checked
// against. Generate a pair with `shipshape-server keygen`, then either paste
// the public key here or set it at build time:
//
//	go build -ldflags "-X github.com/20041540MichaelKelly/shipshape/internal/license.PublicKey=<key>"
var PublicKey = ""

// DefaultServer is the licence server the CLI talks to when SHIPSHAPE_SERVER
// is not set, for example https://api.example.com. Set it like PublicKey.
var DefaultServer = ""

// Claims is the signed content of a licence.
type Claims struct {
	Subject string `json:"sub"`  // Stripe customer id
	Plan    string `json:"plan"` // "team"
	Expires int64  `json:"exp"`  // unix seconds
}

var enc = base64.RawURLEncoding

// Keygen returns a new key pair as base64 strings: the public key for the
// CLI and the private seed for the server.
func Keygen() (public, private string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(priv.Seed()), nil
}

// ParsePrivate decodes a base64 seed produced by Keygen.
func ParsePrivate(seed string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(seed))
	if err != nil || len(raw) != ed25519.SeedSize {
		return nil, errors.New("private key must be a base64 Ed25519 seed from `shipshape-server keygen`")
	}
	return ed25519.NewKeyFromSeed(raw), nil
}

// Sign returns a licence string: base64url(claims) + "." + base64url(signature).
func Sign(priv ed25519.PrivateKey, c Claims) (string, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return enc.EncodeToString(payload) + "." + enc.EncodeToString(ed25519.Sign(priv, payload)), nil
}

// Verify checks a licence against a base64 public key and the clock.
func Verify(publicKey, token string, now time.Time) (Claims, error) {
	var c Claims
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(publicKey))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return c, errors.New("this build has no valid licence public key")
	}
	p, s, ok := strings.Cut(strings.TrimSpace(token), ".")
	if !ok {
		return c, errors.New("licence is malformed")
	}
	payload, err1 := enc.DecodeString(p)
	sig, err2 := enc.DecodeString(s)
	if err1 != nil || err2 != nil {
		return c, errors.New("licence is malformed")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		return c, errors.New("licence signature is not valid")
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return c, errors.New("licence is malformed")
	}
	if now.Unix() >= c.Expires {
		return c, errors.New("licence has expired")
	}
	return c, nil
}

// checkServerURL refuses to send the token over an unencrypted connection.
// Plain http is allowed only to this machine, for local development.
func checkServerURL(server string) error {
	u, err := url.Parse(server)
	if err != nil || u.Host == "" {
		return errors.New("licence server URL is not valid")
	}
	if u.Scheme == "https" {
		return nil
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); u.Scheme == "http" && (host == "localhost" || (ip != nil && ip.IsLoopback())) {
		return nil
	}
	return errors.New("licence server URL must use https")
}

// Fetch exchanges an account token for a fresh licence from the server.
func Fetch(client *http.Client, server, accountToken string) (string, error) {
	if err := checkServerURL(server); err != nil {
		return "", err
	}
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(server, "/")+"/v1/license", bytes.NewReader(nil))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accountToken)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("licence server unreachable: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return "", errors.New("the Team token was not recognised")
	case http.StatusTooManyRequests:
		return "", errors.New("licence server is rate limiting this address, try again in a minute")
	case http.StatusPaymentRequired:
		return "", errors.New("the subscription for this Team token is not active")
	default:
		return "", fmt.Errorf("licence server returned %s", resp.Status)
	}
	var out struct {
		License string `json:"license"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.License == "" {
		return "", errors.New("licence server sent an unreadable reply")
	}
	return out.License, nil
}

// Check runs the whole client flow and returns nil when Team features may
// be used. The error says what is missing in words fit to show a user.
func Check(client *http.Client, server, accountToken string, now time.Time) error {
	if accountToken == "" {
		return errors.New("no Team token set (SHIPSHAPE_TOKEN)")
	}
	if server == "" {
		server = DefaultServer
	}
	if server == "" {
		return errors.New("no licence server configured (SHIPSHAPE_SERVER)")
	}
	lic, err := Fetch(client, server, accountToken)
	if err != nil {
		return err
	}
	c, err := Verify(PublicKey, lic, now)
	if err != nil {
		return err
	}
	if c.Plan != "team" {
		return fmt.Errorf("plan %q does not include Team features", c.Plan)
	}
	return nil
}
