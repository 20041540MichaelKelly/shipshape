package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/20041540MichaelKelly/shipshape/internal/license"
	"github.com/20041540MichaelKelly/shipshape/internal/server"
)

const shop = "../../testdata/shop.yaml"

func cli(t *testing.T, stdin string, args ...string) (code int, out, errOut string) {
	t.Helper()
	var o, e bytes.Buffer
	code = run(args, strings.NewReader(stdin), &o, &e)
	return code, o.String(), e.String()
}

func TestFreeFeatures(t *testing.T) {
	code, out, _ := cli(t, "", "--current", "1.24", "--target", "1.33", shop)
	if code != 1 || !strings.Contains(out, "Not ready for v1.33: 4 of 7") {
		t.Fatalf("code=%d out=%s", code, out)
	}
	if code, _, _ := cli(t, "", "--current", "1.24", "--target", "1.33", "--fail-on", "none", shop); code != 0 {
		t.Fatalf("--fail-on none returned %d", code)
	}
	// A clean manifest passes, and deprecated-only fails only when asked to.
	clean := "apiVersion: v1\nkind: Endpoints\nmetadata:\n  name: e\n"
	if code, _, _ := cli(t, clean, "--current", "1.30", "--target", "1.33", "-"); code != 0 {
		t.Fatalf("deprecated-only with default fail-on returned %d", code)
	}
	if code, _, _ := cli(t, clean, "--current", "1.30", "--target", "1.33", "--fail-on", "deprecated", "-"); code != 1 {
		t.Fatalf("--fail-on deprecated returned %d", code)
	}
	for _, bad := range [][]string{{"--target", "1.33"}, {"--current", "1.33", "--target", "1.30"}, {"--current", "x", "--target", "1.30"}, {"--current", "1.2", "--target", "1.30", "/no/such/path"}} {
		if code, _, _ := cli(t, "", bad...); code != 2 {
			t.Errorf("%v returned %d, want 2", bad, code)
		}
	}
	// The Action passes several paths as one newline-separated argument.
	dir := t.TempDir()
	data, _ := os.ReadFile(shop)
	os.WriteFile(filepath.Join(dir, "a.yaml"), data, 0o644)
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("apiVersion: batch/v1beta1\nkind: CronJob\n"), 0o644)
	code, out, _ = cli(t, "", "--current", "1.24", "--target", "1.33", dir+"\n"+shop+"\n")
	if code != 1 || !strings.Contains(out, "scanned 14") {
		t.Fatalf("multi-path: code=%d out=%s", code, out)
	}
}

// TestTeamFeatures runs the CLI against the real licence server handlers and
// a stand-in for the GitHub API.
func TestTeamFeatures(t *testing.T) {
	pub, seed, _ := license.Keygen()
	priv, _ := license.ParsePrivate(seed)
	store, _ := server.OpenStore(filepath.Join(t.TempDir(), "accounts.json"))
	lic := httptest.NewServer((&server.Server{Store: store, WebhookSecret: "whsec_x", Private: priv}).Handler())
	defer lic.Close()
	license.PublicKey = pub
	t.Setenv("SHIPSHAPE_SERVER", lic.URL)

	// No token: SARIF refuses, the comment is skipped, the check still runs.
	t.Setenv("SHIPSHAPE_TOKEN", "")
	if code, _, errOut := cli(t, "", "--current", "1.24", "--target", "1.33", "--format", "sarif", shop); code != 2 || !strings.Contains(errOut, "Team plan feature") {
		t.Fatalf("sarif without token: %d %s", code, errOut)
	}
	code, out, errOut := cli(t, "", "--current", "1.24", "--target", "1.33", "--pr-comment", shop)
	if code != 1 || !strings.Contains(out, "Not ready") || !strings.Contains(errOut, "skipping the pull request comment") {
		t.Fatalf("pr-comment without token: %d %s", code, errOut)
	}

	// Buy a subscription through a signed Stripe event.
	body := `{"type":"checkout.session.completed","data":{"object":{"id":"cs_1","customer":"cus_1","subscription":"sub_1","customer_details":{"email":"a@b.c"}}}}`
	ts := fmt.Sprint(time.Now().Unix())
	mac := hmac.New(sha256.New, []byte("whsec_x"))
	mac.Write([]byte(ts + "." + body))
	req, _ := http.NewRequest("POST", lic.URL+"/stripe/webhook", strings.NewReader(body))
	req.Header.Set("Stripe-Signature", "t="+ts+",v1="+hex.EncodeToString(mac.Sum(nil)))
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != 200 {
		t.Fatalf("webhook failed: %v", err)
	}
	t.Setenv("SHIPSHAPE_TOKEN", store.Accounts[0].Token)

	// SARIF is valid JSON with one result per finding.
	code, out, errOut = cli(t, "", "--current", "1.24", "--target", "1.33", "--format", "sarif", shop)
	if code != 1 {
		t.Fatalf("sarif: %d %s", code, errOut)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []struct {
				Level     string `json:"level"`
				Locations []struct {
					Physical struct {
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || doc.Version != "2.1.0" || len(doc.Runs[0].Results) != 5 {
		t.Fatalf("bad sarif: %v\n%s", err, out)
	}
	if r := doc.Runs[0].Results[0]; r.Level != "error" || r.Locations[0].Physical.Region.StartLine != 32 {
		t.Fatalf("first sarif result wrong: %+v", r)
	}

	// The pull request comment reaches GitHub.
	var posted string
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			io.WriteString(w, "[]")
			return
		}
		data, _ := io.ReadAll(r.Body)
		posted = string(data)
		w.WriteHeader(201)
		io.WriteString(w, "{}")
	}))
	defer gh.Close()
	event := filepath.Join(t.TempDir(), "event.json")
	os.WriteFile(event, []byte(`{"pull_request":{"number":12}}`), 0o600)
	t.Setenv("GITHUB_API_URL", gh.URL)
	t.Setenv("GITHUB_REPOSITORY", "acme/shop")
	t.Setenv("GITHUB_TOKEN", "t")
	t.Setenv("GITHUB_EVENT_PATH", event)
	code, _, errOut = cli(t, "", "--current", "1.24", "--target", "1.33", "--pr-comment", shop)
	if code != 1 || !strings.Contains(errOut, "pull request comment updated") || !strings.Contains(posted, "Kubernetes upgrade readiness") {
		t.Fatalf("pr-comment: %d %s %s", code, errOut, posted)
	}

	// Licence server down: the check still runs and reports, only the comment is skipped.
	lic.Close()
	code, out, errOut = cli(t, "", "--current", "1.24", "--target", "1.33", "--pr-comment", shop)
	if code != 1 || !strings.Contains(out, "Not ready") || !strings.Contains(errOut, "unreachable") {
		t.Fatalf("server down: %d %s", code, errOut)
	}
}

func TestHostileRepositoryContents(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.yaml")
	os.WriteFile(outside, []byte("apiVersion: batch/v1beta1\nkind: CronJob\nmetadata:\n  name: outside\n"), 0o600)
	if err := os.Symlink(outside, filepath.Join(dir, "link.yaml")); err != nil {
		t.Skip("symlinks not available")
	}
	os.WriteFile(filepath.Join(dir, "ok.yaml"), []byte("apiVersion: batch/v1beta1\nkind: CronJob\nmetadata:\n  name: \"::error::pwned\"\n"), 0o640)
	os.WriteFile(filepath.Join(dir, "big.yaml"), bytes.Repeat([]byte("# pad\n"), maxFileSize/6+10), 0o644)

	code, out, errOut := cli(t, "", "--current", "1.24", "--target", "1.30", "--format", "github", "--fix", dir)
	if code != 1 || strings.Contains(out, "outside") {
		t.Fatalf("symlink was followed: %d\n%s", code, out)
	}
	if !strings.Contains(errOut, "larger than 10 MB") {
		t.Errorf("large file not skipped: %s", errOut)
	}
	// --fix must not have written through the symlink, and keeps file modes.
	if data, _ := os.ReadFile(outside); !strings.Contains(string(data), "batch/v1beta1") {
		t.Fatal("--fix wrote through a symlink")
	}
	if fi, _ := os.Stat(filepath.Join(dir, "ok.yaml")); fi.Mode().Perm() != 0o640 {
		t.Errorf("--fix changed the file mode to %v", fi.Mode().Perm())
	}
	// The plain report is fenced so the runner ignores commands inside it.
	lines := strings.Split(strings.TrimSpace(out), "\n")
	var stop string
	for i, l := range lines {
		if strings.HasPrefix(l, "::stop-commands::") {
			stop = strings.TrimPrefix(l, "::stop-commands::")
			for _, before := range lines[:i] {
				if !strings.HasPrefix(before, "::error ") && !strings.HasPrefix(before, "::warning ") {
					t.Errorf("unexpected line before the fence: %s", before)
				}
			}
		}
	}
	if len(stop) != 32 || lines[len(lines)-1] != "::"+stop+"::" {
		t.Fatalf("report is not fenced with stop-commands:\n%s", out)
	}
}
