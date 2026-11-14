package ghcomment

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpsertCreatesThenEdits(t *testing.T) {
	type comment struct {
		ID   int64  `json:"id"`
		Body string `json:"body"`
	}
	comments := []comment{{ID: 1, Body: "LGTM"}}
	var calls []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer gh-token" {
			w.WriteHeader(401)
			return
		}
		var in struct {
			Body string `json:"body"`
		}
		data, _ := io.ReadAll(r.Body)
		json.Unmarshal(data, &in)
		switch {
		case r.Method == "GET" && r.URL.Path == "/repos/acme/shop/issues/7/comments":
			json.NewEncoder(w).Encode(comments)
		case r.Method == "POST" && r.URL.Path == "/repos/acme/shop/issues/7/comments":
			comments = append(comments, comment{ID: 2, Body: in.Body})
			w.WriteHeader(201)
			w.Write([]byte("{}"))
		case r.Method == "PATCH" && r.URL.Path == "/repos/acme/shop/issues/comments/2":
			comments[1].Body = in.Body
			w.Write([]byte("{}"))
		default:
			w.WriteHeader(404)
		}
	}))
	defer ts.Close()

	event := filepath.Join(t.TempDir(), "event.json")
	os.WriteFile(event, []byte(`{"pull_request":{"number":7}}`), 0o600)
	env := map[string]string{"GITHUB_API_URL": ts.URL, "GITHUB_REPOSITORY": "acme/shop", "GITHUB_TOKEN": "gh-token", "GITHUB_EVENT_PATH": event}
	target, err := FromEnv(func(k string) string { return env[k] })
	if err != nil || target.Number != 7 {
		t.Fatalf("FromEnv: %+v %v", target, err)
	}

	if err := Upsert(ts.Client(), target, "first report"); err != nil {
		t.Fatal(err)
	}
	if err := Upsert(ts.Client(), target, "second report"); err != nil {
		t.Fatal(err)
	}
	if len(comments) != 2 || !strings.HasPrefix(comments[1].Body, Marker) || !strings.Contains(comments[1].Body, "second report") {
		t.Fatalf("expected one Shipshape comment, edited in place: %+v", comments)
	}
	if comments[0].Body != "LGTM" {
		t.Fatal("someone else's comment was changed")
	}
	if last := calls[len(calls)-1]; !strings.HasPrefix(last, "PATCH") {
		t.Fatalf("second run should edit, got %s", last)
	}

	// Not a pull request: a clear error, no API calls.
	os.WriteFile(event, []byte(`{"ref":"refs/heads/main"}`), 0o600)
	if _, err := FromEnv(func(k string) string { return env[k] }); err == nil {
		t.Fatal("push event should not yield a target")
	}
}
