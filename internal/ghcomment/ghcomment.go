// Package ghcomment keeps one Shipshape comment up to date on a pull request.
package ghcomment

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// Marker identifies the comment so later runs edit it instead of adding more.
const Marker = "<!-- shipshape-report -->"

// Target says which pull request to comment on.
type Target struct {
	API    string // e.g. https://api.github.com
	Repo   string // owner/name
	Number int
	Token  string
}

// FromEnv builds a Target from the variables GitHub Actions sets.
func FromEnv(getenv func(string) string) (Target, error) {
	t := Target{API: getenv("GITHUB_API_URL"), Repo: getenv("GITHUB_REPOSITORY"), Token: getenv("GITHUB_TOKEN")}
	if t.API == "" {
		t.API = "https://api.github.com"
	}
	if t.Repo == "" || t.Token == "" {
		return t, errors.New("GITHUB_REPOSITORY and GITHUB_TOKEN must be set")
	}
	path := getenv("GITHUB_EVENT_PATH")
	if path == "" {
		return t, errors.New("GITHUB_EVENT_PATH is not set")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return t, err
	}
	var ev struct {
		PullRequest struct {
			Number int `json:"number"`
		} `json:"pull_request"`
	}
	if err := json.Unmarshal(data, &ev); err != nil || ev.PullRequest.Number == 0 {
		return t, errors.New("this run was not triggered by a pull request")
	}
	t.Number = ev.PullRequest.Number
	return t, nil
}

func (t Target) do(client *http.Client, method, url string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+t.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		hint := ""
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
			hint = " (the workflow needs `permissions: pull-requests: write`)"
		}
		return fmt.Errorf("GitHub API %s %s%s", method, resp.Status, hint)
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// Upsert creates the Shipshape comment, or edits it when one already exists.
func Upsert(client *http.Client, t Target, markdown string) error {
	base := strings.TrimRight(t.API, "/") + "/repos/" + t.Repo
	body := map[string]string{"body": Marker + "\n" + markdown}

	for page := 1; page <= 10; page++ {
		var comments []struct {
			ID   int64  `json:"id"`
			Body string `json:"body"`
		}
		url := fmt.Sprintf("%s/issues/%d/comments?per_page=100&page=%d", base, t.Number, page)
		if err := t.do(client, http.MethodGet, url, nil, &comments); err != nil {
			return err
		}
		for _, c := range comments {
			if strings.HasPrefix(c.Body, Marker) {
				return t.do(client, http.MethodPatch, fmt.Sprintf("%s/issues/comments/%d", base, c.ID), body, nil)
			}
		}
		if len(comments) < 100 {
			break
		}
	}
	return t.do(client, http.MethodPost, fmt.Sprintf("%s/issues/%d/comments", base, t.Number), body, nil)
}
