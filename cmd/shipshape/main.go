// Command shipshape checks Kubernetes manifests for API versions that stop
// being served between two releases, and can fail a CI job when it finds any.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/20041540MichaelKelly/shipshape/internal/check"
	"github.com/20041540MichaelKelly/shipshape/internal/ghcomment"
	"github.com/20041540MichaelKelly/shipshape/internal/license"
)

// maxFileSize keeps one huge or hostile file from exhausting memory in CI.
const maxFileSize = 10 << 20

func hasControlChars(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

const usage = `Usage: shipshape --current 1.24 --target 1.33 [flags] [path ...]

Paths are files or directories (searched for .yaml, .yml and .json).
Use "-" to read from stdin, for example: helm template ./chart | shipshape --current 1.24 --target 1.33 -
With no path, the current directory is scanned.

Exit codes: 0 ready, 1 findings at or above --fail-on, 2 usage or read error.

Team plan features (--pr-comment, --format sarif) need SHIPSHAPE_TOKEN.

Flags:
`

var reVersion = regexp.MustCompile(`^v?1\.(\d+)(\.\d+)?([-+].*)?$`)

func parseVersion(s string) (int, error) {
	m := reVersion.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, fmt.Errorf("%q is not a Kubernetes version such as 1.29", s)
	}
	return strconv.Atoi(m[1])
}

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("shipshape", flag.ContinueOnError)
	fl.SetOutput(stderr)
	current := fl.String("current", "", "Kubernetes version the cluster runs now, e.g. 1.24 (required)")
	target := fl.String("target", "", "Kubernetes version you are upgrading to, e.g. 1.33 (required)")
	format := fl.String("format", "text", "report format: text, markdown, github or sarif (sarif needs the Team plan)")
	prComment := fl.Bool("pr-comment", false, "post the report as one pull request comment, kept up to date (Team plan)")
	failOn := fl.String("fail-on", "blocker", "exit 1 on: blocker, deprecated or none")
	fix := fl.Bool("fix", false, "rewrite files in place where only the apiVersion line changes")
	fl.Usage = func() { fmt.Fprint(stderr, usage); fl.PrintDefaults() }
	if err := fl.Parse(args); err != nil {
		return 2
	}
	fail := func(msg string) int { fmt.Fprintln(stderr, "shipshape: "+msg); return 2 }

	if *current == "" || *target == "" {
		fl.Usage()
		return fail("--current and --target are required")
	}
	cur, err := parseVersion(*current)
	if err != nil {
		return fail("--current: " + err.Error())
	}
	tgt, err := parseVersion(*target)
	if err != nil {
		return fail("--target: " + err.Error())
	}
	if tgt <= cur {
		return fail(fmt.Sprintf("--target (1.%d) must be newer than --current (1.%d)", tgt, cur))
	}
	switch *format {
	case "text", "markdown", "github", "sarif":
	default:
		return fail("--format must be text, markdown, github or sarif")
	}
	switch *failOn {
	case "blocker", "deprecated", "none":
	default:
		return fail("--fail-on must be blocker, deprecated or none")
	}

	// Team features are checked up front so a licence problem is reported
	// before any work. The core check never depends on the licence server.
	client := &http.Client{Timeout: 15 * time.Second}
	var teamErr error
	if *prComment || *format == "sarif" {
		teamErr = license.Check(client, os.Getenv("SHIPSHAPE_SERVER"), os.Getenv("SHIPSHAPE_TOKEN"), time.Now())
	}
	if *format == "sarif" && teamErr != nil {
		return fail("--format sarif is a Team plan feature: " + teamErr.Error())
	}

	// A GitHub Action passes its "paths" input as one argument, one path per line.
	var paths []string
	for _, a := range fl.Args() {
		for _, p := range strings.Split(a, "\n") {
			if p = strings.TrimSpace(p); p != "" {
				paths = append(paths, p)
			}
		}
	}
	if len(paths) == 0 {
		paths = []string{"."}
	}
	sources := map[string]string{}
	var order []string
	add := func(name, text string) {
		if _, seen := sources[name]; !seen {
			order = append(order, name)
		}
		sources[name] = text
	}
	for _, p := range paths {
		if p == "-" {
			data, err := io.ReadAll(stdin)
			if err != nil {
				return fail("reading stdin: " + err.Error())
			}
			add("stdin", string(data))
			continue
		}
		st, err := os.Stat(p)
		if err != nil {
			return fail(err.Error())
		}
		if !st.IsDir() {
			data, err := os.ReadFile(p)
			if err != nil {
				return fail(err.Error())
			}
			add(filepath.ToSlash(filepath.Clean(p)), string(data))
			continue
		}
		err = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			name := d.Name()
			// A pull request from a fork controls the files being scanned, so
			// never follow symlinks out of the tree, and skip names that could
			// inject terminal or workflow control sequences into the report.
			if d.Type()&fs.ModeSymlink != 0 {
				return nil
			}
			if hasControlChars(path) {
				fmt.Fprintln(stderr, "shipshape: skipped a file whose name contains control characters")
				return nil
			}
			if d.IsDir() {
				if path != p && (strings.HasPrefix(name, ".") || name == "node_modules" || name == "vendor") {
					return filepath.SkipDir
				}
				return nil
			}
			switch strings.ToLower(filepath.Ext(name)) {
			case ".yaml", ".yml", ".json":
			default:
				return nil
			}
			if name == "package.json" || name == "package-lock.json" || name == "tsconfig.json" {
				return nil
			}
			if fi, err := d.Info(); err == nil && fi.Size() > maxFileSize {
				fmt.Fprintf(stderr, "shipshape: skipped %s, larger than 10 MB\n", path)
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			add(filepath.ToSlash(filepath.Clean(path)), string(data))
			return nil
		})
		if err != nil {
			return fail(err.Error())
		}
	}

	var resources []check.Resource
	for _, name := range order {
		resources = append(resources, check.ParseSource(sources[name], name)...)
	}
	res := check.Evaluate(resources, cur, tgt)

	if *fix {
		fixed := 0
		for _, name := range order {
			if name == "stdin" {
				continue
			}
			text, n := check.ApplyFixes(sources[name], name, res.Findings)
			if n == 0 {
				continue
			}
			mode := os.FileMode(0o644)
			if fi, err := os.Stat(filepath.FromSlash(name)); err == nil {
				mode = fi.Mode().Perm()
			}
			if err := os.WriteFile(filepath.FromSlash(name), []byte(text), mode); err != nil {
				return fail(err.Error())
			}
			fixed += n
		}
		fmt.Fprintf(stderr, "shipshape: rewrote %d apiVersion line(s)\n", fixed)
	}

	switch *format {
	case "markdown":
		fmt.Fprint(stdout, check.Markdown(res, cur, tgt))
	case "github":
		fmt.Fprint(stdout, check.GitHubAnnotations(res, cur))
		// The plain report repeats text taken from the scanned files. Tell the
		// runner to stop interpreting workflow commands while it is printed,
		// so a crafted manifest cannot issue commands of its own.
		stop := make([]byte, 16)
		if _, err := rand.Read(stop); err != nil {
			return fail(err.Error())
		}
		fmt.Fprintf(stdout, "::stop-commands::%s\n", hex.EncodeToString(stop))
		fmt.Fprint(stdout, check.Text(res, cur, tgt))
		fmt.Fprintf(stdout, "::%s::\n", hex.EncodeToString(stop))
		if path := os.Getenv("GITHUB_STEP_SUMMARY"); path != "" {
			if f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
				fmt.Fprint(f, check.Markdown(res, cur, tgt))
				f.Close()
			}
		}
	case "sarif":
		out, err := check.SARIF(res, cur)
		if err != nil {
			return fail(err.Error())
		}
		fmt.Fprint(stdout, out)
	default:
		fmt.Fprint(stdout, check.Text(res, cur, tgt))
	}

	if *prComment {
		// A failed comment never changes the result of the check itself.
		if teamErr != nil {
			fmt.Fprintln(stderr, "shipshape: skipping the pull request comment, a Team plan feature: "+teamErr.Error())
		} else if target, err := ghcomment.FromEnv(os.Getenv); err != nil {
			fmt.Fprintln(stderr, "shipshape: skipping the pull request comment: "+err.Error())
		} else if err := ghcomment.Upsert(client, target, check.Markdown(res, cur, tgt)); err != nil {
			fmt.Fprintln(stderr, "shipshape: could not post the pull request comment: "+err.Error())
		} else {
			fmt.Fprintln(stderr, "shipshape: pull request comment updated")
		}
	}

	if *failOn == "blocker" && res.Breaking > 0 {
		return 1
	}
	if *failOn == "deprecated" && len(res.Findings) > 0 {
		return 1
	}
	return 0
}
