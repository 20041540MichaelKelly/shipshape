package check

import (
	"encoding/json"
	"fmt"
	"strings"
)

func (r Resource) title() string {
	s := r.Kind
	if r.Name != "" {
		s += "/" + r.Name
	}
	return s
}

func (r Resource) where() string {
	if r.Line > 0 {
		return fmt.Sprintf("%s:%d", r.File, r.Line)
	}
	return r.File
}

// Verdict is the one-line outcome of a scan.
func (res Result) Verdict(cur, tgt int) string {
	switch {
	case res.Scanned == 0 && len(res.Findings) == 0:
		return "No Kubernetes resources found to check."
	case res.Breaking > 0:
		return fmt.Sprintf("Not ready for v1.%d: %d of %d resources use an API that v1.%d no longer serves.", tgt, res.Breaking, res.Scanned, tgt)
	case res.Deprecated > 0:
		return fmt.Sprintf("Ready for v1.%d, with %d deprecated API(s) to plan for.", tgt, res.Deprecated)
	}
	return fmt.Sprintf("Ready for v1.%d: all %d resources use API versions it still serves.", tgt, res.Scanned)
}

// Text renders a terminal report.
func Text(res Result, cur, tgt int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Shipshape: v1.%d -> v1.%d\n%s\n", cur, tgt, res.Verdict(cur, tgt))
	fmt.Fprintf(&b, "scanned %d | break %d | deprecated %d | ready %d\n", res.Scanned, res.Breaking, res.Deprecated, res.Ready)
	if res.Templated > 0 {
		fmt.Fprintf(&b, "skipped %d resource(s) with unrendered template values (run helm template first)\n", res.Templated)
	}
	for _, f := range res.Findings {
		r := f.Resource
		repl := f.Repl
		if repl == "" {
			repl = "no replacement API"
		}
		fmt.Fprintf(&b, "\n[%s] %s\n  %s\n  %s -> %s\n", f.Label(), r.title(), r.where(), r.APIVersion, repl)
		if d := f.Detail(cur); d != "" {
			fmt.Fprintf(&b, "  %s\n", d)
		}
	}
	return b.String()
}

var mdReplacer = strings.NewReplacer(
	"|", "\\|", "`", "'", "<", "&lt;", ">", "&gt;", "[", "\\[", "]", "\\]",
	"@", "(at)", "\r", " ", "\n", " ",
)

// mdSafe makes text taken from a scanned file safe to place in Markdown that
// is posted to a pull request: it cannot break the table, add links or
// images, or mention users. Valid Kubernetes names are unaffected.
func mdSafe(s string) string {
	if r := []rune(s); len(r) > 200 {
		s = string(r[:200]) + "..."
	}
	return mdReplacer.Replace(s)
}

// Markdown renders a report for pull requests, tickets and job summaries.
func Markdown(res Result, cur, tgt int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## Kubernetes upgrade readiness: v1.%d to v1.%d\n\n**%s**\n\n", cur, tgt, res.Verdict(cur, tgt))
	fmt.Fprintf(&b, "- Resources scanned: %d\n- Break on upgrade: %d\n- Deprecated: %d\n- Ready: %d\n", res.Scanned, res.Breaking, res.Deprecated, res.Ready)
	if res.Templated > 0 {
		fmt.Fprintf(&b, "- Skipped (unrendered template values): %d\n", res.Templated)
	}
	if len(res.Findings) == 0 {
		return b.String()
	}
	b.WriteString("\n| Status | Resource | Current API | Replace with | Where |\n|---|---|---|---|---|\n")
	for _, f := range res.Findings {
		r := f.Resource
		name := mdSafe(r.title())
		if r.Namespace != "" {
			name += " (" + mdSafe(r.Namespace) + ")"
		}
		if r.Nested {
			name += " (nested reference)"
		}
		repl := "No replacement API"
		if f.Repl != "" {
			repl = "`" + f.Repl + "`"
		}
		fmt.Fprintf(&b, "| %s | %s | `%s` | %s | %s |\n", f.Label(), name, mdSafe(r.APIVersion), repl, mdSafe(r.where()))
	}
	b.WriteString("\n### Notes\n\n")
	for _, f := range res.Findings {
		d := f.Detail(cur)
		if d == "" {
			d = "Change the apiVersion."
		}
		fmt.Fprintf(&b, "- **%s**: %s\n", mdSafe(f.Resource.title()), d)
	}
	return b.String()
}

var (
	escData = strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A")
	escProp = strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C")
)

// GitHubAnnotations renders workflow commands that GitHub shows inline on
// the changed files of a pull request.
func GitHubAnnotations(res Result, cur int) string {
	var b strings.Builder
	for _, f := range res.Findings {
		level := "warning"
		if f.Status == Broken || f.Status == Blocker {
			level = "error"
		}
		r := f.Resource
		repl := f.Repl
		if repl == "" {
			repl = "no replacement API"
		}
		msg := fmt.Sprintf("%s uses %s. Replace with %s.", r.title(), r.APIVersion, repl)
		if d := f.Detail(cur); d != "" {
			msg += " " + d
		}
		props := "file=" + escProp.Replace(r.File)
		if r.Line > 0 {
			props += fmt.Sprintf(",line=%d", r.Line)
		}
		props += ",title=" + escProp.Replace(f.Label())
		fmt.Fprintf(&b, "::%s %s::%s\n", level, props, escData.Replace(msg))
	}
	return b.String()
}

// SARIF renders findings in SARIF 2.1.0, the format GitHub code scanning
// and most security dashboards import.
func SARIF(res Result, cur int) (string, error) {
	type msg struct {
		Text string `json:"text"`
	}
	type rule struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Desc msg    `json:"shortDescription"`
		Help string `json:"helpUri"`
	}
	type region struct {
		StartLine int `json:"startLine"`
	}
	type physical struct {
		Artifact struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region *region `json:"region,omitempty"`
	}
	type location struct {
		Physical physical `json:"physicalLocation"`
	}
	type result struct {
		RuleID    string     `json:"ruleId"`
		Level     string     `json:"level"`
		Message   msg        `json:"message"`
		Locations []location `json:"locations"`
	}
	const guide = "https://kubernetes.io/docs/reference/using-api/deprecation-guide/"
	rules := []rule{}
	results := []result{}
	seen := map[string]bool{}
	for _, f := range res.Findings {
		r := f.Resource
		id := "removed-api/" + r.APIVersion + "/" + r.Kind
		level := "warning"
		if f.Status == Broken || f.Status == Blocker {
			level = "error"
		} else if f.Status == Notice {
			id = "deprecated-api/" + r.APIVersion + "/" + r.Kind
			level = "note"
		}
		if !seen[id] {
			seen[id] = true
			rules = append(rules, rule{ID: id, Name: r.Kind + " " + r.APIVersion, Desc: msg{f.Label() + ": " + r.Kind + " " + r.APIVersion}, Help: guide})
		}
		repl := f.Repl
		if repl == "" {
			repl = "no replacement API"
		}
		text := fmt.Sprintf("%s uses %s. Replace with %s.", r.title(), r.APIVersion, repl)
		if d := f.Detail(cur); d != "" {
			text += " " + d
		}
		var loc location
		loc.Physical.Artifact.URI = r.File
		if r.Line > 0 {
			loc.Physical.Region = &region{r.Line}
		}
		results = append(results, result{RuleID: id, Level: level, Message: msg{text}, Locations: []location{loc}})
	}
	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool":    map[string]any{"driver": map[string]any{"name": "Shipshape", "informationUri": guide, "rules": rules}},
			"results": results,
		}},
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	return string(out) + "\n", err
}
