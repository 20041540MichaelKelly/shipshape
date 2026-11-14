package check

import (
	"fmt"
	"sort"
	"strings"
)

// Status says how a finding affects the upgrade.
type Status int

const (
	Broken  Status = iota // already not served by the current release
	Blocker               // stops being served on the way to the target
	Warning               // deprecated, removed after the target
	Notice                // deprecated with no removal scheduled
)

// Step is one replacement API on the way to a version the target serves.
type Step struct {
	APIVersion string
	Since      int
	Until      int // last release serving it, 0 when it is not removed
}

// Finding is one resource that needs attention.
type Finding struct {
	Resource   Resource
	Status     Status
	Removed    int
	Deprecated int
	Repl       string
	Since      int
	Steps      []Step
	Notes      string
	Auto       bool // only the apiVersion line needs to change
	MigrateNow bool
}

// Result summarises one scan.
type Result struct {
	Findings   []Finding
	Scanned    int
	Breaking   int
	Deprecated int
	Ready      int
	Templated  int
}

// Evaluate checks resources for an upgrade from v1.<cur> to v1.<tgt>.
func Evaluate(resources []Resource, cur, tgt int) Result {
	var res Result
	flagged := 0
	for _, r := range resources {
		if r.Templated {
			res.Templated++
			continue
		}
		rule := findRule(r.APIVersion, r.Kind)
		if r.Nested && rule == nil {
			continue // nested references only matter when they point at a removed API
		}
		if !r.Nested {
			res.Scanned++
		}
		if rule != nil {
			f := Finding{Resource: r, Removed: rule.Removed, Status: Warning}
			if cur >= rule.Removed {
				f.Status = Broken
			} else if tgt >= rule.Removed {
				f.Status = Blocker
			}
			// Follow replacements until one is still served at the target.
			var notes []string
			deadEnd := ""
			for cr, guard := rule, 0; cr != nil && guard < 6; guard++ {
				if cr.Repl == "" {
					// The chain ends in an API with no successor.
					f.Steps, notes, deadEnd = nil, nil, cr.Notes
					break
				}
				next := findRule(cr.Repl, r.Kind)
				step := Step{APIVersion: cr.Repl, Since: cr.Since}
				if next != nil {
					step.Until = next.Removed - 1
				}
				f.Steps = append(f.Steps, step)
				if cr.Notes != "" {
					notes = append(notes, cr.Notes)
				}
				if next == nil || tgt < next.Removed {
					break
				}
				cr = next
			}
			if n := len(f.Steps); n > 0 {
				f.Repl, f.Since = f.Steps[n-1].APIVersion, f.Steps[n-1].Since
				f.Notes = strings.Join(notes, " ")
				f.MigrateNow = f.Since <= cur
			} else {
				f.Notes = deadEnd
			}
			f.Auto = rule.Repl != "" && len(f.Steps) == 1 && !rule.Manual && !r.Nested
			res.Findings = append(res.Findings, f)
			if !r.Nested {
				flagged++
			}
			continue
		}
		if dep := findDeprecation(r.APIVersion, r.Kind); dep != nil && tgt >= dep.Deprecated {
			res.Findings = append(res.Findings, Finding{Resource: r, Status: Notice, Deprecated: dep.Deprecated, Repl: dep.Repl, Notes: dep.Notes, MigrateNow: true})
			flagged++
		}
	}
	sort.SliceStable(res.Findings, func(a, b int) bool {
		fa, fb := res.Findings[a], res.Findings[b]
		if fa.Status != fb.Status {
			return fa.Status < fb.Status
		}
		return fa.Removed < fb.Removed
	})
	for _, f := range res.Findings {
		if f.Status == Broken || f.Status == Blocker {
			res.Breaking++
		}
	}
	res.Deprecated = len(res.Findings) - res.Breaking
	if res.Ready = res.Scanned - flagged; res.Ready < 0 {
		res.Ready = 0
	}
	return res
}

// Label is the short status text for a finding.
func (f Finding) Label() string {
	switch f.Status {
	case Broken:
		return fmt.Sprintf("Already not served on v1.%d+", f.Removed)
	case Blocker:
		return fmt.Sprintf("Breaks at v1.%d", f.Removed)
	case Warning:
		return fmt.Sprintf("Deprecated, removed in v1.%d", f.Removed)
	}
	return fmt.Sprintf("Deprecated since v1.%d", f.Deprecated)
}

// Advice says when and how the resource can be migrated.
func (f Finding) Advice(cur int) string {
	if f.Repl == "" || f.Status == Notice {
		return ""
	}
	if len(f.Steps) > 1 {
		parts := make([]string, len(f.Steps))
		for i, s := range f.Steps {
			parts[i] = fmt.Sprintf("%s (served from v1.%d", s.APIVersion, s.Since)
			if s.Until > 0 {
				parts[i] += fmt.Sprintf(" to v1.%d", s.Until)
			}
			parts[i] += ")"
		}
		return "No single API version spans this upgrade, so migrate in steps: " + strings.Join(parts, ", then ") + "."
	}
	if f.MigrateNow {
		return fmt.Sprintf("The replacement is already served by v1.%d, so you can migrate before upgrading.", cur)
	}
	return fmt.Sprintf("The replacement first appears in v1.%d. Upgrade to v1.%d (no later than v1.%d), migrate this resource, then continue.", f.Since, f.Since, f.Removed-1)
}

// Detail joins the change notes and the migration advice.
func (f Finding) Detail(cur int) string {
	var parts []string
	if f.Notes != "" {
		parts = append(parts, f.Notes)
	} else if f.Auto {
		parts = append(parts, "Only the apiVersion changes. No field changes are needed.")
	}
	if a := f.Advice(cur); a != "" {
		parts = append(parts, a)
	}
	return strings.Join(parts, " ")
}

// ApplyFixes rewrites the apiVersion line of every auto-fixable finding in
// one file and reports how many lines changed.
func ApplyFixes(text, file string, findings []Finding) (string, int) {
	lines := strings.Split(text, "\n")
	n := 0
	for _, f := range findings {
		idx := f.Resource.Line - 1
		if !f.Auto || f.Resource.File != file || idx < 0 || idx >= len(lines) {
			continue
		}
		if strings.Contains(lines[idx], f.Resource.APIVersion) {
			lines[idx] = strings.Replace(lines[idx], f.Resource.APIVersion, f.Repl, 1)
			n++
		}
	}
	return strings.Join(lines, "\n"), n
}
