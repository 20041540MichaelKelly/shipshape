package check

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Resource is one apiVersion/kind pair found in a manifest.
type Resource struct {
	File       string
	Line       int // 1-based, 0 when unknown (JSON input)
	APIVersion string
	Kind       string
	Name       string
	Namespace  string
	Nested     bool // a reference inside another resource, e.g. scaleTargetRef
	Templated  bool // value still contains unrendered {{ }} template syntax
}

var (
	reAPIVersion = regexp.MustCompile(`^(\s*)((?:-\s+)*)["']?apiVersion["']?\s*:\s*(.*)$`)
	rePrefix     = regexp.MustCompile(`^(\s*)((?:-\s+)*)`)
	reBlank      = regexp.MustCompile(`^\s*(#.*)?$`)
	reDocSep     = regexp.MustCompile(`^(---|\.\.\.)(\s|$)`)
	reKind       = regexp.MustCompile(`^["']?kind["']?\s*:\s*(.*)$`)
	reMetadata   = regexp.MustCompile(`^["']?metadata["']?\s*:`)
	reName       = regexp.MustCompile(`^["']?name["']?\s*:\s*(.*)$`)
	reNamespace  = regexp.MustCompile(`^["']?namespace["']?\s*:\s*(.*)$`)
	reItems      = regexp.MustCompile(`^["']?items["']?\s*:`)
	reComment    = regexp.MustCompile(`\s#`)
)

type lineInfo struct {
	lead, content int
	dash          bool
	text          string
}

func info(line string) (lineInfo, bool) {
	if reBlank.MatchString(line) {
		return lineInfo{}, false
	}
	m := rePrefix.FindStringSubmatch(line)
	lead, dashes := len(m[1]), len(m[2])
	return lineInfo{lead: lead, content: lead + dashes, dash: dashes > 0, text: line[lead+dashes:]}, true
}

func stripControl(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

func cleanValue(v string) (value string, templated bool) {
	v = strings.TrimSpace(stripControl(v))
	if strings.Contains(v, "{{") {
		return v, true
	}
	if v != "" && (v[0] == '"' || v[0] == '\'') {
		if end := strings.IndexByte(v[1:], v[0]); end >= 0 {
			return v[1 : end+1], false
		}
		return v[1:], false
	}
	if loc := reComment.FindStringIndex(v); loc != nil {
		v = v[:loc[0]]
	}
	return strings.TrimSpace(v), false
}

// ParseSource extracts resources from YAML (multi-document) or JSON text.
// It reads only apiVersion, kind and metadata, so it tolerates manifests a
// strict parser would reject.
func ParseSource(text, file string) []Resource {
	t := strings.TrimSpace(text)
	if t == "" {
		return nil
	}
	if t[0] == '{' || t[0] == '[' {
		if res, ok := parseJSON(t, file); ok {
			return res
		}
	}
	return parseYAML(text, file)
}

func parseYAML(text, file string) []Resource {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	var out []Resource
	for i, line := range lines {
		m := reAPIVersion.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		indent := len(m[1]) + len(m[2])
		apiVersion, avTemplated := cleanValue(m[3])

		start, end := i, i
		if len(m[2]) == 0 {
			for j := i - 1; j >= 0; j-- {
				if reDocSep.MatchString(lines[j]) {
					break
				}
				li, ok := info(lines[j])
				if !ok {
					continue
				}
				if li.content < indent {
					break
				}
				start = j
				if li.content == indent && li.dash {
					break
				}
			}
		}
		for j := i + 1; j < len(lines); j++ {
			if reDocSep.MatchString(lines[j]) {
				break
			}
			li, ok := info(lines[j])
			if !ok {
				continue
			}
			if li.content < indent || (li.dash && li.lead < indent) {
				break
			}
			end = j
		}

		var kind, name, ns string
		var kindTemplated, haveKind, haveName, haveNS bool
		for j := start; j <= end; j++ {
			li, ok := info(lines[j])
			if !ok || li.content != indent {
				continue
			}
			if km := reKind.FindStringSubmatch(li.text); km != nil && !haveKind {
				kind, kindTemplated = cleanValue(km[1])
				haveKind = true
			}
			if reMetadata.MatchString(li.text) {
				child := -1
				for k := j + 1; k <= end; k++ {
					ci, ok := info(lines[k])
					if !ok {
						continue
					}
					if ci.content <= indent {
						break
					}
					if child == -1 {
						child = ci.content
					}
					if ci.content != child {
						continue
					}
					if nm := reName.FindStringSubmatch(ci.text); nm != nil && !haveName {
						name, _ = cleanValue(nm[1])
						haveName = true
					}
					if nm := reNamespace.FindStringSubmatch(ci.text); nm != nil && !haveNS {
						ns, _ = cleanValue(nm[1])
						haveNS = true
					}
				}
			}
		}
		if kind == "" {
			continue
		}

		nested := false
		if indent > 0 {
			nested = true
			for j := start - 1; j >= 0; j-- {
				if reDocSep.MatchString(lines[j]) {
					break
				}
				li, ok := info(lines[j])
				if !ok {
					continue
				}
				if li.content < indent {
					if reItems.MatchString(li.text) {
						nested = false
					}
					break
				}
			}
		}
		if kind == "List" && apiVersion == "v1" {
			continue
		}
		out = append(out, Resource{File: file, Line: i + 1, APIVersion: apiVersion, Kind: kind, Name: name, Namespace: ns, Nested: nested, Templated: avTemplated || kindTemplated})
	}
	return out
}

func parseJSON(text, file string) ([]Resource, bool) {
	var data any
	if err := json.Unmarshal([]byte(text), &data); err != nil {
		return nil, false
	}
	var out []Resource
	var walk func(v any)
	walk = func(v any) {
		switch o := v.(type) {
		case []any:
			for _, e := range o {
				walk(e)
			}
		case map[string]any:
			av, okA := o["apiVersion"].(string)
			kind, okK := o["kind"].(string)
			if !okA || !okK {
				return
			}
			if items, ok := o["items"].([]any); ok {
				for _, e := range items {
					walk(e)
				}
				if strings.HasSuffix(kind, "List") {
					return
				}
			}
			r := Resource{File: file, APIVersion: stripControl(av), Kind: stripControl(kind)}
			if md, ok := o["metadata"].(map[string]any); ok {
				name, _ := md["name"].(string)
				ns, _ := md["namespace"].(string)
				r.Name, r.Namespace = stripControl(name), stripControl(ns)
			}
			out = append(out, r)
		}
	}
	walk(data)
	return out, true
}
