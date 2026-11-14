package check

import (
	"strings"
	"testing"
)

func TestUntrustedManifestTextIsNeutralised(t *testing.T) {
	evil := "apiVersion: batch/v1beta1\nkind: CronJob\nmetadata:\n  name: \"x | [click](http://evil.example) <img src=x> @everyone `\"\n  namespace: \"a\x1b[31m\x07b\"\n"
	res := ParseSource(evil, "k8s/a|b.yaml")
	if len(res) != 1 || strings.ContainsAny(res[0].Namespace, "\x1b\x07") {
		t.Fatalf("control characters survived parsing: %+v", res)
	}
	ev := Evaluate(res, 24, 30)
	md := Markdown(ev, 24, 30)
	for _, bad := range []string{"[click]", "<img", "@everyone", " | [", "a|b.yaml"} {
		if strings.Contains(md, bad) {
			t.Errorf("markdown still contains %q:\n%s", bad, md)
		}
	}
	// Every table row keeps exactly five cells.
	for _, line := range strings.Split(md, "\n") {
		if strings.HasPrefix(line, "| Breaks") && strings.Count(strings.ReplaceAll(line, `\|`, ""), "|") != 6 {
			t.Errorf("table row broken: %s", line)
		}
	}
	// Annotations: a newline or command in a file name cannot start a new workflow command.
	ev.Findings[0].Resource.File = "a.yaml\n::set-output name=x::y"
	out := GitHubAnnotations(ev, 24)
	if strings.Count(out, "\n") != 1 || !strings.HasPrefix(out, "::error file=a.yaml%0A%3A%3Aset-output") {
		t.Errorf("annotation not escaped:\n%s", out)
	}
}
