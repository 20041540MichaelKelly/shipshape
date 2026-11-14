package check

import (
	"os"
	"strings"
	"testing"
)

func shop(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("../../testdata/shop.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestShopExample(t *testing.T) {
	res := ParseSource(shop(t), "shop.yaml")
	var top []Resource
	for _, r := range res {
		if !r.Nested {
			top = append(top, r)
		}
	}
	if len(top) != 7 {
		t.Fatalf("top-level resources = %d, want 7", len(top))
	}
	if top[2].Name != "nightly-invoices" || top[2].Namespace != "shop" || top[2].Line != 32 {
		t.Errorf("unexpected CronJob: %+v", top[2])
	}

	ev := Evaluate(res, 24, 33)
	if ev.Scanned != 7 || ev.Breaking != 4 || ev.Deprecated != 1 || ev.Ready != 2 {
		t.Fatalf("got scanned=%d breaking=%d deprecated=%d ready=%d", ev.Scanned, ev.Breaking, ev.Deprecated, ev.Ready)
	}
	for _, f := range ev.Findings {
		if f.Resource.Kind != "FlowSchema" {
			continue
		}
		if f.Repl != "flowcontrol.apiserver.k8s.io/v1" || len(f.Steps) != 2 || f.Auto || f.MigrateNow {
			t.Errorf("FlowSchema chain wrong: %+v", f)
		}
		if f.Steps[0].Until != 31 {
			t.Errorf("v1beta3 should be served until 1.31, got %d", f.Steps[0].Until)
		}
	}

	if ev := Evaluate(res, 24, 25); ev.Breaking != 2 {
		t.Errorf("1.24->1.25 breaking = %d, want 2", ev.Breaking)
	}
	broken := 0
	for _, f := range Evaluate(res, 27, 33).Findings {
		if f.Status == Broken {
			broken++
		}
	}
	if broken != 3 {
		t.Errorf("already broken on 1.27 = %d, want 3", broken)
	}
}

func TestFixes(t *testing.T) {
	text := shop(t)
	ev := Evaluate(ParseSource(text, "shop.yaml"), 24, 33)
	fixed, n := ApplyFixes(text, "shop.yaml", ev.Findings)
	if n != 1 || !strings.Contains(fixed, "apiVersion: batch/v1\nkind: CronJob") {
		t.Errorf("expected only the CronJob to be rewritten, n=%d", n)
	}
	if !strings.Contains(fixed, "policy/v1beta1") {
		t.Error("PodDisruptionBudget needs manual review and must not be rewritten")
	}
}

func TestTrickyYAML(t *testing.T) {
	text := strings.Join([]string{
		"apiVersion: v1", "kind: List", "items:",
		"  - kind: Role", `    apiVersion: "rbac.authorization.k8s.io/v1beta1" # old`, "    metadata:", "      name: reader", "      labels:", "        name: not-this",
		"  - apiVersion: extensions/v1beta1", "    kind: Ingress", "    metadata: {name: inline}", "",
		"---", "kind: HorizontalPodAutoscaler", "apiVersion: autoscaling/v2", "metadata:", "  namespace: a", "  name: hpa",
		"spec:", "  scaleTargetRef:", "    apiVersion: extensions/v1beta1", "    kind: Deployment", "    name: old",
		"---", `apiVersion: {{ include "x.apiVersion" . }}`, "kind: Deployment", "metadata:", "  name: t",
	}, "\r\n")
	res := ParseSource(text, "t.yaml")
	if len(res) != 5 {
		t.Fatalf("resources = %d, want 5: %+v", len(res), res)
	}
	if res[0].Name != "reader" || res[0].Nested || res[0].APIVersion != "rbac.authorization.k8s.io/v1beta1" {
		t.Errorf("list item parsed wrong: %+v", res[0])
	}
	if res[2].Name != "hpa" || res[2].Namespace != "a" {
		t.Errorf("kind-first document parsed wrong: %+v", res[2])
	}
	if !res[3].Nested || !res[4].Templated {
		t.Errorf("nested/templated flags wrong: %+v %+v", res[3], res[4])
	}
	ev := Evaluate(res, 20, 30)
	if ev.Scanned != 3 || ev.Templated != 1 || ev.Breaking != 3 || ev.Ready != 1 {
		t.Errorf("got scanned=%d templated=%d breaking=%d ready=%d", ev.Scanned, ev.Templated, ev.Breaking, ev.Ready)
	}
}

func TestJSONAndEdges(t *testing.T) {
	js := `{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"batch/v1beta1","kind":"CronJob","metadata":{"name":"j"}},{"apiVersion":"v1","kind":"Service","metadata":{"name":"s"}}]}`
	res := ParseSource(js, "a.json")
	if len(res) != 2 {
		t.Fatalf("json resources = %d, want 2", len(res))
	}
	if ev := Evaluate(res, 24, 26); ev.Breaking != 1 || ev.Ready != 1 {
		t.Errorf("json evaluate wrong: %+v", ev)
	}
	if len(ParseSource("", "x")) != 0 || len(ParseSource("hello: world\nfoo", "x")) != 0 {
		t.Error("empty or unrelated input should yield no resources")
	}
	ev := Evaluate([]Resource{{File: "f", Line: 1, APIVersion: "extensions/v1beta1", Kind: "PodSecurityPolicy"}}, 15, 30)
	if ev.Findings[0].Repl != "" {
		t.Errorf("PodSecurityPolicy must end with no replacement, got %q", ev.Findings[0].Repl)
	}
}

func TestAnnotations(t *testing.T) {
	ev := Evaluate(ParseSource(shop(t), "k8s/shop.yaml"), 24, 33)
	out := GitHubAnnotations(ev, 24)
	if !strings.Contains(out, "::error file=k8s/shop.yaml,line=32,title=Breaks at v1.25::CronJob/nightly-invoices uses batch/v1beta1.") {
		t.Errorf("missing CronJob annotation:\n%s", out)
	}
	if !strings.Contains(out, "::warning file=k8s/shop.yaml,line=75,") {
		t.Errorf("missing Endpoints warning:\n%s", out)
	}
}
