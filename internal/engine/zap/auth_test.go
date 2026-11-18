package zap

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"bughound/internal/engine"
)

var _ engine.AuthAware = (*Runner)(nil)

// Lever 1: auth headers become a replacer job BEFORE the spider; a broken line & empty
// value are skipped; without headers the plan is unchanged.
func TestPlanYAMLAuthHeaders(t *testing.T) {
	if p := planYAML("https://demo.test", "/out", "report.json", false, nil); strings.Contains(p, "replacer") {
		t.Errorf("without auth headers there must be no replacer job:\n%s", p)
	}

	r := &Runner{}
	r.UseAuthHeaders([]string{"Cookie: session=abc", "garbage", "X-Empty:  ", "Authorization: Bearer xyz"})
	p := planYAML("https://demo.test", "/out", "report.json", false, r.authHeaders)
	for _, want := range []string{
		"  - type: replacer\n",
		`matchString: "Cookie"`, `replacementString: "session=abc"`,
		`matchString: "Authorization"`, `replacementString: "Bearer xyz"`,
	} {
		if !strings.Contains(p, want) {
			t.Errorf("the plan must hold %q:\n%s", want, p)
		}
	}
	if n := strings.Count(p, "matchType: req_header"); n != 2 {
		t.Errorf("want 2 rules (broken line & empty value skipped), got %d:\n%s", n, p)
	}
	if strings.Index(p, "type: replacer") > strings.Index(p, "type: spider") {
		t.Error("the replacer must be BEFORE the spider so every request carries the header")
	}
}

// A value with YAML-sensitive characters must round-trip intact when the plan is parsed, and
// cannot inject a new key/job (e.g. activeScan in passive mode).
func TestPlanYAMLAuthValueRoundTrip(t *testing.T) {
	tricky := "s=\"a\"#b: c\\d'\t\n  - type: activeScan"
	p := planYAML("https://demo.test", "/out", "report.json", false, []string{"Cookie: " + tricky})

	var plan struct {
		Jobs []struct {
			Type  string `yaml:"type"`
			Rules []struct {
				MatchString       string `yaml:"matchString"`
				ReplacementString string `yaml:"replacementString"`
			} `yaml:"rules"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(p), &plan); err != nil {
		t.Fatalf("the plan is not valid YAML: %v\n%s", err, p)
	}
	if len(plan.Jobs) != 4 || plan.Jobs[0].Type != "replacer" {
		t.Fatalf("want 4 job (replacer, spider, passiveScan-wait, report), got %+v", plan.Jobs)
	}
	for _, j := range plan.Jobs {
		if j.Type == "activeScan" {
			t.Fatal("the header value injected an activeScan job into the passive plan")
		}
	}
	rule := plan.Jobs[0].Rules[0]
	if rule.MatchString != "Cookie" || rule.ReplacementString != strings.TrimSpace(tricky) {
		t.Errorf("the value did not round-trip intact: %+v", rule)
	}
}

// Authenticated scan: the ZAP context excludes the logout route (the spider follows the
// logout link → the session dies, live 2026-11-16); without login the context is not restricted.
func TestPlanYAMLExcludesLogoutWhenAuth(t *testing.T) {
	excl := func(p string) []string {
		t.Helper()
		var plan struct {
			Env struct {
				Contexts []struct {
					ExcludePaths []string `yaml:"excludePaths"`
				} `yaml:"contexts"`
			} `yaml:"env"`
		}
		if err := yaml.Unmarshal([]byte(p), &plan); err != nil || len(plan.Env.Contexts) != 1 {
			t.Fatalf("broken plan (err=%v):\n%s", err, p)
		}
		return plan.Env.Contexts[0].ExcludePaths
	}
	if ex := excl(planYAML("https://demo.test", "/out", "report.json", false, nil)); len(ex) != 0 {
		t.Errorf("without auth the context must not be restricted: %v", ex)
	}
	ex := excl(planYAML("https://demo.test", "/out", "report.json", true, []string{"Cookie: s=1"}))
	if len(ex) != 1 || ex[0] != engine.LogoutPattern {
		t.Errorf("with auth, excludePaths must be [%q]; got %v", engine.LogoutPattern, ex)
	}
}
