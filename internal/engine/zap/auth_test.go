package zap

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"bughound/internal/engine"
)

var _ engine.AuthAware = (*Runner)(nil)

// Lever 1: header auth jadi job replacer SEBELUM spider; baris rusak & nilai
// kosong dilewati; tanpa header plan tak berubah.
func TestPlanYAMLAuthHeaders(t *testing.T) {
	if p := planYAML("https://demo.test", "/out", "report.json", false, nil); strings.Contains(p, "replacer") {
		t.Errorf("tanpa header auth tak boleh ada job replacer:\n%s", p)
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
			t.Errorf("plan harus memuat %q:\n%s", want, p)
		}
	}
	if n := strings.Count(p, "matchType: req_header"); n != 2 {
		t.Errorf("mau 2 aturan (baris rusak & nilai kosong dilewati), dapat %d:\n%s", n, p)
	}
	if strings.Index(p, "type: replacer") > strings.Index(p, "type: spider") {
		t.Error("replacer harus SEBELUM spider agar semua request membawa header")
	}
}

// Nilai berisi karakter YAML-sensitif harus kembali utuh saat plan diurai, dan
// tak bisa menyusupkan kunci/job baru (mis. activeScan di mode pasif).
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
		t.Fatalf("plan bukan YAML sah: %v\n%s", err, p)
	}
	if len(plan.Jobs) != 4 || plan.Jobs[0].Type != "replacer" {
		t.Fatalf("mau 4 job (replacer, spider, passiveScan-wait, report), dapat %+v", plan.Jobs)
	}
	for _, j := range plan.Jobs {
		if j.Type == "activeScan" {
			t.Fatal("nilai header menyusupkan job activeScan ke plan pasif")
		}
	}
	rule := plan.Jobs[0].Rules[0]
	if rule.MatchString != "Cookie" || rule.ReplacementString != strings.TrimSpace(tricky) {
		t.Errorf("nilai tak kembali utuh: %+v", rule)
	}
}

// Scan berlogin: context ZAP mengecualikan route logout (spider mengikuti link
// logout → sesi mati, live 2026-11-16); tanpa login context tak dibatasi.
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
			t.Fatalf("plan rusak (err=%v):\n%s", err, p)
		}
		return plan.Env.Contexts[0].ExcludePaths
	}
	if ex := excl(planYAML("https://demo.test", "/out", "report.json", false, nil)); len(ex) != 0 {
		t.Errorf("tanpa auth context tak boleh dibatasi: %v", ex)
	}
	ex := excl(planYAML("https://demo.test", "/out", "report.json", true, []string{"Cookie: s=1"}))
	if len(ex) != 1 || ex[0] != engine.LogoutPattern {
		t.Errorf("dengan auth, excludePaths harus [%q]; dapat %v", engine.LogoutPattern, ex)
	}
}
