package eval

import (
	"fmt"
	"testing"

	"bughound/internal/finding"
)

func f(typ, url, engine string, tags ...string) *finding.Finding {
	return &finding.Finding{
		Type: typ, Title: typ,
		Location:     finding.Location{URL: url},
		SourceEngine: engine, Tags: tags,
	}
}

func TestScoreRecallAndOptional(t *testing.T) {
	b := Baseline{
		Name: "t",
		Detectable: []Expected{
			{ID: "metrics", AnyKeyword: []string{"/metrics"}},
			{ID: "robots", AnyKeyword: []string{"robots.txt"}},
			{ID: "deps", Optional: true, AnyKeyword: []string{"retire"}},
		},
	}
	got := Score([]*finding.Finding{
		f("prometheus", "http://t/metrics", "nuclei"),
		f("retirejs", "http://t/app.js", "retire"),
	}, b)

	if got.Required != 2 || got.RequiredCovered != 1 {
		t.Errorf("required cov: want 1/2, got %d/%d", got.RequiredCovered, got.Required)
	}
	if got.Recall != 0.5 {
		t.Errorf("recall want 0.5, got %v", got.Recall)
	}
	if got.Optional != 1 || got.OptionalCovered != 1 {
		t.Errorf("optional cov: want 1/1, got %d/%d", got.OptionalCovered, got.Optional)
	}
	// robots is not covered → that item has Covered=false
	for _, it := range got.Items {
		if it.Expected.ID == "robots" && it.Covered {
			t.Error("robots should not be covered")
		}
	}
}

func TestScoreExtraNotCountedAsFalsePositive(t *testing.T) {
	b := Baseline{Name: "t", Detectable: []Expected{{ID: "metrics", AnyKeyword: []string{"/metrics"}}}}
	got := Score([]*finding.Finding{
		f("prometheus", "http://t/metrics", "nuclei"), // matches
		f("weird-thing", "http://t/zzz", "x"),         // outside the baseline
	}, b)
	if got.Recall != 1.0 {
		t.Errorf("recall want 1.0 (extras do not drag it down), got %v", got.Recall)
	}
	if len(got.Extra) != 1 || got.Extra[0] != "weird-thing @ http://t/zzz (x)" {
		t.Errorf("extra want 1 short item, got %v", got.Extra)
	}
}

func TestExpectedCWEGate(t *testing.T) {
	e := Expected{ID: "sqli", AnyKeyword: []string{"sql"}, AnyCWE: []string{"CWE-89"}}
	hit := f("sql-injection", "http://t/x", "nuclei-dast")
	hit.CWE = []string{"CWE-89"}
	miss := f("sql-injection", "http://t/x", "nuclei-dast") // the keyword matches, BUT the CWE is wrong
	miss.CWE = []string{"CWE-200"}
	if !e.matches(hit) {
		t.Error("matching CWE + matching keyword must match")
	}
	if e.matches(miss) {
		t.Error("a wrong CWE must block the match even when the keyword matches")
	}
}

func TestLoadBuiltinJuiceShop(t *testing.T) {
	// readFile fails on purpose: it proves the baseline is loaded from the embed, not from disk.
	failRead := func(string) ([]byte, error) { return nil, fmt.Errorf("must not be called") }
	b, err := LoadBaseline("juice-shop", failRead)
	if err != nil {
		t.Fatalf("load built-in juice-shop: %v", err)
	}
	if b.Name != "juice-shop" {
		t.Errorf("name want juice-shop, got %q", b.Name)
	}
	var req, opt int
	for _, e := range b.Detectable {
		if e.Optional {
			opt++
		} else {
			req++
		}
	}
	if req != 7 {
		t.Errorf("the juice-shop baseline want 7 required items, got %d", req)
	}
	if opt == 0 {
		t.Error("the juice-shop baseline must have optional items")
	}
	if len(b.BlindSpots) == 0 {
		t.Error("the juice-shop baseline must document blind spots (set B)")
	}
}

func TestScoreJuiceShopFullRecall(t *testing.T) {
	b, err := LoadBaseline("juice-shop", func(string) ([]byte, error) { return nil, fmt.Errorf("x") })
	if err != nil {
		t.Fatal(err)
	}
	// One finding per REQUIRED class + one optional (injection) + one extra.
	findings := []*finding.Finding{
		f("directory-listing", "http://t/ftp/", "ffuf"),
		f("prometheus-metrics", "http://t/metrics", "nuclei"),
		f("robots-txt", "http://t/robots.txt", "nuclei"),
		f("content-security-policy-header-not-set", "http://t/", "zap"),
		f("cross-domain-misconfiguration", "http://t/", "zap"),
		f("fingerprinthub-web-fingerprints", "http://t/", "nuclei", "tech-detect"),
		f("api-endpoint", "http://t/rest/products", "katana"),
		f("sqli-error-based", "http://t/rest/products/search", "nuclei-dast"), // optional
		f("weak-jwt", "http://t/auth", "x"),                                   // extra
	}
	got := Score(findings, b)
	if got.RequiredCovered != got.Required || got.Recall != 1.0 {
		t.Errorf("want full recall over the 7 required; got %d/%d = %v", got.RequiredCovered, got.Required, got.Recall)
	}
	if got.OptionalCovered < 1 {
		t.Error("the optional injection-error item should be covered by sqli-error-based")
	}
	if len(got.Extra) != 1 {
		t.Errorf("want 1 finding outside the baseline, got %d (%v)", len(got.Extra), got.Extra)
	}
}

func TestParseFindingsBothShapes(t *testing.T) {
	arr := []byte(`[{"type":"a","location":{"url":"u"},"source_engine":"e"}]`)
	wrapped := []byte(`{"program":"p","count":1,"findings":[{"type":"a","location":{"url":"u"},"source_engine":"e"}]}`)
	for name, data := range map[string][]byte{"array": arr, "wrapped": wrapped} {
		fs, err := ParseFindings(data)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(fs) != 1 || fs[0].Type != "a" {
			t.Errorf("%s: wrong parse: %+v", name, fs)
		}
	}
	if _, err := ParseFindings([]byte("   ")); err == nil {
		t.Error("empty input must error")
	}
}

func TestBaselineValidate(t *testing.T) {
	cases := []Baseline{
		{Name: "", Detectable: []Expected{{ID: "x", AnyKeyword: []string{"y"}}}}, // no name
		{Name: "n"}, // no detectable items
		{Name: "n", Detectable: []Expected{{ID: "", AnyKeyword: []string{"y"}}}},                                        // item without an id
		{Name: "n", Detectable: []Expected{{ID: "x"}}},                                                                  // item without criteria
		{Name: "n", Detectable: []Expected{{ID: "x", AnyKeyword: []string{"a"}}, {ID: "x", AnyKeyword: []string{"b"}}}}, // id dup
	}
	for i, b := range cases {
		if err := b.validate(); err == nil {
			t.Errorf("case %d should be invalid", i)
		}
	}
}
