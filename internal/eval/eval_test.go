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
		t.Errorf("required cov: mau 1/2, dapat %d/%d", got.RequiredCovered, got.Required)
	}
	if got.Recall != 0.5 {
		t.Errorf("recall mau 0.5, dapat %v", got.Recall)
	}
	if got.Optional != 1 || got.OptionalCovered != 1 {
		t.Errorf("opsional cov: mau 1/1, dapat %d/%d", got.OptionalCovered, got.Optional)
	}
	// robots tak tercakup → item itu Covered=false
	for _, it := range got.Items {
		if it.Expected.ID == "robots" && it.Covered {
			t.Error("robots semestinya tak tercakup")
		}
	}
}

func TestScoreExtraNotCountedAsFalsePositive(t *testing.T) {
	b := Baseline{Name: "t", Detectable: []Expected{{ID: "metrics", AnyKeyword: []string{"/metrics"}}}}
	got := Score([]*finding.Finding{
		f("prometheus", "http://t/metrics", "nuclei"), // cocok
		f("weird-thing", "http://t/zzz", "x"),         // di luar baseline
	}, b)
	if got.Recall != 1.0 {
		t.Errorf("recall mau 1.0 (extra tak menyeret), dapat %v", got.Recall)
	}
	if len(got.Extra) != 1 || got.Extra[0] != "weird-thing @ http://t/zzz (x)" {
		t.Errorf("extra mau 1 item ringkas, dapat %v", got.Extra)
	}
}

func TestExpectedCWEGate(t *testing.T) {
	e := Expected{ID: "sqli", AnyKeyword: []string{"sql"}, AnyCWE: []string{"CWE-89"}}
	hit := f("sql-injection", "http://t/x", "nuclei-dast")
	hit.CWE = []string{"CWE-89"}
	miss := f("sql-injection", "http://t/x", "nuclei-dast") // keyword cocok, TAPI CWE salah
	miss.CWE = []string{"CWE-200"}
	if !e.matches(hit) {
		t.Error("CWE cocok + keyword cocok harus match")
	}
	if e.matches(miss) {
		t.Error("CWE salah harus menggagalkan match walau keyword cocok")
	}
}

func TestLoadBuiltinJuiceShop(t *testing.T) {
	// readFile sengaja gagal: membuktikan baseline dimuat dari embed, bukan disk.
	failRead := func(string) ([]byte, error) { return nil, fmt.Errorf("tak boleh dipanggil") }
	b, err := LoadBaseline("juice-shop", failRead)
	if err != nil {
		t.Fatalf("muat juice-shop bawaan: %v", err)
	}
	if b.Name != "juice-shop" {
		t.Errorf("nama mau juice-shop, dapat %q", b.Name)
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
		t.Errorf("baseline juice-shop mau 7 item wajib, dapat %d", req)
	}
	if opt == 0 {
		t.Error("baseline juice-shop harus punya item opsional")
	}
	if len(b.BlindSpots) == 0 {
		t.Error("baseline juice-shop harus mendokumentasikan blind-spot (set B)")
	}
}

func TestScoreJuiceShopFullRecall(t *testing.T) {
	b, err := LoadBaseline("juice-shop", func(string) ([]byte, error) { return nil, fmt.Errorf("x") })
	if err != nil {
		t.Fatal(err)
	}
	// Satu temuan per kelas WAJIB + satu opsional (injection) + satu extra.
	findings := []*finding.Finding{
		f("directory-listing", "http://t/ftp/", "ffuf"),
		f("prometheus-metrics", "http://t/metrics", "nuclei"),
		f("robots-txt", "http://t/robots.txt", "nuclei"),
		f("content-security-policy-header-not-set", "http://t/", "zap"),
		f("cross-domain-misconfiguration", "http://t/", "zap"),
		f("fingerprinthub-web-fingerprints", "http://t/", "nuclei", "tech-detect"),
		f("api-endpoint", "http://t/rest/products", "katana"),
		f("sqli-error-based", "http://t/rest/products/search", "nuclei-dast"), // opsional
		f("weak-jwt", "http://t/auth", "x"),                                   // extra
	}
	got := Score(findings, b)
	if got.RequiredCovered != got.Required || got.Recall != 1.0 {
		t.Errorf("mau recall penuh atas 7 wajib; dapat %d/%d = %v", got.RequiredCovered, got.Required, got.Recall)
	}
	if got.OptionalCovered < 1 {
		t.Error("injection-error opsional semestinya tercakup oleh sqli-error-based")
	}
	if len(got.Extra) != 1 {
		t.Errorf("mau 1 temuan di luar baseline, dapat %d (%v)", len(got.Extra), got.Extra)
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
			t.Errorf("%s: parse salah: %+v", name, fs)
		}
	}
	if _, err := ParseFindings([]byte("   ")); err == nil {
		t.Error("input kosong harus error")
	}
}

func TestBaselineValidate(t *testing.T) {
	cases := []Baseline{
		{Name: "", Detectable: []Expected{{ID: "x", AnyKeyword: []string{"y"}}}}, // tanpa nama
		{Name: "n"}, // tanpa detectable
		{Name: "n", Detectable: []Expected{{ID: "", AnyKeyword: []string{"y"}}}},                                        // item tanpa id
		{Name: "n", Detectable: []Expected{{ID: "x"}}},                                                                  // item tanpa kriteria
		{Name: "n", Detectable: []Expected{{ID: "x", AnyKeyword: []string{"a"}}, {ID: "x", AnyKeyword: []string{"b"}}}}, // id dup
	}
	for i, b := range cases {
		if err := b.validate(); err == nil {
			t.Errorf("kasus %d semestinya invalid", i)
		}
	}
}
