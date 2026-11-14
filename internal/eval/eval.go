// Package eval menilai keluaran scan terhadap baseline ground-truth:
// berapa banyak kelas temuan yang MESTINYA ketangkap scanner DAST unauth
// benar-benar ketangkap (recall). Murni offline — membaca dua berkas JSON
// (baseline + temuan) lalu menghitung; TIDAK memindai, tak menyentuh jaringan,
// scope guard, egress, maupun secret.
//
// Catatan metrik: baseline adalah himpunan "wajib-temu" yang representatif,
// BUKAN daftar ekshaustif seluruh true-positive. Karena itu "precision" sejati
// tak bisa dihitung di sini (temuan di luar baseline belum tentu false-positive).
// Yang dilaporkan: recall atas set wajib + daftar temuan di-luar-baseline untuk
// ditinjau manual, bukan vonis false-positive.
package eval

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"bughound/internal/finding"
)

//go:embed baselines/*.json
var builtinFS embed.FS

// Expected = satu kelas temuan yang (untuk baseline ini) semestinya ditemukan.
// Pencocokan best-effort: substring kata kunci terhadap gabungan field temuan,
// opsional dijaga oleh keanggotaan CWE.
type Expected struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Category   string   `json:"category,omitempty"`
	AnyKeyword []string `json:"any_keyword,omitempty"` // cocok bila salah satu = substring (type+title+url+template+engine+tags), huruf kecil
	AnyCWE     []string `json:"any_cwe,omitempty"`     // bila diisi, temuan WAJIB punya salah satu CWE ini
	Optional   bool     `json:"optional,omitempty"`    // tak menyeret recall wajib (mis. butuh engine opsional / true-negative tervalidasi)
	Note       string   `json:"note,omitempty"`
}

// Baseline = acuan untuk satu target/kelas (mis. juice-shop unauth).
type Baseline struct {
	Name       string     `json:"name"`
	Target     string     `json:"target,omitempty"`
	Note       string     `json:"note,omitempty"`
	Detectable []Expected `json:"detectable"`            // set A — di-skor (recall)
	BlindSpots []string   `json:"blind_spots,omitempty"` // set B — didokumentasikan, TAK di-skor
}

func (b Baseline) validate() error {
	if strings.TrimSpace(b.Name) == "" {
		return fmt.Errorf("baseline tanpa nama")
	}
	if len(b.Detectable) == 0 {
		return fmt.Errorf("baseline %q tak punya item detectable", b.Name)
	}
	seen := map[string]bool{}
	for i, e := range b.Detectable {
		if strings.TrimSpace(e.ID) == "" {
			return fmt.Errorf("item detectable #%d tanpa id", i)
		}
		if seen[e.ID] {
			return fmt.Errorf("id detectable duplikat: %q", e.ID)
		}
		seen[e.ID] = true
		if len(e.AnyKeyword) == 0 && len(e.AnyCWE) == 0 {
			return fmt.Errorf("item %q tak punya kriteria cocok (any_keyword/any_cwe)", e.ID)
		}
	}
	return nil
}

func haystack(f *finding.Finding) string {
	parts := make([]string, 0, 5+len(f.Tags))
	parts = append(parts, f.Type, f.Title, f.Location.URL, f.SourceTemplate, f.SourceEngine)
	parts = append(parts, f.Tags...)
	return strings.ToLower(strings.Join(parts, " "))
}

func (e Expected) matches(f *finding.Finding) bool {
	if len(e.AnyCWE) > 0 {
		ok := false
		for _, want := range e.AnyCWE {
			for _, got := range f.CWE {
				if strings.EqualFold(strings.TrimSpace(got), strings.TrimSpace(want)) {
					ok = true
				}
			}
		}
		if !ok {
			return false
		}
		if len(e.AnyKeyword) == 0 {
			return true // hanya gate CWE
		}
	}
	hay := haystack(f)
	for _, kw := range e.AnyKeyword {
		if kw != "" && strings.Contains(hay, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}

// ItemResult = hasil satu Expected.
type ItemResult struct {
	Expected  Expected `json:"expected"`
	Covered   bool     `json:"covered"`
	MatchedBy []string `json:"matched_by,omitempty"` // ringkasan temuan pencocok
}

// Result = skor lengkap sebuah scan terhadap baseline.
type Result struct {
	Baseline        string       `json:"baseline"`
	Items           []ItemResult `json:"items"`
	Required        int          `json:"required"`
	RequiredCovered int          `json:"required_covered"`
	Optional        int          `json:"optional"`
	OptionalCovered int          `json:"optional_covered"`
	Recall          float64      `json:"recall"` // required_covered / required
	TotalFindings   int          `json:"total_findings"`
	Extra           []string     `json:"extra,omitempty"` // temuan tak cocok Expected apa pun — TINJAU MANUAL, bukan vonis false-positive
	BlindSpots      []string     `json:"blind_spots,omitempty"`
}

func summ(f *finding.Finding) string {
	loc := f.Location.URL
	if loc == "" {
		loc = f.Target
	}
	eng := f.SourceEngine
	if eng == "" {
		eng = "?"
	}
	return fmt.Sprintf("%s @ %s (%s)", f.Type, loc, eng)
}

// Score menilai findings terhadap baseline b. Satu temuan boleh mencocoki
// beberapa Expected (tak masalah; recall dihitung per-Expected). Temuan yang
// tak cocok Expected mana pun masuk Extra (tinjau manual).
func Score(findings []*finding.Finding, b Baseline) Result {
	res := Result{Baseline: b.Name, TotalFindings: len(findings), BlindSpots: b.BlindSpots}
	matchedAny := make([]bool, len(findings))
	for _, e := range b.Detectable {
		ir := ItemResult{Expected: e}
		for i, f := range findings {
			if f != nil && e.matches(f) {
				ir.Covered = true
				matchedAny[i] = true
				ir.MatchedBy = append(ir.MatchedBy, summ(f))
			}
		}
		res.Items = append(res.Items, ir)
		if e.Optional {
			res.Optional++
			if ir.Covered {
				res.OptionalCovered++
			}
		} else {
			res.Required++
			if ir.Covered {
				res.RequiredCovered++
			}
		}
	}
	if res.Required > 0 {
		res.Recall = float64(res.RequiredCovered) / float64(res.Required)
	}
	for i, f := range findings {
		if f != nil && !matchedAny[i] {
			res.Extra = append(res.Extra, summ(f))
		}
	}
	sort.Strings(res.Extra)
	return res
}

// LoadBaseline memuat baseline dari nama bawaan (mis. "juice-shop") atau path
// berkas JSON. Nama bawaan dicoba dulu.
func LoadBaseline(nameOrPath string, readFile func(string) ([]byte, error)) (Baseline, error) {
	if data, err := builtinFS.ReadFile("baselines/" + nameOrPath + ".json"); err == nil {
		return parseBaseline(data)
	}
	data, err := readFile(nameOrPath)
	if err != nil {
		return Baseline{}, err
	}
	return parseBaseline(data)
}

func parseBaseline(data []byte) (Baseline, error) {
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return b, fmt.Errorf("baseline JSON tak sah: %w", err)
	}
	if err := b.validate(); err != nil {
		return b, err
	}
	return b, nil
}

// BuiltinBaselines mengembalikan nama baseline bawaan (tanpa .json).
func BuiltinBaselines() []string {
	entries, _ := builtinFS.ReadDir("baselines")
	var names []string
	for _, e := range entries {
		names = append(names, strings.TrimSuffix(e.Name(), ".json"))
	}
	sort.Strings(names)
	return names
}

// ParseFindings menerima BAIK array temuan telanjang `[...]` MAUPUN respons
// terbungkus `{"findings":[...]}` (bentuk /api/v1/findings).
func ParseFindings(data []byte) ([]*finding.Finding, error) {
	t := bytes.TrimSpace(data)
	if len(t) == 0 {
		return nil, fmt.Errorf("berkas temuan kosong")
	}
	if t[0] == '[' {
		var fs []*finding.Finding
		if err := json.Unmarshal(t, &fs); err != nil {
			return nil, fmt.Errorf("array temuan tak sah: %w", err)
		}
		return fs, nil
	}
	var wrap struct {
		Findings []*finding.Finding `json:"findings"`
	}
	if err := json.Unmarshal(t, &wrap); err != nil {
		return nil, fmt.Errorf("objek temuan tak sah: %w", err)
	}
	return wrap.Findings, nil
}

// Report merender Result sebagai kartu-skor teks yang mudah dibaca.
func (r Result) Report() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Eval: %s\n", r.Baseline)
	pct := 0.0
	if r.Required > 0 {
		pct = r.Recall * 100
	}
	fmt.Fprintf(&b, "Recall (wajib): %d/%d = %.1f%%", r.RequiredCovered, r.Required, pct)
	if r.Optional > 0 {
		fmt.Fprintf(&b, "   | opsional: %d/%d", r.OptionalCovered, r.Optional)
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "Temuan total: %d   | di luar baseline (tinjau manual): %d\n\n", r.TotalFindings, len(r.Extra))

	b.WriteString("Set A — DAST-detectable (di-skor):\n")
	for _, it := range r.Items {
		mark := "✗"
		if it.Covered {
			mark = "✓"
		}
		tag := ""
		if it.Expected.Optional {
			tag = " (opsional)"
		}
		fmt.Fprintf(&b, "  [%s] %-22s %s%s\n", mark, it.Expected.ID, it.Expected.Name, tag)
		if it.Covered && len(it.MatchedBy) > 0 {
			fmt.Fprintf(&b, "        ← %s\n", it.MatchedBy[0])
		} else if !it.Covered && it.Expected.Note != "" {
			fmt.Fprintf(&b, "        catatan: %s\n", it.Expected.Note)
		}
	}
	if len(r.BlindSpots) > 0 {
		b.WriteString("\nSet B — blind-spot DAST unauth (TAK di-skor, miss = normal):\n")
		for _, bs := range r.BlindSpots {
			fmt.Fprintf(&b, "  - %s\n", bs)
		}
	}
	if len(r.Extra) > 0 {
		b.WriteString("\nDi luar baseline (baseline tak ekshaustif; ini BUKAN otomatis false-positive — tinjau manual):\n")
		for _, e := range r.Extra {
			fmt.Fprintf(&b, "  · %s\n", e)
		}
	}
	return b.String()
}
