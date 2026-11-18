// Package eval scores scan output against a ground-truth baseline: how many of
// the finding classes that an unauthenticated DAST scanner SHOULD catch were
// actually caught (recall). It works offline: it reads two JSON files (baseline
// + findings) and counts. It does NOT scan and does not touch the network, the
// scope guard, egress or secrets.
//
// A note on the metric: the baseline is a representative "must find" set, NOT
// an exhaustive list of every true positive. So real "precision" cannot be
// computed here (a finding outside the baseline is not necessarily a false
// positive). What is reported: recall over the required set, plus the list of
// findings outside the baseline for manual review. That list is not a
// false-positive verdict.
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

// Expected = one finding class that (for this baseline) should be found.
// Matching is best effort: keyword substrings against the finding's combined
// fields, optionally gated by CWE membership.
type Expected struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Category   string   `json:"category,omitempty"`
	AnyKeyword []string `json:"any_keyword,omitempty"` // matches when any one is a substring (type+title+url+template+engine+tags), lowercase
	AnyCWE     []string `json:"any_cwe,omitempty"`     // when set, the finding MUST have one of these CWEs
	Optional   bool     `json:"optional,omitempty"`    // does not drag required recall down (e.g. needs an optional engine / validated true negative)
	Note       string   `json:"note,omitempty"`
}

// Baseline = the reference for one target/class (e.g. unauthenticated juice-shop).
type Baseline struct {
	Name       string     `json:"name"`
	Target     string     `json:"target,omitempty"`
	Note       string     `json:"note,omitempty"`
	Detectable []Expected `json:"detectable"`            // set A: scored (recall)
	BlindSpots []string   `json:"blind_spots,omitempty"` // set B: documented, NOT scored
}

func (b Baseline) validate() error {
	if strings.TrimSpace(b.Name) == "" {
		return fmt.Errorf("baseline has no name")
	}
	if len(b.Detectable) == 0 {
		return fmt.Errorf("baseline %q has no detectable items", b.Name)
	}
	seen := map[string]bool{}
	for i, e := range b.Detectable {
		if strings.TrimSpace(e.ID) == "" {
			return fmt.Errorf("detectable item #%d has no id", i)
		}
		if seen[e.ID] {
			return fmt.Errorf("duplicate detectable id: %q", e.ID)
		}
		seen[e.ID] = true
		if len(e.AnyKeyword) == 0 && len(e.AnyCWE) == 0 {
			return fmt.Errorf("item %q has no match criteria (any_keyword/any_cwe)", e.ID)
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
			return true // CWE gate only
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

// ItemResult = the result for one Expected.
type ItemResult struct {
	Expected  Expected `json:"expected"`
	Covered   bool     `json:"covered"`
	MatchedBy []string `json:"matched_by,omitempty"` // summaries of the matching findings
}

// Result = the full score of a scan against a baseline.
type Result struct {
	Baseline        string       `json:"baseline"`
	Items           []ItemResult `json:"items"`
	Required        int          `json:"required"`
	RequiredCovered int          `json:"required_covered"`
	Optional        int          `json:"optional"`
	OptionalCovered int          `json:"optional_covered"`
	Recall          float64      `json:"recall"` // required_covered / required
	TotalFindings   int          `json:"total_findings"`
	Extra           []string     `json:"extra,omitempty"` // findings that match no Expected: REVIEW MANUALLY, not a false-positive verdict
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

// Score scores findings against baseline b. One finding may match several
// Expected items (that is fine; recall is counted per Expected). A finding that
// matches no Expected goes into Extra (manual review).
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

// LoadBaseline loads a baseline by built-in name (e.g. "juice-shop") or from a
// JSON file path. The built-in name is tried first.
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
		return b, fmt.Errorf("invalid baseline JSON: %w", err)
	}
	if err := b.validate(); err != nil {
		return b, err
	}
	return b, nil
}

// BuiltinBaselines returns the built-in baseline names (without .json).
func BuiltinBaselines() []string {
	entries, _ := builtinFS.ReadDir("baselines")
	var names []string
	for _, e := range entries {
		names = append(names, strings.TrimSuffix(e.Name(), ".json"))
	}
	sort.Strings(names)
	return names
}

// ParseFindings accepts BOTH a bare findings array `[...]` AND the wrapped
// response `{"findings":[...]}` (the shape of /api/v1/findings).
func ParseFindings(data []byte) ([]*finding.Finding, error) {
	t := bytes.TrimSpace(data)
	if len(t) == 0 {
		return nil, fmt.Errorf("findings file is empty")
	}
	if t[0] == '[' {
		var fs []*finding.Finding
		if err := json.Unmarshal(t, &fs); err != nil {
			return nil, fmt.Errorf("invalid findings array: %w", err)
		}
		return fs, nil
	}
	var wrap struct {
		Findings []*finding.Finding `json:"findings"`
	}
	if err := json.Unmarshal(t, &wrap); err != nil {
		return nil, fmt.Errorf("invalid findings object: %w", err)
	}
	return wrap.Findings, nil
}

// Report renders the Result as a readable text scorecard.
func (r Result) Report() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Eval: %s\n", r.Baseline)
	pct := 0.0
	if r.Required > 0 {
		pct = r.Recall * 100
	}
	fmt.Fprintf(&b, "Recall (required): %d/%d = %.1f%%", r.RequiredCovered, r.Required, pct)
	if r.Optional > 0 {
		fmt.Fprintf(&b, "   | optional: %d/%d", r.OptionalCovered, r.Optional)
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "Total findings: %d   | outside the baseline (manual review): %d\n\n", r.TotalFindings, len(r.Extra))

	b.WriteString("Set A (DAST-detectable, scored):\n")
	for _, it := range r.Items {
		mark := "✗"
		if it.Covered {
			mark = "✓"
		}
		tag := ""
		if it.Expected.Optional {
			tag = " (optional)"
		}
		fmt.Fprintf(&b, "  [%s] %-22s %s%s\n", mark, it.Expected.ID, it.Expected.Name, tag)
		if it.Covered && len(it.MatchedBy) > 0 {
			fmt.Fprintf(&b, "        ← %s\n", it.MatchedBy[0])
		} else if !it.Covered && it.Expected.Note != "" {
			fmt.Fprintf(&b, "        note: %s\n", it.Expected.Note)
		}
	}
	if len(r.BlindSpots) > 0 {
		b.WriteString("\nSet B (unauthenticated DAST blind spots, NOT scored, a miss is normal):\n")
		for _, bs := range r.BlindSpots {
			fmt.Fprintf(&b, "  - %s\n", bs)
		}
	}
	if len(r.Extra) > 0 {
		b.WriteString("\nOutside the baseline (the baseline is not exhaustive, so these are NOT automatically false positives; review manually):\n")
		for _, e := range r.Extra {
			fmt.Fprintf(&b, "  · %s\n", e)
		}
	}
	return b.String()
}
