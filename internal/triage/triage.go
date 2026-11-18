// Package triage ranks findings by "verification priority" with Simple
// Additive Weighting (SAW/SPK). It is deterministic and uses no LLM.
//
// It is a FAITHFUL port to Go of the SPK algorithm in the Analyst app
// (bughound/analyst, modules saw.py + analyst.py + config.py), so the web UI
// can show the SAME ranking as the MCP `rank` tool without linking a Python
// runtime into the application. The constants (weights, engine factors,
// signal patterns, heuristics) are kept identical to the defaults in
// analyst/bughound_analyst/config.py: when one side is tuned, the other MUST
// follow (the tests in triage_test.go pin the values).
//
// The package is read-only: it does not touch targets, does not change the
// store and makes no network calls. It only computes scores for findings that
// already exist.
package triage

import (
	"math"
	"regexp"
	"sort"
	"strings"
	"time"

	"bughound/internal/finding"
)

// ---- SPK constants (mirror analyst/bughound_analyst/config.py _DEFAULTS) ----

// crits: a fixed order (= the insertion order of weights in config.py) so
// normalization and iteration are deterministic.
var crits = []string{
	"exploitability", "signal", "bounty", "severity",
	"fp_likelihood", "effort", "owasp", "freshness",
}

var weights = map[string]float64{
	"exploitability": 0.26, "signal": 0.22, "bounty": 0.16, "severity": 0.12,
	"fp_likelihood": 0.12, "effort": 0.06, "owasp": 0.04, "freshness": 0.02,
}

// critType: "benefit" (higher is better) or "cost" (lower is better).
var critType = map[string]string{
	"exploitability": "benefit", "signal": "benefit", "bounty": "benefit",
	"severity": "benefit", "fp_likelihood": "cost", "effort": "cost",
	"owasp": "benefit", "freshness": "benefit",
}

var sevNum = map[finding.Severity]int{
	finding.SeverityInfo: 1, finding.SeverityLow: 2, finding.SeverityMedium: 3,
	finding.SeverityHigh: 4, finding.SeverityCritical: 5,
}

var confNum = map[finding.Confidence]int{
	finding.ConfidenceLow: 1, finding.ConfidenceMedium: 2, finding.ConfidenceHigh: 3,
}

var engineFactor = map[string]float64{
	"nuclei-dast": 1.0, "dalfox": 1.0, "nuclei": 0.8, "zap": 0.8,
	"ffuf": 0.7, "retire": 0.5, "zap-passive": 0.5, "sast": 0.5,
}

const engineFactorDefault = 0.6

var owaspPriority = map[finding.OWASP]int{
	finding.A01: 5, finding.A02: 4, finding.A03: 5, finding.A04: 3, finding.A05: 3,
	finding.A06: 3, finding.A07: 4, finding.A08: 3, finding.A09: 2, finding.A10: 4,
}

const owaspPriorityDefault = 2

// effortByType: substring match on type (falling back to title), lowercase;
// checked in the same order as config.py (first match wins, e.g. "blind-sqli"
// → sqli=2 because "sqli" comes before "blind").
var effortByType = []struct {
	key string
	val int
}{
	{"reflected", 1}, {"xss", 1}, {"sqli", 2}, {"injection", 2}, {"idor", 2},
	{"access", 2}, {"blind", 3}, {"second-order", 3}, {"ssrf", 3},
}

const effortDefault = 2

// Payout signal (the lever against "header noise"): high→1.0 (exploitable,
// pays out), noise→0.1 (hygiene/header, close to won't-pay), otherwise 0.5.
var signalHigh = []string{
	"sqli", "sql-injection", "sql injection", "nosql",
	"xss", "cross-site-scripting", "cross site scripting",
	"rce", "remote-code", "command-injection", "command injection", "os-command",
	"ssrf", "server-side-request", "xxe", "xml-external",
	"idor", "bola", "broken-access", "broken access",
	"authorization-bypass", "auth-bypass", "authentication-bypass",
	"auth bypass", "login-bypass",
	"path-traversal", "directory-traversal", "lfi", "local-file",
	"rfi", "remote-file", "deserial", "ssti", "template-injection",
	"template injection", "prototype-pollution",
	"exposed-panel", "exposed-admin", "admin-panel", "exposed-config",
	"config-exposure", "backup-file", ".git", "git-config", ".env", "env-file",
	"secret", "api-key", "apikey", "access-key", "private-key",
	"credential", "token-leak", "hardcoded",
	"takeover", "subdomain-takeover", "unrestricted-upload", "file-upload",
	"backup", ".sql", ".bak", ".svn", "wp-admin", "phpmyadmin", "actuator",
}

var signalNoise = []string{
	"content-security-policy", "csp", "sub-resource-integrity",
	"subresource-integrity", "clickjacking", "anti-clickjacking",
	"x-frame", "frame-options", "strict-transport", "hsts", "samesite",
	"cookie-with", "cookie-without", "httponly", "secure-flag",
	"referrer-policy", "permissions-policy", "feature-policy",
	"x-content-type", "content-type-options", "nosniff", "x-xss-protection",
	"x-powered-by", "server-version", "banner", "version-disclosure",
	"timestamp-disclosure", "cache-control", "mixed-content", "autocomplete",
	"cross-domain-javascript", "cross-domain-script",
	"tls-version", "deprecated-tls", "weak-cipher", "ssl-certificate",
	"self-signed", "private-ip-disclosure", "internal-ip", "viewstate",
}

// boringPaths: standard files (not vulnerabilities). They push a NEUTRAL
// exposed-path down to noise so real endpoints rank above static files.
var boringPaths = []string{
	"robots.txt", "sitemap", "favicon", ".well-known", "security.txt",
	"humans.txt", "healthz", "health", "manifest.json", "service-worker",
	"crossdomain.xml", "ads.txt",
}

const (
	ffufFloodThreshold = 8   // >=N ffuf exposed-paths per host → likely soft-404/wildcard
	ffufFloodFP        = 0.6 // minimum fp_likelihood forced during a flood
)

// spaMarkers: SPA shell markers. When one appears in the body, a large ffuf
// response is probably the app shell (soft-200) and not a real path.
var spaMarkers = []string{
	`<div id="root"`, `<div id="app"`, "<app-root", "ng-version", "data-reactroot",
	"window.__", "__next_data__", "__nuxt__", "__initial_state__",
	"data-v-", "data-svelte", "webpackjsonp", "/_next/static",
}

var dropStatus = map[finding.Status]bool{
	finding.StatusDuplicate:     true,
	finding.StatusFalsePositive: true,
	finding.StatusIgnored:       true,
}

// ---- Results ----

// Factor is one criterion's contribution to the final score (for the UI explanation).
type Factor struct {
	Name         string
	Label        string
	Contribution float64
}

var critLabel = map[string]string{
	"exploitability": "Exploitability", "signal": "Payout signal", "bounty": "Bounty",
	"severity": "Severity", "fp_likelihood": "FP risk", "effort": "Effort",
	"owasp": "OWASP", "freshness": "Freshness",
}

// Scored is one finding with its SAW score and per-criterion breakdown.
type Scored struct {
	Finding   *finding.Finding
	Rank      int
	Score     float64
	Breakdown map[string]float64 // w·r contribution per criterion
	Raw       map[string]float64 // raw value per criterion (before normalization)
}

// Pct returns the score as a whole percentage (0..100) for the width of the visual bar.
func (s Scored) Pct() int { return int(math.Round(s.Score * 100)) }

// TopFactors returns up to n criteria that push the score up the most (desc),
// to explain "why is this on top". Cost criteria (fp/effort) are not counted
// as positive drivers.
func (s Scored) TopFactors(n int) []Factor {
	out := make([]Factor, 0, len(s.Breakdown))
	for _, c := range crits {
		if critType[c] == "cost" {
			continue
		}
		out = append(out, Factor{Name: c, Label: critLabel[c], Contribution: s.Breakdown[c]})
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].Contribution > out[b].Contribution })
	if n < len(out) {
		out = out[:n]
	}
	return out
}

// Rank returns the findings ranked by SAW/SPK score (desc), after the
// prefilter (drop duplicate/FP/ignored statuses and info severity, then keep
// one representative per cluster = the highest severity). It matches the MCP
// `rank` tool at its defaults (no scope CSV): `bounty` uses the finding's
// severity as a proxy.
func Rank(findings []*finding.Finding) []Scored {
	kept := prefilter(findings)
	if len(kept) == 0 {
		return nil
	}
	fresh := freshnessMap(kept)
	flood := ffufFloodHosts(kept)

	rows := make([]map[string]float64, len(kept))
	for i, f := range kept {
		fp := fpLikelihood(f)
		if f.Status != finding.StatusConfirmed && f.SourceEngine == "ffuf" && flood[host(f.Location.URL)] {
			fp = math.Max(fp, ffufFloodFP) // prior soft-404/wildcard
		}
		p := pathOf(f.Location.URL)
		sig := signal(signalText(f), p)
		if sig == 0.5 && isBoringPath(p) {
			sig = 0.1 // a boring path (robots/sitemap/.well-known) drops to noise
		}
		sev := float64(sevNumOf(f.Severity))
		rows[i] = map[string]float64{
			"exploitability": exploitability(f),
			"signal":         sig,
			"bounty":         sev, // no scope CSV: proxy = severity (same as the MCP default)
			"severity":       sev,
			"fp_likelihood":  fp,
			"effort":         float64(effortOf(firstNonEmpty(f.Type, f.Title))),
			"owasp":          float64(owaspPriorityOf(f.OWASP)),
			"freshness":      float64(fresh[f.ID]),
		}
	}

	// Normalize per column (batch-relative), then take the weighted sum.
	norm := make(map[string][]float64, len(crits))
	for _, c := range crits {
		col := make([]float64, len(rows))
		for i := range rows {
			col[i] = rows[i][c]
		}
		norm[c] = normalize(col, critType[c])
	}

	scored := make([]Scored, len(kept))
	for i, f := range kept {
		breakdown := make(map[string]float64, len(crits))
		raw := make(map[string]float64, len(crits))
		total := 0.0
		for _, c := range crits {
			contrib := weights[c] * norm[c][i]
			total += contrib
			breakdown[c] = round4(contrib)
			raw[c] = rows[i][c]
		}
		scored[i] = Scored{Finding: f, Score: round6(total), Breakdown: breakdown, Raw: raw}
	}
	sort.SliceStable(scored, func(a, b int) bool { return scored[a].Score > scored[b].Score })
	for i := range scored {
		scored[i].Rank = i + 1
	}
	return scored
}

// ---- Prefilter + clusters ----

func clusterKey(f *finding.Finding) string {
	if f.DedupKey != "" {
		return f.DedupKey
	}
	return host(f.Location.URL) + "|" + f.Type + "|" + f.Location.Parameter
}

// prefilter drops duplicate/FP/ignored statuses and info severity, then picks
// one representative per cluster (the highest severity). Representatives keep
// the order in which their clusters first appear (stable), like
// analyst.prefilter.
func prefilter(findings []*finding.Finding) []*finding.Finding {
	rep := make(map[string]*finding.Finding)
	var order []string
	for _, f := range findings {
		if dropStatus[f.Status] || f.Severity == finding.SeverityInfo {
			continue
		}
		k := clusterKey(f)
		cur, ok := rep[k]
		if !ok {
			rep[k] = f
			order = append(order, k)
			continue
		}
		if sevNumOf(f.Severity) > sevNumOf(cur.Severity) {
			rep[k] = f
		}
	}
	out := make([]*finding.Finding, 0, len(order))
	for _, k := range order {
		out = append(out, rep[k])
	}
	return out
}

// ---- Derived metrics ----

func signalText(f *finding.Finding) string {
	parts := make([]string, 0, 2+len(f.Tags))
	if f.Type != "" {
		parts = append(parts, f.Type)
	}
	if f.Title != "" {
		parts = append(parts, f.Title)
	}
	for _, t := range f.Tags {
		if t != "" {
			parts = append(parts, t)
		}
	}
	return strings.Join(parts, " ")
}

func looksLikeSPA(f *finding.Finding) bool {
	if f.Evidence == nil {
		return false
	}
	body := strings.ToLower(f.Evidence.ResponseExcerpt)
	for _, m := range spaMarkers {
		if strings.Contains(body, m) {
			return true
		}
	}
	return false
}

func fpLikelihood(f *finding.Finding) float64 {
	switch {
	case f.Status == finding.StatusConfirmed:
		return 0.0
	case f.Confidence == finding.ConfidenceHigh && (f.SourceEngine == "nuclei-dast" || f.SourceEngine == "dalfox"):
		return 0.1
	case f.SourceEngine == "ffuf" && looksLikeSPA(f):
		return 0.7
	case (f.SourceEngine == "retire" || f.SourceEngine == "zap-passive") && f.Confidence == finding.ConfidenceLow:
		return 0.5
	default:
		return 0.3
	}
}

func exploitability(f *finding.Finding) float64 {
	return float64(confNumOf(f.Confidence)) * engineF(f.SourceEngine)
}

func ffufFloodHosts(findings []*finding.Finding) map[string]bool {
	count := make(map[string]int)
	for _, f := range findings {
		if f.SourceEngine == "ffuf" && strings.Contains(strings.ToLower(f.Type), "exposed") {
			count[host(f.Location.URL)]++
		}
	}
	out := make(map[string]bool)
	for h, n := range count {
		if n >= ffufFloodThreshold {
			out[h] = true
		}
	}
	return out
}

// freshnessMap: freshness relative to the NEWEST finding in the batch (not the
// current time), so the ranking of an old export stays stable. ≤1h 5 / ≤7h 4 /
// ≤30h 3 / else 2.
func freshnessMap(findings []*finding.Finding) map[string]int {
	var newest time.Time
	any := false
	for _, f := range findings {
		t := f.CreatedAt.Time
		if t.IsZero() {
			continue
		}
		if !any || t.After(newest) {
			newest = t
			any = true
		}
	}
	out := make(map[string]int, len(findings))
	for _, f := range findings {
		t := f.CreatedAt.Time
		if !any || t.IsZero() {
			out[f.ID] = 3 // neutral when no time can be read
			continue
		}
		gapDays := newest.Sub(t).Hours() / 24.0
		out[f.ID] = freshnessBucket(gapDays)
	}
	return out
}

func freshnessBucket(gapDays float64) int {
	switch {
	case gapDays <= 1:
		return 5
	case gapDays <= 7:
		return 4
	case gapDays <= 30:
		return 3
	default:
		return 2
	}
}

// ---- Plain SAW ----

// normalize: benefit r=x/max ; cost r=min/x (0 cost = ideal → r=1).
func normalize(vals []float64, ctype string) []float64 {
	out := make([]float64, len(vals))
	if len(vals) == 0 {
		return out
	}
	if ctype == "cost" {
		mn := 0.0
		for _, v := range vals {
			if v > 0 && (mn == 0 || v < mn) {
				mn = v
			}
		}
		for i, v := range vals {
			switch {
			case v <= 0:
				out[i] = 1.0
			case mn > 0:
				out[i] = mn / v
			default:
				out[i] = 1.0
			}
		}
		return out
	}
	mx := 0.0
	for _, v := range vals {
		if v > mx {
			mx = v
		}
	}
	for i, v := range vals {
		if mx > 0 {
			out[i] = v / mx
		}
	}
	return out
}

// ---- Small helpers ----

func signal(text, extra string) float64 {
	t := strings.ToLower(text)
	if anyTokenMatch(t, signalNoise) { // noise is checked FIRST (the 'x-xss-protection' header must not go high through 'xss')
		return 0.1
	}
	if anyTokenMatch(t+" "+strings.ToLower(extra), signalHigh) { // the path (extra) may only PROMOTE
		return 1.0
	}
	return 0.5
}

func isBoringPath(p string) bool {
	return p != "" && anyTokenMatch(strings.ToLower(p), boringPaths)
}

// anyTokenMatch: true when ANY pattern appears at a token BOUNDARY in text (the
// characters before and after are not [a-z0-9]). It replaces the Python regex
// lookarounds `(?<![a-z0-9])…(?![a-z0-9])`, which RE2 does not support; this
// per-pattern scan has the same existential semantics (and none of the
// alternation backtracking confusion). text and patterns are assumed lowercase.
func anyTokenMatch(text string, patterns []string) bool {
	for _, p := range patterns {
		for from := 0; ; {
			i := strings.Index(text[from:], p)
			if i < 0 {
				break
			}
			lo := from + i
			hi := lo + len(p)
			if (lo == 0 || !isAlnum(text[lo-1])) && (hi == len(text) || !isAlnum(text[hi])) {
				return true
			}
			from = lo + 1
		}
	}
	return false
}

func isAlnum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

var schemeRe = regexp.MustCompile(`^[a-zA-Z][\w+.\-]*://`)

// host: the host(+port) of a URL, without scheme/path/query (for clusters and flood detection).
func host(u string) string {
	u = schemeRe.ReplaceAllString(u, "")
	if i := strings.IndexByte(u, '/'); i >= 0 {
		u = u[:i]
	}
	if i := strings.IndexByte(u, '?'); i >= 0 {
		u = u[:i]
	}
	return u
}

// pathOf: the path+file of a URL (without scheme/host/query/fragment), lowercase.
func pathOf(u string) string {
	u = schemeRe.ReplaceAllString(u, "")
	slash := strings.IndexByte(u, '/')
	if slash < 0 {
		return ""
	}
	p := u[slash:]
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	if i := strings.IndexByte(p, '#'); i >= 0 {
		p = p[:i]
	}
	return strings.ToLower(p)
}

func engineF(engine string) float64 {
	if v, ok := engineFactor[engine]; ok {
		return v
	}
	return engineFactorDefault
}

func confNumOf(c finding.Confidence) int {
	if v, ok := confNum[c]; ok {
		return v
	}
	return 1
}

func sevNumOf(s finding.Severity) int {
	if v, ok := sevNum[s]; ok {
		return v
	}
	return 1
}

func owaspPriorityOf(o finding.OWASP) int {
	if v, ok := owaspPriority[o]; ok {
		return v
	}
	return owaspPriorityDefault
}

func effortOf(ftype string) int {
	t := strings.ToLower(ftype)
	for _, e := range effortByType {
		if strings.Contains(t, e.key) {
			return e.val
		}
	}
	return effortDefault
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func round6(v float64) float64 { return math.Round(v*1e6) / 1e6 }
func round4(v float64) float64 { return math.Round(v*1e4) / 1e4 }
