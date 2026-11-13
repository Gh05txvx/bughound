// Package triage menyusun peringkat "prioritas verifikasi" temuan memakai
// Simple Additive Weighting (SAW/SPK) — deterministik, tanpa LLM.
//
// Ini port SETIA dari algoritma SPK app Analyst (bughound/analyst, modul
// saw.py + analyst.py + config.py) ke Go, supaya web UI bisa menampilkan
// peringkat yang SAMA dengan tool MCP `rank` tanpa menautkan runtime Python
// ke aplikasi. Konstanta (bobot, engine factor, pola sinyal, heuristik) dijaga
// identik dengan default di analyst/bughound_analyst/config.py: bila satu sisi
// di-tune, sisi lain WAJIB diselaraskan (uji di triage_test.go mengunci nilai).
//
// Paket ini murni baca: ia tak menyentuh target, tak mengubah store, tak
// memanggil jaringan — hanya menghitung skor atas temuan yang sudah ada.
package triage

import (
	"math"
	"regexp"
	"sort"
	"strings"
	"time"

	"bughound/internal/finding"
)

// ---- Konstanta SPK (mirror analyst/bughound_analyst/config.py _DEFAULTS) ----

// crits: urutan tetap (= insertion order weights di config.py) agar normalisasi
// dan iterasi deterministik.
var crits = []string{
	"exploitability", "signal", "bounty", "severity",
	"fp_likelihood", "effort", "owasp", "freshness",
}

var weights = map[string]float64{
	"exploitability": 0.26, "signal": 0.22, "bounty": 0.16, "severity": 0.12,
	"fp_likelihood": 0.12, "effort": 0.06, "owasp": 0.04, "freshness": 0.02,
}

// critType: "benefit" (makin besar makin baik) atau "cost" (makin kecil makin baik).
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

// effortByType: substring match pada type (fallback title), lowercase; urutan
// diperiksa seperti config.py (first match wins — mis. "blind-sqli" → sqli=2
// karena "sqli" lebih dulu dari "blind").
var effortByType = []struct {
	key string
	val int
}{
	{"reflected", 1}, {"xss", 1}, {"sqli", 2}, {"injection", 2}, {"idor", 2},
	{"access", 2}, {"blind", 3}, {"second-order", 3}, {"ssrf", 3},
}

const effortDefault = 2

// Sinyal payout (lever anti "header noise"): high→1.0 (eksploitatif/berbayar),
// noise→0.1 (hygiene/header, nyaris won't-pay), selain itu 0.5.
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

// boringPaths: file standar (bukan kerentanan) — menurunkan exposed-path NETRAL
// ke noise agar endpoint nyata naik di atas file statis.
var boringPaths = []string{
	"robots.txt", "sitemap", "favicon", ".well-known", "security.txt",
	"humans.txt", "healthz", "health", "manifest.json", "service-worker",
	"crossdomain.xml", "ads.txt",
}

const (
	ffufFloodThreshold = 8   // >=N exposed-path ffuf per host → kemungkinan soft-404/wildcard
	ffufFloodFP        = 0.6 // fp_likelihood minimal yang dipaksakan saat flood
)

// spaMarkers: penanda shell SPA — bila muncul di body, respons ffuf besar
// kemungkinan app-shell (soft-200), bukan path nyata.
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

// ---- Hasil ----

// Factor adalah kontribusi satu kriteria ke skor akhir (untuk penjelasan UI).
type Factor struct {
	Name         string
	Label        string
	Contribution float64
}

var critLabel = map[string]string{
	"exploitability": "Exploitability", "signal": "Sinyal payout", "bounty": "Bounty",
	"severity": "Severity", "fp_likelihood": "Risiko FP", "effort": "Usaha",
	"owasp": "OWASP", "freshness": "Kebaruan",
}

// Scored adalah satu temuan dengan skor SAW dan rincian kriteria.
type Scored struct {
	Finding   *finding.Finding
	Rank      int
	Score     float64
	Breakdown map[string]float64 // kontribusi w·r per kriteria
	Raw       map[string]float64 // nilai mentah per kriteria (sebelum normalisasi)
}

// Pct mengembalikan skor sebagai persen bulat (0..100) untuk lebar bar visual.
func (s Scored) Pct() int { return int(math.Round(s.Score * 100)) }

// TopFactors mengembalikan hingga n kriteria pendorong skor terbesar (desc),
// untuk menjelaskan "kenapa ini di atas". Kriteria cost (fp/effort) tak
// dimasukkan sebagai pendorong positif.
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

// Rank mengembalikan temuan ter-ranking (skor desc) hasil SAW/SPK, setelah
// prefilter (buang status duplikat/FP/ignored + severity info, lalu satu wakil
// per klaster = severity tertinggi). Setara tool MCP `rank` pada default (tanpa
// scope CSV): `bounty` memakai severity temuan sebagai proxy.
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
			sig = 0.1 // path membosankan (robots/sitemap/.well-known) turun ke noise
		}
		sev := float64(sevNumOf(f.Severity))
		rows[i] = map[string]float64{
			"exploitability": exploitability(f),
			"signal":         sig,
			"bounty":         sev, // tanpa scope CSV: proxy = severity (sama dgn MCP default)
			"severity":       sev,
			"fp_likelihood":  fp,
			"effort":         float64(effortOf(firstNonEmpty(f.Type, f.Title))),
			"owasp":          float64(owaspPriorityOf(f.OWASP)),
			"freshness":      float64(fresh[f.ID]),
		}
	}

	// Normalisasi per kolom (batch-relative), lalu jumlah berbobot.
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

// ---- Prefilter + klaster ----

func clusterKey(f *finding.Finding) string {
	if f.DedupKey != "" {
		return f.DedupKey
	}
	return host(f.Location.URL) + "|" + f.Type + "|" + f.Location.Parameter
}

// prefilter membuang status duplikat/FP/ignored + severity info, lalu memilih
// satu wakil per klaster (severity tertinggi). Urutan wakil = urutan kemunculan
// klaster (stabil), sama seperti analyst.prefilter.
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

// ---- Metrik turunan ----

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

// freshnessMap: kebaruan relatif ke temuan TERBARU di batch (bukan jam
// sekarang) → ranking ekspor lama tetap stabil. ≤1h 5 / ≤7h 4 / ≤30h 3 / else 2.
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
			out[f.ID] = 3 // netral bila tak ada waktu terbaca
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

// ---- SAW murni ----

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

// ---- Helper kecil ----

func signal(text, extra string) float64 {
	t := strings.ToLower(text)
	if anyTokenMatch(t, signalNoise) { // noise dicek DULU (header 'x-xss-protection' tak ter-high via 'xss')
		return 0.1
	}
	if anyTokenMatch(t+" "+strings.ToLower(extra), signalHigh) { // path (extra) hanya boleh MEMPROMOSIKAN
		return 1.0
	}
	return 0.5
}

func isBoringPath(p string) bool {
	return p != "" && anyTokenMatch(strings.ToLower(p), boringPaths)
}

// anyTokenMatch: true bila ADA pola yang muncul pada BATAS token di text
// (char sebelum & sesudah bukan [a-z0-9]). Menggantikan lookaround regex Python
// `(?<![a-z0-9])…(?![a-z0-9])` yang tak didukung RE2 — scan per-pola ini setara
// semantik eksistensialnya (dan tanpa kebingungan backtracking alternasi).
// text & patterns diasumsikan lowercase.
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

// host: host(+port) dari URL, tanpa skema/path/query (untuk klaster & flood).
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

// pathOf: path+file dari URL (tanpa skema/host/query/fragment), lowercase.
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
