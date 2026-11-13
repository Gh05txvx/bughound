// Package aiassist menghasilkan analisis what-if (rencana validasi manual) untuk
// sebuah temuan dengan memanggil Claude API (Anthropic Messages API).
//
// Sifat penting (sejalan dengan prinsip mengikat BugHound):
//   - EGRESS TERKENDALI. Satu-satunya tujuan jaringan paket ini adalah endpoint
//     kontrol-plane Anthropic yang di-hardcode (api.anthropic.com). Ia TIDAK lewat
//     scope guard/proxy egress scan — ini bukan target scan — dan tak bisa diarahkan
//     ke host lain. Memakai net/http langsung (klien terkontrol, tanpa dependensi
//     pihak ketiga baru di tool ofensif) alih-alih SDK.
//   - EVIDENCE DISCRUB DULU. Semua potongan request/response discrub (header
//     sensitif, bearer, api-key, email, param rahasia) + dipangkas SEBELUM dikirim,
//     meniru analyst/bughound_analyst/scrub.py (BH-DESIGN §6).
//   - ADVISORY. Hasil = saran uji NON-DESTRUKTIF yang dijalankan hunter SENDIRI di
//     Burp. App tak pernah mengeksekusi; tak ada auto-submit.
//
// API key TIDAK disimpan di struct ini; dipasok per-panggilan (di-reveal dari
// vault terenkripsi tepat saat dibutuhkan) agar masa hidupnya sependek mungkin.
package aiassist

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// defaultEndpoint adalah endpoint Messages API Anthropic (di-hardcode; egress
// kontrol-plane, bukan target scan).
const defaultEndpoint = "https://api.anthropic.com/v1/messages"

// anthropicVersion adalah header versi API stabil.
const anthropicVersion = "2023-06-01"

// Hypothesis adalah satu uji konkret siap-Repeater yang disarankan LLM.
type Hypothesis struct {
	Mutation string `json:"mutation"` // perubahan request spesifik
	Expected string `json:"expected"` // sinyal yang diharapkan
	Confirms string `json:"confirms"` // apa yang dibuktikan bila sinyal muncul
}

// Analysis adalah bagian what-if yang DITALAR LLM (di-cache sebagai JSON). Bagian
// deterministik (target, seed hint, safety) dibangun di layer web, tak di sini.
type Analysis struct {
	Why        string       `json:"why"`
	Decision   string       `json:"decision"` // verify_now | likely_fp | needs_more_info
	Hypotheses []Hypothesis `json:"hypotheses"`
	Notes      string       `json:"notes,omitempty"`
	Model      string       `json:"model,omitempty"`
}

// Input adalah konteks SATU temuan (field evidence masih mentah; discrub di sini).
type Input struct {
	Type          string
	Title         string
	Severity      string
	Confidence    string
	OWASP         string
	SourceEngine  string
	URL           string
	Method        string
	Parameter     string
	ParamLocation string
	Payload       string
	Matched       string
	Request       string
	Response      string
	SeedHints     []string
}

// Client memanggil Claude API. HTTP boleh di-override untuk test (tanpa jaringan).
type Client struct {
	HTTP     *http.Client
	Model    string
	Endpoint string
}

// NewClient membuat klien dengan timeout wajar untuk satu panggilan analisis.
func NewClient(model string) *Client {
	return &Client{
		HTTP:     &http.Client{Timeout: 60 * time.Second},
		Model:    model,
		Endpoint: defaultEndpoint,
	}
}

// ---- Scrub (port setia scrub.py) ----

const redacted = "[REDACTED]"

var (
	reHeader = regexp.MustCompile(`(?im)^(authorization|cookie|set-cookie|x-api-key|x-auth-token|proxy-authorization)\s*:.*$`)
	reBearer = regexp.MustCompile(`(?i)bearer\s+[a-z0-9._\-]+`)
	reEmail  = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	reParam  = regexp.MustCompile(`(?i)\b(token|password|passwd|secret|access_token|api_key|apikey)=[^&\s"']+`)
)

// ScrubText membuang kredensial & PII dari s lalu memangkas ke limit byte.
func ScrubText(s string, limit int) string {
	if s == "" {
		return ""
	}
	s = reHeader.ReplaceAllStringFunc(s, func(m string) string {
		if name, _, found := strings.Cut(m, ":"); found {
			return name + ": " + redacted
		}
		return redacted
	})
	s = reBearer.ReplaceAllString(s, "Bearer "+redacted)
	s = reParam.ReplaceAllStringFunc(s, func(m string) string {
		if name, _, found := strings.Cut(m, "="); found {
			return name + "=" + redacted
		}
		return redacted
	})
	s = reEmail.ReplaceAllString(s, redacted)
	if len(s) > limit {
		s = s[:limit] + "\n…[dipangkas]"
	}
	return s
}

// ---- Seed hints (port _SEED_HINTS/whatif.py) ----

var seedHints = []struct {
	key   string
	hints []string
}{
	{"sqli", []string{"boolean: `' OR 1=1--`", "time-based: `1;WAITFOR DELAY '0:0:5'--` (ringan, non-destruktif)"}},
	{"injection", []string{"boolean/true-vs-false", "time-based delay ringan"}},
	{"xss", []string{"context-break reflektif: `\"><svg onload=…>`", "cek konteks atribut vs HTML vs JS"}},
	{"idor", []string{"naik/turunkan id objek", "tukar ke objek milik akun lain (baca-saja)"}},
	{"ssrf", []string{"arahkan host ke callback terkendali (OAST) — HATI-HATI RoE", "cek 169.254.169.254 hanya bila eksplisit diizinkan"}},
	{"access", []string{"akses endpoint tanpa sesi / sesi peran lebih rendah (baca-saja)"}},
}

// SeedHintsFor mengembalikan benih hint deterministik untuk kelas bug temuan.
func SeedHintsFor(typ, title string) []string {
	t := strings.ToLower(typ)
	if t == "" {
		t = strings.ToLower(title)
	}
	for _, sh := range seedHints {
		if strings.Contains(t, sh.key) {
			return sh.hints
		}
	}
	return nil
}

// ---- Prompt ----

const systemPrompt = `Kamu asisten validasi untuk hunter bug bounty. Diberi SATU temuan DAST (evidence sudah discrub), tugasmu menilai apakah temuan ini layak diverifikasi manual dan menyusun rencana uji NON-DESTRUKTIF yang akan dijalankan hunter SENDIRI di Burp Repeater.

Aturan keras:
- Hanya uji non-destruktif & reversible (boolean true/false, time-based ringan, ubah satu parameter, baca objek). DILARANG menyarankan: DoS, perubahan/penghapusan data, exploit destruktif, enumerasi masif, atau aksi yang mengubah state otorisasi.
- Hormati Rules of Engagement program & rate limit. Kamu TIDAK mengeksekusi apa pun — hanya menyarankan; hunter yang menjalankan manual.
- Jangan menyarankan menyentuh aset di luar scope/pihak ketiga (mis. SSRF ke metadata cloud) kecuali sebagai catatan hati-hati ber-RoE.
- Jangan mengarang bukti. Bila evidence tak cukup untuk menyimpulkan, katakan dan set decision "needs_more_info".

Jawab HANYA dengan satu objek JSON valid, tanpa teks lain dan tanpa code fence:
{"why":"...","decision":"verify_now|likely_fp|needs_more_info","hypotheses":[{"mutation":"...","expected":"...","confirms":"..."}],"notes":"..."}
- why: 1-3 kalimat kenapa ini berpotensi (atau kenapa mungkin false positive).
- hypotheses: 1-4 uji konkret siap-Repeater. mutation=perubahan request spesifik; expected=sinyal yang diharapkan; confirms=apa yang terbukti bila sinyal muncul.
- notes: opsional (boleh string kosong).`

// RenderContext membangun pesan user (konteks temuan terscrub). Dieskpos agar web
// bisa menghitung fingerprint cache yang deterministik.
func RenderContext(in Input) string {
	var b strings.Builder
	b.WriteString("Temuan:\n")
	fmt.Fprintf(&b, "- type: %s\n", in.Type)
	fmt.Fprintf(&b, "- judul: %s\n", in.Title)
	fmt.Fprintf(&b, "- severity: %s · confidence: %s · owasp: %s\n", in.Severity, in.Confidence, orDash(in.OWASP))
	fmt.Fprintf(&b, "- engine: %s\n", in.SourceEngine)
	fmt.Fprintf(&b, "- target: %s %s\n", orDash(in.Method), in.URL)
	if in.Parameter != "" {
		fmt.Fprintf(&b, "- parameter: %s (%s)\n", in.Parameter, orDash(in.ParamLocation))
	}
	b.WriteString("\nEvidence (discrub):\n")
	writeEv(&b, "payload", ScrubText(in.Payload, 256))
	writeEv(&b, "matched", ScrubText(in.Matched, 256))
	writeEv(&b, "request (potongan)", ScrubText(in.Request, 1024))
	writeEv(&b, "response (potongan)", ScrubText(in.Response, 512))
	if len(in.SeedHints) > 0 {
		fmt.Fprintf(&b, "\nBenih hint (deterministik; sesuaikan ke konteks atau tolak bila tak cocok): %s\n", strings.Join(in.SeedHints, "; "))
	}
	return b.String()
}

func writeEv(b *strings.Builder, label, val string) {
	if strings.TrimSpace(val) == "" {
		return
	}
	fmt.Fprintf(b, "- %s: %s\n", label, val)
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

// Fingerprint adalah hash stabil atas konteks terscrub — kunci validitas cache.
func Fingerprint(in Input) string {
	sum := sha256.Sum256([]byte(RenderContext(in)))
	return hex.EncodeToString(sum[:])
}

// ---- Panggilan API ----

type apiMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type apiReq struct {
	Model     string   `json:"model"`
	MaxTokens int      `json:"max_tokens"`
	System    string   `json:"system,omitempty"`
	Messages  []apiMsg `json:"messages"`
}

type apiResp struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	StopReason string `json:"stop_reason"`
	Error      *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// Analyze memanggil Claude dengan konteks temuan terscrub dan mengembalikan
// analisis terstruktur. apiKey dipasok per-panggilan dan TIDAK disimpan/di-log.
func (c *Client) Analyze(ctx context.Context, apiKey string, in Input) (Analysis, error) {
	if strings.TrimSpace(apiKey) == "" {
		return Analysis{}, fmt.Errorf("aiassist: API key kosong")
	}
	reqBody, err := json.Marshal(apiReq{
		Model:     c.Model,
		MaxTokens: 3000,
		System:    systemPrompt,
		Messages:  []apiMsg{{Role: "user", Content: RenderContext(in)}},
	})
	if err != nil {
		return Analysis{}, fmt.Errorf("aiassist: encode: %w", err)
	}
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = defaultEndpoint
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return Analysis{}, fmt.Errorf("aiassist: request: %w", err)
	}
	httpReq.Header.Set("content-type", "application/json")
	httpReq.Header.Set("x-api-key", apiKey)
	httpReq.Header.Set("anthropic-version", anthropicVersion)

	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return Analysis{}, fmt.Errorf("aiassist: koneksi Claude API gagal")
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	var ar apiResp
	_ = json.Unmarshal(raw, &ar)

	if resp.StatusCode != http.StatusOK {
		// Jangan bocorkan request/key; ringkas tipe galat saja.
		if ar.Error != nil && ar.Error.Type != "" {
			return Analysis{}, fmt.Errorf("aiassist: Claude API menolak (%s)", sanitize(ar.Error.Type))
		}
		return Analysis{}, fmt.Errorf("aiassist: Claude API status %d", resp.StatusCode)
	}
	if ar.StopReason == "refusal" {
		return Analysis{}, fmt.Errorf("aiassist: Claude menolak menganalisis (safety)")
	}

	var text strings.Builder
	for _, blk := range ar.Content {
		if blk.Type == "text" {
			text.WriteString(blk.Text)
		}
	}
	an, err := parseAnalysis(text.String())
	if err != nil {
		return Analysis{}, err
	}
	an.Model = c.Model
	return an, nil
}

// parseAnalysis mengekstrak objek JSON dari teks balasan (toleran terhadap fence
// atau prosa pembungkus) lalu memvalidasi decision.
func parseAnalysis(text string) (Analysis, error) {
	s := strings.TrimSpace(text)
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	// Ambil dari '{' pertama sampai '}' terakhir (buang prosa pembungkus).
	if i := strings.IndexByte(s, '{'); i >= 0 {
		if j := strings.LastIndexByte(s, '}'); j >= i {
			s = s[i : j+1]
		}
	}
	var an Analysis
	if err := json.Unmarshal([]byte(strings.TrimSpace(s)), &an); err != nil {
		return Analysis{}, fmt.Errorf("aiassist: respons AI tak bisa diparse")
	}
	switch an.Decision {
	case "verify_now", "likely_fp", "needs_more_info":
	default:
		an.Decision = "needs_more_info"
	}
	return an, nil
}

// sanitize memangkas token galat ke karakter aman (anti-injeksi ke UI/log).
func sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '_' || r == '-' || r == ' ' {
			return r
		}
		return -1
	}, s)
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}
