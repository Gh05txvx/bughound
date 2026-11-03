package nuclei

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"bughound/internal/egress"
	"bughound/internal/finding"
)

// DASTRunner adalah engine DAST AKTIF berbasis nuclei fuzzing (-dast): ia
// MENGIRIM payload (SQLi/XSS/SSTI/dst.) ke parameter yang ditemukan pada target,
// bukan sekadar mencocokkan pola pasif. Karena agresif, jalankan HANYA pada
// target yang sah (lab/in-scope/izin eksplisit) — tak pernah di dev/test
// sembarangan (lihat CLAUDE.md).
//
// Alur: crawl target dgn katana (lewat proxy egress) → kumpulkan URL same-host
// (yang berparameter diprioritaskan sbg titik fuzz) → `nuclei -dast -list` atas
// URL itu (lewat proxy egress yang SAMA) → normalkan lewat Parse (output JSONL
// nuclei DAST = format yang sama dgn nuclei pasif, jadi parser tak berubah).
//
// Bila diberi spec OpenAPI/Swagger (UseOpenAPISpec), run juga melakukan pass
// `nuclei -dast -input-mode openapi/swagger` SEKALI atas spec itu: membangkitkan
// request lengkap termasuk BODY (mis. POST/PUT JSON), bukan hanya query — titik
// injeksi yang tak tertangkap crawl URL. Pass ini tetap lewat proxy egress yang
// sama & temuannya digabung.
//
// Keamanan (area sensitif): SEMUA request (crawl + fuzz) lewat proxy egress
// scope-enforced; tiap request diperiksa scope guard sebelum dibuka (payload
// mengubah NILAI parameter, host tetap in-scope; OAST/blind ke pihak-3 diblok
// proxy). Volume dibatasi: rate limiter orchestrator + `-rate-limit` nuclei +
// `-fuzz-aggression low` + cap URL. Fail-safe: tanpa proxy = tak ada koneksi.
//
// Profil keamanan (Safety): non-destruktif SELALU aktif (tak kirim payload DoS,
// tanpa callback blind/OAST — lihat safety.go) agar scan mencari kandidat bug
// tanpa merusak/mengubah konfigurasi target; mode stealth (opsional) membuat
// crawl+fuzz low-and-slow untuk jejak minimal pada target ber-SOC.
type DASTRunner struct {
	Binary     string // default "nuclei"
	Katana     string // default "katana"
	RateLimit  int    // -rate-limit (req/dtk) utk crawl & fuzz
	Aggression string // -fuzz-aggression (low|medium|high); default "low"
	Safety     Safety // profil keamanan: non-destruktif (selalu) + stealth (opsional)
	proxyAddr  string

	specBytes []byte // spec OpenAPI/Swagger (opsional) utk fuzz body — lihat UseOpenAPISpec
	specDone  bool   // penanda: pass OpenAPI sudah dijalankan sekali utk run ini
}

// UseOpenAPISpec memenuhi engine.OpenAPIAware: menyetel spec yang akan difuzz
// via `nuclei -im openapi/swagger` (sekali per run), membangkitkan request
// lengkap termasuk BODY. Instance DASTRunner dibuat baru per run, jadi pass ini
// berjalan sekali pada pemanggilan Scan pertama.
func (r *DASTRunner) UseOpenAPISpec(spec []byte) { r.specBytes = spec }

// Name memenuhi engine.Engine.
func (r *DASTRunner) Name() string { return "nuclei-dast" }

// UseProxy memenuhi engine.ProxyAware: crawl + fuzz diarahkan ke proxy egress.
func (r *DASTRunner) UseProxy(addr string) { r.proxyAddr = addr }

const maxDASTURLs = 150 // batas URL yang difuzz per target (volume request terkendali)

// Scan memenuhi engine.Engine.
func (r *DASTRunner) Scan(ctx context.Context, target, program, runID string) ([]*finding.Finding, error) {
	// Fail-safe: tanpa proxy egress, JANGAN buat koneksi apa pun (selaras prinsip
	// "tidak pernah memicu koneksi yang memintas scope guard").
	if r.proxyAddr == "" {
		return nil, nil
	}

	// Pass OpenAPI (sekali per run): fuzz request lengkap termasuk body dari spec.
	// Best-effort — kegagalan di sini tak membatalkan fuzz berbasis URL di bawah.
	var extra []*finding.Finding
	if len(r.specBytes) > 0 && !r.specDone {
		r.specDone = true
		extra = r.fuzzOpenAPI(ctx, program, runID)
	}

	// 1) Perluas target → daftar URL (crawl best-effort; target selalu disertakan).
	urls := r.gatherURLs(ctx, target)

	// 2) Tulis daftar URL ke berkas sementara utk `nuclei -list`.
	listFile, cleanup, err := writeList(urls)
	if err != nil {
		return nil, fmt.Errorf("nuclei-dast: berkas daftar: %w", err)
	}
	defer cleanup()

	// 3) Jalankan nuclei -dast atas daftar (lewat proxy egress).
	bin := r.Binary
	if bin == "" {
		bin = "nuclei"
	}
	cmd := exec.CommandContext(ctx, bin, r.nucleiArgs(listFile)...)
	cmd.Env = egress.ProxyEnv(os.Environ(), "http://"+r.proxyAddr) // belt-and-suspenders
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("nuclei-dast: eksekusi gagal: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}
	fromList, err := Parse(&stdout, program, runID)
	if err != nil {
		return nil, err
	}
	return append(extra, fromList...), nil
}

// fuzzOpenAPI menjalankan `nuclei -dast -im openapi/swagger` atas spec yang
// disetel lewat UseOpenAPISpec — membangkitkan request lengkap (method + BODY)
// untuk difuzz, melengkapi fuzz berbasis URL yang hanya menyentuh query. Semua
// request tetap lewat proxy egress scope-enforced. Best-effort: gagal = nil.
func (r *DASTRunner) fuzzOpenAPI(ctx context.Context, program, runID string) []*finding.Finding {
	f, err := os.CreateTemp("", "nuclei-openapi-*.yaml")
	if err != nil {
		return nil
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err := f.Write(r.specBytes); err != nil {
		_ = f.Close()
		return nil
	}
	if err := f.Close(); err != nil {
		return nil
	}

	bin := r.Binary
	if bin == "" {
		bin = "nuclei"
	}
	cmd := exec.CommandContext(ctx, bin, r.nucleiArgsMode(name, detectSpecMode(r.specBytes))...)
	cmd.Env = egress.ProxyEnv(os.Environ(), "http://"+r.proxyAddr)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil // best-effort: spec bisa tak punya server in-scope / format tak lengkap
	}
	findings, _ := Parse(&stdout, program, runID)
	return findings
}

// detectSpecMode menebak input-mode nuclei dari isi spec: "swagger" untuk
// Swagger 2.0, selain itu "openapi" (OpenAPI 3.x).
func detectSpecMode(spec []byte) string {
	head := strings.ToLower(string(spec))
	if len(head) > 4096 {
		head = head[:4096]
	}
	if strings.Contains(head, "\"swagger\"") || strings.Contains(head, "swagger:") {
		return "swagger"
	}
	return "openapi"
}

// gatherURLs crawl target (best-effort, lewat proxy), menyaring ke same-host,
// dedup, memprioritaskan URL berparameter, lalu membatasi jumlah. Target sendiri
// SELALU disertakan agar fuzzing tetap jalan meski crawl kosong.
func (r *DASTRunner) gatherURLs(ctx context.Context, target string) []string {
	all := append([]string{target}, r.crawl(ctx, target)...)
	return prioritizeURLs(sameHostURLs(target, all), r.Safety.maxURLs())
}

// crawl menjalankan katana atas target lewat proxy egress dan mengembalikan URL
// yang ditemukan. Best-effort: gagal/absen = kembalikan nil (fuzz target saja).
func (r *DASTRunner) crawl(ctx context.Context, target string) []string {
	bin := r.Katana
	if bin == "" {
		bin = "katana"
	}
	cmd := exec.CommandContext(ctx, bin, r.katanaArgs(target)...)
	cmd.Env = egress.ProxyEnv(os.Environ(), "http://"+r.proxyAddr)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return nil
	}
	var urls []string
	sc := bufio.NewScanner(&out)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if ln := strings.TrimSpace(sc.Text()); ln != "" {
			urls = append(urls, ln)
		}
	}
	return urls
}

func (r *DASTRunner) katanaArgs(target string) []string {
	// -jc: crawl JS (penting utk SPA yang mendaftarkan endpoint API di bundel JS).
	// -d 2: batasi kedalaman agar crawl terbatas.
	a := []string{"-silent", "-u", target, "-d", "2", "-jc", "-proxy", "http://" + r.proxyAddr}
	a = append(a, r.Safety.katanaExtraArgs()...)
	if rl := r.Safety.rate(r.RateLimit); rl > 0 {
		a = append(a, "-rate-limit", strconv.Itoa(rl))
	}
	return a
}

// nucleiArgs membangun argumen fuzz berbasis daftar URL (mode "list").
func (r *DASTRunner) nucleiArgs(listFile string) []string {
	return r.nucleiArgsMode(listFile, "")
}

// nucleiArgsMode membangun argumen `nuclei -dast`. inputMode kosong = daftar URL
// biasa; "openapi"/"swagger" = baca inputFile sebagai spec & bangkitkan request
// (termasuk body). Argumen keamanan (non-destruktif selalu + stealth) sama untuk
// kedua mode.
func (r *DASTRunner) nucleiArgsMode(inputFile, inputMode string) []string {
	agg := strings.TrimSpace(r.Aggression)
	if agg == "" {
		agg = "low" // paling sedikit payload; cukup utk kandidat draft→verify
	}
	a := []string{
		"-dast", "-jsonl", "-silent", "-disable-update-check",
		"-list", inputFile,
		"-proxy", "http://" + r.proxyAddr,
		"-fuzz-aggression", agg,
	}
	if inputMode != "" {
		// -skip-format-validation: toleran pada spec tak lengkap (best-effort).
		a = append(a, "-input-mode", inputMode, "-skip-format-validation")
		if r.Safety.Stealth {
			// Stealth: hanya field wajib → lebih sedikit request (jejak minimal).
			a = append(a, "-required-only")
		}
	}
	// Argumen keamanan: non-destruktif (selalu) + stealth (bila aktif).
	a = append(a, r.Safety.nucleiExtraArgs()...)
	if rl := r.Safety.rate(r.RateLimit); rl > 0 {
		a = append(a, "-rate-limit", strconv.Itoa(rl))
	}
	return a
}

// sameHostURLs menyaring urls ke host yang sama dgn target (fuzzing hanya
// menyentuh host target; proxy egress tetap gate tiap request sbg batas keras),
// dedup, pertahankan urutan.
func sameHostURLs(target string, urls []string) []string {
	base, err := url.Parse(target)
	if err != nil || base.Host == "" {
		return dedupURLs(urls)
	}
	seen := map[string]bool{}
	var out []string
	for _, u := range urls {
		pu, err := url.Parse(strings.TrimSpace(u))
		if err != nil || pu.Host == "" {
			continue
		}
		if !strings.EqualFold(pu.Host, base.Host) {
			continue
		}
		s := pu.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// prioritizeURLs menaruh URL berparameter (punya query) lebih dulu — titik fuzz
// paling bernilai — lalu membatasi jumlah total ke limit.
func prioritizeURLs(urls []string, limit int) []string {
	var withQ, rest []string
	for _, u := range urls {
		if strings.Contains(u, "?") {
			withQ = append(withQ, u)
		} else {
			rest = append(rest, u)
		}
	}
	out := append(withQ, rest...)
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func dedupURLs(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// writeList menulis URL (satu per baris) ke berkas sementara utk `nuclei -list`.
func writeList(urls []string) (string, func(), error) {
	f, err := os.CreateTemp("", "nuclei-dast-*.txt")
	if err != nil {
		return "", func() {}, err
	}
	name := f.Name()
	cleanup := func() { _ = os.Remove(name) }
	if _, err := f.WriteString(strings.Join(urls, "\n") + "\n"); err != nil {
		_ = f.Close()
		cleanup()
		return "", func() {}, err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return name, cleanup, nil
}
