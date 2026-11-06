// Package ffuf menormalkan output ffuf (content discovery / fuzzing) ke Skema
// Temuan Seragam (BH-SPEC-FINDING), membuktikan nilai inti bughound: menambah
// engine = menambah satu adapter, tanpa menyentuh triase/report/store.
//
// Menyediakan engine mock untuk M1 (tanpa jaringan).
package ffuf

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"

	"bughound/internal/finding"
)

// ffuf -of json menghasilkan satu objek JSON dengan array "results".
type ffufOutput struct {
	Results []ffufResult `json:"results"`
}

type ffufResult struct {
	Input       map[string]string `json:"input"`
	Status      int               `json:"status"`
	Length      int64             `json:"length"`
	Words       int64             `json:"words"`
	Lines       int64             `json:"lines"`
	ContentType string            `json:"content-type"`
	URL         string            `json:"url"`
	Host        string            `json:"host"`
}

// Ambang kalibrasi catch-all. Bila satu "sidik jari" respons (status|panjang|kata)
// mendominasi hasil, server membalas seragam — khas SPA yang mengembalikan
// index.html untuk hampir semua path — sehingga mayoritas "endpoint ditemukan"
// adalah positif palsu. Grup dominan ditekan jadi SATU temuan info yang
// menjelaskannya, bukan membanjiri store dengan ratusan path semu. Ambang dibuat
// konservatif agar situs sehat (ukuran respons beragam) tak pernah ikut tersaring.
const (
	catchAllMinHits     = 10  // grup dominan minimal sebesar ini baru dianggap wildcard
	catchAllMinFraction = 0.6 // dan minimal menyumbang 60% dari seluruh hasil

	// authWallMinHits adalah ambang grup 401/403, baik identik maupun sebentuk (lihat
	// minHitsFor). Sengaja jauh di atas catchAllMinHits: pada API sehat path tak
	// dikenal dibalas 404, jadi grup 401/403 kecil adalah rute terproteksi NYATA —
	// justru itu yang dicari brute route API. Dinding sungguhan di prefix populer
	// menghasilkan ratusan hingga ribuan hit; di bawah ambang, kebisingannya terbatas.
	authWallMinHits = 100
)

// Parse membaca output ffuf (JSON) dan mengembalikan temuan ternormalkan, setelah
// kalibrasi menekan respons massal yang bukan endpoint nyata (lihat calibrate).
func Parse(r io.Reader, program, runID string) ([]*finding.Finding, error) {
	var out ffufOutput
	if err := json.NewDecoder(r).Decode(&out); err != nil {
		return nil, fmt.Errorf("ffuf: output bukan JSON valid: %w", err)
	}
	items := make([]item, 0, len(out.Results))
	for i, res := range out.Results {
		f, err := mapResult(res, program, runID)
		if err != nil {
			return nil, fmt.Errorf("ffuf: hasil %d: %w", i, err)
		}
		items = append(items, item{res: res, f: f})
	}
	return calibrate(items, program, runID), nil
}

// item memasangkan hasil mentah dengan temuan hasil pemetaannya, agar kalibrasi
// menilai sidik jari respons tanpa mem-parse ulang.
type item struct {
	res ffufResult
	f   *finding.Finding
}

// calibrate menekan respons massal yang bukan endpoint nyata dan menggantinya dengan
// satu temuan info per pola, agar penekanan tetap terlihat. Dua pola dinilai
// berurutan: catch-all (respons identik), lalu dinding auth (401/403 sebentuk,
// panjang berubah). Hasil lain — endpoint dengan sidik jari berbeda — tetap utuh.
func calibrate(items []item, program, runID string) []*finding.Finding {
	var notes []*finding.Finding
	rest, sample, n := splitDominant(items, fingerprintOf)
	if n > 0 {
		notes = append(notes, wildcardNote(sample, n, len(items), program, runID))
	}
	rest, sample, n = splitDominant(rest, authWallFingerprintOf)
	if n > 0 {
		notes = append(notes, authWallNote(sample, n, len(items), program, runID))
	}
	return append(collect(rest), notes...)
}

// splitDominant memisahkan grup terbesar menurut key bila ukurannya memenuhi
// minHitsFor dan menyumbang minimal catchAllMinFraction dari items. Mengembalikan
// sisa item, satu contoh dari grup, dan ukuran grup (0 = tak ada yang ditekan). Key
// kosong berarti item itu tak ikut dinilai. Key wajib memuat status, agar satu grup
// punya satu status dan satu ambang.
func splitDominant(items []item, key func(ffufResult) string) (rest []item, sample ffufResult, n int) {
	counts := map[string]int{}
	for _, it := range items {
		if k := key(it.res); k != "" {
			counts[k]++
		}
	}
	dom, domN := "", 0
	for k, c := range counts {
		if c > domN {
			dom, domN = k, c
		}
	}
	rest = make([]item, 0, len(items)-domN)
	for _, it := range items {
		if key(it.res) == dom {
			sample = it.res
			continue
		}
		rest = append(rest, it)
	}
	if domN < minHitsFor(sample.Status) || float64(domN)/float64(len(items)) < catchAllMinFraction {
		return items, ffufResult{}, 0 // tak ada pola yang meyakinkan
	}
	return rest, sample, domN
}

// minHitsFor mengembalikan ambang ukuran grup menurut status responsnya.
func minHitsFor(status int) int {
	if isAuthStatus(status) {
		return authWallMinHits
	}
	return catchAllMinHits
}

func isAuthStatus(status int) bool {
	return status == 401 || status == 403
}

func collect(items []item) []*finding.Finding {
	fs := make([]*finding.Finding, 0, len(items))
	for _, it := range items {
		fs = append(fs, it.f)
	}
	return fs
}

// fingerprintOf: dua respons dianggap "sama" bila status, panjang, dan jumlah kata
// identik. Kombinasi ini stabil untuk halaman catch-all yang byte-nya sama.
func fingerprintOf(res ffufResult) string {
	return fmt.Sprintf("%d|%d|%d", res.Status, res.Length, res.Words)
}

// authWallFingerprintOf adalah sidik jari longgar untuk dinding auth: panjang
// diabaikan karena banyak gateway menggemakan path di body (mis. Spring Boot:
// {"status":401,"path":"/api/x"}), sehingga panjang berubah per path sementara
// bentuknya tetap. Content-type juga diabaikan: gateway bisa menurunkannya dari
// ekstensi path. Hanya 401/403 (selainnya key kosong): rute 200 nyata sering
// kebetulan sebentuk, mis. JSON tanpa spasi selalu 1 kata.
func authWallFingerprintOf(res ffufResult) string {
	if !isAuthStatus(res.Status) {
		return ""
	}
	return fmt.Sprintf("%d|%d|%d", res.Status, res.Words, res.Lines)
}

func mapResult(res ffufResult, program, runID string) (*finding.Finding, error) {
	if strings.TrimSpace(res.URL) == "" {
		return nil, fmt.Errorf("hasil ffuf tanpa url")
	}
	fuzz := res.Input["FUZZ"]
	title := "Endpoint ditemukan"
	if fuzz != "" {
		title = "Endpoint ditemukan: " + fuzz
	}
	raw, _ := json.Marshal(res)

	return &finding.Finding{
		Program:      program,
		RunID:        runID,
		Target:       firstNonEmpty(res.Host, res.URL),
		Type:         "exposed-path",
		Title:        title,
		Severity:     mapSeverity(res.Status),
		Confidence:   finding.ConfidenceHigh, // ffuf melaporkan match pasti
		Tags:         []string{"content-discovery"},
		Location:     finding.Location{URL: res.URL},
		SourceEngine: "ffuf",
		Status:       finding.StatusNew,
		Evidence: &finding.Evidence{
			Payload: fuzz,
			Matched: fmt.Sprintf("HTTP %d · %d bytes · %d kata · %s", res.Status, res.Length, res.Words, res.ContentType),
		},
		Raw: raw,
	}, nil
}

// wildcardNote merangkum grup catch-all yang ditekan menjadi satu temuan info,
// sehingga penekanan TERLIHAT & dapat diaudit (bukan drop diam-diam) dan hunter
// tahu persis pola apa yang disaring.
func wildcardNote(sample ffufResult, suppressed, total int, program, runID string) *finding.Finding {
	note := calibrationNote(sample, suppressed, total, program, runID)
	note.Type = "content-discovery-wildcard"
	note.Title = fmt.Sprintf("Kalibrasi ffuf: %d path ditekan (respons catch-all seragam)", suppressed)
	note.Description = fmt.Sprintf("Server membalas %d dari %d path uji dengan respons identik "+
		"(HTTP %d · %d bytes · %d kata) — indikasi catch-all/SPA wildcard. Temuan path untuk "+
		"pola ini ditekan sebagai kemungkinan positif palsu; verifikasi manual bila ada path "+
		"spesifik yang diragukan.", suppressed, total, sample.Status, sample.Length, sample.Words)
	note.Evidence = &finding.Evidence{
		Matched: fmt.Sprintf("HTTP %d · %d bytes · %d kata · %d/%d path seragam", sample.Status, sample.Length, sample.Words, suppressed, total),
	}
	return note
}

// authWallNote merangkum dinding auth yang ditekan. Tipenya sendiri, bukan tipe
// catch-all: kunci dedup catatan di akar target hanya bisa berbeda lewat tipe, jadi
// satu target dengan kedua pola tetap menampilkan dua catatan.
func authWallNote(sample ffufResult, suppressed, total int, program, runID string) *finding.Finding {
	note := calibrationNote(sample, suppressed, total, program, runID)
	note.Type = "content-discovery-auth-wall"
	note.Title = fmt.Sprintf("Kalibrasi ffuf: %d path ditekan (dinding auth HTTP %d)", suppressed, sample.Status)
	note.Description = fmt.Sprintf("Server membalas %d dari %d path uji dengan HTTP %d yang sebentuk "+
		"(%d kata, %d baris), hanya panjangnya berubah — indikasi gateway auth yang menggemakan path "+
		"di body, bukan %d endpoint nyata. Contoh: %s. Temuan path untuk pola ini ditekan; rute nyata "+
		"di balik dinding tak terbedakan tanpa kredensial, verifikasi manual bila ada path spesifik "+
		"yang diragukan.", suppressed, total, sample.Status, sample.Words, sample.Lines, suppressed, sample.URL)
	note.Evidence = &finding.Evidence{
		Matched: fmt.Sprintf("HTTP %d · %d kata · %d baris · %d/%d path sebentuk", sample.Status, sample.Words, sample.Lines, suppressed, total),
	}
	return note
}

// calibrationNote membangun kerangka catatan kalibrasi; Type, Title, Description,
// dan Evidence diisi pemanggil sesuai pola yang ditekan.
func calibrationNote(sample ffufResult, suppressed, total int, program, runID string) *finding.Finding {
	base := baseOf(sample.URL)
	raw, _ := json.Marshal(struct {
		Suppressed int   `json:"suppressed"`
		Total      int   `json:"total"`
		Status     int   `json:"status"`
		Length     int64 `json:"length"`
		Words      int64 `json:"words"`
	}{suppressed, total, sample.Status, sample.Length, sample.Words})

	return &finding.Finding{
		Program:      program,
		RunID:        runID,
		Target:       firstNonEmpty(sample.Host, base),
		Severity:     finding.SeverityInfo,
		Confidence:   finding.ConfidenceHigh,
		Tags:         []string{"content-discovery", "calibration"},
		Location:     finding.Location{URL: base},
		SourceEngine: "ffuf",
		Status:       finding.StatusNew,
		Raw:          raw,
	}
}

// baseOf mengambil scheme://host dari sebuah URL hasil, untuk menempatkan temuan
// ringkasan pada akar target alih-alih satu path semu.
func baseOf(rawURL string) string {
	if u, err := url.Parse(strings.TrimSpace(rawURL)); err == nil && u.Host != "" {
		return u.Scheme + "://" + u.Host
	}
	return rawURL
}

// mapSeverity: ffuf menemukan path, bukan kerentanan langsung. 200/204 (dapat
// diakses) diberi low; selain itu info. Severity sebenarnya ditentukan saat
// triase manual.
func mapSeverity(status int) finding.Severity {
	switch status {
	case 200, 204:
		return finding.SeverityLow
	default:
		return finding.SeverityInfo
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
