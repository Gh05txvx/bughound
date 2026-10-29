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
)

// Parse membaca output ffuf (JSON) dan mengembalikan temuan ternormalkan, setelah
// kalibrasi catch-all menekan respons wildcard (lihat calibrate).
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

// calibrate menekan grup respons dominan (catch-all / SPA wildcard) bila melewati
// ambang, mengganti ratusan path semu dengan satu temuan info. Hasil lain —
// endpoint dengan sidik jari berbeda (ukuran/kata lain) — dipertahankan utuh.
func calibrate(items []item, program, runID string) []*finding.Finding {
	if len(items) < catchAllMinHits {
		return collect(items)
	}
	counts := map[string]int{}
	for _, it := range items {
		counts[fingerprintOf(it.res)]++
	}
	domFP, domN := "", 0
	for fp, n := range counts {
		if n > domN {
			domFP, domN = fp, n
		}
	}
	if domN < catchAllMinHits || float64(domN)/float64(len(items)) < catchAllMinFraction {
		return collect(items) // tak ada pola wildcard yang meyakinkan
	}

	kept := make([]*finding.Finding, 0, len(items)-domN+1)
	var sample ffufResult
	for _, it := range items {
		if fingerprintOf(it.res) == domFP {
			sample = it.res // simpan satu contoh untuk ringkasan
			continue
		}
		kept = append(kept, it.f)
	}
	return append(kept, wildcardNote(sample, domN, len(items), program, runID))
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
	base := baseOf(sample.URL)
	raw, _ := json.Marshal(struct {
		Suppressed int   `json:"suppressed"`
		Total      int   `json:"total"`
		Status     int   `json:"status"`
		Length     int64 `json:"length"`
		Words      int64 `json:"words"`
	}{suppressed, total, sample.Status, sample.Length, sample.Words})

	return &finding.Finding{
		Program: program,
		RunID:   runID,
		Target:  firstNonEmpty(sample.Host, base),
		Type:    "content-discovery-wildcard",
		Title:   fmt.Sprintf("Kalibrasi ffuf: %d path ditekan (respons catch-all seragam)", suppressed),
		Description: fmt.Sprintf("Server membalas %d dari %d path uji dengan respons identik "+
			"(HTTP %d · %d bytes · %d kata) — indikasi catch-all/SPA wildcard. Temuan path untuk "+
			"pola ini ditekan sebagai kemungkinan positif palsu; verifikasi manual bila ada path "+
			"spesifik yang diragukan.", suppressed, total, sample.Status, sample.Length, sample.Words),
		Severity:     finding.SeverityInfo,
		Confidence:   finding.ConfidenceHigh,
		Tags:         []string{"content-discovery", "calibration"},
		Location:     finding.Location{URL: base},
		SourceEngine: "ffuf",
		Status:       finding.StatusNew,
		Evidence: &finding.Evidence{
			Matched: fmt.Sprintf("HTTP %d · %d bytes · %d kata · %d/%d path seragam", sample.Status, sample.Length, sample.Words, suppressed, total),
		},
		Raw: raw,
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
