package ffuf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"bughound/internal/finding"
)

func TestParseSample(t *testing.T) {
	fs, err := Parse(strings.NewReader(string(SampleJSON())), "demo", "run1")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(fs) != 4 {
		t.Fatalf("ingin 4 temuan, dapat %d", len(fs))
	}

	byURL := map[string]*finding.Finding{}
	for _, f := range fs {
		byURL[f.Location.URL] = f
		if f.SourceEngine != "ffuf" || f.Type != "exposed-path" {
			t.Errorf("source/type salah: %s/%s", f.SourceEngine, f.Type)
		}
		if f.Confidence != finding.ConfidenceHigh {
			t.Errorf("confidence ffuf harus high, dapat %s", f.Confidence)
		}
		// Setelah id diberikan store, temuan harus valid.
		f.ID = "x"
		if err := f.Finalize(time.Now()); err != nil {
			t.Errorf("Finalize %s: %v", f.Location.URL, err)
		}
	}

	if got := byURL["https://demo.test/admin"]; got == nil || got.Severity != finding.SeverityLow {
		t.Errorf("/admin (200) harus low")
	}
	if got := byURL["https://demo.test/login"]; got == nil || got.Severity != finding.SeverityInfo {
		t.Errorf("/login (401) harus info")
	}
}

func TestParseEmpty(t *testing.T) {
	fs, err := Parse(strings.NewReader(`{"results":[]}`), "p", "r")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("hasil kosong harus 0 temuan, dapat %d", len(fs))
	}
}

func TestParseInvalid(t *testing.T) {
	if _, err := Parse(strings.NewReader(`{bukan json`), "p", "r"); err == nil {
		t.Fatal("JSON rusak harus error")
	}
}

// Kasus Juice Shop: SPA membalas 200 index.html untuk hampir semua path.
// Kalibrasi harus menekan grup seragam jadi satu ringkasan, menyisakan endpoint
// nyata (ukuran berbeda) utuh.
func TestParseCatchAll(t *testing.T) {
	out := ffufOutput{}
	// 1 endpoint nyata dengan ukuran unik (mis. /metrics).
	out.Results = append(out.Results, ffufResult{
		Input: map[string]string{"FUZZ": "metrics"}, Status: 200, Length: 26349, Words: 900, Lines: 300,
		ContentType: "text/plain", URL: "http://t.test/metrics", Host: "t.test",
	})
	// 14 path semu dengan sidik jari respons identik (catch-all SPA).
	for i := 0; i < 14; i++ {
		p := fmt.Sprintf("semu%02d", i)
		out.Results = append(out.Results, ffufResult{
			Input: map[string]string{"FUZZ": p}, Status: 200, Length: 4096, Words: 200, Lines: 80,
			ContentType: "text/html", URL: "http://t.test/" + p, Host: "t.test",
		})
	}
	b, _ := json.Marshal(out)

	fs, err := Parse(bytes.NewReader(b), "demo", "run1")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 { // 14 seragam -> 1 ringkasan; + 1 endpoint nyata
		t.Fatalf("ingin 2 temuan (1 nyata + 1 ringkasan), dapat %d", len(fs))
	}
	var note, real *finding.Finding
	for _, f := range fs {
		if f.Type == "content-discovery-wildcard" {
			note = f
		} else {
			real = f
		}
	}
	if note == nil {
		t.Fatal("ringkasan catch-all tak dibuat")
	}
	if !strings.Contains(note.Title, "14") {
		t.Errorf("ringkasan harus menyebut 14 path ditekan: %q", note.Title)
	}
	if note.Severity != finding.SeverityInfo {
		t.Errorf("ringkasan harus info, dapat %s", note.Severity)
	}
	if note.Location.URL != "http://t.test" {
		t.Errorf("ringkasan harus di akar target, dapat %q", note.Location.URL)
	}
	if real == nil || real.Location.URL != "http://t.test/metrics" {
		t.Error("endpoint nyata (metrics) harus bertahan dari kalibrasi")
	}
	for _, f := range fs { // semua tetap temuan valid
		f.ID = "x"
		if err := f.Finalize(time.Now()); err != nil {
			t.Errorf("Finalize %s: %v", f.Location.URL, err)
		}
	}
}

// Respons beragam (situs sehat) tak boleh memicu penekanan.
func TestParseNoCatchAllWhenDiverse(t *testing.T) {
	out := ffufOutput{}
	for i := 0; i < 12; i++ {
		out.Results = append(out.Results, ffufResult{
			Input: map[string]string{"FUZZ": fmt.Sprintf("p%02d", i)}, Status: 200,
			Length: int64(100 + i*37), Words: int64(10 + i), Lines: 5,
			ContentType: "text/html", URL: fmt.Sprintf("http://t.test/p%02d", i), Host: "t.test",
		})
	}
	b, _ := json.Marshal(out)
	fs, err := Parse(bytes.NewReader(b), "demo", "run1")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 12 {
		t.Fatalf("respons beragam tak boleh ditekan; ingin 12, dapat %d", len(fs))
	}
	for _, f := range fs {
		if f.Type == "content-discovery-wildcard" {
			t.Error("tak boleh ada ringkasan catch-all saat respons beragam")
		}
	}
}
