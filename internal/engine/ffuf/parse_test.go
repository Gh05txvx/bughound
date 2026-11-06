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

const (
	typeExposedPath = "exposed-path"
	typeCatchAll    = "content-discovery-wildcard"
	typeAuthWall    = "content-discovery-auth-wall"
)

// echoResults membangun n hasil yang menggemakan path di body: panjang berubah per
// path, bentuk (kata & baris) tetap. Ini pola gateway 401/403 gaya Spring Boot.
func echoResults(n, status int) []ffufResult {
	rs := make([]ffufResult, 0, n)
	for i := 0; i < n; i++ {
		p := "api/" + strings.Repeat("x", i%40+1) + fmt.Sprint(i)
		rs = append(rs, ffufResult{
			Input: map[string]string{"FUZZ": p}, Status: status,
			Length: int64(40 + len(p)), Words: 1, Lines: 1,
			ContentType: "application/json", URL: "http://t.test/" + p, Host: "t.test",
		})
	}
	return rs
}

// realRoutes adalah dua rute 200 nyata yang harus selalu bertahan dari kalibrasi.
func realRoutes() []ffufResult {
	mk := func(p string, length int64) ffufResult {
		return ffufResult{
			Input: map[string]string{"FUZZ": p}, Status: 200, Length: length, Words: 1, Lines: 1,
			ContentType: "application/json", URL: "http://t.test/" + p, Host: "t.test",
		}
	}
	return []ffufResult{mk("api/v1/bulklog", 31), mk("api/availability/get", 42)}
}

func parseResults(t *testing.T, rs []ffufResult) []*finding.Finding {
	t.Helper()
	b, err := json.Marshal(ffufOutput{Results: rs})
	if err != nil {
		t.Fatal(err)
	}
	fs, err := Parse(bytes.NewReader(b), "demo", "run1")
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

func countByType(fs []*finding.Finding) map[string]int {
	got := map[string]int{}
	for _, f := range fs {
		got[f.Type]++
	}
	return got
}

// Gateway yang menggemakan path: panjang berubah per path, jadi sidik jari
// status|panjang|kata tak pernah dominan. Terbukti live: 7.719 temuan dari satu
// scan, 2 rute nyata tenggelam. Harus kolaps jadi satu catatan, rute nyata utuh.
func TestParseAuthWallEchoCollapsed(t *testing.T) {
	for _, status := range []int{401, 403} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			fs := parseResults(t, append(realRoutes(), echoResults(150, status)...))
			if len(fs) != 3 {
				t.Fatalf("ingin 3 temuan (2 nyata + 1 catatan), dapat %d", len(fs))
			}
			var note *finding.Finding
			urls := map[string]bool{}
			for _, f := range fs {
				if f.Type == typeAuthWall {
					note = f
				} else {
					urls[f.Location.URL] = true
				}
			}
			if note == nil {
				t.Fatalf("catatan dinding auth tak dibuat: %v", countByType(fs))
			}
			if !strings.Contains(note.Title, "150") || !strings.Contains(note.Title, fmt.Sprint(status)) {
				t.Errorf("judul harus menyebut 150 path dan HTTP %d: %q", status, note.Title)
			}
			if note.Severity != finding.SeverityInfo {
				t.Errorf("catatan harus info, dapat %s", note.Severity)
			}
			if note.Location.URL != "http://t.test" {
				t.Errorf("catatan harus di akar target, dapat %q", note.Location.URL)
			}
			if !strings.Contains(note.Description, "http://t.test/api/") {
				t.Errorf("catatan harus memberi contoh path yang ditekan: %q", note.Description)
			}
			for _, u := range []string{"http://t.test/api/v1/bulklog", "http://t.test/api/availability/get"} {
				if !urls[u] {
					t.Errorf("rute nyata %s harus bertahan", u)
				}
			}
			for _, f := range fs {
				f.ID = "x"
				if err := f.Finalize(time.Now()); err != nil {
					t.Errorf("Finalize %s: %v", f.Location.URL, err)
				}
			}
		})
	}
}

// Penjaga recall: pada API sehat path tak dikenal dibalas 404, jadi semua hasil
// adalah rute terproteksi NYATA walau bentuknya sama. Grup di bawah ambang tak
// boleh ditekan, sebab rute itulah yang dicari brute route API.
func TestParseAuthWallThreshold(t *testing.T) {
	cases := []struct {
		name string
		n    int
		want int
	}{
		{"rute nyata", 12, 12},
		{"tepat di bawah ambang", 99, 99},
		{"tepat di ambang", 100, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if fs := parseResults(t, echoResults(c.n, 401)); len(fs) != c.want {
				t.Fatalf("%d hasil: ingin %d temuan, dapat %d", c.n, c.want, len(fs))
			}
		})
	}
}

// Rute nyata berstatus 200 sering kebetulan sebentuk (JSON tanpa spasi = 1 kata).
// Aturan longgar hanya untuk 401/403, sebesar apa pun grupnya.
func TestParseAuthWallIgnoresOtherStatuses(t *testing.T) {
	for _, status := range []int{200, 204, 302, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			if fs := parseResults(t, echoResults(150, status)); len(fs) != 150 {
				t.Fatalf("HTTP %d tak boleh ditekan: ingin 150, dapat %d", status, len(fs))
			}
		})
	}
}

// Bentuk berbeda berarti bukan dinding: kata DAN baris harus sama.
func TestParseAuthWallNeedsSameShape(t *testing.T) {
	vary := map[string]func(*ffufResult, int){
		"kata":  func(r *ffufResult, i int) { r.Words = int64(i + 1) },
		"baris": func(r *ffufResult, i int) { r.Lines = int64(i + 1) },
	}
	for name, mutate := range vary {
		t.Run(name, func(t *testing.T) {
			rs := echoResults(150, 401)
			for i := range rs {
				mutate(&rs[i], i)
			}
			if fs := parseResults(t, rs); len(fs) != 150 {
				t.Fatalf("%s beragam tak boleh ditekan: ingin 150, dapat %d", name, len(fs))
			}
		})
	}
}

// 401 dan 403 adalah pola terpisah: dua grup di bawah ambang tak boleh dijumlahkan
// jadi satu grup yang melewatinya.
func TestParseAuthWallSeparatesStatuses(t *testing.T) {
	rs := append(echoResults(60, 401), echoResults(60, 403)...)
	if fs := parseResults(t, rs); len(fs) != 120 {
		t.Fatalf("status berbeda tak boleh digabung: ingin 120, dapat %d", len(fs))
	}
}

// Dominasi tetap wajib: grup besar yang bukan mayoritas hasil tak ditekan.
func TestParseAuthWallNeedsDominance(t *testing.T) {
	rs := echoResults(120, 401)
	for i := 0; i < 100; i++ { // 120 dari 220 = 54,5%, di bawah 60%
		p := fmt.Sprintf("real%03d", i)
		rs = append(rs, ffufResult{
			Input: map[string]string{"FUZZ": p}, Status: 200, Length: int64(100 + i*3), Words: int64(5 + i), Lines: 2,
			ContentType: "application/json", URL: "http://t.test/" + p, Host: "t.test",
		})
	}
	if fs := parseResults(t, rs); len(fs) != 220 {
		t.Fatalf("grup minoritas tak boleh ditekan: ingin 220, dapat %d", len(fs))
	}
}

// Dua pola pada satu target harus sama-sama terlihat. Tipe catatannya berbeda,
// karena kunci dedup catatan di akar target hanya bisa berbeda lewat tipe.
func TestParseBothWallsReported(t *testing.T) {
	var rs []ffufResult
	for i := 0; i < 400; i++ {
		p := fmt.Sprintf("api/seragam%03d", i)
		rs = append(rs, ffufResult{
			Input: map[string]string{"FUZZ": p}, Status: 401, Length: 24, Words: 1, Lines: 1,
			ContentType: "application/json", URL: "http://t.test/" + p, Host: "t.test",
		})
	}
	rs = append(rs, echoResults(150, 403)...)
	rs = append(rs, realRoutes()...)

	fs := parseResults(t, rs)
	got := countByType(fs)
	if got[typeCatchAll] != 1 || got[typeAuthWall] != 1 || got[typeExposedPath] != 2 {
		t.Fatalf("ingin 1 catch-all + 1 dinding auth + 2 rute nyata, dapat %v", got)
	}
	keys := map[string]bool{}
	for _, f := range fs {
		f.ID = "x"
		if err := f.Finalize(time.Now()); err != nil {
			t.Fatalf("Finalize %s: %v", f.Location.URL, err)
		}
		keys[f.DedupKey] = true
	}
	if len(keys) != len(fs) {
		t.Errorf("tiap temuan harus punya kunci dedup sendiri: %d kunci untuk %d temuan", len(keys), len(fs))
	}
}
