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
	fs, err := Parse(strings.NewReader(string(sampleJSON)), "demo", "run1")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(fs) != 4 {
		t.Fatalf("want 4 findings, got %d", len(fs))
	}

	byURL := map[string]*finding.Finding{}
	for _, f := range fs {
		byURL[f.Location.URL] = f
		if f.SourceEngine != "ffuf" || f.Type != "exposed-path" {
			t.Errorf("wrong source/type: %s/%s", f.SourceEngine, f.Type)
		}
		if f.Confidence != finding.ConfidenceHigh {
			t.Errorf("ffuf confidence must be high, got %s", f.Confidence)
		}
		// Once the store has assigned an id, the finding must be valid.
		f.ID = "x"
		if err := f.Finalize(time.Now()); err != nil {
			t.Errorf("Finalize %s: %v", f.Location.URL, err)
		}
	}

	if got := byURL["https://demo.test/admin"]; got == nil || got.Severity != finding.SeverityLow {
		t.Errorf("/admin (200) must be low")
	}
	if got := byURL["https://demo.test/login"]; got == nil || got.Severity != finding.SeverityInfo {
		t.Errorf("/login (401) must be info")
	}
}

func TestParseEmpty(t *testing.T) {
	fs, err := Parse(strings.NewReader(`{"results":[]}`), "p", "r")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("empty results must be 0 findings, got %d", len(fs))
	}
}

func TestParseInvalid(t *testing.T) {
	if _, err := Parse(strings.NewReader(`{not json`), "p", "r"); err == nil {
		t.Fatal("broken JSON must error")
	}
}

// Juice Shop case: the SPA answers 200 index.html for nearly every path.
// Calibration must suppress the uniform group into one summary, leaving the real
// endpoint (different size) intact.
func TestParseCatchAll(t *testing.T) {
	out := ffufOutput{}
	// 1 real endpoint with a unique size (e.g. /metrics).
	out.Results = append(out.Results, ffufResult{
		Input: map[string]string{"FUZZ": "metrics"}, Status: 200, Length: 26349, Words: 900, Lines: 300,
		ContentType: "text/plain", URL: "http://t.test/metrics", Host: "t.test",
	})
	// 14 decoy paths with an identical response fingerprint (catch-all SPA).
	for i := 0; i < 14; i++ {
		p := fmt.Sprintf("decoy%02d", i)
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
	if len(fs) != 2 { // 14 uniform -> 1 summary; + 1 real endpoint
		t.Fatalf("want 2 findings (1 real + 1 summary), got %d", len(fs))
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
		t.Fatal("the catch-all summary was not created")
	}
	if !strings.Contains(note.Title, "14") {
		t.Errorf("the summary must mention 14 suppressed paths: %q", note.Title)
	}
	if note.Severity != finding.SeverityInfo {
		t.Errorf("the summary must be info, got %s", note.Severity)
	}
	if note.Location.URL != "http://t.test" {
		t.Errorf("the summary must be at the target root, got %q", note.Location.URL)
	}
	if real == nil || real.Location.URL != "http://t.test/metrics" {
		t.Error("the real endpoint (metrics) must survive calibration")
	}
	for _, f := range fs { // all still valid findings
		f.ID = "x"
		if err := f.Finalize(time.Now()); err != nil {
			t.Errorf("Finalize %s: %v", f.Location.URL, err)
		}
	}
}

// Varied responses (a healthy site) must not trigger suppression.
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
		t.Fatalf("varied responses must not be suppressed; want 12, got %d", len(fs))
	}
	for _, f := range fs {
		if f.Type == "content-discovery-wildcard" {
			t.Error("there must be no catch-all summary when responses vary")
		}
	}
}

const (
	typeExposedPath = "exposed-path"
	typeCatchAll    = "content-discovery-wildcard"
	typeErrorWall   = "content-discovery-error-wall"
)

// echoResults builds n results that echo the path in the body: the length
// changes per path, the shape (words & lines) stays. This is the error-wall
// pattern: a Spring Boot style 401/403 gateway, or a 500 handler that prints the
// requested path.
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

// uniformResults builds n results with an identical response across all paths.
func uniformResults(n, status int) []ffufResult {
	rs := make([]ffufResult, 0, n)
	for i := 0; i < n; i++ {
		p := fmt.Sprintf("api/uniform%03d", i)
		rs = append(rs, ffufResult{
			Input: map[string]string{"FUZZ": p}, Status: status, Length: 24, Words: 1, Lines: 1,
			ContentType: "application/json", URL: "http://t.test/" + p, Host: "t.test",
		})
	}
	return rs
}

// realRoutes is two real 200 routes that must always survive calibration.
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

// The identical-group threshold depends on the status. On a healthy API an
// unknown path gets a 404, so a small 401/403/500 group is a REAL route:
// protected (e.g. FastAPI: an identical 401 on every route) or crashing without
// a required parameter. Proven live: 12 real routes once collapsed into one note.
// Other statuses keep the catch-all threshold.
func TestParseCatchAllThresholdByStatus(t *testing.T) {
	cases := []struct {
		name   string
		status int
		n      int
		want   int
	}{
		{"401 real routes", 401, 12, 12},
		{"403 real routes", 403, 12, 12},
		{"500 real routes", 500, 12, 12},
		{"401 below threshold", 401, 99, 99},
		{"403 below threshold", 403, 99, 99},
		{"500 below threshold", 500, 99, 99},
		{"401 at threshold", 401, 100, 1},
		{"403 at threshold", 403, 100, 1},
		{"500 at threshold", 500, 100, 1},
		{"200 below threshold", 200, 9, 9},
		{"200 at threshold", 200, 10, 1},
		{"302 at threshold", 302, 10, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := parseResults(t, uniformResults(c.n, c.status))
			if len(fs) != c.want {
				t.Fatalf("%d results HTTP %d: want %d findings, got %d", c.n, c.status, c.want, len(fs))
			}
			wantType := typeExposedPath
			if c.want == 1 {
				wantType = typeCatchAll // identical responses: a catch-all note, not an error wall
			}
			if got := countByType(fs); got[wantType] != c.want {
				t.Errorf("want %d findings of type %s, got %v", c.want, wantType, got)
			}
		})
	}
}

// A small 401 route must not be lost when it sits beside a real 200 route.
func TestParseSmallAuthGroupKeptWithRealRoutes(t *testing.T) {
	fs := parseResults(t, append(realRoutes(), uniformResults(12, 401)...))
	if got := countByType(fs); got[typeExposedPath] != 14 || len(got) != 1 {
		t.Fatalf("want 14 real routes with no note, got %v", got)
	}
}

// A server that echoes the path: the length changes per path, so the
// status|length|words fingerprint is never dominant. Proven live: 7,719 findings
// (401 gateway) and 7,971 findings (Juice Shop 500) from one scan, real routes
// drowned out. It must collapse into one note labeled by wall type, real routes intact.
func TestParseErrorWallEchoCollapsed(t *testing.T) {
	for _, c := range []struct {
		status int
		label  string
	}{
		{401, "auth wall"},
		{403, "auth wall"},
		{500, "server error wall"},
	} {
		t.Run(fmt.Sprint(c.status), func(t *testing.T) {
			status := c.status
			fs := parseResults(t, append(realRoutes(), echoResults(150, status)...))
			if len(fs) != 3 {
				t.Fatalf("want 3 findings (2 real + 1 note), got %d", len(fs))
			}
			var note *finding.Finding
			urls := map[string]bool{}
			for _, f := range fs {
				if f.Type == typeErrorWall {
					note = f
				} else {
					urls[f.Location.URL] = true
				}
			}
			if note == nil {
				t.Fatalf("the error-wall note was not created: %v", countByType(fs))
			}
			if !strings.Contains(note.Title, "150") || !strings.Contains(note.Title, fmt.Sprint(status)) {
				t.Errorf("the title must mention 150 paths and HTTP %d: %q", status, note.Title)
			}
			if !strings.Contains(note.Title, c.label+" HTTP") || !strings.Contains(note.Description, c.label) {
				t.Errorf("HTTP %d must be labeled %q in the title & description: %q / %q", status, c.label, note.Title, note.Description)
			}
			if note.Severity != finding.SeverityInfo {
				t.Errorf("the note must be info, got %s", note.Severity)
			}
			if note.Location.URL != "http://t.test" {
				t.Errorf("the note must be at the target root, got %q", note.Location.URL)
			}
			if !strings.Contains(note.Description, "http://t.test/api/") {
				t.Errorf("the note must give an example of a suppressed path: %q", note.Description)
			}
			for _, u := range []string{"http://t.test/api/v1/bulklog", "http://t.test/api/availability/get"} {
				if !urls[u] {
					t.Errorf("real route %s must survive", u)
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

// Recall guard: on a healthy API an unknown path gets a 404, so every result is
// a REAL route even when the shape matches. A group below the threshold must not
// be suppressed, since those are the routes API brute-forcing is looking for.
func TestParseErrorWallThreshold(t *testing.T) {
	cases := []struct {
		name string
		n    int
		want int
	}{
		{"real routes", 12, 12},
		{"just below threshold", 99, 99},
		{"at threshold", 100, 1},
	}
	for _, status := range []int{401, 500} {
		for _, c := range cases {
			t.Run(fmt.Sprintf("%d %s", status, c.name), func(t *testing.T) {
				if fs := parseResults(t, echoResults(c.n, status)); len(fs) != c.want {
					t.Fatalf("%d results HTTP %d: want %d findings, got %d", c.n, status, c.want, len(fs))
				}
			})
		}
	}
}

// Real 200 routes are often same-shaped by chance (JSON without spaces = 1 word).
// The loose rule applies only to error-wall statuses (401/403/500), no matter how
// large an other-status group is. This list = the rest of ffuf's default matchers.
func TestParseErrorWallIgnoresOtherStatuses(t *testing.T) {
	for _, status := range []int{200, 204, 301, 302, 307, 405} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			if fs := parseResults(t, echoResults(150, status)); len(fs) != 150 {
				t.Fatalf("HTTP %d must not be suppressed: want 150, got %d", status, len(fs))
			}
		})
	}
}

// Juice Shop (proven live): an unknown path under /api & /rest gets a 500
// "Unexpected path: /api/x" that echoes the path, so 7,971 of 8,002 results are
// same-shaped with varied lengths. That wall must collapse; a differently-shaped
// 500 (/profile, a real route) and real 401 routes from apiroutes must stay intact.
func TestParseErrorWallJuiceShop(t *testing.T) {
	var rs []ffufResult
	for i := 0; i < 300; i++ {
		p := "api/" + strings.Repeat("y", i%71+1) + fmt.Sprint(i)
		rs = append(rs, ffufResult{
			Input: map[string]string{"FUZZ": p}, Status: 500, Length: int64(1043 + 2*len(p)), Words: 210, Lines: 50,
			ContentType: "text/html; charset=utf-8", URL: "http://t.test/" + p, Host: "t.test",
		})
	}
	rs = append(rs, ffufResult{
		Input: map[string]string{"FUZZ": "profile"}, Status: 500, Length: 1154, Words: 153, Lines: 43,
		ContentType: "text/html; charset=utf-8", URL: "http://t.test/profile", Host: "t.test",
	})
	var protected []string
	for i := 0; i < 14; i++ {
		p := fmt.Sprintf("rest/protected%02d", i)
		protected = append(protected, "http://t.test/"+p)
		rs = append(rs, ffufResult{
			Input: map[string]string{"FUZZ": p}, Status: 401, Length: 26, Words: 4, Lines: 1,
			ContentType: "text/html; charset=utf-8", URL: "http://t.test/" + p, Host: "t.test",
		})
	}
	rs = append(rs, realRoutes()...)

	fs := parseResults(t, rs)
	if got := countByType(fs); got[typeErrorWall] != 1 || got[typeExposedPath] != 17 || len(got) != 2 {
		t.Fatalf("want 1 wall note + 17 real routes (/profile, 14x 401, 2x 200), got %v", got)
	}
	urls := map[string]bool{}
	for _, f := range fs {
		urls[f.Location.URL] = true
		if f.Type == typeErrorWall && (!strings.Contains(f.Title, "300") || !strings.Contains(f.Title, "server error wall HTTP 500")) {
			t.Errorf("the note must mention 300 paths & a server error wall HTTP 500: %q", f.Title)
		}
	}
	for _, u := range append(protected, "http://t.test/profile") {
		if !urls[u] {
			t.Errorf("real route %s must survive", u)
		}
	}
}

// A different shape means it is not a wall: words AND lines must match.
func TestParseErrorWallNeedsSameShape(t *testing.T) {
	vary := map[string]func(*ffufResult, int){
		"words": func(r *ffufResult, i int) { r.Words = int64(i + 1) },
		"lines": func(r *ffufResult, i int) { r.Lines = int64(i + 1) },
	}
	for name, mutate := range vary {
		t.Run(name, func(t *testing.T) {
			rs := echoResults(150, 401)
			for i := range rs {
				mutate(&rs[i], i)
			}
			if fs := parseResults(t, rs); len(fs) != 150 {
				t.Fatalf("varied %s must not be suppressed: want 150, got %d", name, len(fs))
			}
		})
	}
}

// Each status is a separate pattern: two groups below the threshold must not be
// summed into one group that crosses it.
func TestParseErrorWallSeparatesStatuses(t *testing.T) {
	for _, pair := range [][2]int{{401, 403}, {403, 500}} {
		t.Run(fmt.Sprintf("%d+%d", pair[0], pair[1]), func(t *testing.T) {
			rs := append(echoResults(60, pair[0]), echoResults(60, pair[1])...)
			if fs := parseResults(t, rs); len(fs) != 120 {
				t.Fatalf("different statuses must not be merged: want 120, got %d", len(fs))
			}
		})
	}
}

// Dominance is still required: a large group that is not the majority of results is not suppressed.
func TestParseErrorWallNeedsDominance(t *testing.T) {
	rs := echoResults(120, 401)
	for i := 0; i < 100; i++ { // 120 of 220 = 54.5%, below 60%
		p := fmt.Sprintf("real%03d", i)
		rs = append(rs, ffufResult{
			Input: map[string]string{"FUZZ": p}, Status: 200, Length: int64(100 + i*3), Words: int64(5 + i), Lines: 2,
			ContentType: "application/json", URL: "http://t.test/" + p, Host: "t.test",
		})
	}
	if fs := parseResults(t, rs); len(fs) != 220 {
		t.Fatalf("a minority group must not be suppressed: want 220, got %d", len(fs))
	}
}

// Both patterns on one target must be visible. Their note types differ, because
// a note's dedup key at the target root can only differ by type.
func TestParseBothWallsReported(t *testing.T) {
	rs := uniformResults(400, 401)
	rs = append(rs, echoResults(150, 403)...)
	rs = append(rs, realRoutes()...)

	fs := parseResults(t, rs)
	got := countByType(fs)
	if got[typeCatchAll] != 1 || got[typeErrorWall] != 1 || got[typeExposedPath] != 2 {
		t.Fatalf("want 1 catch-all + 1 error wall + 2 real routes, got %v", got)
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
		t.Errorf("each finding must have its own dedup key: %d keys for %d findings", len(keys), len(fs))
	}
}
