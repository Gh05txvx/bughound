package retire

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"bughound/internal/egress"
	"bughound/internal/scope"
)

const sampleOutput = `{
  "data": [
    {
      "file": "/tmp/retire-js-abc/000.js",
      "results": [
        {
          "component": "jquery",
          "version": "1.12.4",
          "vulnerabilities": [
            {
              "info": ["https://github.com/advisories/GHSA-gxr4-xjj5-5px2", "not-a-url"],
              "severity": "medium",
              "identifiers": {
                "summary": "jQuery XSS via cross-domain ajax",
                "CVE": ["CVE-2020-11022"]
              }
            }
          ]
        }
      ]
    }
  ]
}`

func TestParse(t *testing.T) {
	fileToURL := map[string]string{"000.js": "http://t.test/js/jquery.min.js"}
	fs, err := Parse([]byte(sampleOutput), fileToURL, "http://t.test", "prog", "run1")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("mau 1 temuan; dapat %d", len(fs))
	}
	f := fs[0]
	if f.Type != "vulnerable-dependency" {
		t.Errorf("Type = %q", f.Type)
	}
	if f.Title != "Library JS rentan: jquery 1.12.4" {
		t.Errorf("Title = %q", f.Title)
	}
	if f.Severity != "medium" {
		t.Errorf("Severity = %q; mau medium", f.Severity)
	}
	if f.Location.URL != "http://t.test/js/jquery.min.js" {
		t.Errorf("Location.URL = %q; mau URL asal berkas, bukan path sementara", f.Location.URL)
	}
	if f.SourceEngine != "retire" {
		t.Errorf("SourceEngine = %q", f.SourceEngine)
	}
	if f.Evidence == nil || !strings.Contains(f.Evidence.Payload, "jquery@1.12.4") || !strings.Contains(f.Evidence.Payload, "CVE-2020-11022") {
		t.Errorf("Evidence.Payload = %+v; mau berisi jquery@1.12.4 & CVE", f.Evidence)
	}
	if !hasTag(f.Tags, "sca") || !hasTag(f.Tags, "dependency") {
		t.Errorf("Tags = %v; mau berisi sca & dependency", f.Tags)
	}
	// Info disaring: hanya URL http(s) yang jadi References.
	if len(f.References) != 1 || f.References[0] != "https://github.com/advisories/GHSA-gxr4-xjj5-5px2" {
		t.Errorf("References = %v; mau 1 URL advisory", f.References)
	}
	// Temuan hasil map wajib lolos kontrak skema. ID diisi store (UUID), bukan
	// adapter/Finalize — jadi set stub dulu seperti yang store lakukan, lalu
	// Finalize membuktikan SEMUA field lain yang jadi tanggung jawab adapter sah.
	f.ID = "stub-id"
	if err := f.Finalize(time.Now()); err != nil {
		t.Errorf("temuan tak lolos Finalize/Validate: %v", err)
	}
}

func TestParseEmptyAndNoData(t *testing.T) {
	if fs, err := Parse([]byte("  "), nil, "t", "p", "r"); err != nil || fs != nil {
		t.Errorf("output kosong harus nil,nil; dapat %v,%v", fs, err)
	}
	if fs, err := Parse([]byte(`{"data":[]}`), nil, "t", "p", "r"); err != nil || fs != nil {
		t.Errorf("data kosong harus nil,nil; dapat %v,%v", fs, err)
	}
	if _, err := Parse([]byte(`{bukan json`), nil, "t", "p", "r"); err == nil {
		t.Error("JSON rusak harus error")
	}
}

func TestParseFallbackLocation(t *testing.T) {
	// Berkas yang basename-nya tak ada di fileToURL -> Location jatuh ke target.
	out := `{"data":[{"file":"/x/zzz.js","results":[{"component":"lodash","version":"4.17.4","vulnerabilities":[{"severity":"high","identifiers":{"summary":"proto pollution","CVE":["CVE-2019-10744"]}}]}]}]}`
	fs, err := Parse([]byte(out), map[string]string{"000.js": "http://t.test/a.js"}, "http://t.test", "p", "r")
	if err != nil || len(fs) != 1 {
		t.Fatalf("Parse: %v / %d", err, len(fs))
	}
	if fs[0].Location.URL != "http://t.test" {
		t.Errorf("Location.URL = %q; mau fallback ke target", fs[0].Location.URL)
	}
	if fs[0].Severity != "high" {
		t.Errorf("Severity = %q; mau high", fs[0].Severity)
	}
}

func TestSameOriginScriptURLs(t *testing.T) {
	html := []byte(`<html><head>
<script src="/main.js"></script>
<script src="bundle.js"></script>
<script src="https://t.test/abs.js"></script>
<script src="https://cdn.example.com/jq.js"></script>
<script src="/main.js"></script>
<script>var inline = 1;</script>
</head></html>`)
	got := sameOriginScriptURLs("http://t.test/app", html)
	want := map[string]bool{
		"http://t.test/main.js":   true,
		"http://t.test/bundle.js": true,
		"https://t.test/abs.js":   true,
	}
	if len(got) != len(want) {
		t.Fatalf("sameOriginScriptURLs = %v; mau %d URL same-origin unik", got, len(want))
	}
	for _, u := range got {
		if !want[u] {
			t.Errorf("URL tak terduga (mungkin cross-origin lolos): %q", u)
		}
	}
}

func TestFetchBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/ok" {
			_, _ = w.Write([]byte("console.log(1)"))
			return
		}
		http.NotFound(w, req)
	}))
	defer srv.Close()
	ctx := context.Background()
	if b := fetchBody(ctx, srv.Client(), srv.URL+"/ok", 1<<20); string(b) != "console.log(1)" {
		t.Errorf("fetchBody(200) = %q", b)
	}
	if b := fetchBody(ctx, srv.Client(), srv.URL+"/missing", 1<<20); b != nil {
		t.Errorf("fetchBody(404) = %q; mau nil", b)
	}
}

// TestScanNoProxyNoConnect: fail-safe keamanan — tanpa proxy egress, Scan tak
// boleh membuat koneksi apa pun (return nil,nil), sehingga tak ada jalur yang
// memintas scope guard. Juga membuat Scan teruji tanpa binary retire.
func TestScanNoProxyNoConnect(t *testing.T) {
	r := &Runner{} // proxyAddr kosong
	fs, err := r.Scan(context.Background(), "http://t.test", "p", "r")
	if err != nil || fs != nil {
		t.Fatalf("tanpa proxy harus nil,nil; dapat %v,%v", fs, err)
	}
}

func TestMapSeverity(t *testing.T) {
	cases := map[string]string{
		"critical": "critical", "high": "high", "medium": "medium",
		"moderate": "medium", "low": "low", "": "medium", "weird": "medium",
	}
	for in, want := range cases {
		if got := string(mapSeverity(in)); got != want {
			t.Errorf("mapSeverity(%q) = %q; mau %q", in, got, want)
		}
	}
}

func hasTag(tags []string, t string) bool {
	for _, x := range tags {
		if x == t {
			return true
		}
	}
	return false
}

// Lihat TestProxiedClientWorksThroughOpenedTunnel di adapter ffuf: klien yang
// memverifikasi gagal diam-diam di host yang TLS-nya dibuka proxy egress.
func TestHTTPClientWorksThroughOpenedTunnel(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "var a=1;")
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "https://")
	g, errs := scope.New([]string{"127.0.0.1"}, []string{"https://" + host + "/admin"})
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	addr, stop, err := egress.New(g, nil).Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	r := &Runner{}
	r.UseProxy(addr)
	client, err := r.httpClient()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Get(srv.URL + "/app.js")
	if err != nil {
		t.Fatalf("GET lewat tunnel terbuka: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, ingin 200", resp.StatusCode)
	}
}
