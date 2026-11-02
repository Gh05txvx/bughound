package ffuf

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestParseRobotsPaths(t *testing.T) {
	body := []byte("# komentar awal\n" +
		"User-agent: *\n" +
		"Disallow: /ftp\n" +
		"Disallow: /ftp/\n" + // sama dgn /ftp setelah trim -> dedup
		"Allow: /public\n" +
		"Disallow:            # kosong -> seluruh diizinkan, lewati\n" +
		"Disallow: /\n" + // seluruh situs, bukan path probe
		"Disallow: /admin/secret/\n" +
		"Disallow: /*.bak$\n" + // pola wildcard, dibuang
		"Disallow: https://evil.test/x\n" + // URL absolut, dibuang
		"Disallow: /search?q=1   # ada query\n" +
		"Sitemap: https://x.test/sitemap.xml\n")
	got := parseRobotsPaths(body, 200)
	want := []string{"ftp", "public", "admin/secret", "search"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("parseRobotsPaths = %v; mau %v", got, want)
	}
}

func TestParseRobotsPathsCap(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 10; i++ {
		fmt.Fprintf(&b, "Disallow: /dir%d\n", i)
	}
	if got := parseRobotsPaths([]byte(b.String()), 5); len(got) != 5 {
		t.Fatalf("cap tak dihormati: dapat %d, mau 5", len(got))
	}
}

func TestRobotsPathsFromFetchesAndParses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/robots.txt" {
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /ftp\nDisallow: /hidden\n"))
			return
		}
		http.NotFound(w, req)
	}))
	defer srv.Close()
	got := robotsPathsFrom(context.Background(), srv.Client(), srv.URL)
	if strings.Join(got, ",") != "ftp,hidden" {
		t.Fatalf("robotsPathsFrom = %v; mau [ftp hidden]", got)
	}
}

func TestRobotsPathsFromNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.NotFound(w, req)
	}))
	defer srv.Close()
	if got := robotsPathsFrom(context.Background(), srv.Client(), srv.URL); got != nil {
		t.Fatalf("robots.txt 404 harus nil; dapat %v", got)
	}
}

// TestRobotsPathsNoProxyNoFetch: tanpa proxy egress, TIDAK boleh ada fetch —
// jaminan tak pernah ada koneksi ke target yang memintas scope guard.
func TestRobotsPathsNoProxyNoFetch(t *testing.T) {
	r := &Runner{} // proxyAddr kosong
	if got := r.robotsPaths(context.Background(), "http://demo.test"); got != nil {
		t.Fatalf("tanpa proxy tak boleh fetch; dapat %v", got)
	}
}

func TestMergeWordlistDedupsAndAppends(t *testing.T) {
	base, err := os.CreateTemp(t.TempDir(), "wl-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = base.WriteString("admin\nftp\n")
	base.Close()

	merged, cleanup, err := mergeWordlist(base.Name(), []string{"ftp", "hidden", "secret"})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	s, err := os.ReadFile(merged)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"admin", "ftp", "hidden", "secret"} {
		if !strings.Contains(string(s), want) {
			t.Errorf("merged harus memuat %q; isi:\n%s", want, s)
		}
	}
	if n := strings.Count(string(s), "ftp\n"); n != 1 {
		t.Errorf("ftp tak boleh dobel (dedup thd base); muncul %dx:\n%s", n, s)
	}
}
