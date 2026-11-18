package ffuf

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"bughound/internal/egress"
	"bughound/internal/scope"
)

func TestParseRobotsPaths(t *testing.T) {
	body := []byte("# leading comment\n" +
		"User-agent: *\n" +
		"Disallow: /ftp\n" +
		"Disallow: /ftp/\n" + // same as /ftp after trim -> dedup
		"Allow: /public\n" +
		"Disallow:            # empty -> everything allowed, skip\n" +
		"Disallow: /\n" + // whole site, not a probe path
		"Disallow: /admin/secret/\n" +
		"Disallow: /*.bak$\n" + // wildcard pattern, dropped
		"Disallow: https://evil.test/x\n" + // absolute URL, dropped
		"Disallow: /search?q=1   # has a query\n" +
		"Sitemap: https://x.test/sitemap.xml\n")
	got := parseRobotsPaths(body, 200)
	want := []string{"ftp", "public", "admin/secret", "search"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("parseRobotsPaths = %v; want %v", got, want)
	}
}

func TestParseRobotsPathsCap(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 10; i++ {
		fmt.Fprintf(&b, "Disallow: /dir%d\n", i)
	}
	if got := parseRobotsPaths([]byte(b.String()), 5); len(got) != 5 {
		t.Fatalf("cap not honored: got %d, want 5", len(got))
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
		t.Fatalf("robotsPathsFrom = %v; want [ftp hidden]", got)
	}
}

func TestRobotsPathsFromNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.NotFound(w, req)
	}))
	defer srv.Close()
	if got := robotsPathsFrom(context.Background(), srv.Client(), srv.URL); got != nil {
		t.Fatalf("robots.txt 404 must be nil; got %v", got)
	}
}

// TestRobotsPathsNoProxyNoFetch: without an egress proxy there must be NO fetch,
// a guarantee that no connection to the target ever bypasses the scope guard.
func TestRobotsPathsNoProxyNoFetch(t *testing.T) {
	r := &Runner{} // proxyAddr empty
	if got := r.robotsPaths(context.Background(), "http://demo.test"); got != nil {
		t.Fatalf("without a proxy there must be no fetch; got %v", got)
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
			t.Errorf("merged must contain %q; contents:\n%s", want, s)
		}
	}
	if n := strings.Count(string(s), "ftp\n"); n != 1 {
		t.Errorf("ftp must not be doubled (deduped against base); appears %dx:\n%s", n, s)
	}
}

// The egress proxy opens TLS for a host with a path-based exclusion using a
// single-use certificate. A verifying client would fail silently and recall would drop.
func TestProxiedClientWorksThroughOpenedTunnel(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "User-agent: *\nDisallow: /secret\n")
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

	client, err := proxiedClient(addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got := robotsPathsFrom(context.Background(), client, srv.URL); len(got) != 1 || got[0] != "secret" {
		t.Errorf("robotsPathsFrom = %v, want [secret]", got)
	}
}

// Lever 1: robots.txt & spec behind a login are only readable with a session, so
// enrichment must carry the same auth headers as the ffuf probe (-H). Before,
// without the headers, the result on an authenticated target was always empty.
func TestEnrichmentCarriesAuthHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "s=secret" {
			http.Error(w, "log in first", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/robots.txt":
			fmt.Fprint(w, "Disallow: /internal\n")
		case "/openapi.json":
			fmt.Fprint(w, `{"openapi":"3.0.0","servers":[{"url":"/"}],"paths":{"/api/admin":{"get":{}}}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	g, errs := scope.New([]string{"127.0.0.1"}, nil)
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
	r.UseAuthHeaders([]string{"Cookie: s=secret"})
	if got := r.robotsPaths(context.Background(), srv.URL); strings.Join(got, ",") != "internal" {
		t.Errorf("authenticated robots.txt: got %v, want [internal]", got)
	}
	if got := r.specPaths(context.Background(), srv.URL); strings.Join(got, ",") != "api/admin" {
		t.Errorf("authenticated spec: got %v, want [api/admin]", got)
	}
}
