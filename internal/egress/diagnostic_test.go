package egress

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"bughound/internal/scope"
)

func TestParseChainValidAndInvalid(t *testing.T) {
	if _, err := ParseChain([]string{"http://127.0.0.1:8080", "socks5://127.0.0.1:9050"}); err != nil {
		t.Fatalf("rantai valid harusnya lolos: %v", err)
	}
	if _, err := ParseChain([]string{"ftp://x:21"}); err == nil {
		t.Error("skema tak didukung harus ditolak")
	}
	if _, err := ParseChain([]string{"   "}); err == nil {
		t.Error("rantai kosong harus error")
	}
	// Error tak boleh meng-echo kredensial baris mentah.
	_, err := ParseChain([]string{"ftp://user:s3cr3t@host:21"})
	if err == nil || strings.Contains(err.Error(), "s3cr3t") {
		t.Errorf("error tak boleh membocorkan kredensial: %v", err)
	}
}

func TestRedactCreds(t *testing.T) {
	cases := map[string]string{
		"socks5://user:pass@10.0.0.1:9050": "socks5://10.0.0.1:9050",
		"http://bob:hunter2@proxy:8080":    "http://proxy:8080",
		"https://no-creds:8443":            "https://no-creds:8443",
	}
	for in, want := range cases {
		if got := redactCreds(in); got != want {
			t.Errorf("redactCreds(%q) = %q, mau %q", in, got, want)
		}
	}
	if strings.Contains(redactCreds("dial socks5://u:p@h:9050: timeout"), "p@") {
		t.Error("kredensial dalam pesan error harus tersensor")
	}
}

func TestExtractClientIP(t *testing.T) {
	cases := map[string]string{
		"203.0.113.9":            "203.0.113.9",
		`{"ip":"198.51.100.2"}`:  "198.51.100.2",
		"your ip is 192.0.2.44.": "192.0.2.44",
		"no ip here":             "",
	}
	for body, want := range cases {
		if got := ExtractClientIP(body); got != want {
			t.Errorf("ExtractClientIP(%q) = %q, mau %q", body, got, want)
		}
	}
}

func TestTestChainReachableAndDead(t *testing.T) {
	// Listener lokal = "hop" yang hidup (TCP accept saja cukup untuk hop pertama).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	live := "http://" + ln.Addr().String()

	hops, err := ParseChain([]string{live})
	if err != nil {
		t.Fatal(err)
	}
	st := TestChain(context.Background(), hops, 2*time.Second)
	if len(st) != 1 || !st[0].Reachable {
		t.Fatalf("hop hidup harus reachable: %+v", st)
	}
	if len(st[0].ResolvedIPs) == 0 {
		t.Error("127.0.0.1 harus ter-resolve")
	}

	// Port mati → gagal, dengan pesan error (tersensor).
	dead, _ := ParseChain([]string{"socks5://u:p@127.0.0.1:1"})
	ds := TestChain(context.Background(), dead, time.Second)
	if ds[0].Reachable {
		t.Error("port mati tak boleh reachable")
	}
	if ds[0].Err == "" || strings.Contains(ds[0].Err, "p@") {
		t.Errorf("error hop harus ada & tersensor: %q", ds[0].Err)
	}
}

func TestFetchScopeEnforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		fmt.Fprintf(w, `{"ip":%q}`, host)
	}))
	defer srv.Close()

	// In-scope: 127.0.0.1 (host httptest) → Fetch diizinkan & mengembalikan IP.
	guard, errs := scope.New([]string{"127.0.0.1"}, nil)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	ok := New(guard, nil).Fetch(context.Background(), srv.URL+"/ip", 5*time.Second)
	if !ok.Allowed || ok.Status != http.StatusOK {
		t.Fatalf("echo in-scope harus diizinkan 200: %+v", ok)
	}
	if ExtractClientIP(ok.Body) == "" {
		t.Errorf("body echo harus memuat IP: %q", ok.Body)
	}

	// Out-of-scope host → ditolak scope guard SEBELUM koneksi (default-deny).
	deny, _ := scope.New([]string{"example.test"}, nil)
	res := New(deny, nil).Fetch(context.Background(), srv.URL+"/ip", 5*time.Second)
	if res.Allowed {
		t.Errorf("host di luar scope harus ditolak: %+v", res)
	}
}
