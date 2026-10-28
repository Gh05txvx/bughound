package egress

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"bughound/internal/scope"
)

// inScopeTarget: httptest server di 127.0.0.1 yang kita jadikan in-scope lewat
// IP loopback (scope guard mengizinkan IP in-scope eksplisit; dialGuarded pun
// mengizinkan loopback hanya bila in-scope).
func newGatewayToEcho(t *testing.T, lim Waiter) (*Gateway, *httptest.Server) {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "echo %s %s", r.Method, r.URL.RequestURI())
	}))
	g, _ := scope.New([]string{"127.0.0.1"}, nil)
	p := New(g, nil)
	gw, err := NewGateway(p, ts.URL, lim)
	if err != nil {
		ts.Close()
		t.Fatalf("NewGateway: %v", err)
	}
	t.Cleanup(ts.Close)
	return gw, ts
}

func TestGatewayForwardsAndCaptures(t *testing.T) {
	gw, _ := newGatewayToEcho(t, nil)
	addr, stop, err := gw.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	resp, err := http.Get("http://" + addr + "/api/users?id=1")
	if err != nil {
		t.Fatalf("GET lewat gateway: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if got := string(body); !strings.Contains(got, "echo GET /api/users?id=1") {
		t.Errorf("respons target tak diteruskan: %q", got)
	}

	recs := gw.Records()
	if len(recs) != 1 {
		t.Fatalf("ingin 1 kandidat terekam, dapat %d: %+v", len(recs), recs)
	}
	if recs[0].Method != "GET" || !strings.HasSuffix(recs[0].URL, "/api/users?id=1") {
		t.Errorf("kandidat salah: %+v", recs[0])
	}
	if recs[0].Status != http.StatusOK {
		t.Errorf("status kandidat = %d, ingin 200", recs[0].Status)
	}
}

func TestGatewayDedupCounts(t *testing.T) {
	gw, _ := newGatewayToEcho(t, nil)
	addr, stop, _ := gw.Listen("127.0.0.1:0")
	defer stop()

	for i := 0; i < 3; i++ {
		resp, err := http.Get("http://" + addr + "/same")
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	recs := gw.Records()
	if len(recs) != 1 {
		t.Fatalf("path sama harus dedup jadi 1 kandidat, dapat %d", len(recs))
	}
	if recs[0].Count != 3 {
		t.Errorf("Count = %d, ingin 3", recs[0].Count)
	}
}

func TestGatewayRejectsOutOfScopeTarget(t *testing.T) {
	g, _ := scope.New([]string{"demo.test"}, []string{"evil.test"})
	p := New(g, nil)
	if _, err := NewGateway(p, "http://evil.test", nil); err == nil {
		t.Error("target out-of-scope harus ditolak saat pembuatan (fail closed)")
	}
	if _, err := NewGateway(p, "http://tak-terdaftar.test", nil); err == nil {
		t.Error("target yang tak terbukti in-scope harus ditolak (default-deny)")
	}
	if _, err := NewGateway(p, "", nil); err == nil {
		t.Error("target kosong harus error")
	}
	if _, err := NewGateway(p, "ftp://demo.test", nil); err == nil {
		t.Error("skema non-http harus error")
	}
}

// countingWaiter memastikan rate limiter dipanggil pada tiap penerusan.
type countingWaiter struct {
	mu sync.Mutex
	n  int
}

func (c *countingWaiter) Wait(context.Context) error {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return nil
}

func TestGatewayRateLimited(t *testing.T) {
	cw := &countingWaiter{}
	gw, _ := newGatewayToEcho(t, cw)
	addr, stop, _ := gw.Listen("127.0.0.1:0")
	defer stop()

	for i := 0; i < 2; i++ {
		resp, err := http.Get("http://" + addr + "/x")
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	if cw.n != 2 {
		t.Errorf("rate limiter dipanggil %d kali, ingin 2 (satu per penerusan)", cw.n)
	}
}
