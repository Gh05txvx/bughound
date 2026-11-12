package web

import (
	"net/http/httptest"
	"strings"
	"testing"

	"bughound/internal/audit"
	"bughound/internal/engine"
	"bughound/internal/engine/ffuf"
	"bughound/internal/engine/nuclei"
	"bughound/internal/geoip"
	"bughound/internal/recon"
	"bughound/internal/secret"
	"bughound/internal/store"
)

// fakeGeo adalah Resolver offline palsu untuk menguji wiring tanpa file .mmdb.
type fakeGeo struct {
	m      map[string]geoip.Info
	loaded bool
}

func (f fakeGeo) Resolve(ip string) geoip.Info { return f.m[ip] }
func (f fakeGeo) Loaded() bool                 { return f.loaded }

func newServerWithGeo(t *testing.T, geo geoip.Resolver) *Server {
	t.Helper()
	k, _ := secret.NewRandomKey()
	srv, err := NewServer(Config{
		Store:        store.NewMem(),
		Engines:      []engine.Engine{nuclei.Mock{}, ffuf.Mock{}},
		Recon:        recon.MockPipeline{},
		Vault:        secret.NewMemVault(secret.NewKeyring(k)),
		Audit:        audit.NewMemLog([]byte("test-audit-key")),
		AuthDisabled: true,
		GeoIP:        geo,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv
}

// Tanpa Config.GeoIP, server memakai Nop (fitur mati) — tak pernah nil.
func TestServerGeoDefaultsToNop(t *testing.T) {
	srv, _ := newTestServer(t)
	if srv.geo == nil {
		t.Fatal("s.geo tak boleh nil")
	}
	if srv.geo.Loaded() {
		t.Error("tanpa DB, Loaded() harus false")
	}
	if _, ok := srv.geo.(geoip.Nop); !ok {
		t.Errorf("default harus geoip.Nop, dapat %T", srv.geo)
	}
}

func TestServerGeoInjected(t *testing.T) {
	fake := fakeGeo{loaded: true}
	srv := newServerWithGeo(t, fake)
	if !srv.geo.Loaded() {
		t.Error("resolver yang di-inject harus dipakai (Loaded=true)")
	}
}

// renderProxyResult mengeksekusi partial proxy_result dengan data yang diberikan.
func renderProxyResult(t *testing.T, srv *Server, res *proxyCheckResult) string {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/proxy/check", nil)
	srv.render(rec, req, "proxy", "proxy_result", res)
	if rec.Code != 200 {
		t.Fatalf("render proxy_result code=%d, body=%s", rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

// DB termuat → negara & ASN IP exit tampil di hasil.
func TestProxyResultShowsCountryAndASN(t *testing.T) {
	srv, _ := newTestServer(t)
	res := &proxyCheckResult{Echo: &proxyEchoResult{
		Allowed:   true,
		SourceIP:  "203.0.113.9",
		ExitIP:    "185.220.101.4",
		Changed:   true,
		GeoLoaded: true,
		SourceGeo: geoip.Info{CountryCode: "ID", Country: "Indonesia"},
		ExitGeo:   geoip.Info{CountryCode: "NL", Country: "Netherlands", ASN: 205100, ASNOrg: "DigitalOcean, LLC"},
	}}
	body := renderProxyResult(t, srv, res)
	for _, want := range []string{"185.220.101.4", "Netherlands (NL)", "AS205100", "DigitalOcean, LLC", "Indonesia (ID)"} {
		if !strings.Contains(body, want) {
			t.Errorf("hasil harus memuat %q\n%s", want, body)
		}
	}
	// Hint "DB tak dimuat" TAK boleh muncul saat GeoLoaded.
	if strings.Contains(body, "BUGHOUND_GEOIP_COUNTRY_DB") {
		t.Error("hint DB-tak-dimuat tak boleh tampil saat GeoLoaded=true")
	}
}

// DB tak termuat → IP tetap tampil, plus hint cara mengaktifkan (tanpa negara).
func TestProxyResultGeoDisabledHint(t *testing.T) {
	srv, _ := newTestServer(t)
	res := &proxyCheckResult{Echo: &proxyEchoResult{
		Allowed: true, SourceIP: "203.0.113.9", ExitIP: "185.220.101.4", Changed: true,
		GeoLoaded: false,
	}}
	body := renderProxyResult(t, srv, res)
	if !strings.Contains(body, "185.220.101.4") {
		t.Error("IP exit tetap harus tampil")
	}
	if !strings.Contains(body, "BUGHOUND_GEOIP_COUNTRY_DB") {
		t.Errorf("harus ada hint cara aktifkan GeoIP\n%s", body)
	}
	// Tak ada label negara apa pun.
	if strings.Contains(body, "class=\"geo\"") {
		t.Error("tak boleh ada span geo saat DB tak dimuat")
	}
}

// DB termuat tapi IP tak ada di DB (mis. IP privat) → catatan "tak ditemukan".
func TestProxyResultGeoNotFound(t *testing.T) {
	srv, _ := newTestServer(t)
	res := &proxyCheckResult{Echo: &proxyEchoResult{
		Allowed: true, SourceIP: "203.0.113.9", ExitIP: "10.0.0.5", Changed: true,
		GeoLoaded: true, // DB ada, tapi ExitGeo kosong (tak terdaftar)
	}}
	body := renderProxyResult(t, srv, res)
	if !strings.Contains(body, "tak ditemukan di DB GeoIP") {
		t.Errorf("harus ada catatan negara tak ditemukan\n%s", body)
	}
}
