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

// fakeGeo is a fake offline Resolver to test the wiring without an .mmdb file.
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

// Without Config.GeoIP, the server uses Nop (feature off) — never nil.
func TestServerGeoDefaultsToNop(t *testing.T) {
	srv, _ := newTestServer(t)
	if srv.geo == nil {
		t.Fatal("s.geo must not be nil")
	}
	if srv.geo.Loaded() {
		t.Error("without a DB, Loaded() must be false")
	}
	if _, ok := srv.geo.(geoip.Nop); !ok {
		t.Errorf("default must be geoip.Nop, got %T", srv.geo)
	}
}

func TestServerGeoInjected(t *testing.T) {
	fake := fakeGeo{loaded: true}
	srv := newServerWithGeo(t, fake)
	if !srv.geo.Loaded() {
		t.Error("the injected resolver must be used (Loaded=true)")
	}
}

// renderProxyResult runs the proxy_result partial with the given data.
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

// DB loaded → the exit IP's country & ASN show in the result.
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
			t.Errorf("the result must contain %q\n%s", want, body)
		}
	}
	// The "DB not loaded" hint must NOT show when GeoLoaded.
	if strings.Contains(body, "BUGHOUND_GEOIP_COUNTRY_DB") {
		t.Error("the DB-not-loaded hint must not show when GeoLoaded=true")
	}
}

// DB not loaded → the IP still shows, plus a hint on how to enable it (without a country).
func TestProxyResultGeoDisabledHint(t *testing.T) {
	srv, _ := newTestServer(t)
	res := &proxyCheckResult{Echo: &proxyEchoResult{
		Allowed: true, SourceIP: "203.0.113.9", ExitIP: "185.220.101.4", Changed: true,
		GeoLoaded: false,
	}}
	body := renderProxyResult(t, srv, res)
	if !strings.Contains(body, "185.220.101.4") {
		t.Error("the exit IP must still show")
	}
	if !strings.Contains(body, "BUGHOUND_GEOIP_COUNTRY_DB") {
		t.Errorf("there must be a hint on how to enable GeoIP\n%s", body)
	}
	// No country label at all.
	if strings.Contains(body, "class=\"geo\"") {
		t.Error("there must be no geo span when the DB is not loaded")
	}
}

// DB loaded but the IP is not in the DB (e.g. a private IP) → a "not found" note.
func TestProxyResultGeoNotFound(t *testing.T) {
	srv, _ := newTestServer(t)
	res := &proxyCheckResult{Echo: &proxyEchoResult{
		Allowed: true, SourceIP: "203.0.113.9", ExitIP: "10.0.0.5", Changed: true,
		GeoLoaded: true, // the DB is present, but ExitGeo is empty (unlisted)
	}}
	body := renderProxyResult(t, srv, res)
	if !strings.Contains(body, "was not found in the GeoIP DB") {
		t.Errorf("there must be a country-not-found note\n%s", body)
	}
}
