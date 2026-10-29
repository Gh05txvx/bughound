package payload

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"bughound/internal/finding"
)

// writeFile menulis berkas (membuat dir induk) untuk menyiapkan sumber uji.
func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

const sampleNucleiTemplate = `id: prometheus-metrics
info:
  name: Prometheus Metrics Exposure
  severity: medium
  tags: exposure,prometheus
  reference:
    - https://example.com/ref
http:
  - method: GET
    path:
      - "{{BaseURL}}/metrics"
`

func findEntry(entries []Entry, id string) (Entry, bool) {
	for _, e := range entries {
		if e.TemplateID == id {
			return e, true
		}
	}
	return Entry{}, false
}

// Template nuclei dari sumber trusted → metadata diturunkan dari info:, aktif.
func TestBuild_NucleiTrustedDerivesMetadata(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "http", "prometheus.yaml"), sampleNucleiTemplate)
	// Berkas tersembunyi & non-template harus dilewati.
	writeFile(t, filepath.Join(dir, ".git", "x.yaml"), "id: should-be-skipped\ninfo:\n  name: x\n")
	writeFile(t, filepath.Join(dir, "config.yaml"), "settings:\n  foo: bar\n")

	cat := Build(context.Background(), []Source{
		{ID: "nuclei-official", Engine: "nuclei", Kind: KindNucleiDir, Path: dir, Trust: TrustTrusted},
	})

	e, ok := findEntry(cat.Entries, "nuclei:prometheus-metrics")
	if !ok {
		t.Fatalf("entri nuclei:prometheus-metrics tak ada; entries=%+v", cat.Entries)
	}
	if e.Engine != "nuclei" {
		t.Errorf("engine=%q, ingin nuclei", e.Engine)
	}
	if e.Name != "Prometheus Metrics Exposure" {
		t.Errorf("name=%q", e.Name)
	}
	if e.SeverityDefault != finding.SeverityMedium {
		t.Errorf("severity=%q, ingin medium", e.SeverityDefault)
	}
	if e.Type != "prometheus-metrics" {
		t.Errorf("type=%q, ingin prometheus-metrics (selaras finding.Type)", e.Type)
	}
	if len(e.Tags) != 2 || e.Tags[0] != "exposure" || e.Tags[1] != "prometheus" {
		t.Errorf("tags=%v, ingin [exposure prometheus]", e.Tags)
	}
	if e.Trust != TrustTrusted || !e.Enabled {
		t.Errorf("trust=%q enabled=%v, ingin trusted+aktif", e.Trust, e.Enabled)
	}
	if e.Version == "" {
		t.Errorf("version (hash isi) harus terisi")
	}
	if e.NativeRef != "http/prometheus.yaml" {
		t.Errorf("native_ref=%q, ingin http/prometheus.yaml", e.NativeRef)
	}
	// config.yaml (tanpa id/info) & berkas di .git harus dilewati → hanya 1 entri.
	if len(cat.Entries) != 1 {
		t.Errorf("jumlah entri=%d, ingin 1 (non-template & hidden dilewati)", len(cat.Entries))
	}
	if len(cat.Sources) != 1 || !cat.Sources[0].Available || cat.Sources[0].Count != 1 || cat.Sources[0].Enabled != 1 {
		t.Errorf("ringkasan sumber salah: %+v", cat.Sources)
	}
}

// Template dari sumber non-trusted (review) MASUK katalog tapi NONAKTIF sampai
// ditinjau (BH-SPEC-PAYLOAD §Keamanan).
func TestBuild_ReviewSourceDisabledByDefault(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "x.yaml"), sampleNucleiTemplate)

	cat := Build(context.Background(), []Source{
		{ID: "komunitas", Engine: "nuclei", Kind: KindNucleiDir, Path: dir, Trust: TrustReview},
	})
	e, ok := findEntry(cat.Entries, "nuclei:prometheus-metrics")
	if !ok {
		t.Fatal("entri tak ada")
	}
	if e.Trust != TrustReview {
		t.Errorf("trust=%q, ingin review", e.Trust)
	}
	if e.Enabled {
		t.Errorf("template review tak boleh aktif otomatis")
	}
	if e.Note == "" {
		t.Errorf("template review nonaktif harus punya catatan alasan")
	}
}

// Payload non-nuclei memakai sidecar .meta.yaml untuk metadata (BH-SPEC-PAYLOAD
// §Format satu template).
func TestBuild_SidecarMetadata(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "openredirect.yaml"), "payloads:\n  - \"/logout?next=//evil\"\n")
	writeFile(t, filepath.Join(dir, "openredirect.meta.yaml"), `template_id: custom:open-redirect-logout
engine: custom
name: Open redirect pada parameter logout
type: open-redirect
severity_default: medium
tags: [open-redirect, custom]
trust: trusted
`)

	cat := Build(context.Background(), []Source{
		{ID: "custom", Engine: "custom", Kind: KindCustomDir, Path: dir, Trust: TrustTrusted},
	})
	e, ok := findEntry(cat.Entries, "custom:open-redirect-logout")
	if !ok {
		t.Fatalf("entri sidecar tak ada; entries=%+v", cat.Entries)
	}
	if e.Engine != "custom" {
		t.Errorf("engine=%q, ingin custom", e.Engine)
	}
	if e.Name != "Open redirect pada parameter logout" {
		t.Errorf("name=%q", e.Name)
	}
	if e.Type != "open-redirect" || e.SeverityDefault != finding.SeverityMedium {
		t.Errorf("type=%q sev=%q", e.Type, e.SeverityDefault)
	}
	if !e.Enabled {
		t.Errorf("sidecar trusted dengan metadata lengkap harus aktif")
	}
	// Hanya satu entri (file .meta.yaml tidak dihitung sebagai entri sendiri).
	if len(cat.Entries) != 1 {
		t.Errorf("jumlah entri=%d, ingin 1", len(cat.Entries))
	}
}

// Sumber yang direktorinya tak ada ditandai tak tersedia, tanpa panik/gagal.
func TestBuild_MissingDirIsNotFatal(t *testing.T) {
	cat := Build(context.Background(), []Source{
		{ID: "hilang", Engine: "nuclei", Kind: KindNucleiDir, Path: filepath.Join(t.TempDir(), "tidak-ada"), Trust: TrustTrusted},
	})
	if len(cat.Entries) != 0 {
		t.Errorf("tak boleh ada entri dari dir yang hilang")
	}
	if len(cat.Sources) != 1 || cat.Sources[0].Available {
		t.Errorf("sumber harus ditandai tak tersedia: %+v", cat.Sources)
	}
}

// Versi = hash isi: isi berubah → versi berubah (deteksi perubahan).
func TestBuild_VersionTracksContent(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "t.yaml")
	writeFile(t, p, sampleNucleiTemplate)
	v1 := Build(context.Background(), []Source{{ID: "s", Engine: "nuclei", Kind: KindNucleiDir, Path: dir, Trust: TrustTrusted}}).Entries[0].Version

	writeFile(t, p, sampleNucleiTemplate+"\n# diubah\n")
	v2 := Build(context.Background(), []Source{{ID: "s", Engine: "nuclei", Kind: KindNucleiDir, Path: dir, Trust: TrustTrusted}}).Entries[0].Version

	if v1 == v2 {
		t.Errorf("versi harus berubah saat isi berubah: %s == %s", v1, v2)
	}
}

func TestDefaultSources_NucleiFromEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NUCLEI_TEMPLATES_DIR", dir)
	t.Setenv("BUGHOUND_CUSTOM_TEMPLATES", "")
	srcs := DefaultSources("", "")
	if len(srcs) != 1 || srcs[0].Path != dir || srcs[0].Kind != KindNucleiDir || srcs[0].Trust != TrustTrusted {
		t.Fatalf("DefaultSources dari env salah: %+v", srcs)
	}
}
