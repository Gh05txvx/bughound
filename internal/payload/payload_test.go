package payload

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"bughound/internal/finding"
)

// writeFile writes a file (creating parent dirs) to set up a test source.
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

// A nuclei template from a trusted source → metadata derived from info:, enabled.
func TestBuild_NucleiTrustedDerivesMetadata(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "http", "prometheus.yaml"), sampleNucleiTemplate)
	// Hidden files and non-templates must be skipped.
	writeFile(t, filepath.Join(dir, ".git", "x.yaml"), "id: should-be-skipped\ninfo:\n  name: x\n")
	writeFile(t, filepath.Join(dir, "config.yaml"), "settings:\n  foo: bar\n")

	cat := Build(context.Background(), []Source{
		{ID: "nuclei-official", Engine: "nuclei", Kind: KindNucleiDir, Path: dir, Trust: TrustTrusted},
	})

	e, ok := findEntry(cat.Entries, "nuclei:prometheus-metrics")
	if !ok {
		t.Fatalf("entry nuclei:prometheus-metrics is missing; entries=%+v", cat.Entries)
	}
	if e.Engine != "nuclei" {
		t.Errorf("engine=%q, want nuclei", e.Engine)
	}
	if e.Name != "Prometheus Metrics Exposure" {
		t.Errorf("name=%q", e.Name)
	}
	if e.SeverityDefault != finding.SeverityMedium {
		t.Errorf("severity=%q, want medium", e.SeverityDefault)
	}
	if e.Type != "prometheus-metrics" {
		t.Errorf("type=%q, want prometheus-metrics (in line with finding.Type)", e.Type)
	}
	if len(e.Tags) != 2 || e.Tags[0] != "exposure" || e.Tags[1] != "prometheus" {
		t.Errorf("tags=%v, want [exposure prometheus]", e.Tags)
	}
	if e.Trust != TrustTrusted || !e.Enabled {
		t.Errorf("trust=%q enabled=%v, want trusted+enabled", e.Trust, e.Enabled)
	}
	if e.Version == "" {
		t.Errorf("version (content hash) must be set")
	}
	if e.NativeRef != "http/prometheus.yaml" {
		t.Errorf("native_ref=%q, want http/prometheus.yaml", e.NativeRef)
	}
	// config.yaml (no id/info) and the file under .git must be skipped → only 1 entry.
	if len(cat.Entries) != 1 {
		t.Errorf("entry count=%d, want 1 (non-template and hidden files skipped)", len(cat.Entries))
	}
	if len(cat.Sources) != 1 || !cat.Sources[0].Available || cat.Sources[0].Count != 1 || cat.Sources[0].Enabled != 1 {
		t.Errorf("wrong source summary: %+v", cat.Sources)
	}
}

// A template from a non-trusted source (review) ENTERS the catalog but stays
// DISABLED until it is reviewed (BH-SPEC-PAYLOAD §Security).
func TestBuild_ReviewSourceDisabledByDefault(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "x.yaml"), sampleNucleiTemplate)

	cat := Build(context.Background(), []Source{
		{ID: "community", Engine: "nuclei", Kind: KindNucleiDir, Path: dir, Trust: TrustReview},
	})
	e, ok := findEntry(cat.Entries, "nuclei:prometheus-metrics")
	if !ok {
		t.Fatal("entry is missing")
	}
	if e.Trust != TrustReview {
		t.Errorf("trust=%q, want review", e.Trust)
	}
	if e.Enabled {
		t.Errorf("a review template must not be enabled automatically")
	}
	if e.Note == "" {
		t.Errorf("a disabled review template must carry a note with the reason")
	}
}

// A non-nuclei payload uses a .meta.yaml sidecar for its metadata
// (BH-SPEC-PAYLOAD §Format of one template).
func TestBuild_SidecarMetadata(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "openredirect.yaml"), "payloads:\n  - \"/logout?next=//evil\"\n")
	writeFile(t, filepath.Join(dir, "openredirect.meta.yaml"), `template_id: custom:open-redirect-logout
engine: custom
name: Open redirect in the logout parameter
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
		t.Fatalf("sidecar entry is missing; entries=%+v", cat.Entries)
	}
	if e.Engine != "custom" {
		t.Errorf("engine=%q, want custom", e.Engine)
	}
	if e.Name != "Open redirect in the logout parameter" {
		t.Errorf("name=%q", e.Name)
	}
	if e.Type != "open-redirect" || e.SeverityDefault != finding.SeverityMedium {
		t.Errorf("type=%q sev=%q", e.Type, e.SeverityDefault)
	}
	if !e.Enabled {
		t.Errorf("a trusted sidecar with complete metadata must be enabled")
	}
	// Only one entry (the .meta.yaml file does not count as an entry of its own).
	if len(cat.Entries) != 1 {
		t.Errorf("entry count=%d, want 1", len(cat.Entries))
	}
}

// A source whose directory is missing is marked unavailable, with no panic or failure.
func TestBuild_MissingDirIsNotFatal(t *testing.T) {
	cat := Build(context.Background(), []Source{
		{ID: "missing", Engine: "nuclei", Kind: KindNucleiDir, Path: filepath.Join(t.TempDir(), "does-not-exist"), Trust: TrustTrusted},
	})
	if len(cat.Entries) != 0 {
		t.Errorf("there must be no entries from a missing dir")
	}
	if len(cat.Sources) != 1 || cat.Sources[0].Available {
		t.Errorf("the source must be marked unavailable: %+v", cat.Sources)
	}
}

// Version = content hash: the content changes → the version changes (change detection).
func TestBuild_VersionTracksContent(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "t.yaml")
	writeFile(t, p, sampleNucleiTemplate)
	v1 := Build(context.Background(), []Source{{ID: "s", Engine: "nuclei", Kind: KindNucleiDir, Path: dir, Trust: TrustTrusted}}).Entries[0].Version

	writeFile(t, p, sampleNucleiTemplate+"\n# changed\n")
	v2 := Build(context.Background(), []Source{{ID: "s", Engine: "nuclei", Kind: KindNucleiDir, Path: dir, Trust: TrustTrusted}}).Entries[0].Version

	if v1 == v2 {
		t.Errorf("the version must change when the content changes: %s == %s", v1, v2)
	}
}

func TestDefaultSources_NucleiFromEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NUCLEI_TEMPLATES_DIR", dir)
	t.Setenv("BUGHOUND_CUSTOM_TEMPLATES", "")
	srcs := DefaultSources("", "")
	if len(srcs) != 1 || srcs[0].Path != dir || srcs[0].Kind != KindNucleiDir || srcs[0].Trust != TrustTrusted {
		t.Fatalf("wrong DefaultSources from env: %+v", srcs)
	}
}
