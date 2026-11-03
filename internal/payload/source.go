package payload

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// SourceKind menentukan cara sebuah sumber di-scan.
type SourceKind string

const (
	// KindNucleiDir: direktori berisi template nuclei (YAML dengan blok `info:`).
	// Metadata diturunkan otomatis dari body native (BH-SPEC-PAYLOAD §Format).
	KindNucleiDir SourceKind = "nuclei-dir"
	// KindCustomDir: direktori template milik sendiri. Template nuclei-style
	// diturunkan dari `info:`; payload lain memakai sidecar `<nama>.meta.yaml`.
	KindCustomDir SourceKind = "custom-dir"
)

// Source adalah satu sumber template yang didaftarkan di konfigurasi
// (BH-SPEC-PAYLOAD §Struktur bank & sumber). Menambah sumber = menambah satu
// entri konfigurasi; tak perlu mengubah kode.
type Source struct {
	ID     string
	Engine string
	Kind   SourceKind
	Path   string
	Trust  Trust
}

// maxTemplateBytes membatasi ukuran file yang dibaca untuk metadata (template
// nuclei kecil; file raksasa hampir pasti bukan template). Menjaga memori.
const maxTemplateBytes = 1 << 20 // 1 MiB

// Build men-scan semua sumber dan membangun katalog. Tidak pernah gagal fatal
// karena satu file rusak atau satu sumber tak tersedia: file yang gagal diurai
// dilewati, sumber yang direktorinya tak ada ditandai Available=false. Hanya
// membaca file lokal — tanpa jaringan.
func Build(ctx context.Context, sources []Source) Catalog {
	now := time.Now().UTC().Truncate(time.Second)
	cat := Catalog{BuiltAt: now}
	seen := map[string]bool{} // dedup template_id lintas sumber (yang pertama menang)
	for _, src := range sources {
		entries, info := scanSource(ctx, src, now)
		info.UpdatedAt = now
		kept := entries[:0]
		for _, e := range entries {
			if seen[e.TemplateID] {
				continue
			}
			seen[e.TemplateID] = true
			kept = append(kept, e)
		}
		info.Count = len(kept)
		info.Enabled = 0
		for _, e := range kept {
			if e.Enabled {
				info.Enabled++
			}
		}
		cat.Entries = append(cat.Entries, kept...)
		cat.Sources = append(cat.Sources, info)
	}
	sort.SliceStable(cat.Entries, func(i, j int) bool {
		return cat.Entries[i].TemplateID < cat.Entries[j].TemplateID
	})
	return cat
}

func scanSource(ctx context.Context, src Source, now time.Time) ([]Entry, SourceInfo) {
	info := SourceInfo{
		ID: src.ID, Engine: src.Engine, Kind: string(src.Kind),
		Path: src.Path, Trust: src.Trust,
	}
	if strings.TrimSpace(src.Path) == "" {
		info.Note = "path sumber kosong"
		return nil, info
	}
	st, err := os.Stat(src.Path)
	if err != nil || !st.IsDir() {
		info.Note = "direktori tak tersedia"
		return nil, info
	}
	info.Available = true
	info.Version = nucleiTemplatesVersion(src) // best-effort, "" bila tak diketahui

	var entries []Entry
	var skipped int
	_ = filepath.WalkDir(src.Path, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return nil // lewati entri yang tak terbaca, jangan hentikan walk
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if isHiddenDir(d.Name()) && path != src.Path {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !isYAML(name) || strings.HasSuffix(name, ".meta.yaml") || strings.HasSuffix(name, ".meta.yml") {
			return nil
		}
		e, ok := entryFromFile(src, path, now)
		if !ok {
			skipped++
			return nil
		}
		entries = append(entries, e)
		return nil
	})
	if skipped > 0 {
		info.Note = fmt.Sprintf("%d berkas dilewati (bukan template / gagal urai)", skipped)
	}
	return entries, info
}

// entryFromFile membangun satu Entry dari file template. Mengembalikan ok=false
// bila file bukan template yang bisa dikatalogkan (tak ada id/info dan tak ada
// sidecar).
func entryFromFile(src Source, path string, now time.Time) (Entry, bool) {
	body, err := readCapped(path)
	if err != nil {
		return Entry{}, false
	}
	rel := relPath(src.Path, path)
	version := "sha256:" + hashHex(body)

	var tmpl nucleiTemplate
	_ = yaml.Unmarshal(body, &tmpl) // abaikan error: file bisa saja bukan template nuclei

	// Sidecar (opsional) melengkapi/menimpa metadata untuk payload non-nuclei.
	sidecar, hasSidecar := readSidecar(path)

	nativeID := strings.TrimSpace(tmpl.ID)
	if nativeID == "" && !hasSidecar {
		return Entry{}, false // bukan template nuclei & tak ada sidecar → bukan entri
	}

	engine := src.Engine
	if hasSidecar && strings.TrimSpace(sidecar.Engine) != "" {
		engine = strings.TrimSpace(sidecar.Engine)
	}
	if engine == "" {
		engine = "nuclei"
	}

	e := Entry{
		Source:     src.ID,
		Engine:     engine,
		NativeRef:  rel,
		Trust:      src.Trust,
		Version:    version,
		AddedAt:    now,
		Name:       strings.TrimSpace(tmpl.Info.Name),
		Tags:       dedupStrings(tmpl.Info.Tags),
		References: dedupStrings(tmpl.Info.Reference),
	}
	if nativeID != "" {
		e.Type = strings.ToLower(nativeID) // selaras finding.Type (adapter nuclei memakai template-id)
	}
	if sev, known := normSeverity(tmpl.Info.Severity); known {
		e.SeverityDefault = sev
	}

	// template_id: "<engine>:<native-id>" (BH-SPEC-PAYLOAD §Pertanyaan terbuka).
	idPart := nativeID
	if idPart == "" {
		idPart = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	e.TemplateID = engine + ":" + idPart

	// Terapkan sidecar di atas metadata turunan.
	if hasSidecar {
		applySidecar(&e, sidecar)
	}
	if strings.TrimSpace(e.Name) == "" {
		e.Name = idPart
		e.Note = "metadata nama tak ditemukan — perlu dilengkapi"
	}
	if !e.SeverityDefault.Valid() {
		e.Note = strings.TrimSpace(e.Note + " severity_default tak diketahui")
	}
	// Safety: pakai nilai sidecar bila diset & sah; selain itu turunkan dari tag.
	if !e.Safety.Valid() {
		e.Safety = classifySafety(e.Tags)
	}

	e.Enabled = e.canEnable()
	if !e.Enabled && e.Note == "" && e.Trust != TrustTrusted {
		e.Note = "sumber non-trusted — nonaktif sampai ditinjau"
	}
	return e, true
}

func applySidecar(e *Entry, s metaSidecar) {
	if v := strings.TrimSpace(s.TemplateID); v != "" {
		e.TemplateID = v
	}
	if v := strings.TrimSpace(s.Name); v != "" {
		e.Name = v
	}
	if v := strings.TrimSpace(s.Type); v != "" {
		e.Type = strings.ToLower(v)
	}
	if sev, known := normSeverity(s.SeverityDefault); known {
		e.SeverityDefault = sev
	}
	if len(s.Tags) > 0 {
		e.Tags = dedupStrings(s.Tags)
	}
	if len(s.References) > 0 {
		e.References = dedupStrings(s.References)
	}
	if sf := Safety(strings.ToLower(strings.TrimSpace(s.Safety))); sf.Valid() {
		e.Safety = sf
	}
	// trust sidecar hanya boleh MENURUNKAN, tak boleh menaikkan di atas sumber:
	// sumber adalah batas kepercayaan, bukan file yang dikatalogkan.
	if t := Trust(strings.ToLower(strings.TrimSpace(s.Trust))); t.Valid() && trustRank(t) < trustRank(e.Trust) {
		e.Trust = t
	}
}

// nucleiTemplate adalah subset blok yang kita baca dari template nuclei.
type nucleiTemplate struct {
	ID   string `yaml:"id"`
	Info struct {
		Name      string      `yaml:"name"`
		Severity  string      `yaml:"severity"`
		Tags      yamlStrList `yaml:"tags"`
		Reference yamlStrList `yaml:"reference"`
	} `yaml:"info"`
}

// metaSidecar adalah isi file "<nama>.meta.yaml" untuk payload non-nuclei.
type metaSidecar struct {
	TemplateID      string   `yaml:"template_id"`
	Engine          string   `yaml:"engine"`
	Name            string   `yaml:"name"`
	Type            string   `yaml:"type"`
	SeverityDefault string   `yaml:"severity_default"`
	Tags            []string `yaml:"tags"`
	References      []string `yaml:"references"`
	Trust           string   `yaml:"trust"`
	Safety          string   `yaml:"safety"`
}

// yamlStrList menerima nilai YAML berupa sequence string ATAU satu skalar
// (dipisah koma), karena template nuclei menulis tags/reference dengan salah
// satu bentuk.
type yamlStrList []string

func (s *yamlStrList) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.SequenceNode:
		var arr []string
		if err := node.Decode(&arr); err != nil {
			return err
		}
		*s = arr
	case yaml.ScalarNode:
		var str string
		if err := node.Decode(&str); err != nil {
			return err
		}
		var out yamlStrList
		for _, p := range strings.Split(str, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		*s = out
	}
	return nil
}

func readSidecar(templatePath string) (metaSidecar, bool) {
	base := strings.TrimSuffix(templatePath, filepath.Ext(templatePath))
	for _, ext := range []string{".meta.yaml", ".meta.yml"} {
		if body, err := readCapped(base + ext); err == nil {
			var m metaSidecar
			if yaml.Unmarshal(body, &m) == nil {
				return m, true
			}
		}
	}
	return metaSidecar{}, false
}

// nucleiTemplatesVersion mencoba membaca versi nuclei-templates dari konfigurasi
// nuclei (~/.config/nuclei/.templates-config.json). Best-effort; "" bila gagal.
func nucleiTemplatesVersion(src Source) string {
	if src.Kind != KindNucleiDir {
		return ""
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	cfg := filepath.Join(home, ".config", "nuclei", ".templates-config.json")
	body, err := readCapped(cfg)
	if err != nil {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
		return ""
	}
	for _, k := range []string{"nuclei-templates-version", "nuclei-templates-latest-version", "templateVersion", "version"} {
		if v, ok := m[k].(string); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func readCapped(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Size() > maxTemplateBytes {
		return nil, fmt.Errorf("payload: berkas terlalu besar (%d byte)", st.Size())
	}
	return os.ReadFile(path)
}

func hashHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])[:12]
}

func isYAML(name string) bool {
	return strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")
}

func isHiddenDir(name string) bool {
	return strings.HasPrefix(name, ".") || name == "node_modules"
}

func relPath(root, path string) string {
	if r, err := filepath.Rel(root, path); err == nil {
		return filepath.ToSlash(r)
	}
	return filepath.ToSlash(path)
}

func dedupStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func trustRank(t Trust) int {
	switch t {
	case TrustTrusted:
		return 3
	case TrustReview:
		return 2
	case TrustUntrusted:
		return 1
	}
	return 0
}

// ResolveNucleiDir memilih direktori nuclei-templates: argumen eksplisit →
// env NUCLEI_TEMPLATES_DIR → $HOME/nuclei-templates (lokasi default nuclei).
func ResolveNucleiDir(explicit string) string {
	if strings.TrimSpace(explicit) != "" {
		return explicit
	}
	if v := strings.TrimSpace(os.Getenv("NUCLEI_TEMPLATES_DIR")); v != "" {
		return v
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, "nuclei-templates")
	}
	return ""
}

// DefaultSources membangun daftar sumber bawaan: nuclei-templates resmi (trusted,
// di-bake saat build image) + direktori custom milik sendiri bila dikonfigurasi.
// customDir kosong → coba env BUGHOUND_CUSTOM_TEMPLATES; tetap kosong → dilewati.
func DefaultSources(nucleiDir, customDir string) []Source {
	var out []Source
	if d := ResolveNucleiDir(nucleiDir); d != "" {
		out = append(out, Source{ID: "nuclei-official", Engine: "nuclei", Kind: KindNucleiDir, Path: d, Trust: TrustTrusted})
	}
	cd := strings.TrimSpace(customDir)
	if cd == "" {
		cd = strings.TrimSpace(os.Getenv("BUGHOUND_CUSTOM_TEMPLATES"))
	}
	if cd != "" {
		out = append(out, Source{ID: "custom", Engine: "custom", Kind: KindCustomDir, Path: cd, Trust: TrustTrusted})
	}
	return out
}
