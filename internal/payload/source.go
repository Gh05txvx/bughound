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

// SourceKind decides how a source is scanned.
type SourceKind string

const (
	// KindNucleiDir: a directory of nuclei templates (YAML with an `info:` block).
	// Metadata is derived automatically from the native body (BH-SPEC-PAYLOAD §Format).
	KindNucleiDir SourceKind = "nuclei-dir"
	// KindCustomDir: a directory of your own templates. nuclei-style templates
	// are derived from `info:`; other payloads use a `<name>.meta.yaml` sidecar.
	KindCustomDir SourceKind = "custom-dir"
)

// Source is one template source registered in the configuration
// (BH-SPEC-PAYLOAD §Bank structure and sources). Adding a source = adding one
// configuration entry; no code change is needed.
type Source struct {
	ID     string
	Engine string
	Kind   SourceKind
	Path   string
	Trust  Trust
}

// maxTemplateBytes caps the size of a file read for metadata (nuclei templates
// are small; a huge file is almost certainly not a template). It protects memory.
const maxTemplateBytes = 1 << 20 // 1 MiB

// Build scans every source and builds the catalog. It never fails fatally
// because of one broken file or one unavailable source: a file that fails to
// parse is skipped, and a source whose directory is missing is marked
// Available=false. It only reads local files, with no network.
func Build(ctx context.Context, sources []Source) Catalog {
	now := time.Now().UTC().Truncate(time.Second)
	cat := Catalog{BuiltAt: now}
	seen := map[string]bool{} // dedup template_id across sources (the first one wins)
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
		info.Note = "source path is empty"
		return nil, info
	}
	st, err := os.Stat(src.Path)
	if err != nil || !st.IsDir() {
		info.Note = "directory not available"
		return nil, info
	}
	info.Available = true
	info.Version = nucleiTemplatesVersion(src) // best effort, "" when unknown

	var entries []Entry
	var skipped int
	_ = filepath.WalkDir(src.Path, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return nil // skip entries that cannot be read, do not stop the walk
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
		info.Note = fmt.Sprintf("%d files skipped (not a template / failed to parse)", skipped)
	}
	return entries, info
}

// entryFromFile builds one Entry from a template file. It returns ok=false when
// the file is not a template that can be cataloged (no id/info and no sidecar).
func entryFromFile(src Source, path string, now time.Time) (Entry, bool) {
	body, err := readCapped(path)
	if err != nil {
		return Entry{}, false
	}
	rel := relPath(src.Path, path)
	version := "sha256:" + hashHex(body)

	var tmpl nucleiTemplate
	_ = yaml.Unmarshal(body, &tmpl) // ignore the error: the file may not be a nuclei template

	// The (optional) sidecar completes or overrides the metadata for non-nuclei payloads.
	sidecar, hasSidecar := readSidecar(path)

	nativeID := strings.TrimSpace(tmpl.ID)
	if nativeID == "" && !hasSidecar {
		return Entry{}, false // not a nuclei template and no sidecar → not an entry
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
		e.Type = strings.ToLower(nativeID) // in line with finding.Type (the nuclei adapter uses the template-id)
	}
	if sev, known := normSeverity(tmpl.Info.Severity); known {
		e.SeverityDefault = sev
	}

	// template_id: "<engine>:<native-id>" (BH-SPEC-PAYLOAD §Open questions).
	idPart := nativeID
	if idPart == "" {
		idPart = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	e.TemplateID = engine + ":" + idPart

	// Apply the sidecar on top of the derived metadata.
	if hasSidecar {
		applySidecar(&e, sidecar)
	}
	if strings.TrimSpace(e.Name) == "" {
		e.Name = idPart
		e.Note = "name metadata not found; needs completing"
	}
	if !e.SeverityDefault.Valid() {
		e.Note = strings.TrimSpace(e.Note + " severity_default unknown")
	}
	// Safety: use the sidecar value when it is set and valid; otherwise derive it from the tags.
	if !e.Safety.Valid() {
		e.Safety = classifySafety(e.Tags)
	}

	e.Enabled = e.canEnable()
	if !e.Enabled && e.Note == "" && e.Trust != TrustTrusted {
		e.Note = "non-trusted source; disabled until reviewed"
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
	// A sidecar's trust may only LOWER the level, never raise it above the source:
	// the source is the trust boundary, not the cataloged file.
	if t := Trust(strings.ToLower(strings.TrimSpace(s.Trust))); t.Valid() && trustRank(t) < trustRank(e.Trust) {
		e.Trust = t
	}
}

// nucleiTemplate is the subset of blocks we read from a nuclei template.
type nucleiTemplate struct {
	ID   string `yaml:"id"`
	Info struct {
		Name      string      `yaml:"name"`
		Severity  string      `yaml:"severity"`
		Tags      yamlStrList `yaml:"tags"`
		Reference yamlStrList `yaml:"reference"`
	} `yaml:"info"`
}

// metaSidecar is the content of a "<name>.meta.yaml" file for non-nuclei payloads.
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

// yamlStrList accepts a YAML value that is a sequence of strings OR a single
// scalar (comma-separated), because nuclei templates write tags/reference in
// either form.
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

// nucleiTemplatesVersion tries to read the nuclei-templates version from the
// nuclei configuration (~/.config/nuclei/.templates-config.json). Best effort;
// "" on failure.
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
		return nil, fmt.Errorf("payload: file too large (%d bytes)", st.Size())
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

// ResolveNucleiDir picks the nuclei-templates directory: the explicit argument
// → env NUCLEI_TEMPLATES_DIR → $HOME/nuclei-templates (nuclei's default location).
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

// DefaultSources builds the built-in source list: the official nuclei-templates
// (trusted, baked in when the image is built) + your own custom directory when
// one is configured. An empty customDir → try env BUGHOUND_CUSTOM_TEMPLATES;
// still empty → skipped.
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
