// Package payload implements the Payload & Template Bank (BH-SPEC-PAYLOAD): one
// neutral CATALOG layer on top of each engine's native templates. Payload
// content is never translated (a nuclei template stays nuclei YAML); bughound
// only adds uniform metadata that catalogs each template so the bank can be
// filtered, updated, extended and traced back.
//
// Model: "hybrid, leaning thin" (BH-SPEC-PAYLOAD §Chosen model). This package
// READS sources (template directories) and builds the catalog; it runs nothing
// and opens no network connections. Execution stays with the engine adapters,
// and every outbound connection still passes the scope guard (BH-SPEC-SCOPE),
// so a template cannot bypass scope.
//
// Traceability: a template_id in the catalog has the form
// "<engine>:<native-id>", and that value is carried into the source_template
// field of a finding (BH-SPEC-FINDING), so every finding can be traced back to
// the payload it came from.
package payload

import (
	"strings"
	"time"

	"bughound/internal/finding"
)

// Trust is the trust level of a template source (BH-SPEC-PAYLOAD §Security).
// Only templates from a `trusted` source may be enabled automatically;
// `review`/`untrusted` templates enter the catalog disabled until they are
// reviewed and their trust is raised deliberately.
type Trust string

const (
	TrustTrusted   Trust = "trusted"
	TrustReview    Trust = "review"
	TrustUntrusted Trust = "untrusted"
)

// Valid reports whether t is one of the valid trust levels.
func (t Trust) Valid() bool {
	switch t {
	case TrustTrusted, TrustReview, TrustUntrusted:
		return true
	}
	return false
}

// Safety classifies a payload's impact on the target (BH-SPEC-PAYLOAD
// §Security, additive). It is used to filter payloads that could CHANGE the
// target's state or configuration: bughound's bug bounty flow looks for
// candidate bugs to verify manually and does not execute to the point of
// damage.
type Safety string

const (
	// SafetyReadOnly: a detection payload that does not change state (boolean/
	// time/error probes, reflection checks). The default for most nuclei templates.
	SafetyReadOnly Safety = "read-only"
	// SafetyMutating: could change or damage things (e.g. DoS, intrusive/
	// destructive tags). DAST engines do not run it by default.
	SafetyMutating Safety = "mutating"
)

// Valid reports whether s is one of the valid safety values.
func (s Safety) Valid() bool { return s == SafetyReadOnly || s == SafetyMutating }

// mutatingTags are the tags that mark a payload as changing or damaging.
// Conservative and extensible; in line with the engines' destructiveExcludeTags.
var mutatingTags = map[string]bool{"dos": true, "intrusive": true, "destructive": true}

// classifySafety derives Safety from a template's tags: mutating when a
// dangerous marker is present, otherwise read-only (most nuclei templates are
// detection/read-only).
func classifySafety(tags []string) Safety {
	for _, t := range tags {
		if mutatingTags[strings.ToLower(strings.TrimSpace(t))] {
			return SafetyMutating
		}
	}
	return SafetyReadOnly
}

// Entry is one catalog row: uniform metadata for one template/payload, whatever
// engine it comes from (BH-SPEC-PAYLOAD §Catalog metadata). The native template
// body is NOT copied here; NativeRef only points at it.
type Entry struct {
	// TemplateID: a stable id, unique across the bank, "<engine>:<native-id>"
	// (e.g. "nuclei:prometheus-metrics"). Carried into a finding's source_template.
	TemplateID string `json:"template_id"`
	// Source: the id of the originating source (e.g. "nuclei-official", "custom").
	Source string `json:"source"`
	// Engine: the engine that runs it (e.g. "nuclei", "custom").
	Engine string `json:"engine"`
	// NativeRef: where the template lives in its native format in the source (relative path).
	NativeRef string `json:"native_ref"`
	// Name: a short human-readable name.
	Name string `json:"name"`
	// Type: the vulnerability type, in line with the `type` taxonomy of the finding schema.
	Type string `json:"type,omitempty"`
	// SeverityDefault: the default severity (finding schema enum).
	SeverityDefault finding.Severity `json:"severity_default,omitempty"`
	// Tags: labels for selection (e.g. "ssrf", "cve", "fast").
	Tags []string `json:"tags,omitempty"`
	// Safety: the payload impact class (read-only | mutating). Derived from the
	// tags; a sidecar can override it. DAST engines only send read-only by default.
	Safety Safety `json:"safety,omitempty"`
	// References: reference links.
	References []string `json:"references,omitempty"`
	// Trust: inherited from the source; it decides the security treatment.
	Trust Trust `json:"trust"`
	// Version: the version of the template content (content hash), so changes are detected.
	Version string `json:"version"`
	// Enabled: whether it runs by default. True only when the source is
	// `trusted` AND the minimum metadata is complete (see canEnable).
	Enabled bool `json:"enabled"`
	// AddedAt: when it entered the catalog (set at build time).
	AddedAt time.Time `json:"added_at,omitempty"`
	// Note: a note for when the metadata is incomplete or the template needs
	// completing. The template still enters the catalog but is not used silently
	// with empty metadata (BH-SPEC-PAYLOAD §Format of one template).
	Note string `json:"note,omitempty"`
}

// hasMinMeta reports whether the minimum metadata needed to be `enabled` is
// there: a name, a valid severity and a type (BH-SPEC-PAYLOAD §Open questions:
// minimum metadata). Without it the template is still cataloged but disabled.
func (e Entry) hasMinMeta() bool {
	return strings.TrimSpace(e.Name) != "" &&
		e.SeverityDefault.Valid() &&
		strings.TrimSpace(e.Type) != ""
}

// canEnable applies the security rule: only a `trusted` source with complete
// minimum metadata may be enabled automatically.
func (e Entry) canEnable() bool {
	return e.Trust == TrustTrusted && e.hasMinMeta()
}

// SourceInfo summarizes one source after it is scanned (for the sources panel
// in the UI and for traceability). Version is the source's version when known
// (e.g. the nuclei-templates version), not the version of each template.
type SourceInfo struct {
	ID        string    `json:"id"`
	Engine    string    `json:"engine"`
	Kind      string    `json:"kind"`
	Path      string    `json:"path"`
	Trust     Trust     `json:"trust"`
	Version   string    `json:"version,omitempty"`
	Count     int       `json:"count"`
	Enabled   int       `json:"enabled"`
	Available bool      `json:"available"`
	UpdatedAt time.Time `json:"updated_at"`
	Note      string    `json:"note,omitempty"`
}

// Catalog is a snapshot of the bank: every entry + the source summaries + the build time.
type Catalog struct {
	Entries []Entry      `json:"entries"`
	Sources []SourceInfo `json:"sources"`
	BuiltAt time.Time    `json:"built_at"`
}

// normSeverity maps a native severity (string) to the finding schema enum. An
// unknown or empty value → info (safe), with known=false so the caller knows
// the severity metadata was not explicit.
func normSeverity(s string) (sev finding.Severity, known bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return finding.SeverityCritical, true
	case "high":
		return finding.SeverityHigh, true
	case "medium":
		return finding.SeverityMedium, true
	case "low":
		return finding.SeverityLow, true
	case "info", "informational", "unknown":
		return finding.SeverityInfo, true
	default:
		return finding.SeverityInfo, false
	}
}
