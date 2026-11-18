// Package finding defines the Uniform Finding Schema (BH-SPEC-FINDING): the
// single format every engine (recon and DAST) normalizes its results into, and
// the data source for triage and reports.
//
// The package has no external dependencies on purpose: it is the foundation
// that the store, triage, report and engine adapters refer to, so it has to be
// stable and light.
package finding

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// CurrentSchemaVersion is the schema version components write today.
// Version bumps follow the MAJOR.MINOR rule in BH-SPEC-FINDING.
//
// 1.0 → 1.1 (MINOR, additive): adds the optional `impact` field (filled in by
// the hunter during triage to complete the draft report). Old consumers can
// still read it; old findings (schema_version 1.0, no impact) stay valid. 1.2
// adds the `owasp` field (OWASP 2021 classification, additive) and is also
// compatible.
const CurrentSchemaVersion = "1.2"

// Severity: how severe a finding is. A closed enum (BH-SPEC-FINDING).
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Valid reports whether s is one of the valid severity values.
func (s Severity) Valid() bool {
	switch s {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	}
	return false
}

// Confidence: the automatic confidence before manual verification. A closed enum.
type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

// Valid reports whether c is one of the valid confidence values.
func (c Confidence) Valid() bool {
	switch c {
	case ConfidenceLow, ConfidenceMedium, ConfidenceHigh:
		return true
	}
	return false
}

// Status: the triage status of a finding. A closed enum (BH-SPEC-FINDING).
type Status string

const (
	StatusNew           Status = "new"
	StatusConfirmed     Status = "confirmed"
	StatusDuplicate     Status = "duplicate"
	StatusFalsePositive Status = "false_positive"
	StatusIgnored       Status = "ignored"
)

// Valid reports whether s is one of the valid status values.
func (s Status) Valid() bool {
	switch s {
	case StatusNew, StatusConfirmed, StatusDuplicate, StatusFalsePositive, StatusIgnored:
		return true
	}
	return false
}

// ParamLocation: where the entry-point parameter is. Optional; validated when set.
type ParamLocation string

const (
	ParamQuery  ParamLocation = "query"
	ParamBody   ParamLocation = "body"
	ParamHeader ParamLocation = "header"
	ParamCookie ParamLocation = "cookie"
	ParamPath   ParamLocation = "path"
)

// Valid reports whether p is one of the valid parameter locations.
func (p ParamLocation) Valid() bool {
	switch p {
	case ParamQuery, ParamBody, ParamHeader, ParamCookie, ParamPath:
		return true
	}
	return false
}

// timeLayout: UTC ISO 8601 with second precision, e.g. "2026-10-21T09:14:03Z".
const timeLayout = "2006-01-02T15:04:05Z07:00"

// Time is a timestamp that is always serialized as UTC ISO 8601 with second
// precision, following the "Time in UTC ISO 8601" principle in BH-SPEC-FINDING.
type Time struct{ time.Time }

// NewTime normalizes t to UTC with second precision.
func NewTime(t time.Time) Time { return Time{t.UTC().Truncate(time.Second)} }

// MarshalJSON writes the time as a UTC ISO 8601 string with second precision.
func (t Time) MarshalJSON() ([]byte, error) {
	return []byte(`"` + t.UTC().Truncate(time.Second).Format(timeLayout) + `"`), nil
}

// UnmarshalJSON reads a UTC ISO 8601 string; an empty string or null becomes the zero time.
func (t *Time) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		t.Time = time.Time{}
		return nil
	}
	parsed, err := time.Parse(timeLayout, s)
	if err != nil {
		return fmt.Errorf("finding: invalid time %q: %w", s, err)
	}
	t.Time = parsed.UTC()
	return nil
}

// CVSS carries an optional CVSS score when the engine/template provides one.
type CVSS struct {
	Version string  `json:"version,omitempty"`
	Vector  string  `json:"vector,omitempty"`
	Score   float64 `json:"score,omitempty"`
}

// Location points at exactly where the finding is. Only URL is required.
type Location struct {
	URL           string        `json:"url"`
	Method        string        `json:"method,omitempty"`
	Parameter     string        `json:"parameter,omitempty"`
	ParamLocation ParamLocation `json:"param_location,omitempty"`
}

// Evidence holds evidence that has ALREADY been cleaned of secrets. Every
// sub-field is optional, but at least one should be set so the finding can be
// verified. Redacting secrets is the adapter's job before it fills this struct
// (BH-SPEC-FINDING: the schema never stores a raw secret).
type Evidence struct {
	Request         string `json:"request,omitempty"`
	ResponseExcerpt string `json:"response_excerpt,omitempty"`
	Payload         string `json:"payload,omitempty"`
	Matched         string `json:"matched,omitempty"`
	ScreenshotRef   string `json:"screenshot_ref,omitempty"`
}

// maxEvidenceField caps the length (in bytes) of each textual evidence
// sub-field stored inline. Requests and responses from engines can be very
// large; storing them whole bloats the store and the report without adding
// verification value. The limit is loose enough to keep a request replayable
// (e.g. in Burp) while preventing bloat from huge responses. (It answers the
// open question in BH-SPEC-FINDING about an evidence size limit.)
const maxEvidenceField = 32 * 1024

// clampFields truncates each textual evidence sub-field that exceeds
// maxEvidenceField, at a rune boundary (it does not split a UTF-8 character),
// then appends a marker with the number of bytes dropped. Idempotent.
// ScreenshotRef is only a reference (path/URL), not content, so it is not
// truncated.
func (e *Evidence) clampFields() {
	e.Request = clampText(e.Request, maxEvidenceField)
	e.ResponseExcerpt = clampText(e.ResponseExcerpt, maxEvidenceField)
	e.Payload = clampText(e.Payload, maxEvidenceField)
	e.Matched = clampText(e.Matched, maxEvidenceField)
}

// clampText truncates s to at most limit bytes (including the marker) at a rune
// boundary, then appends a marker with the number of bytes dropped. It returns
// s unchanged when it is already <= limit, so it is safe to call repeatedly
// (idempotent).
func clampText(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	const markerBudget = 80 // room reserved for the truncation marker
	budget := limit - markerBudget
	if budget < 0 {
		budget = 0
	}
	cut := budget
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + fmt.Sprintf("\n…[evidence truncated: %d bytes removed, limit %d]", len(s)-cut, limit)
}

// Finding is one normalized record: one security issue at one location, in the
// same shape whatever engine it came from.
//
// Optional fields use omitempty, so they are left out of the JSON when empty
// instead of being written as null (BH-SPEC-FINDING).
type Finding struct {
	SchemaVersion string `json:"schema_version"`
	ID            string `json:"id"`
	DedupKey      string `json:"dedup_key"`
	Program       string `json:"program"`
	RunID         string `json:"run_id"`
	Target        string `json:"target"`
	Type          string `json:"type"`
	Title         string `json:"title"`
	Description   string `json:"description,omitempty"`

	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence"`
	CVSS       *CVSS      `json:"cvss,omitempty"`
	CWE        []string   `json:"cwe,omitempty"`
	Tags       []string   `json:"tags,omitempty"`
	OWASP      OWASP      `json:"owasp,omitempty"` // OWASP 2021 category (additive, from classification)

	Location     Location  `json:"location"`
	Evidence     *Evidence `json:"evidence,omitempty"`
	Reproduction []string  `json:"reproduction,omitempty"`
	Impact       string    `json:"impact,omitempty"` // impact; filled in by the hunter during triage for the draft report

	SourceEngine   string          `json:"source_engine"`
	SourceTemplate string          `json:"source_template,omitempty"`
	References     []string        `json:"references,omitempty"`
	Raw            json.RawMessage `json:"raw,omitempty"`

	Status      Status `json:"status"`
	DuplicateOf string `json:"duplicate_of,omitempty"`
	InReport    bool   `json:"in_report,omitempty"`
	VerifiedBy  string `json:"verified_by,omitempty"`

	CreatedAt Time  `json:"created_at"`
	UpdatedAt *Time `json:"updated_at,omitempty"`
}

// Finalize fills in derived fields that are still empty (schema_version,
// created_at, dedup_key) and then validates. Engine adapters call it after
// mapping raw output to the schema. The ID stays the caller's job (a UUID from
// the store).
func (f *Finding) Finalize(now time.Time) error {
	if f.SchemaVersion == "" {
		f.SchemaVersion = CurrentSchemaVersion
	}
	if f.CreatedAt.IsZero() {
		f.CreatedAt = NewTime(now)
	}
	if f.DedupKey == "" {
		f.DedupKey = ComputeDedupKey(f.Type, f.Target, f.Location.URL, f.Location.Method, f.Location.Parameter)
	}
	if f.Evidence != nil {
		f.Evidence.clampFields()
	}
	if f.OWASP == OWASPNone {
		f.OWASP = ClassifyOWASP(f)
	}
	return f.Validate()
}

// Validate makes sure every required field is set and every enum is valid. The
// store uses it as a guard before saving.
func (f *Finding) Validate() error {
	required := map[string]string{
		"schema_version": f.SchemaVersion,
		"id":             f.ID,
		"dedup_key":      f.DedupKey,
		"program":        f.Program,
		"run_id":         f.RunID,
		"target":         f.Target,
		"type":           f.Type,
		"title":          f.Title,
		"source_engine":  f.SourceEngine,
	}
	var missing []string
	for name, val := range required {
		if strings.TrimSpace(val) == "" {
			missing = append(missing, name)
		}
	}
	if strings.TrimSpace(f.Location.URL) == "" {
		missing = append(missing, "location.url")
	}
	if f.CreatedAt.IsZero() {
		missing = append(missing, "created_at")
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("finding: required fields are empty: %s", strings.Join(missing, ", "))
	}

	if !f.Severity.Valid() {
		return fmt.Errorf("finding: invalid severity: %q", f.Severity)
	}
	if !f.Confidence.Valid() {
		return fmt.Errorf("finding: invalid confidence: %q", f.Confidence)
	}
	if !f.Status.Valid() {
		return fmt.Errorf("finding: invalid status: %q", f.Status)
	}
	if f.Location.ParamLocation != "" && !f.Location.ParamLocation.Valid() {
		return fmt.Errorf("finding: invalid param_location: %q", f.Location.ParamLocation)
	}
	if f.Status == StatusDuplicate && strings.TrimSpace(f.DuplicateOf) == "" {
		return fmt.Errorf("finding: status=duplicate requires duplicate_of")
	}
	return nil
}
