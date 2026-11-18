// Package ffuf normalizes ffuf output (content discovery / fuzzing) into the
// Unified Finding Schema (BH-SPEC-FINDING), which proves bughound's core idea:
// adding an engine means adding one adapter, without touching triage, report,
// or store.
//
// It also provides a mock engine for M1 (no network).
package ffuf

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"

	"bughound/internal/finding"
)

// ffuf -of json produces a single JSON object with a "results" array.
type ffufOutput struct {
	Results []ffufResult `json:"results"`
}

type ffufResult struct {
	Input       map[string]string `json:"input"`
	Status      int               `json:"status"`
	Length      int64             `json:"length"`
	Words       int64             `json:"words"`
	Lines       int64             `json:"lines"`
	ContentType string            `json:"content-type"`
	URL         string            `json:"url"`
	Host        string            `json:"host"`
}

// Catch-all calibration thresholds. When one response "fingerprint"
// (status|length|words) dominates the results, the server is answering
// uniformly, typical of an SPA that returns index.html for nearly every path, so
// most of the "endpoints found" are false positives. The dominant group is
// suppressed into ONE info finding that explains it, instead of flooding the
// store with hundreds of decoy paths. The thresholds are kept conservative so a
// healthy site (varied response sizes) is never caught in the filter.
const (
	catchAllMinHits     = 10  // the dominant group must be at least this big to count as wildcard
	catchAllMinFraction = 0.6 // and make up at least 60% of all results

	// errorWallMinHits is the threshold for a wall-status group (401/403/500),
	// whether identical or same-shaped (see minHitsFor). Deliberately well above
	// catchAllMinHits: on a healthy API an unknown path gets a 404, so a small group
	// with one of these statuses is a REAL route, either protected (401/403) or
	// crashing without a required parameter (500), which is exactly what API route
	// brute-forcing looks for. A genuine wall on a popular prefix produces hundreds
	// to thousands of hits; below the threshold the noise stays limited.
	errorWallMinHits = 100
)

// Parse reads ffuf output (JSON) and returns normalized findings, after
// calibration suppresses bulk responses that are not real endpoints (see calibrate).
func Parse(r io.Reader, program, runID string) ([]*finding.Finding, error) {
	var out ffufOutput
	if err := json.NewDecoder(r).Decode(&out); err != nil {
		return nil, fmt.Errorf("ffuf: output is not valid JSON: %w", err)
	}
	items := make([]item, 0, len(out.Results))
	for i, res := range out.Results {
		f, err := mapResult(res, program, runID)
		if err != nil {
			return nil, fmt.Errorf("ffuf: result %d: %w", i, err)
		}
		items = append(items, item{res: res, f: f})
	}
	return calibrate(items, program, runID), nil
}

// item pairs a raw result with its mapped finding, so calibration can judge the
// response fingerprint without re-parsing.
type item struct {
	res ffufResult
	f   *finding.Finding
}

// calibrate suppresses bulk responses that are not real endpoints and replaces
// them with one info finding per pattern, so the suppression stays visible. Two
// patterns are judged in order: catch-all (identical responses), then the error
// wall (401/403/500 same-shaped, length varies). Other results, endpoints with a
// different fingerprint, stay intact.
func calibrate(items []item, program, runID string) []*finding.Finding {
	var notes []*finding.Finding
	rest, sample, n := splitDominant(items, fingerprintOf)
	if n > 0 {
		notes = append(notes, wildcardNote(sample, n, len(items), program, runID))
	}
	rest, sample, n = splitDominant(rest, wallFingerprintOf)
	if n > 0 {
		notes = append(notes, wallNote(sample, n, len(items), program, runID))
	}
	return append(collect(rest), notes...)
}

// splitDominant separates the largest group by key when its size meets
// minHitsFor and makes up at least catchAllMinFraction of items. It returns the
// remaining items, one sample from the group, and the group size (0 = nothing
// suppressed). An empty key means that item is not judged. The key must include
// the status, so one group has one status and one threshold.
func splitDominant(items []item, key func(ffufResult) string) (rest []item, sample ffufResult, n int) {
	counts := map[string]int{}
	for _, it := range items {
		if k := key(it.res); k != "" {
			counts[k]++
		}
	}
	dom, domN := "", 0
	for k, c := range counts {
		if c > domN {
			dom, domN = k, c
		}
	}
	rest = make([]item, 0, len(items)-domN)
	for _, it := range items {
		if key(it.res) == dom {
			sample = it.res
			continue
		}
		rest = append(rest, it)
	}
	if domN < minHitsFor(sample.Status) || float64(domN)/float64(len(items)) < catchAllMinFraction {
		return items, ffufResult{}, 0 // no convincing pattern
	}
	return rest, sample, domN
}

// minHitsFor returns the group-size threshold for a response status.
func minHitsFor(status int) int {
	if isWallStatus(status) {
		return errorWallMinHits
	}
	return catchAllMinHits
}

// isWallStatus: statuses that can form an error wall. 401/403 = auth gateway;
// 500 = an error handler that prints the path (e.g. Juice Shop "Unexpected path:
// /api/x"). No other status qualifies: real 200 routes are often same-shaped by chance.
func isWallStatus(status int) bool {
	return status == 401 || status == 403 || status == 500
}

func collect(items []item) []*finding.Finding {
	fs := make([]*finding.Finding, 0, len(items))
	for _, it := range items {
		fs = append(fs, it.f)
	}
	return fs
}

// fingerprintOf: two responses count as "the same" when status, length, and word
// count are identical. This combination is stable for a catch-all page whose bytes match.
func fingerprintOf(res ffufResult) string {
	return fmt.Sprintf("%d|%d|%d", res.Status, res.Length, res.Words)
}

// wallFingerprintOf is a loose fingerprint for an error wall: length is ignored
// because many servers echo the path in the body (e.g. a Spring Boot gateway
// {"status":401,"path":"/api/x"}, a 500 error page that prints the path), so the
// length changes per path while the shape stays. Content-type is also ignored: a
// gateway may derive it from the path extension. Only wall statuses count
// (otherwise the key is empty): real 200 routes are often same-shaped by chance,
// e.g. JSON without spaces is always 1 word.
func wallFingerprintOf(res ffufResult) string {
	if !isWallStatus(res.Status) {
		return ""
	}
	return fmt.Sprintf("%d|%d|%d", res.Status, res.Words, res.Lines)
}

func mapResult(res ffufResult, program, runID string) (*finding.Finding, error) {
	if strings.TrimSpace(res.URL) == "" {
		return nil, fmt.Errorf("ffuf result without a url")
	}
	fuzz := res.Input["FUZZ"]
	title := "Endpoint found"
	if fuzz != "" {
		title = "Endpoint found: " + fuzz
	}
	raw, _ := json.Marshal(res)

	return &finding.Finding{
		Program:      program,
		RunID:        runID,
		Target:       firstNonEmpty(res.Host, res.URL),
		Type:         "exposed-path",
		Title:        title,
		Severity:     mapSeverity(res.Status),
		Confidence:   finding.ConfidenceHigh, // ffuf reports a definite match
		Tags:         []string{"content-discovery"},
		Location:     finding.Location{URL: res.URL},
		SourceEngine: "ffuf",
		Status:       finding.StatusNew,
		Evidence: &finding.Evidence{
			Payload: fuzz,
			Matched: fmt.Sprintf("HTTP %d · %d bytes · %d words · %s", res.Status, res.Length, res.Words, res.ContentType),
		},
		Raw: raw,
	}, nil
}

// wildcardNote summarizes the suppressed catch-all group into one info finding,
// so the suppression is VISIBLE and auditable (not a silent drop) and the hunter
// knows exactly which pattern was filtered.
func wildcardNote(sample ffufResult, suppressed, total int, program, runID string) *finding.Finding {
	note := calibrationNote(sample, suppressed, total, program, runID)
	note.Type = "content-discovery-wildcard"
	note.Title = fmt.Sprintf("ffuf calibration: %d paths suppressed (uniform catch-all response)", suppressed)
	note.Description = fmt.Sprintf("The server answered %d of %d probed paths with an identical response "+
		"(HTTP %d · %d bytes · %d words), a sign of a catch-all/SPA wildcard. Path findings for "+
		"this pattern are suppressed as likely false positives; verify by hand if a specific "+
		"path is in doubt.", suppressed, total, sample.Status, sample.Length, sample.Words)
	note.Evidence = &finding.Evidence{
		Matched: fmt.Sprintf("HTTP %d · %d bytes · %d words · %d/%d uniform paths", sample.Status, sample.Length, sample.Words, suppressed, total),
	}
	return note
}

// wallNote summarizes the suppressed error wall. It has its own type, not the
// catch-all type: a note's dedup key at the target root can only differ by type,
// so one target with both patterns still shows two notes.
func wallNote(sample ffufResult, suppressed, total int, program, runID string) *finding.Finding {
	note := calibrationNote(sample, suppressed, total, program, runID)
	kind := wallKind(sample.Status)
	note.Type = "content-discovery-error-wall"
	note.Title = fmt.Sprintf("ffuf calibration: %d paths suppressed (%s wall HTTP %d)", suppressed, kind, sample.Status)
	note.Description = fmt.Sprintf("The server answered %d of %d probed paths with a same-shaped HTTP %d "+
		"(%d words, %d lines), only the length changing, a sign of a %s wall that echoes the path "+
		"in the body rather than %d real endpoints. Example: %s. Path findings for this pattern are "+
		"suppressed; a real route behind the wall is indistinguishable from a decoy path, so verify "+
		"by hand if a specific path is in doubt.", suppressed, total, sample.Status, sample.Words, sample.Lines, kind, suppressed, sample.URL)
	note.Evidence = &finding.Evidence{
		Matched: fmt.Sprintf("HTTP %d · %d words · %d lines · %d/%d same-shaped paths", sample.Status, sample.Words, sample.Lines, suppressed, total),
	}
	return note
}

// wallKind labels the wall type for the note text.
func wallKind(status int) string {
	if status == 500 {
		return "server error"
	}
	return "auth"
}

// calibrationNote builds the skeleton of a calibration note; Type, Title,
// Description, and Evidence are filled by the caller per the suppressed pattern.
func calibrationNote(sample ffufResult, suppressed, total int, program, runID string) *finding.Finding {
	base := baseOf(sample.URL)
	raw, _ := json.Marshal(struct {
		Suppressed int   `json:"suppressed"`
		Total      int   `json:"total"`
		Status     int   `json:"status"`
		Length     int64 `json:"length"`
		Words      int64 `json:"words"`
	}{suppressed, total, sample.Status, sample.Length, sample.Words})

	return &finding.Finding{
		Program:      program,
		RunID:        runID,
		Target:       firstNonEmpty(sample.Host, base),
		Severity:     finding.SeverityInfo,
		Confidence:   finding.ConfidenceHigh,
		Tags:         []string{"content-discovery", "calibration"},
		Location:     finding.Location{URL: base},
		SourceEngine: "ffuf",
		Status:       finding.StatusNew,
		Raw:          raw,
	}
}

// baseOf takes scheme://host from a result URL, to place the summary finding at
// the target root instead of on one decoy path.
func baseOf(rawURL string) string {
	if u, err := url.Parse(strings.TrimSpace(rawURL)); err == nil && u.Host != "" {
		return u.Scheme + "://" + u.Host
	}
	return rawURL
}

// mapSeverity: ffuf finds a path, not a vulnerability directly. 200/204
// (reachable) get low; everything else gets info. The real severity is decided
// during manual triage.
func mapSeverity(status int) finding.Severity {
	switch status {
	case 200, 204:
		return finding.SeverityLow
	default:
		return finding.SeverityInfo
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
