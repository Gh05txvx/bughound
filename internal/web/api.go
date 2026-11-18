// Package web — see server.go. This file adds the READ-ONLY JSON API
// under /api/ for machine consumers — mainly the bughound Burp extension
// (see burp-ext/) — so a hunter can pull findings + evidence
// (the raw request) straight into Burp Repeater without switching tools.
//
// Security (deliberately minimal, no new secrets):
//   - Endpoints under /api/ go through the same front controller (ServeHTTP),
//     so auth (login session OR HTTP Basic — the automation path that already
//     exists) and RBAC (GET needs a read role) apply AUTOMATICALLY. No side path.
//   - Every handler is a pure GET (no mutation): it does not touch the scope guard,
//     egress, rate limiter, or audit writes. This API never
//     reaches the target.
//   - The data served is exactly what the UI already shows (the uniform finding
//     schema BH-SPEC-FINDING). It opens no new data and has no
//     auto-submit.
package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"bughound/internal/finding"
	"bughound/internal/store"
)

// apiPrefix: every machine endpoint lives under this. isAPIPath is used by the front
// controller so an API client receives a 401 JSON error (not an HTML redirect to
// /login) when the credentials are missing/invalid.
const apiPrefix = "/api/"

func isAPIPath(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, apiPrefix)
}

// writeJSON writes v as JSON with the given status. SetEscapeHTML is
// turned off so characters like < > & inside the request/evidence are not changed
// into unicode escapes (important: the request sent to Repeater must stay intact).
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// apiError: a uniform JSON error shape, {"error":"..."}.
type apiError struct {
	Error string `json:"error"`
}

func writeAPIError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, apiError{Error: msg})
}

// apiFindingsResponse wraps the findings list of one program.
type apiFindingsResponse struct {
	Program  string             `json:"program"`
	Count    int                `json:"count"`
	Findings []*finding.Finding `json:"findings"`
}

// handleAPIFindings — GET /api/v1/findings?program=<name>
//
// Query parameters:
//   - program            (required) the program name.
//   - run_id             (optional) limit to one run.
//   - status             (optional) comma-separated list; strictly validated.
//   - severity           (optional) comma-separated list; strictly validated.
//   - include_duplicates (optional) 1/true/yes to include duplicates.
//
// It returns findings in the uniform schema (including evidence.request when present)
// so the Burp extension can reconstruct the request for Repeater.
func (s *Server) handleAPIFindings(w http.ResponseWriter, r *http.Request) {
	program := strings.TrimSpace(r.URL.Query().Get("program"))
	if program == "" {
		writeAPIError(w, http.StatusBadRequest, "the 'program' parameter is required")
		return
	}
	q := store.Query{Program: program, RunID: strings.TrimSpace(r.URL.Query().Get("run_id"))}

	// Optional status/severity filter. An unknown value is rejected (400), not silently
	// ignored — consistent with the tool's default-deny stance.
	for _, raw := range csvFields(r.URL.Query().Get("status")) {
		st := finding.Status(raw)
		if !st.Valid() {
			writeAPIError(w, http.StatusBadRequest, "invalid status: "+raw)
			return
		}
		q.Statuses = append(q.Statuses, st)
	}
	for _, raw := range csvFields(r.URL.Query().Get("severity")) {
		sv := finding.Severity(raw)
		if !sv.Valid() {
			writeAPIError(w, http.StatusBadRequest, "invalid severity: "+raw)
			return
		}
		q.Severities = append(q.Severities, sv)
	}
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("include_duplicates"))) {
	case "1", "true", "yes":
		q.IncludeDuplicates = true
	}

	findings, err := s.store.List(r.Context(), q)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "could not fetch findings")
		return
	}
	if findings == nil {
		findings = []*finding.Finding{} // always a JSON array, not null
	}
	writeJSON(w, http.StatusOK, apiFindingsResponse{Program: program, Count: len(findings), Findings: findings})
}

// handleAPIFinding — GET /api/v1/findings/{id}
//
// Returns one full finding (uniform schema). 404 when the id does not exist.
func (s *Server) handleAPIFinding(w http.ResponseWriter, r *http.Request) {
	f, err := s.store.Get(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) || (err == nil && f == nil) {
		writeAPIError(w, http.StatusNotFound, "finding not found")
		return
	}
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "could not fetch findings")
		return
	}
	writeJSON(w, http.StatusOK, f)
}

// csvFields splits "a, b ,,c" → ["a","b","c"] (dropping spaces & empty elements).
func csvFields(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
