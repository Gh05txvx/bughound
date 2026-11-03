// Package web — lihat server.go. Berkas ini menambahkan API JSON BACA-SAJA
// (read-only) di bawah /api/ untuk konsumen mesin — terutama extension Burp
// bughound (lihat burp-ext/) — agar hunter bisa menarik temuan + evidence
// (request mentah) langsung ke Burp Repeater tanpa pindah tool.
//
// Keamanan (sengaja minimal, tanpa secret baru):
//   - Endpoint di bawah /api/ melewati front controller yang sama (ServeHTTP),
//     jadi auth (sesi login ATAU HTTP Basic — jalur otomasi yang sudah ada) dan
//     RBAC (GET butuh peran baca) berlaku OTOMATIS. Tak ada jalur samping.
//   - Semua handler GET murni (tanpa mutasi): tidak menyentuh scope guard,
//     egress, rate limiter, maupun penulisan audit. API ini tidak pernah
//     menjangkau target.
//   - Data yang disajikan sama persis dengan yang sudah tampil di UI (skema
//     temuan seragam BH-SPEC-FINDING). Tidak membuka data baru, tidak ada
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

// apiPrefix: semua endpoint mesin hidup di bawah ini. isAPIPath dipakai front
// controller agar klien API menerima galat JSON 401 (bukan redirect HTML ke
// /login) ketika kredensial belum/tidak valid.
const apiPrefix = "/api/"

func isAPIPath(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, apiPrefix)
}

// writeJSON menulis v sebagai JSON dengan status yang diberikan. SetEscapeHTML
// dimatikan agar karakter seperti < > & di dalam request/evidence tidak diubah
// jadi escape unicode (penting: request yang dikirim ke Repeater harus utuh).
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// apiError: bentuk galat JSON seragam, {"error":"..."}.
type apiError struct {
	Error string `json:"error"`
}

func writeAPIError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, apiError{Error: msg})
}

// apiFindingsResponse membungkus daftar temuan satu program.
type apiFindingsResponse struct {
	Program  string             `json:"program"`
	Count    int                `json:"count"`
	Findings []*finding.Finding `json:"findings"`
}

// handleAPIFindings — GET /api/v1/findings?program=<nama>
//
// Parameter query:
//   - program            (wajib) nama program.
//   - run_id             (opsional) batasi ke satu run.
//   - status             (opsional) daftar dipisah koma; divalidasi ketat.
//   - severity           (opsional) daftar dipisah koma; divalidasi ketat.
//   - include_duplicates (opsional) 1/true/yes untuk ikut sertakan duplikat.
//
// Mengembalikan temuan dalam skema seragam (termasuk evidence.request bila ada)
// agar extension Burp dapat merekonstruksi request untuk Repeater.
func (s *Server) handleAPIFindings(w http.ResponseWriter, r *http.Request) {
	program := strings.TrimSpace(r.URL.Query().Get("program"))
	if program == "" {
		writeAPIError(w, http.StatusBadRequest, "parameter 'program' wajib")
		return
	}
	q := store.Query{Program: program, RunID: strings.TrimSpace(r.URL.Query().Get("run_id"))}

	// Filter status/severity opsional. Nilai asing ditolak (400), tidak diam-diam
	// diabaikan — konsisten dengan sifat default-deny tool.
	for _, raw := range csvFields(r.URL.Query().Get("status")) {
		st := finding.Status(raw)
		if !st.Valid() {
			writeAPIError(w, http.StatusBadRequest, "status tidak sah: "+raw)
			return
		}
		q.Statuses = append(q.Statuses, st)
	}
	for _, raw := range csvFields(r.URL.Query().Get("severity")) {
		sv := finding.Severity(raw)
		if !sv.Valid() {
			writeAPIError(w, http.StatusBadRequest, "severity tidak sah: "+raw)
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
		writeAPIError(w, http.StatusInternalServerError, "gagal mengambil temuan")
		return
	}
	if findings == nil {
		findings = []*finding.Finding{} // selalu array JSON, bukan null
	}
	writeJSON(w, http.StatusOK, apiFindingsResponse{Program: program, Count: len(findings), Findings: findings})
}

// handleAPIFinding — GET /api/v1/findings/{id}
//
// Mengembalikan satu temuan lengkap (skema seragam). 404 bila id tak ada.
func (s *Server) handleAPIFinding(w http.ResponseWriter, r *http.Request) {
	f, err := s.store.Get(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) || (err == nil && f == nil) {
		writeAPIError(w, http.StatusNotFound, "temuan tidak ditemukan")
		return
	}
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "gagal mengambil temuan")
		return
	}
	writeJSON(w, http.StatusOK, f)
}

// csvFields memecah "a, b ,,c" → ["a","b","c"] (buang spasi & elemen kosong).
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
