// Package web menyajikan antarmuka bughound (Go + HTMX + html/template).
// Semua aset di-embed sehingga aplikasi tetap satu binary. UI M0 membuktikan
// gate: input scope, jalankan scan (engine mock), lihat target yang ditolak
// scope guard, dan triase temuan.
package web

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"bughound/internal/engine"
	"bughound/internal/finding"
	"bughound/internal/orchestrator"
	"bughound/internal/ratelimit"
	"bughound/internal/recon"
	"bughound/internal/report"
	"bughound/internal/scope"
	"bughound/internal/store"
)

//go:embed templates
var tmplFS embed.FS

//go:embed static
var staticFS embed.FS

// Server adalah handler HTTP utama bughound.
type Server struct {
	mux    *http.ServeMux
	store  store.Store
	engine engine.Engine

	mu       sync.Mutex
	programs map[string]*programState

	pages map[string]*template.Template
}

// programState menyimpan scope terakhir dan audit trail per program (in-memory
// untuk M0; persistensi menyusul bersama store SQLite).
type programState struct {
	Name     string
	InScope  []string
	OutScope []string
	Audit    []orchestrator.AuditEvent
}

// NewServer menyiapkan server dengan store dan engine yang diberikan.
func NewServer(st store.Store, eng engine.Engine) (*Server, error) {
	pages, err := parseTemplates()
	if err != nil {
		return nil, err
	}
	s := &Server{
		mux:      http.NewServeMux(),
		store:    st,
		engine:   eng,
		programs: map[string]*programState{},
		pages:    pages,
	}
	s.routes()
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	staticSub, _ := fs.Sub(staticFS, "static")
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(staticSub)))

	s.mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/scan", http.StatusFound)
	})
	s.mux.HandleFunc("GET /scan", s.handleScanForm)
	s.mux.HandleFunc("POST /scan", s.handleScanRun)
	s.mux.HandleFunc("GET /findings", s.handleFindings)
	s.mux.HandleFunc("GET /findings/{id}", s.handleFindingDetail)
	s.mux.HandleFunc("POST /findings/{id}/status", s.handleTriage)
	s.mux.HandleFunc("GET /report", s.handleReport)
	s.mux.HandleFunc("GET /report/download", s.handleReportDownload)
	s.mux.HandleFunc("GET /report/print", s.handleReportPrint)
}

// ---- Scan ----

type scanPage struct {
	Nav      string
	Title    string
	Program  string
	Seeds    string
	InScope  string
	OutScope string
	Targets  string
	RPS      string
	Errors   []string
	Result   *scanView
}

type scanView struct {
	RunID      string
	Discovered int
	Scanned    []string
	Saved      int
	Duplicates int
	Denials    []denialView
	AuditCount int
}

type denialView struct {
	Target string
	Reason string
	Layer  string
	Entry  string
}

func (s *Server) handleScanForm(w http.ResponseWriter, r *http.Request) {
	// Prefill dengan contoh yang langsung mendemokan gate (engine mock => demo.test).
	s.render(w, "scan", "base", scanPage{
		Nav:      "scan",
		Title:    "Scan",
		Program:  "demo",
		Seeds:    "demo.test",
		InScope:  "demo.test\n*.demo.test",
		OutScope: "admin.demo.test",
		Targets:  "demo.test\nevil.test",
		RPS:      "10",
	})
}

func (s *Server) handleScanRun(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form tidak valid", http.StatusBadRequest)
		return
	}
	program := strings.TrimSpace(r.FormValue("program"))
	seeds := splitLines(r.FormValue("seeds"))
	inScope := splitLines(r.FormValue("in_scope"))
	outScope := splitLines(r.FormValue("out_scope"))
	targets := splitLines(r.FormValue("targets"))
	rps := parseRPS(r.FormValue("rps"))

	page := scanPage{
		Nav: "scan", Title: "Scan", Program: program,
		Seeds:    r.FormValue("seeds"),
		InScope:  r.FormValue("in_scope"),
		OutScope: r.FormValue("out_scope"),
		Targets:  r.FormValue("targets"),
		RPS:      r.FormValue("rps"),
	}

	if program == "" {
		page.Errors = append(page.Errors, "Nama program wajib diisi.")
	}
	if len(targets) == 0 && len(seeds) == 0 {
		page.Errors = append(page.Errors, "Isi minimal satu target, atau satu seed domain untuk recon.")
	}

	guard, errs := scope.New(inScope, outScope)
	for _, e := range errs {
		// Fail closed: entri scope tak terurai menghalangi scan (khususnya out-of-scope).
		page.Errors = append(page.Errors, "Scope tak valid: "+e.Error())
	}
	if len(page.Errors) > 0 {
		s.renderPartial(w, "scan", "scan_result_errors", page)
		return
	}

	ps := s.programStateFor(program)
	ps.InScope, ps.OutScope = inScope, outScope
	ps.Audit = nil
	audit := func(e orchestrator.AuditEvent) {
		s.mu.Lock()
		ps.Audit = append(ps.Audit, e)
		s.mu.Unlock()
	}

	o := orchestrator.New(guard, s.engine, s.store,
		ratelimit.New(ratelimit.Config{RequestsPerSecond: rps, Burst: 5}), audit)
	if len(seeds) > 0 {
		o.UseRecon(recon.MockPipeline{})
	}
	res, err := o.RunScan(r.Context(), orchestrator.ScanRequest{Program: program, Seeds: seeds, Targets: targets})
	if err != nil {
		page.Errors = append(page.Errors, "Scan gagal: "+err.Error())
		s.renderPartial(w, "scan", "scan_result_errors", page)
		return
	}

	view := &scanView{
		RunID:      res.RunID,
		Discovered: res.Discovered,
		Scanned:    res.Scanned,
		Saved:      res.FindingsSaved,
		Duplicates: res.Duplicates,
		AuditCount: len(ps.Audit),
	}
	for _, d := range res.Denied {
		view.Denials = append(view.Denials, denialView{
			Target: d.Target, Reason: string(d.Reason), Layer: string(d.Layer), Entry: d.MatchedEntry,
		})
	}
	page.Result = view
	s.renderPartial(w, "scan", "scan_result", page)
}

// ---- Findings ----

type findingsPage struct {
	Nav      string
	Title    string
	Program  string
	Programs []string
	Findings []*finding.Finding
	Selected *finding.Finding
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	program := strings.TrimSpace(r.URL.Query().Get("program"))
	progs := s.programNames(r.Context())
	if program == "" && len(progs) > 0 {
		program = progs[0]
	}

	var findings []*finding.Finding
	if program != "" {
		findings, _ = s.store.List(r.Context(), store.Query{Program: program})
	}

	page := findingsPage{
		Nav: "findings", Title: "Findings", Program: program,
		Programs: progs, Findings: findings,
	}
	if id := strings.TrimSpace(r.URL.Query().Get("id")); id != "" {
		if f, err := s.store.Get(r.Context(), id); err == nil {
			page.Selected = f
		}
	}
	s.render(w, "findings", "base", page)
}

func (s *Server) handleFindingDetail(w http.ResponseWriter, r *http.Request) {
	f, err := s.store.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, "temuan tidak ditemukan", http.StatusNotFound)
		return
	}
	s.renderPartial(w, "findings", "finding_detail", f)
}

func (s *Server) handleTriage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form tidak valid", http.StatusBadRequest)
		return
	}
	status := finding.Status(strings.TrimSpace(r.FormValue("status")))
	verifiedBy := strings.TrimSpace(r.FormValue("verified_by"))

	// Triase manual tak boleh menetapkan duplicate (itu jalur dedup store).
	switch status {
	case finding.StatusConfirmed, finding.StatusFalsePositive, finding.StatusIgnored, finding.StatusNew:
	default:
		http.Error(w, "status triase tidak diizinkan", http.StatusBadRequest)
		return
	}

	if err := s.store.SetStatus(r.Context(), id, status, verifiedBy); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f, err := s.store.Get(r.Context(), id)
	if err != nil {
		http.Error(w, "temuan tidak ditemukan", http.StatusNotFound)
		return
	}
	s.renderPartial(w, "findings", "finding_detail", f)
}

// ---- Report ----

type reportPage struct {
	Nav     string
	Title   string
	Program string
	Report  report.Report
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	program := strings.TrimSpace(r.URL.Query().Get("program"))
	if progs := s.programNames(r.Context()); program == "" && len(progs) > 0 {
		program = progs[0]
	}
	page := reportPage{Nav: "report", Title: "Reports", Program: program}
	if program != "" {
		findings, _ := s.store.List(r.Context(), store.Query{Program: program})
		page.Report = report.Build(program, findings, time.Now())
	}
	s.render(w, "report", "base", page)
}

func (s *Server) handleReportDownload(w http.ResponseWriter, r *http.Request) {
	program := strings.TrimSpace(r.URL.Query().Get("program"))
	if program == "" {
		http.Error(w, "program wajib", http.StatusBadRequest)
		return
	}
	findings, _ := s.store.List(r.Context(), store.Query{Program: program})
	rep := report.Build(program, findings, time.Now())
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="report-%s.md"`, safeFilename(program)))
	io.WriteString(w, rep.Markdown)
}

func (s *Server) handleReportPrint(w http.ResponseWriter, r *http.Request) {
	program := strings.TrimSpace(r.URL.Query().Get("program"))
	if program == "" {
		http.Error(w, "program wajib", http.StatusBadRequest)
		return
	}
	findings, _ := s.store.List(r.Context(), store.Query{Program: program})
	rep := report.Build(program, findings, time.Now())
	s.render(w, "report_print", "report_print", rep)
}

// ---- helpers ----

func (s *Server) programStateFor(name string) *programState {
	s.mu.Lock()
	defer s.mu.Unlock()
	ps := s.programs[name]
	if ps == nil {
		ps = &programState{Name: name}
		s.programs[name] = ps
	}
	return ps
}

// programNames menggabungkan program yang punya temuan tersimpan (dari store,
// sehingga persisten lintas-restart) dengan program yang baru discan di sesi ini
// (registry in-memory, termasuk yang belum punya temuan).
func (s *Server) programNames(ctx context.Context) []string {
	set := map[string]bool{}
	if progs, err := s.store.Programs(ctx); err == nil {
		for _, p := range progs {
			set[p] = true
		}
	}
	s.mu.Lock()
	for n := range s.programs {
		set[n] = true
	}
	s.mu.Unlock()

	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func (s *Server) render(w http.ResponseWriter, page, name string, data any) {
	t := s.pages[page]
	if t == nil {
		http.Error(w, "template tidak ada: "+page, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) renderPartial(w http.ResponseWriter, page, name string, data any) {
	s.render(w, page, name, data)
}

// splitLines memecah textarea jadi daftar entri: trim, buang baris kosong dan
// komentar (#).
func splitLines(raw string) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// parseRPS membaca laju dari form; nilai kosong/tak sah => 10 req/dtk (limiter
// tetap menjepit ke rentang amannya).
func parseRPS(s string) float64 {
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || v <= 0 {
		return 10
	}
	return v
}

// safeFilename menyaring nama program menjadi nama berkas yang aman.
func safeFilename(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return "report"
	}
	return b.String()
}

func parseTemplates() (map[string]*template.Template, error) {
	funcs := template.FuncMap{
		"sevClass":    func(s finding.Severity) string { return "sev-" + strings.ToLower(string(s)) },
		"statusClass": func(s finding.Status) string { return "st-" + strings.ToLower(string(s)) },
		"join":        func(v []string, sep string) string { return strings.Join(v, sep) },
		"add":         func(a, b int) int { return a + b },
	}
	sets := map[string][]string{
		"scan":         {"templates/base.html", "templates/scan.html", "templates/scan_result.html"},
		"findings":     {"templates/base.html", "templates/findings.html", "templates/finding_detail.html"},
		"report":       {"templates/base.html", "templates/report.html"},
		"report_print": {"templates/report_print.html"},
	}
	out := map[string]*template.Template{}
	for name, files := range sets {
		t, err := template.New(name).Funcs(funcs).ParseFS(tmplFS, files...)
		if err != nil {
			return nil, err
		}
		out[name] = t
	}
	return out, nil
}
