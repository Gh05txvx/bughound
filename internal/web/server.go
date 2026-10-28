// Package web menyajikan antarmuka bughound (Go + HTMX + html/template).
// Semua aset di-embed sehingga aplikasi tetap satu binary. UI M0 membuktikan
// gate: input scope, jalankan scan (engine mock), lihat target yang ditolak
// scope guard, dan triase temuan.
package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"bughound/internal/audit"
	"bughound/internal/egress"
	"bughound/internal/engine"
	"bughound/internal/engine/grpc"
	"bughound/internal/finding"
	"bughound/internal/jobs"
	"bughound/internal/orchestrator"
	"bughound/internal/ratelimit"
	"bughound/internal/openapi"
	"bughound/internal/recon"
	"bughound/internal/report"
	"bughound/internal/sast"
	"bughound/internal/scope"
	"bughound/internal/secret"
	"bughound/internal/store"
)

//go:embed templates
var tmplFS embed.FS

//go:embed static
var staticFS embed.FS

// Server adalah handler HTTP utama bughound.
type Server struct {
	mux     *http.ServeMux
	store   store.Store
	engines []engine.Engine
	recon   recon.Engine
	vault   secret.Vault
	audit   audit.Log
	authSecret string
	queue   *jobs.Queue
	version string
	sastRoot string // root kode yang diizinkan untuk SAST; kosong = SAST nonaktif
	grpcEngine grpc.Scanner // enumerasi/fuzz gRPC (mock default; grpcurl bila -grpc real)

	captureMu sync.Mutex
	captures  map[string]*captureSession // sesi capture reverse-proxy aktif per program

	pages map[string]*template.Template
}

// Config mengonfigurasi server: store, engine DAST (minimal 1), recon & vault opsional.
type Config struct {
	Store   store.Store
	Engines []engine.Engine
	Recon   recon.Engine
	Vault   secret.Vault
	Audit   audit.Log
	// AuthSecret, bila tidak kosong, mewajibkan HTTP Basic auth (password =
	// AuthSecret, username diabaikan). Kosong = tanpa auth (hanya aman untuk
	// bind localhost tepercaya).
	AuthSecret string
	// Version adalah versi build (di-inject lewat ldflags); kosong = "dev".
	// Ditampilkan di footer UI agar rilis mudah dikenali.
	Version string
	// SASTRoot, bila diset, mengaktifkan SAST dan MENGURUNG analisis ke dalam
	// direktori ini (path scope, default-deny). Kosong = SAST nonaktif.
	SASTRoot string
	// GRPCReal memakai grpcurl nyata untuk enumerasi gRPC (butuh binary);
	// default mock. GRPCPlaintext mengirim -plaintext (gRPC tanpa TLS).
	GRPCReal      bool
	GRPCPlaintext bool
}

// NewServer menyiapkan server dengan store dan engine yang diberikan.
func NewServer(cfg Config) (*Server, error) {
	if len(cfg.Engines) == 0 {
		return nil, fmt.Errorf("web: minimal satu engine DAST")
	}
	version := cfg.Version
	if version == "" {
		version = "dev"
	}
	pages, err := parseTemplates(version)
	if err != nil {
		return nil, err
	}
	s := &Server{
		mux:      http.NewServeMux(),
		store:    cfg.Store,
		engines:  cfg.Engines,
		recon:    cfg.Recon,
		vault:    cfg.Vault,
		audit:    cfg.Audit,
		authSecret: cfg.AuthSecret,
		queue:    jobs.New(4),
		version:  version,
		sastRoot: strings.TrimSpace(cfg.SASTRoot),
		captures: map[string]*captureSession{},
		pages:    pages,
	}
	if cfg.GRPCReal {
		s.grpcEngine = &grpc.Runner{Plaintext: cfg.GRPCPlaintext}
	} else {
		s.grpcEngine = grpc.Mock{}
	}
	s.routes()
	return s, nil
}

// Close menghentikan sesi capture yang aktif lalu worker pool (menunggu scan
// yang berjalan selesai).
func (s *Server) Close() error {
	s.captureMu.Lock()
	for _, sess := range s.captures {
		if sess.stop != nil {
			_ = sess.stop()
		}
	}
	s.captures = map[string]*captureSession{}
	s.captureMu.Unlock()
	s.queue.Close()
	return nil
}

const csrfCookie = "bh_csrf"

type csrfCtxKey struct{}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")

	if !s.checkAuth(w, r) {
		return
	}

	// CSRF: pastikan cookie token ada; sediakan ke handler lewat context agar
	// ter-render ke form/hx-headers. Tiap permintaan state-changing wajib
	// mengirim token yang cocok (double-submit) — memblok CSRF lintas-situs.
	token := s.ensureCSRFCookie(w, r)
	r = r.WithContext(context.WithValue(r.Context(), csrfCtxKey{}, token))
	if isStateChanging(r.Method) && !validCSRF(r, token) {
		http.Error(w, "CSRF: token tidak valid atau permintaan lintas-situs", http.StatusForbidden)
		return
	}

	s.mux.ServeHTTP(w, r)
}

// checkAuth menegakkan HTTP Basic bila authSecret diset (username diabaikan).
func (s *Server) checkAuth(w http.ResponseWriter, r *http.Request) bool {
	if s.authSecret == "" {
		return true
	}
	if _, pass, ok := r.BasicAuth(); ok && subtle.ConstantTimeCompare([]byte(pass), []byte(s.authSecret)) == 1 {
		return true
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="bughound"`)
	http.Error(w, "autentikasi diperlukan", http.StatusUnauthorized)
	return false
}

func (s *Server) ensureCSRFCookie(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(csrfCookie); err == nil && c.Value != "" {
		return c.Value
	}
	tok := randToken()
	http.SetCookie(w, &http.Cookie{
		Name: csrfCookie, Value: tok, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	return tok
}

func (s *Server) csrfToken(r *http.Request) string {
	if v, ok := r.Context().Value(csrfCtxKey{}).(string); ok {
		return v
	}
	return ""
}

func isStateChanging(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

func validCSRF(r *http.Request, cookieTok string) bool {
	if cookieTok == "" {
		return false
	}
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" { // browser modern: tolak lintas-situs
		return false
	}
	// Origin "null" diperlakukan seperti tak ada Origin: di bawah
	// Referrer-Policy: no-referrer, Chromium mengirim `Origin: null` untuk POST
	// form navigasi same-origin yang SAH. Menolaknya akan mematahkan semua form
	// non-HTMX. Pertahanan tetap utuh: token double-submit (di bawah) tak bisa
	// dipalsukan lintas-situs, dan POST lintas-situs sudah ditolak oleh
	// Sec-Fetch-Site di atas.
	if o := r.Header.Get("Origin"); o != "" && o != "null" {
		if u, err := url.Parse(o); err != nil || u.Host != r.Host {
			return false
		}
	}
	sent := r.Header.Get("X-CSRF-Token")
	if sent == "" {
		sent = r.FormValue("csrf")
	}
	return sent != "" && subtle.ConstantTimeCompare([]byte(sent), []byte(cookieTok)) == 1
}

func randToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Server) routes() {
	staticSub, _ := fs.Sub(staticFS, "static")
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(staticSub)))

	s.mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	})
	s.mux.HandleFunc("GET /dashboard", s.handleDashboard)
	s.mux.HandleFunc("GET /sast", s.handleSAST)
	s.mux.HandleFunc("POST /sast/run", s.handleSASTRun)
	s.mux.HandleFunc("GET /grpc", s.handleGRPC)
	s.mux.HandleFunc("POST /grpc/run", s.handleGRPCRun)
	s.mux.HandleFunc("GET /capture", s.handleCapture)
	s.mux.HandleFunc("POST /capture/start", s.handleCaptureStart)
	s.mux.HandleFunc("POST /capture/stop", s.handleCaptureStop)
	s.mux.HandleFunc("POST /capture/promote", s.handleCapturePromote)
	s.mux.HandleFunc("GET /programs", s.handlePrograms)
	s.mux.HandleFunc("GET /programs/edit", s.handleProgramEdit)
	s.mux.HandleFunc("POST /programs", s.handleProgramSave)
	s.mux.HandleFunc("POST /programs/preview", s.handleProgramPreview)
	s.mux.HandleFunc("GET /scan", s.handleScanForm)
	s.mux.HandleFunc("POST /scan", s.handleScanRun)
	s.mux.HandleFunc("GET /runs/{id}", s.handleRunStatus)
	s.mux.HandleFunc("GET /findings", s.handleFindings)
	s.mux.HandleFunc("POST /findings/bulk", s.handleBulkTriage)
	s.mux.HandleFunc("GET /findings/{id}", s.handleFindingDetail)
	s.mux.HandleFunc("POST /findings/{id}/status", s.handleTriage)
	s.mux.HandleFunc("GET /report", s.handleReport)
	s.mux.HandleFunc("GET /report/download", s.handleReportDownload)
	s.mux.HandleFunc("GET /report/print", s.handleReportPrint)
	s.mux.HandleFunc("GET /report/export", s.handleReportExport)
	s.mux.HandleFunc("GET /settings", s.handleSettings)
	s.mux.HandleFunc("POST /settings/secrets", s.handleAddSecret)
	s.mux.HandleFunc("POST /settings/secrets/delete", s.handleDeleteSecret)
	s.mux.HandleFunc("GET /audit", s.handleAudit)
}

// ---- Scan ----

type scanPage struct {
	Nav      string
	Title    string
	Program  string
	CSRF     string
	Seeds    string
	InScope  string
	OutScope string
	Targets       string
	OpenAPI       string
	UpstreamProxy string
	RPS           string
	Errors        []string
	Result        *scanView
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
	page := scanPage{Nav: "scan", Title: "Scan", CSRF: s.csrfToken(r), RPS: "10"}

	// Bila diberi ?program=, prefill scope dari program tersimpan.
	if prog := strings.TrimSpace(r.URL.Query().Get("program")); prog != "" {
		if p, err := s.store.GetProgram(r.Context(), prog); err == nil {
			page.Program = p.Name
			page.InScope = strings.Join(p.InScope, "\n")
			page.OutScope = strings.Join(p.OutScope, "\n")
		}
	}
	// Default contoh (langsung mendemokan gate) bila tak ada program.
	if page.Program == "" {
		page.Program = "demo"
		page.Seeds = "demo.test"
		page.InScope = "demo.test\n*.demo.test"
		page.OutScope = "admin.demo.test"
		page.Targets = "demo.test\nevil.test"
	}
	s.render(w, "scan", "base", page)
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
	proxyChain := splitLines(r.FormValue("upstream_proxy")) // satu hop per baris

	page := scanPage{
		Nav: "scan", Title: "Scan", Program: program,
		Seeds:         r.FormValue("seeds"),
		InScope:       r.FormValue("in_scope"),
		OutScope:      r.FormValue("out_scope"),
		Targets:       r.FormValue("targets"),
		OpenAPI:       r.FormValue("openapi"),
		UpstreamProxy: r.FormValue("upstream_proxy"),
		RPS:           r.FormValue("rps"),
	}

	// Scan ter-arah spec: perluas OpenAPI/Swagger jadi endpoint → target. Tiap
	// endpoint TETAP lewat scope guard di bawah (spec tak memintas batas).
	if spec := strings.TrimSpace(r.FormValue("openapi")); spec != "" {
		base := ""
		if len(targets) > 0 {
			base = targets[0]
		}
		eps, perr := openapi.Endpoints([]byte(spec), base)
		if perr != nil {
			page.Errors = append(page.Errors, "OpenAPI/Swagger: "+perr.Error())
		} else {
			targets = append(targets, eps...)
		}
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

	// Simpan/perbarui definisi scope program (persisten lintas-restart).
	_ = s.store.SaveProgram(r.Context(), store.Program{Name: program, InScope: inScope, OutScope: outScope})

	// Enqueue: scan berjalan di latar belakang; handler membalas run_id seketika.
	runID := s.enqueueScan(program, guard, seeds, targets, rps, proxyChain)

	if run, ok := s.queue.Get(runID); ok {
		s.renderPartial(w, "scan", "run_status", toRunView(run))
	}
}

// enqueueScan menjalankan satu scan di latar belakang (worker pool) dan
// mengembalikan run id seketika. Satu jalur peluncuran scan dipakai bersama oleh
// form Scan dan "promote" dari Capture. Task memakai ctx milik queue (bukan
// r.Context()) agar tak dibatalkan saat response web dikirim. Rate limiter selalu
// dipasang (tak bisa dimatikan); scope guard menjadi satu-satunya gate.
func (s *Server) enqueueScan(program string, guard *scope.Guard, seeds, targets []string, rps float64, proxyChain []string) string {
	storeRef := s.store
	return s.queue.Enqueue(program, scanLabel(seeds, targets), func(ctx context.Context, runID string) (jobs.Summary, error) {
		s.auditAppend(ctx, audit.Event{Kind: "run.start", Program: program, RunID: runID, Message: scanLabel(seeds, targets)})

		auditSink := func(e orchestrator.AuditEvent) {
			s.auditAppend(ctx, audit.Event{
				Kind: "scope.decision", Program: e.Program, RunID: e.RunID, Target: e.Target,
				Allowed: e.Allowed, Reason: string(e.Reason), Layer: string(e.Layer), Message: e.MatchedEntry,
			})
		}
		o := orchestrator.New(guard, s.engines[0], storeRef,
			ratelimit.New(ratelimit.Config{RequestsPerSecond: rps, Burst: 5}), auditSink)
		for _, e := range s.engines[1:] {
			o.AddEngine(e)
		}
		if len(seeds) > 0 && s.recon != nil {
			o.UseRecon(s.recon)
		}
		res, err := o.RunScan(ctx, orchestrator.ScanRequest{Program: program, RunID: runID, Seeds: seeds, Targets: targets, ProxyChain: proxyChain})
		if err != nil {
			s.auditAppend(ctx, audit.Event{Kind: "run.finish", Program: program, RunID: runID, Message: "gagal: " + err.Error()})
			return jobs.Summary{}, err
		}
		s.auditAppend(ctx, audit.Event{Kind: "run.finish", Program: program, RunID: runID,
			Message: fmt.Sprintf("saved=%d dup=%d denied=%d", res.FindingsSaved, res.Duplicates, len(res.Denied))})

		sum := jobs.Summary{
			Discovered: res.Discovered,
			Scanned:    res.Scanned,
			Saved:      res.FindingsSaved,
			Duplicates: res.Duplicates,
		}
		for _, d := range res.Denied {
			sum.Denied = append(sum.Denied, fmt.Sprintf("%s — %s (%s)", d.Target, d.Reason, d.Layer))
		}
		return sum, nil
	})
}

func (s *Server) handleRunStatus(w http.ResponseWriter, r *http.Request) {
	run, ok := s.queue.Get(r.PathValue("id"))
	if !ok {
		http.Error(w, "run tidak ditemukan", http.StatusNotFound)
		return
	}
	s.renderPartial(w, "scan", "run_status", toRunView(run))
}

type runView struct {
	ID         string
	Program    string
	Status     string
	Label      string
	Err        string
	Active     bool
	Discovered int
	Scanned    int
	Saved      int
	Duplicates int
	Denied     []string
}

func toRunView(r *jobs.Run) runView {
	return runView{
		ID:         r.ID,
		Program:    r.Program,
		Status:     string(r.Status),
		Label:      r.Label,
		Err:        r.Err,
		Active:     r.Status == jobs.Queued || r.Status == jobs.Running,
		Discovered: r.Summary.Discovered,
		Scanned:    len(r.Summary.Scanned),
		Saved:      r.Summary.Saved,
		Duplicates: r.Summary.Duplicates,
		Denied:     r.Summary.Denied,
	}
}

func scanLabel(seeds, targets []string) string {
	var parts []string
	if len(seeds) > 0 {
		parts = append(parts, fmt.Sprintf("%d seed", len(seeds)))
	}
	if len(targets) > 0 {
		parts = append(parts, fmt.Sprintf("%d target", len(targets)))
	}
	return strings.Join(parts, " + ")
}

// ---- Findings ----

type findingsPage struct {
	Nav      string
	Title    string
	Program  string
	CSRF     string
	Programs []string
	Findings []*finding.Finding
	Selected *finding.Finding
	// filter aktif (untuk mengisi ulang kontrol & mempertahankan di query).
	FSeverity string
	FStatus   string
	FType     string
	FRun      string
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	program := strings.TrimSpace(r.URL.Query().Get("program"))
	progs := s.programNames(r.Context())
	if program == "" && len(progs) > 0 {
		program = progs[0]
	}

	q := store.Query{Program: program, RunID: strings.TrimSpace(r.URL.Query().Get("run"))}
	fSev := strings.TrimSpace(r.URL.Query().Get("severity"))
	fStatus := strings.TrimSpace(r.URL.Query().Get("status"))
	fType := strings.TrimSpace(r.URL.Query().Get("type"))
	if fSev != "" {
		q.Severities = []finding.Severity{finding.Severity(fSev)}
	}
	if fStatus != "" {
		q.Statuses = []finding.Status{finding.Status(fStatus)}
	}
	if fType != "" {
		q.Types = []string{fType}
	}

	var findings []*finding.Finding
	if program != "" {
		findings, _ = s.store.List(r.Context(), q)
	}

	page := findingsPage{
		Nav: "findings", Title: "Findings", Program: program, CSRF: s.csrfToken(r),
		Programs: progs, Findings: findings,
		FSeverity: fSev, FStatus: fStatus, FType: fType, FRun: q.RunID,
	}
	if id := strings.TrimSpace(r.URL.Query().Get("id")); id != "" {
		if f, err := s.store.Get(r.Context(), id); err == nil {
			page.Selected = f
		}
	}
	s.render(w, "findings", "base", page)
}

func (s *Server) handleBulkTriage(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form tidak valid", http.StatusBadRequest)
		return
	}
	status := finding.Status(strings.TrimSpace(r.FormValue("status")))
	switch status {
	case finding.StatusConfirmed, finding.StatusFalsePositive, finding.StatusIgnored, finding.StatusNew:
	default:
		http.Error(w, "status triase tidak diizinkan", http.StatusBadRequest)
		return
	}
	for _, id := range r.Form["ids"] {
		_ = s.store.SetStatus(r.Context(), id, status, "")
	}
	http.Redirect(w, r, "/findings?program="+url.QueryEscape(strings.TrimSpace(r.FormValue("program"))), http.StatusSeeOther)
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
	CSRF    string
	Report  report.Report
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	program := strings.TrimSpace(r.URL.Query().Get("program"))
	if progs := s.programNames(r.Context()); program == "" && len(progs) > 0 {
		program = progs[0]
	}
	page := reportPage{Nav: "report", Title: "Reports", Program: program, CSRF: s.csrfToken(r)}
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

// handleReportExport mengunduh draft terformat template platform (HackerOne /
// Bugcrowd). Dengan ?id= -> satu temuan terkonfirmasi; tanpa id -> seluruh
// report. Hanya menghasilkan berkas untuk disalin/submit MANUAL — tanpa
// auto-submit, tanpa koneksi keluar.
func (s *Server) handleReportExport(w http.ResponseWriter, r *http.Request) {
	program := strings.TrimSpace(r.URL.Query().Get("program"))
	platform := report.Platform(strings.TrimSpace(r.URL.Query().Get("platform")))
	if program == "" {
		http.Error(w, "program wajib", http.StatusBadRequest)
		return
	}
	if !platform.Valid() {
		http.Error(w, "platform export tidak didukung", http.StatusBadRequest)
		return
	}

	var md, fname string
	if id := strings.TrimSpace(r.URL.Query().Get("id")); id != "" {
		f, err := s.store.Get(r.Context(), id)
		if err != nil || f.Program != program {
			http.Error(w, "temuan tidak ditemukan", http.StatusNotFound)
			return
		}
		if f.Status != finding.StatusConfirmed {
			http.Error(w, "hanya temuan terkonfirmasi yang bisa diekspor", http.StatusBadRequest)
			return
		}
		md = report.ExportFinding(f, platform)
		fname = fmt.Sprintf("%s-%s.md", platform, safeFilename(id))
	} else {
		findings, _ := s.store.List(r.Context(), store.Query{Program: program})
		md = report.ExportReport(report.Build(program, findings, time.Now()), platform)
		fname = fmt.Sprintf("%s-%s.md", platform, safeFilename(program))
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, fname))
	io.WriteString(w, md)
}

// ---- Programs / scope editor ----

type programsPage struct {
	Nav      string
	Title    string
	Program  string
	CSRF     string
	Programs []*store.Program
}

func (s *Server) handlePrograms(w http.ResponseWriter, r *http.Request) {
	progs, _ := s.store.ListPrograms(r.Context())
	s.render(w, "programs", "base", programsPage{
		Nav: "programs", Title: "Programs", CSRF: s.csrfToken(r), Programs: progs,
	})
}

type programEditPage struct {
	Nav      string
	Title    string
	Program  string
	CSRF     string
	Name     string
	InScope  string
	OutScope string
	Targets  string
	IsNew    bool
	Errors   []string
}

func (s *Server) handleProgramEdit(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	page := programEditPage{Nav: "programs", Title: "Scope editor", CSRF: s.csrfToken(r), Program: name, Name: name, IsNew: true}
	if name != "" {
		if p, err := s.store.GetProgram(r.Context(), name); err == nil {
			page.InScope = strings.Join(p.InScope, "\n")
			page.OutScope = strings.Join(p.OutScope, "\n")
			page.IsNew = false
		}
	}
	s.render(w, "program_edit", "base", page)
}

func (s *Server) handleProgramSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form tidak valid", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	inScope := splitLines(r.FormValue("in_scope"))
	outScope := splitLines(r.FormValue("out_scope"))

	page := programEditPage{
		Nav: "programs", Title: "Scope editor", CSRF: s.csrfToken(r), Program: name, Name: name,
		InScope: r.FormValue("in_scope"), OutScope: r.FormValue("out_scope"), Targets: r.FormValue("targets"),
		IsNew: false,
	}
	if name == "" {
		page.Errors = append(page.Errors, "Nama program wajib.")
	}
	// Fail-closed: tolak simpan bila ada entri scope tak terurai (khususnya out-of-scope).
	if _, errs := scope.New(inScope, outScope); len(errs) > 0 {
		for _, e := range errs {
			page.Errors = append(page.Errors, "Scope tak valid: "+e.Error())
		}
	}
	if len(page.Errors) > 0 {
		s.render(w, "program_edit", "base", page)
		return
	}
	if err := s.store.SaveProgram(r.Context(), store.Program{Name: name, InScope: inScope, OutScope: outScope}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/programs", http.StatusSeeOther)
}

type previewResult struct {
	Warnings []string
	Rows     []previewRow
}

type previewRow struct {
	Target  string
	Allowed bool
	Reason  string
}

func (s *Server) handleProgramPreview(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form tidak valid", http.StatusBadRequest)
		return
	}
	guard, errs := scope.New(splitLines(r.FormValue("in_scope")), splitLines(r.FormValue("out_scope")))
	res := previewResult{}
	for _, e := range errs {
		res.Warnings = append(res.Warnings, e.Error())
	}
	for _, t := range splitLines(r.FormValue("targets")) {
		d := guard.Evaluate(t)
		res.Rows = append(res.Rows, previewRow{Target: d.Target, Allowed: d.Allowed, Reason: string(d.Reason)})
	}
	s.renderPartial(w, "program_edit", "program_preview", res)
}

// ---- Audit ----

func (s *Server) auditAppend(ctx context.Context, e audit.Event) {
	if s.audit != nil {
		_, _ = s.audit.Append(ctx, e)
	}
}

type auditPage struct {
	Nav       string
	Title     string
	Program   string
	CSRF      string
	Programs  []string
	Events    []audit.Event
	Integrity audit.Result
	AuditOn   bool
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	program := strings.TrimSpace(r.URL.Query().Get("program"))
	page := auditPage{
		Nav: "audit", Title: "Audit", Program: program, CSRF: s.csrfToken(r),
		AuditOn:  s.audit != nil,
		Programs: s.programNames(r.Context()),
	}
	if s.audit != nil {
		page.Events, _ = s.audit.List(r.Context(), audit.Filter{Program: program, Limit: 200})
		page.Integrity, _ = s.audit.Verify(r.Context())
	}
	s.render(w, "audit", "base", page)
}

// ---- Dashboard ----

type dashSev struct {
	Severity finding.Severity
	Count    int
}

type dashRow struct {
	Program     string
	Total       int
	Confirmed   int
	New         int
	Severities  []dashSev // urut critical..info (termasuk 0 untuk penjajaran kolom)
	Runs        int
	LastRun     string
	LastAt      time.Time
	HasActivity bool
}

type dashboardPage struct {
	Nav            string
	Title          string
	Program        string
	CSRF           string
	Rows           []dashRow
	TotalPrograms  int
	TotalFindings  int
	TotalConfirmed int
	TotalRuns      int
}

var dashSevOrder = []finding.Severity{
	finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium,
	finding.SeverityLow, finding.SeverityInfo,
}

// handleDashboard menampilkan ringkasan lintas-program (hitungan dari store;
// read-only, tanpa jaringan). Duplikat dikecualikan (List default).
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	page := dashboardPage{Nav: "dashboard", Title: "Dashboard", CSRF: s.csrfToken(r)}

	for _, name := range s.programNames(ctx) {
		fs, _ := s.store.List(ctx, store.Query{Program: name})
		row := dashRow{Program: name}
		sevc := map[finding.Severity]int{}
		runs := map[string]bool{}
		for _, f := range fs {
			row.Total++
			sevc[f.Severity]++
			switch f.Status {
			case finding.StatusConfirmed:
				row.Confirmed++
			case finding.StatusNew:
				row.New++
			}
			if f.RunID != "" {
				runs[f.RunID] = true
			}
			if t := f.CreatedAt.Time; t.After(row.LastAt) {
				row.LastAt = t
				if f.RunID != "" {
					row.LastRun = f.RunID
				}
			}
		}
		for _, sev := range dashSevOrder {
			row.Severities = append(row.Severities, dashSev{Severity: sev, Count: sevc[sev]})
		}
		row.Runs = len(runs)
		row.HasActivity = !row.LastAt.IsZero()

		page.Rows = append(page.Rows, row)
		page.TotalFindings += row.Total
		page.TotalConfirmed += row.Confirmed
		page.TotalRuns += row.Runs
	}
	page.TotalPrograms = len(page.Rows)

	// Paling baru aktif di atas; tanpa aktivitas di bawah (urut nama).
	sort.SliceStable(page.Rows, func(i, j int) bool {
		a, b := page.Rows[i], page.Rows[j]
		if a.HasActivity != b.HasActivity {
			return a.HasActivity
		}
		if a.HasActivity && !a.LastAt.Equal(b.LastAt) {
			return a.LastAt.After(b.LastAt)
		}
		return a.Program < b.Program
	})

	s.render(w, "dashboard", "base", page)
}

// ---- SAST (plugin) ----

type sastResult struct {
	Engine     string
	Path       string
	Saved      int
	Duplicates int
}

type sastPage struct {
	Nav     string
	Title   string
	Program string
	CSRF    string
	Enabled bool
	Root    string
	Engines []string
	Subpath string
	Engine  string
	Result  *sastResult
	Error   string
}

func (s *Server) sastBasePage() sastPage {
	return sastPage{
		Nav: "sast", Title: "SAST", Enabled: s.sastRoot != "",
		Root: s.sastRoot, Engines: sast.Names(), Engine: "mock",
	}
}

func (s *Server) handleSAST(w http.ResponseWriter, r *http.Request) {
	page := s.sastBasePage()
	page.Program = strings.TrimSpace(r.URL.Query().Get("program"))
	page.CSRF = s.csrfToken(r)
	s.render(w, "sast", "base", page)
}

// handleSASTRun menjalankan satu adapter SAST pada subpath DI DALAM sastRoot.
// Path scope ditegakkan oleh sast.Resolve (default-deny); analisis lokal, tak
// menyentuh jaringan. Temuan masuk ke store & Findings seperti engine lain.
func (s *Server) handleSASTRun(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form tidak valid", http.StatusBadRequest)
		return
	}
	page := s.sastBasePage()
	page.CSRF = s.csrfToken(r)
	page.Program = strings.TrimSpace(r.FormValue("program"))
	page.Subpath = strings.TrimSpace(r.FormValue("subpath"))
	page.Engine = strings.TrimSpace(r.FormValue("engine"))

	if !page.Enabled {
		page.Error = "SAST dinonaktifkan. Jalankan server dengan -sast-root <dir>."
		s.render(w, "sast", "base", page)
		return
	}
	if page.Program == "" {
		page.Error = "Program wajib diisi."
		s.render(w, "sast", "base", page)
		return
	}
	eng, ok := sast.Lookup(page.Engine)
	if !ok {
		page.Error = "Adapter SAST tidak dikenal: " + page.Engine
		s.render(w, "sast", "base", page)
		return
	}

	dir, err := sast.Resolve(s.sastRoot, page.Subpath)
	if err != nil {
		// Boundary ditolak — catat ke audit (seperti penolakan scope DAST).
		if s.audit != nil {
			_, _ = s.audit.Append(r.Context(), audit.Event{
				Kind: "sast.scope", Program: page.Program, Target: page.Subpath,
				Allowed: false, Reason: err.Error(), Layer: "path",
			})
		}
		page.Error = "Path ditolak: " + err.Error()
		s.render(w, "sast", "base", page)
		return
	}

	runID := fmt.Sprintf("sast-%d", time.Now().UnixNano())
	res, err := sast.Run(r.Context(), dir, page.Subpath, page.Program, runID, []sast.Engine{eng}, s.store, s.audit)
	if err != nil {
		page.Error = "Analisis gagal: " + err.Error()
		s.render(w, "sast", "base", page)
		return
	}
	page.Result = &sastResult{Engine: eng.Name(), Path: page.Subpath, Saved: res.Saved, Duplicates: res.Duplicates}
	s.render(w, "sast", "base", page)
}

// ---- gRPC (enumerasi) ----

type grpcResult struct {
	Scanned int
	Saved   int
	Denied  []string
}

type grpcPage struct {
	Nav        string
	Title      string
	Program    string
	CSRF       string
	Programs   []string
	EngineName string
	Targets    string
	Fuzz       bool
	Result     *grpcResult
	Error      string
}

func (s *Server) handleGRPC(w http.ResponseWriter, r *http.Request) {
	page := grpcPage{
		Nav: "grpc", Title: "gRPC", CSRF: s.csrfToken(r),
		Program: strings.TrimSpace(r.URL.Query().Get("program")),
		Programs: s.programNames(r.Context()), EngineName: s.grpcEngine.Name(),
	}
	s.render(w, "grpc", "base", page)
}

// handleGRPCRun mengenumerasi target gRPC (host:port) via reflection. Tiap host
// WAJIB lolos scope guard program (grpcurl tak bisa diproxy; scope ditegakkan di
// hulu). Temuan masuk store & Findings seperti engine lain.
func (s *Server) handleGRPCRun(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form tidak valid", http.StatusBadRequest)
		return
	}
	page := grpcPage{
		Nav: "grpc", Title: "gRPC", CSRF: s.csrfToken(r),
		Program: strings.TrimSpace(r.FormValue("program")),
		Targets: r.FormValue("targets"), Programs: s.programNames(r.Context()),
		EngineName: s.grpcEngine.Name(), Fuzz: r.FormValue("fuzz") != "",
	}
	targets := splitLines(r.FormValue("targets"))
	if page.Program == "" || len(targets) == 0 {
		page.Error = "Program dan minimal satu target host:port wajib diisi."
		s.render(w, "grpc", "base", page)
		return
	}
	prog, err := s.store.GetProgram(r.Context(), page.Program)
	if err != nil {
		page.Error = "Program belum punya scope tersimpan — simpan scope-nya dulu di halaman Programs."
		s.render(w, "grpc", "base", page)
		return
	}
	guard, errs := scope.New(prog.InScope, prog.OutScope)
	if len(errs) > 0 {
		page.Error = "Scope program tak valid: " + errs[0].Error()
		s.render(w, "grpc", "base", page)
		return
	}

	runID := fmt.Sprintf("grpc-%d", time.Now().UnixNano())
	res := &grpcResult{}
	for _, tgt := range targets {
		host := tgt
		if h, _, e := net.SplitHostPort(tgt); e == nil {
			host = h
		}
		if d := guard.Evaluate(host); !d.Allowed {
			res.Denied = append(res.Denied, tgt)
			s.auditAppend(r.Context(), audit.Event{Kind: "grpc.scope", Program: page.Program, RunID: runID, Target: tgt, Allowed: false, Reason: string(d.Reason), Layer: "input"})
			continue
		}
		s.auditAppend(r.Context(), audit.Event{Kind: "grpc.scope", Program: page.Program, RunID: runID, Target: tgt, Allowed: true, Layer: "input"})
		scan := s.grpcEngine.Scan
		if page.Fuzz {
			scan = s.grpcEngine.Fuzz
		}
		fs, serr := scan(r.Context(), tgt, page.Program, runID)
		if serr != nil {
			page.Error = "Enumerasi gagal untuk " + tgt + ": " + serr.Error()
			continue
		}
		res.Scanned++
		for _, f := range fs {
			if sr, e := s.store.Save(r.Context(), f); e == nil && !sr.Deduplicated {
				res.Saved++
			}
		}
	}
	page.Result = res
	s.render(w, "grpc", "base", page)
}

// ---- Capture (reverse proxy perekam) ----

// captureSession adalah satu gateway reverse-proxy aktif untuk sebuah program.
type captureSession struct {
	Program string
	Target  string
	Addr    string
	Started time.Time
	gw      *egress.Gateway
	stop    func() error
}

type capturePage struct {
	Nav      string
	Title    string
	Program  string
	CSRF     string
	Programs []string
	Target   string
	RPS      string
	Session  *captureSessionView
	Records  []egress.CaptureRecord
	Error    string
	Note     string
}

type captureSessionView struct {
	Program string
	Target  string
	Addr    string
	Started string
	Count   int
}

func (s *Server) getCapture(program string) *captureSession {
	s.captureMu.Lock()
	defer s.captureMu.Unlock()
	return s.captures[program]
}

func (s *Server) setCapture(program string, sess *captureSession) {
	s.captureMu.Lock()
	s.captures[program] = sess
	s.captureMu.Unlock()
}

// delCapture menghapus sesi dari peta dan mengembalikannya (nil bila tak ada).
func (s *Server) delCapture(program string) *captureSession {
	s.captureMu.Lock()
	defer s.captureMu.Unlock()
	sess := s.captures[program]
	delete(s.captures, program)
	return sess
}

func (s *Server) capturePageFor(r *http.Request, program string) capturePage {
	page := capturePage{
		Nav: "capture", Title: "Capture", CSRF: s.csrfToken(r),
		Program: program, Programs: s.programNames(r.Context()), RPS: "10",
	}
	if sess := s.getCapture(program); sess != nil {
		recs := sess.gw.Records()
		page.Target = sess.Target
		page.Records = recs
		page.Session = &captureSessionView{
			Program: sess.Program, Target: sess.Target, Addr: sess.Addr,
			Started: sess.Started.Format("15:04:05"), Count: len(recs),
		}
	}
	return page
}

func (s *Server) handleCapture(w http.ResponseWriter, r *http.Request) {
	program := strings.TrimSpace(r.URL.Query().Get("program"))
	page := s.capturePageFor(r, program)
	if run := strings.TrimSpace(r.URL.Query().Get("run")); run != "" {
		page.Note = fmt.Sprintf("%s endpoint dipromosikan jadi scan %s — lihat Findings/Audit.", r.URL.Query().Get("n"), run)
	}
	s.render(w, "capture", "base", page)
}

// handleCaptureStart membuka gateway reverse-proxy ke satu target in-scope. Target
// WAJIB lolos scope guard program (fail closed); gateway memakai transport egress
// ter-guard sehingga hanya host in-scope yang diteruskan.
func (s *Server) handleCaptureStart(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form tidak valid", http.StatusBadRequest)
		return
	}
	program := strings.TrimSpace(r.FormValue("program"))
	target := strings.TrimSpace(r.FormValue("target"))
	rps := parseRPS(r.FormValue("rps"))

	page := s.capturePageFor(r, program)
	page.Target = target
	page.RPS = r.FormValue("rps")

	if program == "" || target == "" {
		page.Error = "Program dan target wajib diisi."
		s.render(w, "capture", "base", page)
		return
	}
	if s.getCapture(program) != nil {
		page.Error = "Sesi capture untuk program ini sudah berjalan — hentikan dulu."
		s.render(w, "capture", "base", page)
		return
	}
	prog, err := s.store.GetProgram(r.Context(), program)
	if err != nil {
		page.Error = "Program belum punya scope tersimpan — simpan scope-nya dulu di halaman Programs."
		s.render(w, "capture", "base", page)
		return
	}
	guard, errs := scope.New(prog.InScope, prog.OutScope)
	if len(errs) > 0 {
		page.Error = "Scope program tak valid: " + errs[0].Error()
		s.render(w, "capture", "base", page)
		return
	}

	// Audit penolakan egress gateway (host di luar scope saat browsing). Memakai
	// context.Background karena gateway hidup melampaui request ini.
	auditSink := func(d egress.Decision) {
		if d.Allowed {
			return
		}
		s.auditAppend(context.Background(), audit.Event{
			Kind: "capture.egress", Program: program, Target: d.Target,
			Allowed: false, Reason: string(d.Reason), Layer: "egress",
		})
	}
	px := egress.New(guard, auditSink)
	lim := ratelimit.New(ratelimit.Config{RequestsPerSecond: rps, Burst: 5})
	gw, err := egress.NewGateway(px, target, lim)
	if err != nil {
		s.auditAppend(r.Context(), audit.Event{Kind: "capture.start", Program: program, Target: target, Allowed: false, Reason: "out-of-scope", Message: err.Error()})
		page.Error = "Tidak bisa memulai gateway: " + err.Error()
		s.render(w, "capture", "base", page)
		return
	}
	addr, stop, err := gw.Listen("127.0.0.1:0")
	if err != nil {
		page.Error = "Gagal membuka listener: " + err.Error()
		s.render(w, "capture", "base", page)
		return
	}
	s.setCapture(program, &captureSession{
		Program: program, Target: gw.Target(), Addr: addr, Started: time.Now(), gw: gw, stop: stop,
	})
	s.auditAppend(r.Context(), audit.Event{Kind: "capture.start", Program: program, Target: gw.Target(), Allowed: true, Message: "listener " + addr})
	http.Redirect(w, r, "/capture?program="+url.QueryEscape(program), http.StatusSeeOther)
}

func (s *Server) handleCaptureStop(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form tidak valid", http.StatusBadRequest)
		return
	}
	program := strings.TrimSpace(r.FormValue("program"))
	if sess := s.delCapture(program); sess != nil {
		if sess.stop != nil {
			_ = sess.stop()
		}
		s.auditAppend(r.Context(), audit.Event{Kind: "capture.stop", Program: program, Target: sess.Target, Allowed: true, Message: fmt.Sprintf("%d kandidat", len(sess.gw.Records()))})
	}
	http.Redirect(w, r, "/capture?program="+url.QueryEscape(program), http.StatusSeeOther)
}

// handleCapturePromote mengubah endpoint terpilih menjadi scan. Endpoint TETAP
// lewat scope guard + rate limiter + egress (jalur scan yang sama) — tak ada
// pintasan. Tanpa auto-submit.
func (s *Server) handleCapturePromote(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form tidak valid", http.StatusBadRequest)
		return
	}
	program := strings.TrimSpace(r.FormValue("program"))
	targets := r.Form["url"]
	rps := parseRPS(r.FormValue("rps"))

	if program == "" || len(targets) == 0 {
		page := s.capturePageFor(r, program)
		page.Error = "Pilih minimal satu endpoint untuk di-promote."
		s.render(w, "capture", "base", page)
		return
	}
	prog, err := s.store.GetProgram(r.Context(), program)
	if err != nil {
		page := s.capturePageFor(r, program)
		page.Error = "Program belum punya scope tersimpan."
		s.render(w, "capture", "base", page)
		return
	}
	guard, errs := scope.New(prog.InScope, prog.OutScope)
	if len(errs) > 0 {
		page := s.capturePageFor(r, program)
		page.Error = "Scope program tak valid: " + errs[0].Error()
		s.render(w, "capture", "base", page)
		return
	}
	runID := s.enqueueScan(program, guard, nil, targets, rps, nil)
	s.auditAppend(r.Context(), audit.Event{Kind: "capture.promote", Program: program, RunID: runID, Allowed: true, Message: fmt.Sprintf("%d endpoint", len(targets))})
	http.Redirect(w, r, fmt.Sprintf("/capture?program=%s&run=%s&n=%d", url.QueryEscape(program), url.QueryEscape(runID), len(targets)), http.StatusSeeOther)
}

// ---- Settings / secrets ----

type settingsPage struct {
	Nav     string
	Title   string
	Program string
	CSRF    string
	Scope   string
	Scopes  []string
	Secrets []secret.Meta
	VaultOn bool
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	scope := normScope(r.URL.Query().Get("scope"))
	page := settingsPage{
		Nav: "settings", Title: "Settings", Scope: scope, CSRF: s.csrfToken(r),
		VaultOn: s.vault != nil,
		Scopes:  append([]string{"global"}, s.programNames(r.Context())...),
	}
	if s.vault != nil {
		page.Secrets, _ = s.vault.List(r.Context(), scope)
	}
	s.render(w, "settings", "base", page)
}

func (s *Server) handleAddSecret(w http.ResponseWriter, r *http.Request) {
	if s.vault == nil {
		http.Error(w, "vault tidak dikonfigurasi", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form tidak valid", http.StatusBadRequest)
		return
	}
	scope := normScope(r.FormValue("scope"))
	name := strings.TrimSpace(r.FormValue("name"))
	value := r.FormValue("value")
	if name == "" || value == "" {
		http.Error(w, "nama & nilai wajib", http.StatusBadRequest)
		return
	}
	if err := s.vault.Put(r.Context(), scope, name, []byte(value)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/settings?scope="+url.QueryEscape(scope), http.StatusSeeOther)
}

func (s *Server) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	if s.vault == nil {
		http.Error(w, "vault tidak dikonfigurasi", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form tidak valid", http.StatusBadRequest)
		return
	}
	scope := normScope(r.FormValue("scope"))
	name := strings.TrimSpace(r.FormValue("name"))
	_ = s.vault.Delete(r.Context(), scope, name)
	http.Redirect(w, r, "/settings?scope="+url.QueryEscape(scope), http.StatusSeeOther)
}

func normScope(s string) string {
	if s = strings.TrimSpace(s); s != "" {
		return s
	}
	return "global"
}

// ---- helpers ----

// programNames menggabungkan program yang punya temuan tersimpan dengan program
// yang scope-nya sudah didefinisikan — keduanya persisten lintas-restart.
func (s *Server) programNames(ctx context.Context) []string {
	set := map[string]bool{}
	if progs, err := s.store.Programs(ctx); err == nil {
		for _, p := range progs {
			set[p] = true
		}
	}
	if defs, err := s.store.ListPrograms(ctx); err == nil {
		for _, p := range defs {
			set[p.Name] = true
		}
	}
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

func parseTemplates(version string) (map[string]*template.Template, error) {
	funcs := template.FuncMap{
		"sevClass":    func(s finding.Severity) string { return "sev-" + strings.ToLower(string(s)) },
		"statusClass": func(s finding.Status) string { return "st-" + strings.ToLower(string(s)) },
		"join":        func(v []string, sep string) string { return strings.Join(v, sep) },
		"add":         func(a, b int) int { return a + b },
		"strs":        func(v ...string) []string { return v },
		"appVersion":  func() string { return version },
	}
	sets := map[string][]string{
		"dashboard":    {"templates/base.html", "templates/dashboard.html"},
		"sast":         {"templates/base.html", "templates/sast.html"},
		"grpc":         {"templates/base.html", "templates/grpc.html"},
		"capture":      {"templates/base.html", "templates/capture.html"},
		"scan":         {"templates/base.html", "templates/scan.html", "templates/scan_result.html", "templates/run_status.html"},
		"findings":     {"templates/base.html", "templates/findings.html", "templates/finding_detail.html"},
		"report":       {"templates/base.html", "templates/report.html"},
		"report_print": {"templates/report_print.html"},
		"settings":     {"templates/base.html", "templates/settings.html"},
		"audit":        {"templates/base.html", "templates/audit.html"},
		"programs":     {"templates/base.html", "templates/programs.html"},
		"program_edit": {"templates/base.html", "templates/program_edit.html", "templates/program_preview.html"},
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
