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
	"errors"
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
	"bughound/internal/auth"
	"bughound/internal/egress"
	"bughound/internal/engine"
	"bughound/internal/engine/grpc"
	"bughound/internal/finding"
	"bughound/internal/jobs"
	"bughound/internal/openapi"
	"bughound/internal/orchestrator"
	"bughound/internal/payload"
	"bughound/internal/ratelimit"
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
	users   store.UserStore // akun RBAC (nil bila authDisabled)
	engines []engine.Engine
	recon   recon.Engine
	// newEngines, bila diset, membangun instance engine + recon BARU untuk tiap
	// scan (laju request dijepit ke rps scan). Dipakai mode engine nyata agar tiap
	// run punya engine sendiri: menjepit laju per-engine DAN mencegah proxy egress
	// antar-run saling tumpang-tindih (tiap run menegakkan scope guard-nya sendiri).
	// nil (mock/test) = pakai instance tetap di `engines`/`recon`.
	newEngines func(rps float64, sel Selection) ([]engine.Engine, recon.Engine)
	// catalog mempersist Bank Payload (BH-SPEC-PAYLOAD); nil bila store tak
	// mendukung (mendeteksi lewat type assertion, seperti users). payloadSources
	// adalah sumber yang di-scan saat refresh katalog.
	catalog        store.CatalogStore
	payloadSources []payload.Source
	vault          secret.Vault
	audit          audit.Log
	authDisabled   bool // true = akses terbuka tanpa login (hanya -no-auth / test)
	queue          *jobs.Queue
	version        string
	sastRoot       string       // root kode yang diizinkan untuk SAST; kosong = SAST nonaktif
	grpcEngine     grpc.Scanner // enumerasi/fuzz gRPC (mock default; grpcurl bila -grpc real)

	captureMu sync.Mutex
	captures  map[string]*captureSession // sesi capture reverse-proxy aktif per program

	sessMu   sync.Mutex
	sessions map[string]sessionInfo // token sesi login → pengguna+peran

	pages map[string]*template.Template
}

// Selection menyeleksi subset template nuclei yang dijalankan sebuah scan,
// berdasarkan metadata bank payload (BH-SPEC-PAYLOAD §Seleksi). Kosong = semua
// template terpasang. Tags/Severity hanya memengaruhi engine nuclei; Stealth
// memengaruhi engine DAST (low-and-slow) dan laju scan keseluruhan.
type Selection struct {
	Tags     []string
	Severity []string
	// Stealth meminta profil low-and-slow: laju scan dijepit sangat rendah dan
	// engine DAST memakai satu koneksi + UA browser (jejak minimal pada target
	// ber-SOC). Non-destruktif selalu aktif terlepas dari ini.
	Stealth bool
	// APIRoutes menambahkan wordlist route API ter-bundle (Assetnote apiroutes)
	// ke engine ffuf — brute path API bervolume besar (opt-in per scan).
	APIRoutes bool
}

// Config mengonfigurasi server: store, engine DAST (minimal 1), recon & vault opsional.
type Config struct {
	Store   store.Store
	Engines []engine.Engine
	Recon   recon.Engine
	// NewEngines (opsional) membangun engine + recon BARU per scan dengan laju
	// request dijepit ke rps scan. Bila diset, dipakai menggantikan Engines/Recon
	// untuk tiap run (lihat Server.newEngines). Engines tetap wajib (≥1) sebagai
	// fallback & validasi; Recon boleh nil.
	NewEngines func(rps float64, sel Selection) ([]engine.Engine, recon.Engine)
	// PayloadSources adalah sumber Bank Payload yang di-scan saat refresh katalog
	// (BH-SPEC-PAYLOAD). Kosong = tombol refresh nonaktif; katalog tetap bisa
	// ditampilkan dari data tersimpan. Men-scan hanya berkas lokal (tanpa jaringan).
	PayloadSources []payload.Source
	Vault          secret.Vault
	Audit          audit.Log
	// Users adalah store akun RBAC. Wajib kecuali AuthDisabled=true. Login
	// (sesi) & HTTP Basic (otomasi) diverifikasi terhadapnya; peran menentukan
	// hak (viewer baca, operator ubah, admin kelola user).
	Users store.UserStore
	// AuthDisabled membuka akses tanpa autentikasi (TANPA login, TANPA RBAC).
	// Hanya untuk test dan flag eksplisit -no-auth di localhost tepercaya.
	// Default false: login WAJIB.
	AuthDisabled bool
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
	if !cfg.AuthDisabled && cfg.Users == nil {
		return nil, fmt.Errorf("web: Users wajib kecuali AuthDisabled=true")
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
		mux:            http.NewServeMux(),
		store:          cfg.Store,
		users:          cfg.Users,
		engines:        cfg.Engines,
		recon:          cfg.Recon,
		newEngines:     cfg.NewEngines,
		payloadSources: cfg.PayloadSources,
		vault:          cfg.Vault,
		audit:          cfg.Audit,
		authDisabled:   cfg.AuthDisabled,
		queue:          jobs.New(4),
		version:        version,
		sastRoot:       strings.TrimSpace(cfg.SASTRoot),
		captures:       map[string]*captureSession{},
		sessions:       map[string]sessionInfo{},
		pages:          pages,
	}
	if cfg.GRPCReal {
		s.grpcEngine = &grpc.Runner{Plaintext: cfg.GRPCPlaintext}
	} else {
		s.grpcEngine = grpc.Mock{}
	}
	// Bank Payload: store yang mendukung katalog dipakai; bila tidak, halaman
	// /payloads menampilkan pesan "tak didukung" (fitur degradasi mulus).
	if cs, ok := cfg.Store.(store.CatalogStore); ok {
		s.catalog = cs
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

type userCtxKey struct{}
type roleCtxKey struct{}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")

	// CSRF: pastikan cookie token ada lebih dulu (juga agar form login punya token),
	// dan sediakan ke handler lewat context untuk di-render ke form/hx-headers.
	token := s.ensureCSRFCookie(w, r)
	r = r.WithContext(context.WithValue(r.Context(), csrfCtxKey{}, token))

	// Auth: login WAJIB (kecuali AuthDisabled). Manusia memakai sesi login;
	// otomasi/CLI boleh HTTP Basic. Peran pengguna dibawa lewat context.
	if !s.authDisabled && !authExempt(r) {
		user, role, ok := s.authUser(r)
		if !ok {
			// Klien API (mesin) selalu dapat galat JSON 401, tak pernah redirect HTML.
			if isAPIPath(r) {
				writeAPIError(w, http.StatusUnauthorized, "autentikasi diperlukan (sesi login atau HTTP Basic)")
				return
			}
			// Kredensial Basic eksplisit yang gagal → 401 untuk otomasi/CLI.
			if r.Header.Get("Authorization") != "" {
				http.Error(w, "autentikasi gagal", http.StatusUnauthorized)
				return
			}
			// Browser tanpa sesi: arahkan ke halaman login untuk GET; tolak selain itu.
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			http.Error(w, "sesi tidak valid — silakan login", http.StatusUnauthorized)
			return
		}
		r = r.WithContext(context.WithValue(
			context.WithValue(r.Context(), userCtxKey{}, user), roleCtxKey{}, role))
	}

	// Tiap permintaan state-changing wajib mengirim token yang cocok (double-submit)
	// — memblok CSRF lintas-situs. Berlaku juga untuk POST /login.
	if isStateChanging(r.Method) && !validCSRF(r, token) {
		http.Error(w, "CSRF: token tidak valid atau permintaan lintas-situs", http.StatusForbidden)
		return
	}

	// Otorisasi RBAC: peran menentukan apa yang boleh diakses (default-deny bila
	// peran tak cukup). Dilewati saat auth dinonaktifkan atau path dikecualikan.
	if !s.authDisabled && !authExempt(r) {
		if !authorize(s.roleOf(r), r) {
			http.Error(w, "akses ditolak: peran tidak cukup untuk aksi ini", http.StatusForbidden)
			return
		}
	}

	s.mux.ServeHTTP(w, r)
}

// authExempt: halaman login & aset statis boleh diakses tanpa sesi.
func authExempt(r *http.Request) bool {
	return r.URL.Path == "/login" || strings.HasPrefix(r.URL.Path, "/static/")
}

// authUser mengautentikasi permintaan lewat sesi login ATAU HTTP Basic
// (username+password diverifikasi terhadap UserStore). Mengembalikan pengguna,
// peran, dan apakah berhasil.
func (s *Server) authUser(r *http.Request) (string, auth.Role, bool) {
	if info, ok := s.validSession(r); ok {
		return info.User, info.Role, true
	}
	if user, pass, ok := r.BasicAuth(); ok {
		if u, err := s.users.GetUser(r.Context(), user); err == nil {
			if auth.VerifyPassword(u.PassHash, pass) {
				return u.Username, auth.Role(u.Role), true
			}
		} else {
			auth.VerifyPassword(dummyHash, pass) // seragamkan waktu utk user tak dikenal
		}
	}
	return "", auth.Role(""), false
}

// authorize menegakkan RBAC: area /users hanya admin; aksi state-changing (selain
// logout) butuh operator ke atas; GET boleh untuk semua peran valid (default-deny).
func authorize(role auth.Role, r *http.Request) bool {
	switch {
	case r.URL.Path == "/users" || strings.HasPrefix(r.URL.Path, "/users/"):
		return auth.CanAdmin(role)
	case r.URL.Path == "/logout":
		return role.Valid()
	case isStateChanging(r.Method):
		return auth.CanWrite(role)
	default:
		return auth.CanRead(role)
	}
}

// currentUser mengembalikan pengguna & peran dari context (kosong bila auth
// nonaktif atau belum terautentikasi).
func (s *Server) currentUser(r *http.Request) (string, auth.Role) {
	user, _ := r.Context().Value(userCtxKey{}).(string)
	role, _ := r.Context().Value(roleCtxKey{}).(auth.Role)
	return user, role
}

func (s *Server) roleOf(r *http.Request) auth.Role {
	role, _ := r.Context().Value(roleCtxKey{}).(auth.Role)
	return role
}

// dummyHash menyeragamkan waktu verifikasi saat username tak dikenal (lawan
// enumerasi via timing). Dihitung sekali; tak pernah cocok kata sandi apa pun.
var dummyHash = func() string {
	h, _ := auth.HashPassword(randToken())
	return h
}()

const sessionCookie = "bh_session"
const sessionTTL = 12 * time.Hour

// sessionInfo adalah state satu sesi login: pengguna, peran, waktu dibuat.
type sessionInfo struct {
	User    string
	Role    auth.Role
	Created time.Time
}

func (s *Server) newSession(w http.ResponseWriter, r *http.Request, user string, role auth.Role) {
	tok := randToken()
	s.sessMu.Lock()
	s.sessions[tok] = sessionInfo{User: user, Role: role, Created: time.Now()}
	s.sessMu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: tok, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil,
	})
}

func (s *Server) validSession(r *http.Request) (sessionInfo, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return sessionInfo{}, false
	}
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	info, ok := s.sessions[c.Value]
	if !ok {
		return sessionInfo{}, false
	}
	if time.Since(info.Created) > sessionTTL {
		delete(s.sessions, c.Value)
		return sessionInfo{}, false
	}
	return info, true
}

func (s *Server) destroySession(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		s.sessMu.Lock()
		delete(s.sessions, c.Value)
		s.sessMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
}

// ---- Login ----

type loginPage struct {
	CSRF    string
	Error   string
	Version string
}

func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	if s.authDisabled {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	if _, ok := s.validSession(r); ok {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	s.render(w, r, "login", "login", loginPage{CSRF: s.csrfToken(r), Version: s.version})
}

func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if s.authDisabled {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form tidak valid", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	u, err := s.users.GetUser(r.Context(), username)
	if err == nil && auth.VerifyPassword(u.PassHash, password) {
		s.newSession(w, r, u.Username, auth.Role(u.Role))
		s.auditAppend(r.Context(), audit.Event{Kind: "auth.login", Allowed: true, Message: u.Username})
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	if err != nil {
		auth.VerifyPassword(dummyHash, password) // seragamkan waktu utk user tak dikenal
	}
	s.auditAppend(r.Context(), audit.Event{Kind: "auth.login", Allowed: false, Message: username})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_ = s.pages["login"].ExecuteTemplate(w, "login", loginPage{CSRF: s.csrfToken(r), Error: "Username atau password salah.", Version: s.version})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	user, _ := s.currentUser(r)
	s.destroySession(w, r)
	s.auditAppend(r.Context(), audit.Event{Kind: "auth.logout", Allowed: true, Message: user})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---- Users (RBAC admin) ----

type userRow struct {
	Username string
	Role     string
	Created  string
	IsSelf   bool
}

type usersPage struct {
	Nav     string
	Title   string
	Program string
	CSRF    string
	Me      string
	Users   []userRow
	Roles   []auth.Role
	Error   string
	Note    string
}

func (s *Server) usersPageFor(r *http.Request) usersPage {
	me, _ := s.currentUser(r)
	page := usersPage{Nav: "users", Title: "Users", CSRF: s.csrfToken(r), Me: me, Roles: auth.Roles()}
	if s.users != nil {
		list, _ := s.users.ListUsers(r.Context())
		for _, u := range list {
			page.Users = append(page.Users, userRow{
				Username: u.Username, Role: u.Role,
				Created: u.Created.Format("2006-01-02"), IsSelf: u.Username == me,
			})
		}
	}
	return page
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	if s.users == nil {
		http.Error(w, "manajemen user nonaktif (auth dinonaktifkan)", http.StatusServiceUnavailable)
		return
	}
	page := s.usersPageFor(r)
	switch r.URL.Query().Get("ok") {
	case "created":
		page.Note = "Pengguna dibuat."
	case "deleted":
		page.Note = "Pengguna dihapus."
	case "password":
		page.Note = "Kata sandi diperbarui."
	}
	s.render(w, r, "users", "base", page)
}

func (s *Server) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	if s.users == nil {
		http.Error(w, "manajemen user nonaktif", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form tidak valid", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	role := auth.Role(strings.TrimSpace(r.FormValue("role")))

	page := s.usersPageFor(r)
	if username == "" || password == "" {
		page.Error = "Username dan kata sandi wajib diisi."
		s.renderUsers(w, r, page, http.StatusBadRequest)
		return
	}
	if !role.Valid() {
		page.Error = "Peran tidak dikenal."
		s.renderUsers(w, r, page, http.StatusBadRequest)
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		page.Error = "Gagal meng-hash kata sandi: " + err.Error()
		s.renderUsers(w, r, page, http.StatusBadRequest)
		return
	}
	if err := s.users.CreateUser(r.Context(), store.User{Username: username, Role: string(role), PassHash: hash}); err != nil {
		if errors.Is(err, store.ErrUserExists) {
			page.Error = "Username sudah dipakai."
		} else {
			page.Error = "Gagal membuat pengguna: " + err.Error()
		}
		s.renderUsers(w, r, page, http.StatusBadRequest)
		return
	}
	actor, _ := s.currentUser(r)
	s.auditAppend(r.Context(), audit.Event{Kind: "user.create", Allowed: true, Message: fmt.Sprintf("%s membuat %s (%s)", actor, username, role)})
	http.Redirect(w, r, "/users?ok=created", http.StatusSeeOther)
}

func (s *Server) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	if s.users == nil {
		http.Error(w, "manajemen user nonaktif", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form tidak valid", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	me, _ := s.currentUser(r)

	page := s.usersPageFor(r)
	if username == me {
		page.Error = "Tidak bisa menghapus akun yang sedang login."
		s.renderUsers(w, r, page, http.StatusBadRequest)
		return
	}
	// Jangan sampai sistem kehilangan admin terakhir (anti kunci-diri).
	if s.isLastAdmin(r, username) {
		page.Error = "Tidak bisa menghapus admin terakhir."
		s.renderUsers(w, r, page, http.StatusBadRequest)
		return
	}
	if err := s.users.DeleteUser(r.Context(), username); err != nil {
		page.Error = "Gagal menghapus: " + err.Error()
		s.renderUsers(w, r, page, http.StatusBadRequest)
		return
	}
	s.auditAppend(r.Context(), audit.Event{Kind: "user.delete", Allowed: true, Message: fmt.Sprintf("%s menghapus %s", me, username)})
	http.Redirect(w, r, "/users?ok=deleted", http.StatusSeeOther)
}

func (s *Server) handleUserPassword(w http.ResponseWriter, r *http.Request) {
	if s.users == nil {
		http.Error(w, "manajemen user nonaktif", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form tidak valid", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	page := s.usersPageFor(r)
	if username == "" || password == "" {
		page.Error = "Username dan kata sandi baru wajib diisi."
		s.renderUsers(w, r, page, http.StatusBadRequest)
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		page.Error = "Gagal meng-hash kata sandi: " + err.Error()
		s.renderUsers(w, r, page, http.StatusBadRequest)
		return
	}
	if err := s.users.SetPassword(r.Context(), username, hash); err != nil {
		page.Error = "Gagal memperbarui kata sandi: " + err.Error()
		s.renderUsers(w, r, page, http.StatusBadRequest)
		return
	}
	me, _ := s.currentUser(r)
	s.auditAppend(r.Context(), audit.Event{Kind: "user.password", Allowed: true, Message: fmt.Sprintf("%s mereset kata sandi %s", me, username)})
	http.Redirect(w, r, "/users?ok=password", http.StatusSeeOther)
}

// renderUsers merender halaman Users dengan kode status tertentu (mis. 400 saat
// validasi gagal) tanpa mengganggu pembungkus chrome base.
func (s *Server) renderUsers(w http.ResponseWriter, r *http.Request, page usersPage, code int) {
	user, role := s.currentUser(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_ = s.pages["users"].ExecuteTemplate(w, "base", shellData{
		User: user, Role: string(role), AuthOn: !s.authDisabled, Body: page,
	})
}

// isLastAdmin melaporkan apakah username adalah satu-satunya admin tersisa.
func (s *Server) isLastAdmin(r *http.Request, username string) bool {
	list, err := s.users.ListUsers(r.Context())
	if err != nil {
		return true // fail closed: bila ragu, jangan izinkan penghapusan
	}
	admins, isAdmin := 0, false
	for _, u := range list {
		if auth.Role(u.Role) == auth.RoleAdmin {
			admins++
			if u.Username == username {
				isAdmin = true
			}
		}
	}
	return isAdmin && admins <= 1
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

	s.mux.HandleFunc("GET /login", s.handleLoginForm)
	s.mux.HandleFunc("POST /login", s.handleLoginSubmit)
	s.mux.HandleFunc("POST /logout", s.handleLogout)
	s.mux.HandleFunc("GET /users", s.handleUsers)
	s.mux.HandleFunc("POST /users", s.handleUserCreate)
	s.mux.HandleFunc("POST /users/delete", s.handleUserDelete)
	s.mux.HandleFunc("POST /users/password", s.handleUserPassword)
	s.mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	})
	s.mux.HandleFunc("GET /dashboard", s.handleDashboard)
	s.mux.HandleFunc("GET /dashboard/scans", s.handleDashboardScans)
	s.mux.HandleFunc("POST /dashboard/findings/delete", s.handleDashboardDeleteFindings)
	s.mux.HandleFunc("GET /sast", s.handleSAST)
	s.mux.HandleFunc("POST /sast/run", s.handleSASTRun)
	s.mux.HandleFunc("GET /grpc", s.handleGRPC)
	s.mux.HandleFunc("POST /grpc/run", s.handleGRPCRun)
	s.mux.HandleFunc("GET /capture", s.handleCapture)
	s.mux.HandleFunc("POST /capture/start", s.handleCaptureStart)
	s.mux.HandleFunc("POST /capture/stop", s.handleCaptureStop)
	s.mux.HandleFunc("POST /capture/promote", s.handleCapturePromote)
	s.mux.HandleFunc("GET /proxy", s.handleProxyForm)
	s.mux.HandleFunc("POST /proxy/check", s.handleProxyCheck)
	s.mux.HandleFunc("GET /programs", s.handlePrograms)
	s.mux.HandleFunc("GET /programs/edit", s.handleProgramEdit)
	s.mux.HandleFunc("POST /programs", s.handleProgramSave)
	s.mux.HandleFunc("POST /programs/delete", s.handleProgramDelete)
	s.mux.HandleFunc("POST /programs/preview", s.handleProgramPreview)
	s.mux.HandleFunc("POST /programs/import", s.handleProgramImport)
	s.mux.HandleFunc("GET /payloads", s.handlePayloads)
	s.mux.HandleFunc("POST /payloads/refresh", s.handlePayloadsRefresh)
	s.mux.HandleFunc("GET /scan", s.handleScanForm)
	s.mux.HandleFunc("POST /scan", s.handleScanRun)
	s.mux.HandleFunc("GET /runs/{id}", s.handleRunStatus)
	s.mux.HandleFunc("GET /findings", s.handleFindings)
	s.mux.HandleFunc("POST /findings/bulk", s.handleBulkTriage)
	s.mux.HandleFunc("GET /findings/{id}", s.handleFindingDetail)
	s.mux.HandleFunc("POST /findings/{id}/status", s.handleTriage)
	s.mux.HandleFunc("POST /findings/{id}/edit", s.handleFindingEdit)
	// API JSON baca-saja untuk konsumen mesin (extension Burp). Lihat api.go.
	// Terlindungi otomatis oleh front controller (auth+RBAC baca); GET murni.
	s.mux.HandleFunc("GET /api/v1/findings", s.handleAPIFindings)
	s.mux.HandleFunc("GET /api/v1/findings/{id}", s.handleAPIFinding)
	s.mux.HandleFunc("GET /burp", s.handleBurp)
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
	Nav           string
	Title         string
	Program       string
	CSRF          string
	Seeds         string
	InScope       string
	OutScope      string
	Targets       string
	OpenAPI       string
	UpstreamProxy string
	RPS           string
	Tags          string   // seleksi template: -tags (dipisah koma/spasi)
	Severity      []string // seleksi template: -severity (checkbox tercentang)
	Stealth       bool     // profil low-and-slow (DAST + laju scan)
	APIRoutes     bool     // ikutkan wordlist route API ter-bundle (ffuf)
	SavePreset    bool     // simpan seleksi ini sebagai preset program
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

	// Bila diberi ?program=, prefill scope DAN preset seleksi dari program tersimpan.
	if prog := strings.TrimSpace(r.URL.Query().Get("program")); prog != "" {
		if p, err := s.store.GetProgram(r.Context(), prog); err == nil {
			page.Program = p.Name
			page.InScope = strings.Join(p.InScope, "\n")
			page.OutScope = strings.Join(p.OutScope, "\n")
			// Preset seleksi template per program (ditimpa query eksplisit di bawah).
			page.Tags = strings.Join(p.Preset.Tags, ",")
			page.Severity = p.Preset.Severity
			page.Stealth = p.Preset.Stealth
			page.APIRoutes = p.Preset.APIRoutes
		}
	}
	// Query eksplisit mengalahkan preset — dipakai tautan "Scan pakai filter ini"
	// di Bank Payload (membawa ?tags= / ?severity= dari filter katalog yang aktif).
	if q := strings.TrimSpace(r.URL.Query().Get("tags")); q != "" {
		page.Tags = q
	}
	if sv := filterSeverities(r.URL.Query()["severity"]); len(sv) > 0 {
		page.Severity = sv
	}
	// Default contoh (langsung mendemokan gate) bila tak ada program.
	if page.Program == "" {
		page.Program = "demo"
		page.Seeds = "demo.test"
		page.InScope = "demo.test\n*.demo.test"
		page.OutScope = "admin.demo.test"
		page.Targets = "demo.test\nevil.test"
	}
	s.render(w, r, "scan", "base", page)
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
	sel := Selection{Tags: splitList(r.FormValue("tags")), Severity: filterSeverities(r.Form["severity"]), Stealth: r.FormValue("stealth") != "", APIRoutes: r.FormValue("api_routes") != ""}
	// Stealth = low-and-slow: jepit laju scan keseluruhan ke mode senyap (≤
	// stealthScanRPS). Ini MENAMBAH pembatasan (arah aman), rate limiter tetap
	// wajib di jalur eksekusi — tak pernah dimatikan.
	if sel.Stealth {
		rps = stealthScanRPS(rps)
	}

	page := scanPage{
		Nav: "scan", Title: "Scan", Program: program,
		Seeds:         r.FormValue("seeds"),
		InScope:       r.FormValue("in_scope"),
		OutScope:      r.FormValue("out_scope"),
		Targets:       r.FormValue("targets"),
		OpenAPI:       r.FormValue("openapi"),
		UpstreamProxy: r.FormValue("upstream_proxy"),
		RPS:           r.FormValue("rps"),
		Tags:          strings.TrimSpace(r.FormValue("tags")),
		Severity:      sel.Severity,
		Stealth:       sel.Stealth,
		APIRoutes:     sel.APIRoutes,
		SavePreset:    r.FormValue("save_preset") != "",
	}

	// Scan ter-arah spec: perluas OpenAPI/Swagger jadi endpoint → target. Tiap
	// endpoint TETAP lewat scope guard di bawah (spec tak memintas batas). Spec
	// mentah juga diteruskan ke engine DAST utk fuzz request+body (`-im openapi`).
	var openapiSpec []byte
	if spec := strings.TrimSpace(r.FormValue("openapi")); spec != "" {
		openapiSpec = []byte(spec)
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
		s.renderPartial(w, r, "scan", "scan_result_errors", page)
		return
	}

	// Simpan/perbarui definisi scope program (persisten lintas-restart). Preset
	// seleksi dipertahankan apa adanya kecuali pengguna mencentang "simpan preset",
	// agar scan biasa tak diam-diam menimpa preset program.
	prog := store.Program{Name: program, InScope: inScope, OutScope: outScope}
	if existing, err := s.store.GetProgram(r.Context(), program); err == nil {
		prog.Preset = existing.Preset
	}
	if page.SavePreset {
		prog.Preset = store.ScanPreset{Tags: sel.Tags, Severity: sel.Severity, Stealth: sel.Stealth, APIRoutes: sel.APIRoutes}
	}
	_ = s.store.SaveProgram(r.Context(), prog)

	// Enqueue: scan berjalan di latar belakang; handler membalas run_id seketika.
	runID := s.enqueueScan(program, guard, seeds, targets, rps, proxyChain, sel, openapiSpec)

	if run, ok := s.queue.Get(runID); ok {
		s.renderPartial(w, r, "scan", "run_status", toRunView(run))
	}
}

// enqueueScan menjalankan satu scan di latar belakang (worker pool) dan
// mengembalikan run id seketika. Satu jalur peluncuran scan dipakai bersama oleh
// form Scan dan "promote" dari Capture. Task memakai ctx milik queue (bukan
// r.Context()) agar tak dibatalkan saat response web dikirim. Rate limiter selalu
// dipasang (tak bisa dimatikan); scope guard menjadi satu-satunya gate.
func (s *Server) enqueueScan(program string, guard *scope.Guard, seeds, targets []string, rps float64, proxyChain []string, sel Selection, openapiSpec []byte) string {
	storeRef := s.store
	return s.queue.Enqueue(program, scanLabel(seeds, targets), func(ctx context.Context, runID string) (jobs.Summary, error) {
		s.auditAppend(ctx, audit.Event{Kind: "run.start", Program: program, RunID: runID, Message: scanLabel(seeds, targets)})

		auditSink := func(e orchestrator.AuditEvent) {
			s.auditAppend(ctx, audit.Event{
				Kind: "scope.decision", Program: e.Program, RunID: e.RunID, Target: e.Target,
				Allowed: e.Allowed, Reason: string(e.Reason), Layer: string(e.Layer), Message: e.MatchedEntry,
			})
		}
		// Engine per-run: mode nyata membangun instance BARU dengan laju dijepit
		// ke rps (throttle per-engine di jalur eksekusi) sehingga tiap run punya
		// engine + proxy egress sendiri; mock/test pakai instance tetap. Seleksi
		// template (tags/severity) diteruskan ke engine agar hanya subset yang jalan.
		engines, rec := s.engines, s.recon
		if s.newEngines != nil {
			engines, rec = s.newEngines(rps, sel)
		}
		o := orchestrator.New(guard, engines[0], storeRef,
			ratelimit.New(ratelimit.Config{RequestsPerSecond: rps, Burst: 5}), auditSink)
		for _, e := range engines[1:] {
			o.AddEngine(e)
		}
		if len(seeds) > 0 && rec != nil {
			o.UseRecon(rec)
		}
		res, err := o.RunScan(ctx, orchestrator.ScanRequest{Program: program, RunID: runID, Seeds: seeds, Targets: targets, ProxyChain: proxyChain, OpenAPISpec: openapiSpec})
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
		for _, ee := range res.EngineErrors {
			sum.Warnings = append(sum.Warnings, fmt.Sprintf("engine %s @ %s: %s", ee.Engine, ee.Target, ee.Err))
			s.auditAppend(ctx, audit.Event{Kind: "run.engine_error", Program: program, RunID: runID,
				Message: fmt.Sprintf("engine %s gagal di %s: %s", ee.Engine, ee.Target, ee.Err)})
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
	s.renderPartial(w, r, "scan", "run_status", toRunView(run))
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
	Warnings   []string
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
		Warnings:   r.Summary.Warnings,
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
	s.render(w, r, "findings", "base", page)
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
	s.renderPartial(w, r, "findings", "finding_detail", f)
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
	s.renderPartial(w, r, "findings", "finding_detail", f)
}

// handleFindingEdit menyimpan field naratif report (deskripsi, langkah
// reproduksi, dampak) yang dilengkapi hunter saat triase, agar draft report &
// export platform lengkap (prinsip: report selalu draft, dilengkapi+diverifikasi
// manual sebelum submit). Tak mengubah status/severity/dedup.
func (s *Server) handleFindingEdit(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form tidak valid", http.StatusBadRequest)
		return
	}
	description := strings.TrimSpace(r.FormValue("description"))
	impact := strings.TrimSpace(r.FormValue("impact"))
	reproduction := splitLines(r.FormValue("reproduction"))

	if err := s.store.UpdateContent(r.Context(), id, description, impact, reproduction); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f, err := s.store.Get(r.Context(), id)
	if err != nil {
		http.Error(w, "temuan tidak ditemukan", http.StatusNotFound)
		return
	}
	me, _ := s.currentUser(r)
	s.auditAppend(r.Context(), audit.Event{Kind: "finding.edit", Program: f.Program, Allowed: true,
		Message: fmt.Sprintf("%s melengkapi draft temuan %s (deskripsi/langkah/dampak)", me, id)})
	s.renderPartial(w, r, "findings", "finding_detail", f)
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
	s.render(w, r, "report", "base", page)
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
	s.render(w, r, "report_print", "report_print", rep)
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
	Note     string // flash setelah aksi (mis. hapus)
	Programs []*store.Program
}

func (s *Server) handlePrograms(w http.ResponseWriter, r *http.Request) {
	progs, _ := s.store.ListPrograms(r.Context())
	note := ""
	if r.URL.Query().Get("ok") == "deleted" {
		note = "Program dihapus (temuan & audit tetap tersimpan)."
	}
	s.render(w, r, "programs", "base", programsPage{
		Nav: "programs", Title: "Programs", CSRF: s.csrfToken(r), Note: note, Programs: progs,
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

	PlatformData string        // data platform yang ditempel, dipertahankan saat impor ditahan
	Import       *importReport // ringkasan impor untuk ditinjau; nil bila tak ada
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
	s.render(w, r, "program_edit", "base", page)
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
		s.render(w, r, "program_edit", "base", page)
		return
	}
	if err := s.store.SaveProgram(r.Context(), store.Program{Name: name, InScope: inScope, OutScope: outScope}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	me, _ := s.currentUser(r)
	s.auditAppend(r.Context(), audit.Event{Kind: "program.save", Program: name, Allowed: true,
		Message: fmt.Sprintf("%s menyimpan scope: %d in-scope, %d out-of-scope", me, len(inScope), len(outScope))})
	http.Redirect(w, r, "/programs", http.StatusSeeOther)
}

// importReport adalah ringkasan impor yang ditinjau di scope editor.
type importReport struct {
	scope.ImportResult
	Held     bool     // ditahan: Unresolved belum disetujui, form tak diisi
	Replaced []string // entri in-scope lama di form yang digantikan hasil impor
}

// handleProgramImport mengonversi data scope platform lalu mengisi form scope
// editor untuk ditinjau. Handler ini TIDAK menyimpan apa pun: entri baru berlaku
// hanya setelah pengguna menekan Simpan, lewat handleProgramSave yang fail-closed.
//
// Penggabungan mengikuti arah aman yang sama dengan importer: in-scope DIGANTI
// (entri lama bisa jadi aset yang sudah dicabut program), out-of-scope DIGABUNG
// (eksklusi yang ditulis pengguna tak boleh hilang karena impor).
//
// Bila ada eksklusi tak terwakili, form tak diisi sampai pengguna menyetujui
// daftarnya. Persetujuan terikat ke Digest, jadi tak berlaku untuk data lain.
func (s *Server) handleProgramImport(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form tidak valid", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	raw := r.FormValue("platform_data")
	page := programEditPage{
		Nav: "programs", Title: "Scope editor", CSRF: s.csrfToken(r), Program: name, Name: name,
		InScope: r.FormValue("in_scope"), OutScope: r.FormValue("out_scope"), Targets: r.FormValue("targets"),
		PlatformData: raw, IsNew: true,
	}
	if name != "" {
		if _, err := s.store.GetProgram(r.Context(), name); err == nil {
			page.IsNew = false
		}
	}
	me, _ := s.currentUser(r)

	res, err := scope.ImportPlatform(raw)
	if err != nil {
		page.Errors = append(page.Errors, "Impor gagal: "+err.Error())
		s.auditAppend(r.Context(), audit.Event{Kind: "program.import", Program: name, Allowed: false,
			Reason: err.Error(), Message: me + " gagal mengimpor scope platform"})
		s.render(w, r, "program_edit", "base", page)
		return
	}

	summary := fmt.Sprintf("%s · %d in-scope, %d out-of-scope, %d eksklusi tak terwakili · sha256 %s",
		res.Format, len(res.InScope), len(res.OutScope), len(res.Unresolved), res.Digest)
	report := &importReport{ImportResult: res}
	page.Import = report
	if len(res.Unresolved) > 0 && r.FormValue("ack_unresolved") != res.Digest {
		report.Held = true
		s.auditAppend(r.Context(), audit.Event{Kind: "program.import", Program: name, Allowed: false,
			Reason: "eksklusi tak terwakili belum disetujui", Message: me + " · " + summary})
		s.render(w, r, "program_edit", "base", page)
		return
	}

	imported := make(map[string]bool, len(res.InScope))
	for _, e := range res.InScope {
		imported[e] = true
	}
	for _, e := range splitLines(page.InScope) {
		if !imported[e] {
			report.Replaced = append(report.Replaced, e)
		}
	}
	page.InScope = strings.Join(res.InScope, "\n")
	page.OutScope = appendMissingLines(page.OutScope, res.OutScope)
	page.PlatformData = ""
	s.auditAppend(r.Context(), audit.Event{Kind: "program.import", Program: name, Allowed: true, Message: me + " · " + summary})
	s.render(w, r, "program_edit", "base", page)
}

// appendMissingLines menambahkan entri yang belum ada ke isi textarea, tanpa
// mengubah baris yang sudah ditulis pengguna (termasuk komentar).
func appendMissingLines(text string, entries []string) string {
	have := map[string]bool{}
	for _, line := range splitLines(text) {
		have[line] = true
	}
	lines := []string{}
	if t := strings.TrimRight(text, " \t\r\n"); t != "" {
		lines = append(lines, t)
	}
	for _, e := range entries {
		if !have[e] {
			lines = append(lines, e)
		}
	}
	return strings.Join(lines, "\n")
}

// handleProgramDelete menghapus definisi scope sebuah program. Yang dibuang HANYA
// definisi program (agar daftar tak menumpuk); temuan tetap tersimpan sebagai
// hasil kerja dan audit append-only tidak disentuh — penghapusan ini sendiri
// DICATAT di audit. State-changing → butuh operator+ & CSRF (middleware authorize).
func (s *Server) handleProgramDelete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form tidak valid", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		http.Redirect(w, r, "/programs", http.StatusSeeOther)
		return
	}
	me, _ := s.currentUser(r)
	err := s.store.DeleteProgram(r.Context(), name)
	if err != nil && err != store.ErrNotFound { // idempoten: sudah tak ada = sukses senyap
		http.Error(w, "gagal menghapus program: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err == nil {
		s.auditAppend(r.Context(), audit.Event{Kind: "program.delete", Program: name, Allowed: true, Message: fmt.Sprintf("%s menghapus definisi program (temuan & audit tetap)", me)})
	}
	http.Redirect(w, r, "/programs?ok=deleted", http.StatusSeeOther)
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
	s.renderPartial(w, r, "program_edit", "program_preview", res)
}

// ---- Bank Payload (BH-SPEC-PAYLOAD) ----

const payloadPageSize = 50

type payloadsPage struct {
	Nav        string
	Title      string
	Program    string
	CSRF       string
	Supported  bool // store mendukung katalog
	CanRefresh bool // ada sumber & peran operator ke atas
	HasSources bool
	Sources    []payload.SourceInfo
	Stats      store.CatalogStats
	Entries    []payload.Entry

	// filter aktif (untuk mengisi ulang form)
	Q, Engine, Trust, Severity, Tag, Enabled string

	// paginasi
	Total, Page, Pages, From, To int
	HasPrev, HasNext             bool
	PrevURL, NextURL             string

	Flash string // banner setelah refresh
}

func (s *Server) handlePayloads(w http.ResponseWriter, r *http.Request) {
	page := payloadsPage{
		Nav: "payloads", Title: "Bank Payload", CSRF: s.csrfToken(r),
		Program:    strings.TrimSpace(r.URL.Query().Get("program")),
		HasSources: len(s.payloadSources) > 0,
	}
	if s.catalog == nil {
		s.render(w, r, "payloads", "base", page)
		return
	}
	page.Supported = true
	ctx := r.Context()
	q := r.URL.Query()

	cq := store.CatalogQuery{
		Search:   strings.TrimSpace(q.Get("q")),
		Engine:   strings.TrimSpace(q.Get("engine")),
		Trust:    strings.TrimSpace(q.Get("trust")),
		Severity: strings.TrimSpace(q.Get("severity")),
		Tag:      strings.TrimSpace(q.Get("tag")),
		Enabled:  strings.TrimSpace(q.Get("enabled")),
		Limit:    payloadPageSize,
	}
	pageNo := 1
	if n, err := strconv.Atoi(q.Get("page")); err == nil && n > 1 {
		pageNo = n
	}
	cq.Offset = (pageNo - 1) * payloadPageSize

	entries, total, err := s.catalog.ListCatalog(ctx, cq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	page.Entries = entries
	page.Total = total
	page.Stats, _ = s.catalog.CatalogStats(ctx)
	page.Sources, _ = s.catalog.ListCatalogSources(ctx)
	page.Q, page.Engine, page.Trust = cq.Search, cq.Engine, cq.Trust
	page.Severity, page.Tag, page.Enabled = cq.Severity, cq.Tag, cq.Enabled

	pages := (total + payloadPageSize - 1) / payloadPageSize
	if pages < 1 {
		pages = 1
	}
	if pageNo > pages {
		pageNo = pages
	}
	page.Page, page.Pages = pageNo, pages
	if total > 0 {
		page.From = cq.Offset + 1
		page.To = cq.Offset + len(entries)
	}
	base := payloadFilterQuery(cq)
	if pageNo > 1 {
		page.HasPrev = true
		page.PrevURL = "/payloads?" + appendPage(base, pageNo-1)
	}
	if pageNo < pages {
		page.HasNext = true
		page.NextURL = "/payloads?" + appendPage(base, pageNo+1)
	}

	_, role := s.currentUser(r)
	page.CanRefresh = page.HasSources && (s.authDisabled || auth.CanWrite(role))
	if q.Get("refreshed") == "1" {
		if t := q.Get("total"); t != "" {
			page.Flash = "Katalog diperbarui — " + t + " template dikatalogkan."
		} else {
			page.Flash = "Katalog diperbarui."
		}
	}
	s.render(w, r, "payloads", "base", page)
}

func (s *Server) handlePayloadsRefresh(w http.ResponseWriter, r *http.Request) {
	if s.catalog == nil {
		http.Error(w, "katalog tak didukung oleh store ini", http.StatusServiceUnavailable)
		return
	}
	if len(s.payloadSources) == 0 {
		http.Error(w, "tak ada sumber payload terkonfigurasi (set -nuclei-templates / -custom-templates)", http.StatusServiceUnavailable)
		return
	}
	ctx := r.Context()
	before, _ := s.catalog.CatalogStats(ctx)
	// Build men-scan berkas lokal sumber (tanpa jaringan) lalu ReplaceCatalog
	// mengganti katalog secara atomik.
	cat := payload.Build(ctx, s.payloadSources)
	if err := s.catalog.ReplaceCatalog(ctx, cat); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	user, _ := s.currentUser(r)
	s.auditAppend(ctx, audit.Event{
		Kind:    "catalog.refresh",
		Allowed: true,
		Message: fmt.Sprintf("bank payload di-refresh oleh %s: %d template dari %d sumber (sebelumnya %d)",
			firstNonEmptyStr(user, "sistem"), len(cat.Entries), len(cat.Sources), before.Total),
	})
	v := url.Values{}
	v.Set("refreshed", "1")
	v.Set("total", strconv.Itoa(len(cat.Entries)))
	http.Redirect(w, r, "/payloads?"+v.Encode(), http.StatusSeeOther)
}

// payloadFilterQuery menyusun query string filter (tanpa page) untuk link paginasi.
func payloadFilterQuery(cq store.CatalogQuery) string {
	v := url.Values{}
	set := func(k, val string) {
		if strings.TrimSpace(val) != "" {
			v.Set(k, val)
		}
	}
	set("q", cq.Search)
	set("engine", cq.Engine)
	set("trust", cq.Trust)
	set("severity", cq.Severity)
	set("tag", cq.Tag)
	set("enabled", cq.Enabled)
	return v.Encode()
}

func appendPage(base string, n int) string {
	if base == "" {
		return "page=" + strconv.Itoa(n)
	}
	return base + "&page=" + strconv.Itoa(n)
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
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
	s.render(w, r, "audit", "base", page)
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
	Note           string // flash setelah aksi (mis. hapus temuan)
	Rows           []dashRow
	TotalPrograms  int
	TotalFindings  int
	TotalConfirmed int
	TotalNew       int
	TotalRuns      int
	SevTotals      []dashSev    // total per severity lintas-program (untuk bar ringkasan)
	SevDonut       template.CSS // conic-gradient komposisi severity (aman: template.CSS)
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
	if r.URL.Query().Get("ok") == "findings-deleted" {
		prog := strings.TrimSpace(r.URL.Query().Get("program"))
		n := strings.TrimSpace(r.URL.Query().Get("n"))
		page.Note = fmt.Sprintf("%s temuan program %q dihapus. Definisi scope & audit tetap.", n, prog)
	}
	sevTotal := map[finding.Severity]int{}

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
			sevTotal[sev] += sevc[sev]
		}
		row.Runs = len(runs)
		row.HasActivity = !row.LastAt.IsZero()

		page.Rows = append(page.Rows, row)
		page.TotalFindings += row.Total
		page.TotalConfirmed += row.Confirmed
		page.TotalNew += row.New
		page.TotalRuns += row.Runs
	}
	page.TotalPrograms = len(page.Rows)
	for _, sev := range dashSevOrder {
		page.SevTotals = append(page.SevTotals, dashSev{Severity: sev, Count: sevTotal[sev]})
	}
	if page.TotalFindings > 0 {
		sevVar := map[finding.Severity]string{
			finding.SeverityCritical: "var(--crit)",
			finding.SeverityHigh:     "var(--high)",
			finding.SeverityMedium:   "var(--warn)",
			finding.SeverityLow:      "var(--low)",
			finding.SeverityInfo:     "var(--info)",
		}
		acc := 0
		parts := make([]string, 0, len(page.SevTotals))
		for _, sv := range page.SevTotals {
			if sv.Count == 0 {
				continue
			}
			start := float64(acc) / float64(page.TotalFindings) * 360
			acc += sv.Count
			end := float64(acc) / float64(page.TotalFindings) * 360
			parts = append(parts, fmt.Sprintf("%s %.2fdeg %.2fdeg", sevVar[sv.Severity], start, end))
		}
		page.SevDonut = template.CSS("conic-gradient(" + strings.Join(parts, ", ") + ")")
	}

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

	s.render(w, r, "dashboard", "base", page)
}

// handleDashboardDeleteFindings menghapus SEMUA temuan sebuah program (aksi dari
// baris "Temuan per program"). Sesuai pilihan: HANYA temuan — definisi scope
// program tetap (dikelola di menu Programs) dan audit append-only tak disentuh;
// penghapusan ini sendiri dicatat (findings.delete). State-changing → operator+
// & CSRF via middleware authorize(). Idempoten: program tanpa temuan → 0, 303.
func (s *Server) handleDashboardDeleteFindings(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form tidak valid", http.StatusBadRequest)
		return
	}
	program := strings.TrimSpace(r.FormValue("program"))
	if program == "" {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	me, _ := s.currentUser(r)
	n, err := s.store.DeleteFindingsByProgram(r.Context(), program)
	if err != nil {
		http.Error(w, "gagal menghapus temuan: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditAppend(r.Context(), audit.Event{Kind: "findings.delete", Program: program, Allowed: true,
		Message: fmt.Sprintf("%s menghapus %d temuan program (definisi scope tetap)", me, n)})
	http.Redirect(w, r, fmt.Sprintf("/dashboard?ok=findings-deleted&program=%s&n=%d", url.QueryEscape(program), n), http.StatusSeeOther)
}

// ---- Monitor scan live (dashboard) ----

type scanLiveRow struct {
	ID          string
	Program     string
	Label       string
	Status      string
	Active      bool
	Done        bool
	Failed      bool
	Saved       int
	Scanned     int
	Discovered  int
	DeniedCount int
	Err         string
	Elapsed     string
}

type scansLivePage struct {
	Rows        []scanLiveRow
	ActiveCount int
	QueuedCount int
	DoneCount   int
	Total       int
	HasAny      bool
	Interval    string // interval polling HTMX (adaptif)
	UpdatedAt   string
}

const scansLiveLimit = 12

// handleDashboardScans merender panel "Proses scanning" (live) dari job queue
// in-process — read-only, tanpa jaringan & tanpa query store (murah untuk
// polling). HTMX memanggilnya berulang (trigger self-chained) sehingga status
// run tampil berubah real-time: antre → berjalan → selesai/gagal, lengkap durasi.
func (s *Server) handleDashboardScans(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	runs := s.queue.List("") // semua, terbaru dulu
	page := scansLivePage{Total: len(runs), UpdatedAt: now.Format("15:04:05")}
	for _, rn := range runs {
		switch rn.Status {
		case jobs.Queued:
			page.QueuedCount++
		case jobs.Running:
			page.ActiveCount++
		case jobs.Done:
			page.DoneCount++
		}
		if len(page.Rows) >= scansLiveLimit {
			continue
		}
		v := toRunView(rn)
		page.Rows = append(page.Rows, scanLiveRow{
			ID: v.ID, Program: v.Program, Label: rn.Label,
			Status:      string(rn.Status),
			Active:      v.Active,
			Done:        rn.Status == jobs.Done,
			Failed:      rn.Status == jobs.Failed,
			Saved:       v.Saved,
			Scanned:     v.Scanned,
			Discovered:  v.Discovered,
			DeniedCount: len(v.Denied),
			Err:         v.Err,
			Elapsed:     runElapsed(rn, now),
		})
	}
	page.HasAny = len(page.Rows) > 0
	// Polling adaptif: 2 dtk saat ada scan aktif/antre, 6 dtk saat idle (tetap
	// memantau scan baru) — murah karena hanya baca queue in-memory.
	page.Interval = "6s"
	if page.ActiveCount > 0 || page.QueuedCount > 0 {
		page.Interval = "2s"
	}
	s.renderPartial(w, r, "dashboard", "scans_live", page)
}

// runElapsed: berjalan = sejak mulai; selesai/gagal = total runtime; antre = tunggu.
func runElapsed(r *jobs.Run, now time.Time) string {
	switch r.Status {
	case jobs.Queued:
		return "antre"
	case jobs.Running:
		if r.StartedAt.IsZero() {
			return "—"
		}
		return humanDur(now.Sub(r.StartedAt))
	default:
		if r.StartedAt.IsZero() || r.FinishedAt.IsZero() {
			return "—"
		}
		return humanDur(r.FinishedAt.Sub(r.StartedAt))
	}
}

// humanDur memformat durasi ringkas: "<1s", "9s", "1m 05s", "2h 10m".
func humanDur(d time.Duration) string {
	if d < time.Second {
		return "<1s"
	}
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	sec := int(d.Seconds()) % 60
	switch {
	case h > 0:
		return fmt.Sprintf("%dh %dm", h, m)
	case m > 0:
		return fmt.Sprintf("%dm %02ds", m, sec)
	default:
		return fmt.Sprintf("%ds", sec)
	}
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
	s.render(w, r, "sast", "base", page)
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
		s.render(w, r, "sast", "base", page)
		return
	}
	if page.Program == "" {
		page.Error = "Program wajib diisi."
		s.render(w, r, "sast", "base", page)
		return
	}
	eng, ok := sast.Lookup(page.Engine)
	if !ok {
		page.Error = "Adapter SAST tidak dikenal: " + page.Engine
		s.render(w, r, "sast", "base", page)
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
		s.render(w, r, "sast", "base", page)
		return
	}

	runID := fmt.Sprintf("sast-%d", time.Now().UnixNano())
	res, err := sast.Run(r.Context(), dir, page.Subpath, page.Program, runID, []sast.Engine{eng}, s.store, s.audit)
	if err != nil {
		page.Error = "Analisis gagal: " + err.Error()
		s.render(w, r, "sast", "base", page)
		return
	}
	page.Result = &sastResult{Engine: eng.Name(), Path: page.Subpath, Saved: res.Saved, Duplicates: res.Duplicates}
	s.render(w, r, "sast", "base", page)
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
		Program:  strings.TrimSpace(r.URL.Query().Get("program")),
		Programs: s.programNames(r.Context()), EngineName: s.grpcEngine.Name(),
	}
	s.render(w, r, "grpc", "base", page)
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
		s.render(w, r, "grpc", "base", page)
		return
	}
	prog, err := s.store.GetProgram(r.Context(), page.Program)
	if err != nil {
		page.Error = "Program belum punya scope tersimpan — simpan scope-nya dulu di halaman Programs."
		s.render(w, r, "grpc", "base", page)
		return
	}
	guard, errs := scope.New(prog.InScope, prog.OutScope)
	if len(errs) > 0 {
		page.Error = "Scope program tak valid: " + errs[0].Error()
		s.render(w, r, "grpc", "base", page)
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
	s.render(w, r, "grpc", "base", page)
}

// ---- Proxy / Egress check (diagnostik rantai proxy & IP exit) ----

type proxyPage struct {
	Nav, Title, Program, CSRF string
	Programs                  []string
	Chain, Echo               string
	Result                    *proxyCheckResult
}

type proxyCheckResult struct {
	Hops     []egress.HopStatus
	Echo     *proxyEchoResult
	EchoNote string
	Error    string
}

type proxyEchoResult struct {
	Allowed                  bool
	Reason                   string
	SourceIP, ExitIP         string
	SourceStatus, ExitStatus int
	SourceErr, ExitErr       string
	Changed                  bool
}

// handleProxyForm menampilkan menu diagnostik proxy.
func (s *Server) handleProxyForm(w http.ResponseWriter, r *http.Request) {
	program := strings.TrimSpace(r.URL.Query().Get("program"))
	s.render(w, r, "proxy", "base", proxyPage{
		Nav: "proxy", Title: "Proxy", Program: program, CSRF: s.csrfToken(r),
		Programs: s.programNames(r.Context()),
	})
}

// burpPage: halaman onboarding integrasi Burp (lihat burp.html). Murni
// informatif — menampilkan endpoint API baca-saja + cara build/load extension.
type burpPage struct {
	Nav, Title, Program, CSRF string
	BaseURL                   string   // skema+host dari request, untuk contoh perintah
	User                      string   // username login, untuk contoh curl -u
	Programs                  []string // program yang punya temuan, untuk pilih contoh
	SampleProgram             string   // program yang dipakai di contoh perintah
}

// handleBurp menampilkan halaman integrasi Burp: titik masuk di UI untuk API
// baca-saja + extension. Tidak menjalankan Burp; murni onboarding.
func (s *Server) handleBurp(w http.ResponseWriter, r *http.Request) {
	program := strings.TrimSpace(r.URL.Query().Get("program"))
	user, _ := s.currentUser(r)
	if user == "" {
		user = "admin" // auth nonaktif / sekadar contoh
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	progs := s.programNames(r.Context())
	sample := program
	if sample == "" {
		if len(progs) > 0 {
			sample = progs[0]
		} else {
			sample = "nama-program"
		}
	}
	s.render(w, r, "burp", "base", burpPage{
		Nav: "burp", Title: "Integrasi Burp", Program: program, CSRF: s.csrfToken(r),
		BaseURL: scheme + "://" + r.Host, User: user, Programs: progs, SampleProgram: sample,
	})
}

// handleProxyCheck memvalidasi & menguji rantai proxy, lalu (opsional) mengukur
// IP yang dilihat target langsung vs lewat rantai memakai endpoint echo yang
// WAJIB lolos scope guard program (default-deny). State-changing → operator+
// (middleware authorize). Kredensial proxy tak pernah ditampilkan/dicatat.
func (s *Server) handleProxyCheck(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form tidak valid", http.StatusBadRequest)
		return
	}
	program := strings.TrimSpace(r.FormValue("program"))
	echo := strings.TrimSpace(r.FormValue("echo_url"))
	chainLines := splitLines(r.FormValue("upstream_proxy"))

	res := &proxyCheckResult{}
	hops, err := egress.ParseChain(chainLines)
	if err != nil {
		res.Error = "Rantai tak valid: " + err.Error()
		s.renderPartial(w, r, "proxy", "proxy_result", res)
		return
	}
	res.Hops = egress.TestChain(r.Context(), hops, 8*time.Second)

	if echo != "" {
		res.Echo, res.EchoNote = s.proxyEchoCheck(r, program, chainLines, echo)
	}

	reachable := 0
	for _, h := range res.Hops {
		if h.Reachable {
			reachable++
		}
	}
	me, _ := s.currentUser(r)
	changed := res.Echo != nil && res.Echo.Changed
	s.auditAppend(r.Context(), audit.Event{
		Kind: "egress.check", Program: program, Allowed: true, Layer: "egress",
		Message: fmt.Sprintf("%s uji proxy: %d/%d hop reachable, echo=%t, ip-berubah=%t", me, reachable, len(res.Hops), echo != "", changed),
	})
	s.renderPartial(w, r, "proxy", "proxy_result", res)
}

// proxyEchoCheck mengukur IP yang terlihat target: satu GET langsung dan satu
// lewat rantai, ke endpoint echo yang sama. Echo WAJIB lolos scope guard program
// (default-deny — Prinsip #2). Mengembalikan hasil + catatan bila tak bisa.
func (s *Server) proxyEchoCheck(r *http.Request, program string, chain []string, echo string) (*proxyEchoResult, string) {
	if program == "" {
		return nil, "Pilih program dulu agar endpoint echo dicek scope guard (default-deny)."
	}
	prog, err := s.store.GetProgram(r.Context(), program)
	if err != nil {
		return nil, "Program belum punya scope tersimpan — simpan dulu di halaman Programs."
	}
	guard, errs := scope.New(prog.InScope, prog.OutScope)
	if len(errs) > 0 {
		return nil, "Scope program tak valid: " + errs[0].Error()
	}
	auditSink := func(d egress.Decision) {
		if d.Allowed {
			return
		}
		s.auditAppend(context.Background(), audit.Event{
			Kind: "egress.check", Program: program, Target: d.Target,
			Allowed: false, Reason: string(d.Reason), Layer: "egress",
		})
	}

	timeout := 10 * time.Second
	direct := egress.New(guard, auditSink).Fetch(r.Context(), echo, timeout)
	out := &proxyEchoResult{
		Allowed:      direct.Allowed,
		Reason:       direct.Reason,
		SourceIP:     egress.ExtractClientIP(direct.Body),
		SourceStatus: direct.Status,
		SourceErr:    direct.Err,
	}
	if !direct.Allowed {
		return out, ""
	}
	chained := egress.New(guard, auditSink)
	if err := chained.SetUpstream(chain...); err != nil {
		out.ExitErr = "rantai tak bisa dibangun: " + err.Error()
		return out, ""
	}
	exit := chained.Fetch(r.Context(), echo, timeout)
	out.ExitIP, out.ExitStatus, out.ExitErr = egress.ExtractClientIP(exit.Body), exit.Status, exit.Err
	out.Changed = out.SourceIP != "" && out.ExitIP != "" && out.SourceIP != out.ExitIP
	return out, ""
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
	s.render(w, r, "capture", "base", page)
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
		s.render(w, r, "capture", "base", page)
		return
	}
	if s.getCapture(program) != nil {
		page.Error = "Sesi capture untuk program ini sudah berjalan — hentikan dulu."
		s.render(w, r, "capture", "base", page)
		return
	}
	prog, err := s.store.GetProgram(r.Context(), program)
	if err != nil {
		page.Error = "Program belum punya scope tersimpan — simpan scope-nya dulu di halaman Programs."
		s.render(w, r, "capture", "base", page)
		return
	}
	guard, errs := scope.New(prog.InScope, prog.OutScope)
	if len(errs) > 0 {
		page.Error = "Scope program tak valid: " + errs[0].Error()
		s.render(w, r, "capture", "base", page)
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
		s.render(w, r, "capture", "base", page)
		return
	}
	addr, stop, err := gw.Listen("127.0.0.1:0")
	if err != nil {
		page.Error = "Gagal membuka listener: " + err.Error()
		s.render(w, r, "capture", "base", page)
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
		s.render(w, r, "capture", "base", page)
		return
	}
	prog, err := s.store.GetProgram(r.Context(), program)
	if err != nil {
		page := s.capturePageFor(r, program)
		page.Error = "Program belum punya scope tersimpan."
		s.render(w, r, "capture", "base", page)
		return
	}
	guard, errs := scope.New(prog.InScope, prog.OutScope)
	if len(errs) > 0 {
		page := s.capturePageFor(r, program)
		page.Error = "Scope program tak valid: " + errs[0].Error()
		s.render(w, r, "capture", "base", page)
		return
	}
	runID := s.enqueueScan(program, guard, nil, targets, rps, nil, Selection{}, nil)
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
	s.render(w, r, "settings", "base", page)
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

// shellData membungkus data halaman penuh (yang dirender lewat "base") dengan
// konteks chrome: pengguna & peran saat ini untuk topbar + menu admin. Template
// isi tetap menerima data aslinya lewat .Body, jadi tak ada struct halaman yang
// perlu tahu soal auth.
type shellData struct {
	User   string
	Role   string
	AuthOn bool
	Body   any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, page, name string, data any) {
	t := s.pages[page]
	if t == nil {
		http.Error(w, "template tidak ada: "+page, http.StatusInternalServerError)
		return
	}
	// Hanya halaman penuh (base) dibungkus; partial HTMX & halaman mandiri
	// (login, report_print) menerima datanya langsung.
	if name == "base" {
		user, role := s.currentUser(r)
		data = shellData{User: user, Role: string(role), AuthOn: !s.authDisabled, Body: data}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) renderPartial(w http.ResponseWriter, r *http.Request, page, name string, data any) {
	s.render(w, r, page, name, data)
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

// splitList memecah daftar dipisah koma atau spasi (mis. input tags seleksi
// template) menjadi token non-kosong. Dipakai untuk field tags pada form scan.
func splitList(raw string) []string {
	return strings.Fields(strings.ReplaceAll(raw, ",", " "))
}

// scanSeverities adalah himpunan severity yang sah untuk seleksi template nuclei
// (-severity). Urutan = prioritas tampilan checkbox pada form scan.
var scanSeverities = []string{"critical", "high", "medium", "low", "info"}

// filterSeverities menormalkan input severity seleksi: lowercase, buang duplikat,
// dan simpan hanya nilai yang dikenal (checkbox form selalu sah, tapi query
// ?severity= dari tautan luar bisa apa saja — jangan teruskan sampah ke engine).
func filterSeverities(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range in {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" || seen[v] {
			continue
		}
		for _, k := range scanSeverities {
			if v == k {
				out = append(out, v)
				seen[v] = true
				break
			}
		}
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

// stealthScanRPS menjepit laju scan ke mode low-and-slow saat stealth aktif:
// tak pernah melebihi stealthScanMax (jejak minimal). Hanya bisa MENURUNKAN laju,
// tak pernah menaikkan — rate limiter tetap wajib & tak dimatikan.
const stealthScanMax = 3.0

func stealthScanRPS(rps float64) float64 {
	if rps <= 0 || rps > stealthScanMax {
		return stealthScanMax
	}
	return rps
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
		"hasStr": func(v []string, s string) bool {
			for _, x := range v {
				if x == s {
					return true
				}
			}
			return false
		},
		"appVersion": func() string { return version },
	}
	sets := map[string][]string{
		"dashboard":    {"templates/base.html", "templates/dashboard.html", "templates/scans_live.html"},
		"login":        {"templates/login.html"},
		"users":        {"templates/base.html", "templates/users.html"},
		"sast":         {"templates/base.html", "templates/sast.html"},
		"grpc":         {"templates/base.html", "templates/grpc.html"},
		"capture":      {"templates/base.html", "templates/capture.html"},
		"proxy":        {"templates/base.html", "templates/proxy.html"},
		"burp":         {"templates/base.html", "templates/burp.html"},
		"scan":         {"templates/base.html", "templates/scan.html", "templates/scan_result.html", "templates/run_status.html"},
		"findings":     {"templates/base.html", "templates/findings.html", "templates/finding_detail.html"},
		"report":       {"templates/base.html", "templates/report.html"},
		"report_print": {"templates/report_print.html"},
		"settings":     {"templates/base.html", "templates/settings.html"},
		"audit":        {"templates/base.html", "templates/audit.html"},
		"programs":     {"templates/base.html", "templates/programs.html"},
		"program_edit": {"templates/base.html", "templates/program_edit.html", "templates/program_preview.html"},
		"payloads":     {"templates/base.html", "templates/payloads.html"},
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
