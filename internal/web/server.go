// Package web serves the bughound interface (Go + HTMX + html/template).
// Every asset is embedded so the app stays a single binary. The M0 UI proves
// the gate: enter a scope, run a scan (mock engine), see targets denied by the
// scope guard, and triage findings.
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
	"bughound/internal/geoip"
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
	"bughound/internal/triage"
)

//go:embed templates
var tmplFS embed.FS

//go:embed static
var staticFS embed.FS

// Server is bughound's main HTTP handler.
type Server struct {
	mux     *http.ServeMux
	store   store.Store
	users   store.UserStore // RBAC accounts (nil when authDisabled)
	engines []engine.Engine
	recon   recon.Engine
	// newEngines, when set, builds a NEW engine + recon instance for each
	// scan (request rate clamped to the scan rps). Used in real-engine mode so each
	// run has its own engines: it clamps the rate per engine AND keeps the egress
	// proxies of concurrent runs from overlapping (each run enforces its own scope guard).
	// nil (mock/test) = use the fixed instances in `engines`/`recon`.
	newEngines func(rps float64, sel Selection) ([]engine.Engine, recon.Engine)
	// catalog persists the Payload Bank (BH-SPEC-PAYLOAD); nil when the store does not
	// support it (detected through a type assertion, like users). payloadSources
	// are the sources scanned when the catalog is refreshed.
	catalog        store.CatalogStore
	payloadSources []payload.Source
	vault          secret.Vault
	audit          audit.Log
	authDisabled   bool // true = open access without login (only -no-auth / test)
	queue          *jobs.Queue
	version        string
	sastRoot       string         // the code root allowed for SAST; empty = SAST off
	grpcEngine     grpc.Scanner   // gRPC enumeration/fuzz (mock by default; grpcurl when -grpc real)
	geo            geoip.Resolver // country/ASN lookup of the egress IP (offline; Nop when the DB is not loaded)
	aistore        store.AIStore  // AI analysis cache + model settings; nil when the store does not support it
	aiGen          sync.Map       // finding id → *sync.Mutex: one AI generation in flight per finding

	captureMu sync.Mutex
	captures  map[string]*captureSession // active reverse-proxy capture session per program

	specMu    sync.Mutex
	specs     map[string]scanSpec // run id → scan parameters, for "Rerun"
	specOrder []string            // insertion order; trimmed to rerunKeep

	sessMu   sync.Mutex
	sessions map[string]sessionInfo // login session token → user+role

	pages map[string]*template.Template
}

// Selection picks the subset of nuclei templates a scan runs,
// based on the payload bank metadata (BH-SPEC-PAYLOAD §Selection). Empty = all
// installed templates. Tags/Severity only affect the nuclei engine; Stealth
// affects the DAST engine (low-and-slow) and the overall scan rate.
type Selection struct {
	Tags     []string
	Severity []string
	// Stealth asks for a low-and-slow profile: the scan rate is clamped very low and
	// the DAST engine uses one connection + a browser UA (a minimal footprint on a
	// SOC-monitored target). Non-destructive is always on regardless of this.
	Stealth bool
	// APIRoutes adds the bundled API-route wordlist (Assetnote apiroutes)
	// to the ffuf engine — large-volume API path brute (opt-in per scan).
	APIRoutes bool
}

// Config configures the server: store, DAST engines (at least 1), optional recon & vault.
type Config struct {
	Store   store.Store
	Engines []engine.Engine
	Recon   recon.Engine
	// NewEngines (optional) builds NEW engines + recon per scan with the request
	// rate clamped to the scan rps. When set, it is used instead of Engines/Recon
	// for each run (see Server.newEngines). Engines is still required (≥1) as a
	// fallback & validation; Recon may be nil.
	NewEngines func(rps float64, sel Selection) ([]engine.Engine, recon.Engine)
	// PayloadSources are the Payload Bank sources scanned when the catalog is refreshed
	// (BH-SPEC-PAYLOAD). Empty = the refresh button is off; the catalog can still
	// be shown from stored data. It scans local files only (no network).
	PayloadSources []payload.Source
	Vault          secret.Vault
	Audit          audit.Log
	// Users is the RBAC account store. Required unless AuthDisabled=true. Login
	// (session) & HTTP Basic (automation) are verified against it; the role decides
	// the rights (viewer reads, operator changes, admin manages users).
	Users store.UserStore
	// AuthDisabled opens access without authentication (NO login, NO RBAC).
	// For tests and the explicit -no-auth flag on a trusted localhost only.
	// Default false: login is REQUIRED.
	AuthDisabled bool
	// Version is the build version (injected through ldflags); empty = "dev".
	// Shown in the UI footer so releases are easy to recognize.
	Version string
	// SASTRoot, when set, enables SAST and CONFINES analysis to this
	// directory (a scope path, default-deny). Empty = SAST off.
	SASTRoot string
	// GRPCReal uses real grpcurl for gRPC enumeration (needs the binary);
	// default mock. GRPCPlaintext sends -plaintext (gRPC without TLS).
	GRPCReal      bool
	GRPCPlaintext bool
	// GeoIP (optional) labels the egress IP in the Proxy menu with the country & ASN from
	// a LOCAL GeoLite2 database (offline — it never calls a third-party
	// service). nil = feature off; the Proxy menu still shows the IP without a country.
	GeoIP geoip.Resolver
}

// NewServer sets up the server with the given store and engines.
func NewServer(cfg Config) (*Server, error) {
	if len(cfg.Engines) == 0 {
		return nil, fmt.Errorf("web: at least one DAST engine")
	}
	if !cfg.AuthDisabled && cfg.Users == nil {
		return nil, fmt.Errorf("web: Users required unless AuthDisabled=true")
	}
	version := cfg.Version
	if version == "" {
		version = "dev"
	}
	pages, err := parseTemplates(version, engineLabel(cfg.Engines), reconLabel(cfg.Recon))
	if err != nil {
		return nil, err
	}
	// Persistent run history: when the store supports jobs.Store, the queue saves each
	// transition & reloads it at start (an orphaned run is finalized Failed) → the
	// Processes panel survives a restart/redeploy. Graceful degradation: a store without
	// support → the queue stays in-memory (the old behavior).
	var queueOpts []jobs.Option
	if rs, ok := cfg.Store.(jobs.Store); ok {
		queueOpts = append(queueOpts, jobs.WithStore(rs))
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
		queue:          jobs.New(4, queueOpts...),
		version:        version,
		sastRoot:       strings.TrimSpace(cfg.SASTRoot),
		captures:       map[string]*captureSession{},
		specs:          map[string]scanSpec{},
		sessions:       map[string]sessionInfo{},
		pages:          pages,
		geo:            cfg.GeoIP,
	}
	if s.geo == nil {
		s.geo = geoip.Nop{} // feature off without a nil-check in the request path
	}
	if cfg.GRPCReal {
		s.grpcEngine = &grpc.Runner{Plaintext: cfg.GRPCPlaintext}
	} else {
		s.grpcEngine = grpc.Mock{}
	}
	// Payload Bank: a store that supports the catalog is used; if not, the /payloads
	// page shows a "not supported" message (the feature degrades gracefully).
	if cs, ok := cfg.Store.(store.CatalogStore); ok {
		s.catalog = cs
	}
	// AI analysis cache + model settings (AIStore). When the store does not support it, the
	// MCP/AI menu & what-if card degrade gracefully (off) without a nil panic.
	if as, ok := cfg.Store.(store.AIStore); ok {
		s.aistore = as
	}
	s.routes()
	return s, nil
}

// Close stops the active capture sessions, then the worker pool (waiting for the
// running scans to finish).
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
	if c, ok := s.geo.(io.Closer); ok {
		_ = c.Close() // close the GeoIP reader when the DB is loaded (Nop is not a Closer)
	}
	return nil
}

const csrfCookie = "bh_csrf"

type csrfCtxKey struct{}

type userCtxKey struct{}
type roleCtxKey struct{}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")

	// CSRF: make sure the token cookie exists first (also so the login form has a token),
	// and provide it to the handler through the context to render into the form/hx-headers.
	token := s.ensureCSRFCookie(w, r)
	r = r.WithContext(context.WithValue(r.Context(), csrfCtxKey{}, token))

	// Auth: login is REQUIRED (unless AuthDisabled). People use a login session;
	// automation/CLI may use HTTP Basic. The user's role rides on the context.
	if !s.authDisabled && !authExempt(r) {
		user, role, ok := s.authUser(r)
		if !ok {
			// API (machine) clients always get a 401 JSON error, never an HTML redirect.
			if isAPIPath(r) {
				writeAPIError(w, http.StatusUnauthorized, "authentication required (login session or HTTP Basic)")
				return
			}
			// An explicit Basic credential that fails → 401 for automation/CLI.
			if r.Header.Get("Authorization") != "" {
				http.Error(w, "authentication failed", http.StatusUnauthorized)
				return
			}
			// A browser without a session: send a GET to the login page; reject anything else.
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			http.Error(w, "invalid session — please sign in", http.StatusUnauthorized)
			return
		}
		r = r.WithContext(context.WithValue(
			context.WithValue(r.Context(), userCtxKey{}, user), roleCtxKey{}, role))
	}

	// Every state-changing request must send a matching token (double-submit),
	// which blocks cross-site CSRF. It applies to POST /login too.
	if isStateChanging(r.Method) && !validCSRF(r, token) {
		http.Error(w, "CSRF: invalid token or cross-site request", http.StatusForbidden)
		return
	}

	// RBAC authorization: the role decides what may be accessed (default-deny when
	// the role is not enough). Skipped when auth is disabled or the path is exempt.
	if !s.authDisabled && !authExempt(r) {
		if !authorize(s.roleOf(r), r) {
			http.Error(w, "access denied: your role is not enough for this action", http.StatusForbidden)
			return
		}
	}

	s.mux.ServeHTTP(w, r)
}

// authExempt: the login page & static assets may be reached without a session.
func authExempt(r *http.Request) bool {
	return r.URL.Path == "/login" || strings.HasPrefix(r.URL.Path, "/static/")
}

// authUser authenticates the request through a login session OR HTTP Basic
// (username+password verified against the UserStore). It returns the user,
// the role, and whether it succeeded.
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
			auth.VerifyPassword(dummyHash, pass) // even out the timing for an unknown user
		}
	}
	return "", auth.Role(""), false
}

// authorize enforces RBAC: the /users area is admin-only; a state-changing action (other
// than logout) needs operator or above; GET is allowed for every valid role (default-deny).
func authorize(role auth.Role, r *http.Request) bool {
	switch {
	case r.URL.Path == "/users" || strings.HasPrefix(r.URL.Path, "/users/"):
		return auth.CanAdmin(role)
	// AI settings store an API key (secret) → admin only. The what-if card
	// (/ai/finding/...) is not here: it follows the default rule (GET=read, regen POST=write).
	case r.URL.Path == "/ai/settings" || strings.HasPrefix(r.URL.Path, "/ai/key/"):
		return auth.CanAdmin(role)
	case r.URL.Path == "/logout":
		return role.Valid()
	case isStateChanging(r.Method):
		return auth.CanWrite(role)
	default:
		return auth.CanRead(role)
	}
}

// currentUser returns the user & role from the context (empty when auth is
// off or not yet authenticated).
func (s *Server) currentUser(r *http.Request) (string, auth.Role) {
	user, _ := r.Context().Value(userCtxKey{}).(string)
	role, _ := r.Context().Value(roleCtxKey{}).(auth.Role)
	return user, role
}

func (s *Server) roleOf(r *http.Request) auth.Role {
	role, _ := r.Context().Value(roleCtxKey{}).(auth.Role)
	return role
}

// dummyHash evens out the verification timing when a username is unknown (against
// timing enumeration). Computed once; it never matches any password.
var dummyHash = func() string {
	h, _ := auth.HashPassword(randToken())
	return h
}()

const sessionCookie = "bh_session"
const sessionTTL = 12 * time.Hour

// sessionInfo is the state of one login session: user, role, creation time.
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
		http.Error(w, "invalid form", http.StatusBadRequest)
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
		auth.VerifyPassword(dummyHash, password) // even out the timing for an unknown user
	}
	s.auditAppend(r.Context(), audit.Event{Kind: "auth.login", Allowed: false, Message: username})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_ = s.pages["login"].ExecuteTemplate(w, "login", loginPage{CSRF: s.csrfToken(r), Error: "Wrong username or password.", Version: s.version})
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
		http.Error(w, "user management off (auth disabled)", http.StatusServiceUnavailable)
		return
	}
	page := s.usersPageFor(r)
	switch r.URL.Query().Get("ok") {
	case "created":
		page.Note = "User created."
	case "deleted":
		page.Note = "User deleted."
	case "password":
		page.Note = "Password updated."
	}
	s.render(w, r, "users", "base", page)
}

func (s *Server) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	if s.users == nil {
		http.Error(w, "user management off", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	role := auth.Role(strings.TrimSpace(r.FormValue("role")))

	page := s.usersPageFor(r)
	if username == "" || password == "" {
		page.Error = "Username and password are required."
		s.renderUsers(w, r, page, http.StatusBadRequest)
		return
	}
	if !role.Valid() {
		page.Error = "Unknown role."
		s.renderUsers(w, r, page, http.StatusBadRequest)
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		page.Error = "Could not hash the password: " + err.Error()
		s.renderUsers(w, r, page, http.StatusBadRequest)
		return
	}
	if err := s.users.CreateUser(r.Context(), store.User{Username: username, Role: string(role), PassHash: hash}); err != nil {
		if errors.Is(err, store.ErrUserExists) {
			page.Error = "Username already taken."
		} else {
			page.Error = "Could not create the user: " + err.Error()
		}
		s.renderUsers(w, r, page, http.StatusBadRequest)
		return
	}
	actor, _ := s.currentUser(r)
	s.auditAppend(r.Context(), audit.Event{Kind: "user.create", Allowed: true, Message: fmt.Sprintf("%s created %s (%s)", actor, username, role)})
	http.Redirect(w, r, "/users?ok=created", http.StatusSeeOther)
}

func (s *Server) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	if s.users == nil {
		http.Error(w, "user management off", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	me, _ := s.currentUser(r)

	page := s.usersPageFor(r)
	if username == me {
		page.Error = "Cannot delete the account that is currently signed in."
		s.renderUsers(w, r, page, http.StatusBadRequest)
		return
	}
	// Do not let the system lose its last admin (anti self-lockout).
	if s.isLastAdmin(r, username) {
		page.Error = "Cannot delete the last admin."
		s.renderUsers(w, r, page, http.StatusBadRequest)
		return
	}
	if err := s.users.DeleteUser(r.Context(), username); err != nil {
		page.Error = "Could not delete: " + err.Error()
		s.renderUsers(w, r, page, http.StatusBadRequest)
		return
	}
	s.auditAppend(r.Context(), audit.Event{Kind: "user.delete", Allowed: true, Message: fmt.Sprintf("%s deleted %s", me, username)})
	http.Redirect(w, r, "/users?ok=deleted", http.StatusSeeOther)
}

func (s *Server) handleUserPassword(w http.ResponseWriter, r *http.Request) {
	if s.users == nil {
		http.Error(w, "user management off", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	page := s.usersPageFor(r)
	if username == "" || password == "" {
		page.Error = "Username and new password are required."
		s.renderUsers(w, r, page, http.StatusBadRequest)
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		page.Error = "Could not hash the password: " + err.Error()
		s.renderUsers(w, r, page, http.StatusBadRequest)
		return
	}
	if err := s.users.SetPassword(r.Context(), username, hash); err != nil {
		page.Error = "Could not update the password: " + err.Error()
		s.renderUsers(w, r, page, http.StatusBadRequest)
		return
	}
	me, _ := s.currentUser(r)
	s.auditAppend(r.Context(), audit.Event{Kind: "user.password", Allowed: true, Message: fmt.Sprintf("%s reset the password of %s", me, username)})
	http.Redirect(w, r, "/users?ok=password", http.StatusSeeOther)
}

// renderUsers renders the Users page with a given status code (e.g. 400 on a
// validation failure) without disturbing the base chrome wrapper.
func (s *Server) renderUsers(w http.ResponseWriter, r *http.Request, page usersPage, code int) {
	user, role := s.currentUser(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_ = s.pages["users"].ExecuteTemplate(w, "base", shellData{
		User: user, Role: string(role), AuthOn: !s.authDisabled, Body: page,
	})
}

// isLastAdmin reports whether username is the only admin left.
func (s *Server) isLastAdmin(r *http.Request, username string) bool {
	list, err := s.users.ListUsers(r.Context())
	if err != nil {
		return true // fail closed: when in doubt, do not allow the deletion
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
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" { // modern browser: reject cross-site
		return false
	}
	// Origin "null" is treated like no Origin: under
	// Referrer-Policy: no-referrer, Chromium sends `Origin: null` for a VALID
	// same-origin navigation form POST. Rejecting it would break every
	// non-HTMX form. The defense stays intact: the double-submit token (below) cannot
	// be forged cross-site, and a cross-site POST is already rejected by
	// Sec-Fetch-Site above.
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
	s.mux.HandleFunc("POST /runs/{id}/stop", s.handleRunStop)
	s.mux.HandleFunc("POST /runs/{id}/rerun", s.handleRunRerun)
	s.mux.HandleFunc("POST /runs/{id}/delete", s.handleRunDelete)
	s.mux.HandleFunc("GET /findings", s.handleFindings)
	s.mux.HandleFunc("GET /priority", s.handlePriority)
	s.mux.HandleFunc("POST /findings/bulk", s.handleBulkTriage)
	s.mux.HandleFunc("GET /findings/{id}", s.handleFindingDetail)
	s.mux.HandleFunc("POST /findings/{id}/status", s.handleTriage)
	s.mux.HandleFunc("POST /findings/{id}/edit", s.handleFindingEdit)
	// Read-only JSON API for machine consumers (the Burp extension). See api.go.
	// Automatically protected by the front controller (auth+RBAC read); pure GET.
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
	// MCP/AI: settings (admin — touches secrets) + a per-finding what-if card (read).
	s.mux.HandleFunc("GET /ai/settings", s.handleAISettings)
	s.mux.HandleFunc("POST /ai/settings", s.handleAISettingsSave)
	s.mux.HandleFunc("POST /ai/key/delete", s.handleAIKeyDelete)
	s.mux.HandleFunc("GET /ai/finding/{id}", s.handleAIFinding)
	s.mux.HandleFunc("POST /ai/finding/{id}/regen", s.handleAIFindingRegen)
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
	Tags          string   // template selection: -tags (comma/space separated)
	Severity      []string // template selection: -severity (checked checkboxes)
	Stealth       bool     // low-and-slow profile (DAST + scan rate)
	APIRoutes     bool     // include the bundled API-route wordlist (ffuf)
	SavePreset    bool     // save this selection as the program preset
	// Authenticated session (Lever 1). The header VALUE is never echoed to the form
	// (secret); only the status & toggle are carried.
	HasSavedAuth bool // the vault has a saved session for this program
	UseSavedAuth bool // checked: use the saved session
	SaveAuth     bool // checked: save the pasted session to the vault
	AuthRoE      bool // checked: RoE statement (authorized for an authenticated scan)
	Errors       []string
	Result       *scanView
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

	// Given ?program=, prefill the scope AND the selection preset from the saved program.
	if prog := strings.TrimSpace(r.URL.Query().Get("program")); prog != "" {
		if p, err := s.store.GetProgram(r.Context(), prog); err == nil {
			page.Program = p.Name
			page.InScope = strings.Join(p.InScope, "\n")
			page.OutScope = strings.Join(p.OutScope, "\n")
			// The per-program template selection preset (overridden by an explicit query below).
			page.Tags = strings.Join(p.Preset.Tags, ",")
			page.Severity = p.Preset.Severity
			page.Stealth = p.Preset.Stealth
			page.APIRoutes = p.Preset.APIRoutes
			page.HasSavedAuth = s.hasSavedAuth(r.Context(), p.Name) // a saved authenticated session?
		}
	}
	// An explicit query beats the preset — used by the "Scan with this filter" link
	// in the Payload Bank (it carries ?tags= / ?severity= from the active catalog filter).
	if q := strings.TrimSpace(r.URL.Query().Get("tags")); q != "" {
		page.Tags = q
	}
	if sv := filterSeverities(r.URL.Query()["severity"]); len(sv) > 0 {
		page.Severity = sv
	}
	// Example defaults (demonstrate the gate directly) when there is no program.
	if page.Program == "" {
		page.Program = "demo"
		page.Seeds = "demo.test"
		page.InScope = "demo.test\n*.demo.test"
		page.OutScope = "admin.demo.test"
		page.Targets = "demo.test\nevil.test"
	}
	s.render(w, r, "scan", "base", page)
}

// authSessionScope is the vault scope for the per-program authenticated session
// (Lever 1): one named entry = the program name, holding encrypted "Name: value"
// header lines. Separate from other secrets; access is logged via the audit reveal hook.
const authSessionScope = "authsession"

// hasSavedAuth reports whether the vault holds a session for the program — only a
// metadata List, WITHOUT revealing its value (it does not trigger a reveal audit).
func (s *Server) hasSavedAuth(ctx context.Context, program string) bool {
	if s.vault == nil || strings.TrimSpace(program) == "" {
		return false
	}
	metas, err := s.vault.List(ctx, authSessionScope)
	if err != nil {
		return false
	}
	for _, m := range metas {
		if m.Name == program {
			return true
		}
	}
	return false
}

// validAuthHeaderLine makes sure the line has the shape "Name: value" with a token
// name and no spaces (rejecting random text pasted in the wrong place). The value is
// free (cookie/token), passed as-is to the engine argv (no shell).
func validAuthHeaderLine(line string) bool {
	name, val, ok := strings.Cut(line, ":")
	if !ok {
		return false
	}
	return strings.TrimSpace(name) != "" && strings.TrimSpace(val) != "" && !strings.ContainsAny(name, " \t")
}

// clampHeaderForErr gives a safe label for an error message: only the header name
// (before ':'), or a short slice when there is no ':'. It NEVER shows the header
// value (secret) in a response.
func clampHeaderForErr(line string) string {
	if name, _, ok := strings.Cut(line, ":"); ok {
		return strings.TrimSpace(name)
	}
	line = strings.TrimSpace(line)
	if len(line) > 16 {
		return line[:16] + "…"
	}
	return line
}

func (s *Server) handleScanRun(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	program := strings.TrimSpace(r.FormValue("program"))
	seeds := splitLines(r.FormValue("seeds"))
	inScope := splitLines(r.FormValue("in_scope"))
	outScope := splitLines(r.FormValue("out_scope"))
	targets := splitLines(r.FormValue("targets"))
	rps := parseRPS(r.FormValue("rps"))
	proxyChain := splitLines(r.FormValue("upstream_proxy")) // one hop per line
	// Authenticated session (Lever 1): the pasted headers, the use-saved toggle,
	// save, and the RoE statement. The header value is NEVER echoed back to the form.
	pastedAuth := splitLines(r.FormValue("auth_headers"))
	useSavedAuth := r.FormValue("use_saved_auth") != ""
	saveAuth := r.FormValue("save_auth") != ""
	authRoE := r.FormValue("auth_roe") != ""
	sel := Selection{Tags: splitList(r.FormValue("tags")), Severity: filterSeverities(r.Form["severity"]), Stealth: r.FormValue("stealth") != "", APIRoutes: r.FormValue("api_routes") != ""}
	// Stealth = low-and-slow: clamp the overall scan rate to quiet mode (≤
	// stealthScanRPS). This ADDS a restriction (the safe direction); the rate limiter stays
	// required in the execution path — it is never turned off.
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
		HasSavedAuth:  s.hasSavedAuth(r.Context(), program),
		UseSavedAuth:  useSavedAuth,
		SaveAuth:      saveAuth,
		AuthRoE:       authRoE,
	}

	// Spec-directed scan: expand OpenAPI/Swagger into endpoints → targets. Each
	// endpoint STILL goes through the scope guard below (the spec does not bypass the boundary). The raw
	// spec is also passed to the DAST engine to fuzz the request+body (`-im openapi`).
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

	// Resolving the authenticated session (Lever 1). Precedence: pasted headers >
	// the session saved in the vault. RoE is required when used; its value is redacted from
	// evidence downstream (orchestrator) and never echoed to the form.
	authHeaders := pastedAuth
	if len(authHeaders) == 0 && useSavedAuth && program != "" && s.vault != nil {
		if raw, err := s.vault.Reveal(r.Context(), authSessionScope, program); err == nil {
			authHeaders = splitLines(string(raw))
		} else {
			page.Errors = append(page.Errors, "The saved session could not be read for this program.")
		}
	}
	for _, h := range authHeaders {
		if !validAuthHeaderLine(h) {
			page.Errors = append(page.Errors, "Invalid session header (format 'Name: value'): "+clampHeaderForErr(h))
		}
	}
	if len(authHeaders) > 0 && !authRoE {
		page.Errors = append(page.Errors, "Authenticated scan: tick the RoE statement (authorized) before running.")
	}

	if program == "" {
		page.Errors = append(page.Errors, "The program name is required.")
	}
	if len(targets) == 0 && len(seeds) == 0 {
		page.Errors = append(page.Errors, "Enter at least one target, or one seed domain for recon.")
	}

	guard, errs := scope.New(inScope, outScope)
	for _, e := range errs {
		// Fail closed: an unparsed scope entry blocks the scan (especially an out-of-scope one).
		page.Errors = append(page.Errors, "Invalid scope: "+e.Error())
	}
	if len(page.Errors) > 0 {
		s.renderPartial(w, r, "scan", "scan_result_errors", page)
		return
	}

	// Save/update the program scope definition (persistent across restarts). The selection
	// preset is kept as-is unless the user ticks "save preset", so an ordinary scan does
	// not silently overwrite the program preset.
	prog := store.Program{Name: program, InScope: inScope, OutScope: outScope}
	if existing, err := s.store.GetProgram(r.Context(), program); err == nil {
		prog.Preset = existing.Preset
	}
	if page.SavePreset {
		prog.Preset = store.ScanPreset{Tags: sel.Tags, Severity: sel.Severity, Stealth: sel.Stealth, APIRoutes: sel.APIRoutes}
	}
	_ = s.store.SaveProgram(r.Context(), prog)

	// Save the authenticated session (Lever 1) to the vault if asked — ONLY the pasted
	// headers (not the already-saved one). Encrypted; non-fatal on failure
	// (the scan still runs using the headers for this run).
	if saveAuth && len(pastedAuth) > 0 && s.vault != nil {
		_ = s.vault.Put(r.Context(), authSessionScope, program, []byte(r.FormValue("auth_headers")))
	}

	// Enqueue: the scan runs in the background; the handler replies with the run_id at once.
	runID := s.enqueueScan(program, guard, scanSpec{
		seeds: seeds, targets: targets, rps: rps, proxyChain: proxyChain, sel: sel, openapiSpec: openapiSpec,
		authHeaders: authHeaders,
	})

	if run, ok := s.queue.Get(runID); ok {
		s.renderPartial(w, r, "scan", "run_status", s.runViewFor(r, run))
	}
}

// scanSpec holds one scan's parameters other than scope, kept in-memory so the run
// can be rerun from the Scanning processes panel (for the lifetime of the run history in the queue,
// lost on restart). Scope is deliberately NOT stored: Rerun re-evaluates the
// current program scope from the store.
type scanSpec struct {
	seeds, targets []string
	rps            float64
	proxyChain     []string // may hold user:pass credentials: do not render/log it
	sel            Selection
	openapiSpec    []byte
	authHeaders    []string // auth session (Lever 1): secret, do not render/log it (String redacts the whole spec)
}

// String/GoString redact the spec's content (the proxy chain may hold credentials) so it
// does not leak if accidentally formatted to a log/error (Principle #5). fmt does not
// call the String() of an unexported field, so the guard lives on this holder.
func (scanSpec) String() string      { return "scanSpec{redacted}" }
func (sp scanSpec) GoString() string { return sp.String() }

// rerunKeep caps the remembered specs (a spec may hold a large OpenAPI); enough
// for every row of the Scanning processes panel.
const rerunKeep = 2 * scansLiveLimit

func (s *Server) rememberSpec(runID string, sp scanSpec) {
	s.specMu.Lock()
	defer s.specMu.Unlock()
	s.specs[runID] = sp
	s.specOrder = append(s.specOrder, runID)
	for len(s.specOrder) > rerunKeep {
		delete(s.specs, s.specOrder[0])
		s.specOrder = s.specOrder[1:]
	}
}

func (s *Server) specFor(runID string) (scanSpec, bool) {
	s.specMu.Lock()
	defer s.specMu.Unlock()
	sp, ok := s.specs[runID]
	return sp, ok
}

// forgetSpec drops the saved rerun spec for a run (used
// when a run is removed from the monitor so no orphan parameters are left).
func (s *Server) forgetSpec(runID string) {
	s.specMu.Lock()
	defer s.specMu.Unlock()
	if _, ok := s.specs[runID]; !ok {
		return
	}
	delete(s.specs, runID)
	for i, id := range s.specOrder {
		if id == runID {
			s.specOrder = append(s.specOrder[:i], s.specOrder[i+1:]...)
			break
		}
	}
}

// enqueueScan runs one scan in the background (worker pool) and
// returns a run id at once. One scan-launch path is shared by the
// Scan form, "promote" from Capture, and Rerun. The task uses the queue's ctx
// (not r.Context()) so it is not cancelled when the web response is sent; that ctx
// is only cancelled by Stop. The rate limiter is always installed (it cannot be
// turned off); the scope guard is the only gate.
func (s *Server) enqueueScan(program string, guard *scope.Guard, sp scanSpec) string {
	storeRef := s.store
	seeds, targets, rps, sel := sp.seeds, sp.targets, sp.rps, sp.sel
	runID := s.queue.Enqueue(program, scanLabel(seeds, targets), func(ctx context.Context, runID string) (jobs.Summary, error) {
		// The audit uses a ctx WITHOUT cancellation: Stop cancels the run's ctx (the engines
		// are killed), but the audit trail must stay intact (Principle #6). The
		// SQLite store rejects a query on an already-cancelled ctx.
		actx := context.WithoutCancel(ctx)
		s.auditAppend(actx, audit.Event{Kind: "run.start", Program: program, RunID: runID, Message: scanLabel(seeds, targets)})

		auditSink := func(e orchestrator.AuditEvent) {
			s.auditAppend(actx, audit.Event{
				Kind: "scope.decision", Program: e.Program, RunID: e.RunID, Target: e.Target,
				Allowed: e.Allowed, Reason: string(e.Reason), Layer: string(e.Layer), Message: e.MatchedEntry,
			})
		}
		// Engines per run: real mode builds a NEW instance with the rate clamped
		// to rps (per-engine throttle in the execution path) so each run has its own
		// engines + egress proxy; mock/test use the fixed instances. The template
		// selection (tags/severity) is passed to the engines so only a subset runs.
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
		res, err := o.RunScan(ctx, orchestrator.ScanRequest{Program: program, RunID: runID, Seeds: seeds, Targets: targets, ProxyChain: sp.proxyChain, OpenAPISpec: sp.openapiSpec, AuthHeaders: sp.authHeaders})
		sum := runSummary(res)
		if err != nil {
			msg := "failed: " + err.Error()
			if ctx.Err() != nil {
				msg = fmt.Sprintf("stopped: saved=%d dup=%d denied=%d", res.FindingsSaved, res.Duplicates, len(res.Denied))
			}
			s.auditAppend(actx, audit.Event{Kind: "run.finish", Program: program, RunID: runID, Message: msg})
			return sum, err
		}
		s.auditAppend(actx, audit.Event{Kind: "run.finish", Program: program, RunID: runID,
			Message: fmt.Sprintf("saved=%d dup=%d denied=%d", res.FindingsSaved, res.Duplicates, len(res.Denied))})
		for _, ee := range res.EngineErrors {
			s.auditAppend(actx, audit.Event{Kind: "run.engine_error", Program: program, RunID: runID,
				Message: fmt.Sprintf("engine %s failed at %s: %s", ee.Engine, ee.Target, ee.Err)})
		}
		return sum, nil
	})
	s.rememberSpec(runID, sp)
	return runID
}

// runSummary summarizes the orchestrator result for the queue. On a failed or
// stopped run, res holds a partial result (findings already saved stay).
func runSummary(res orchestrator.ScanResult) jobs.Summary {
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
	}
	return sum
}

func (s *Server) handleRunStatus(w http.ResponseWriter, r *http.Request) {
	run, ok := s.queue.Get(r.PathValue("id"))
	if !ok {
		http.Error(w, "run not found", http.StatusNotFound)
		return
	}
	s.renderPartial(w, r, "scan", "run_status", s.runViewFor(r, run))
}

// handleRunStop stops a queued/running run. The run's context is cancelled
// so the engine subprocess is killed too; findings already saved stay.
// State-changing → operator+ & CSRF through middleware. Audit run.stop
// only when this call is the one that stopped it (a repeated Stop = no-op).
func (s *Server) handleRunStop(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	run, ok := s.queue.Get(id)
	if !ok {
		http.Error(w, "run not found", http.StatusNotFound)
		return
	}
	if s.queue.Cancel(id) {
		me, _ := s.currentUser(r)
		s.auditAppend(r.Context(), audit.Event{Kind: "run.stop", Program: run.Program, RunID: id, Allowed: true,
			Message: fmt.Sprintf("%s stopped the run (%s)", me, run.Status)})
	}
	if r.FormValue("view") == "dashboard" {
		s.renderScansLive(w, r, "")
		return
	}
	run, _ = s.queue.Get(id)
	s.renderPartial(w, r, "scan", "run_status", s.runViewFor(r, run))
}

// handleRunRerun reruns a finished run with the same scan
// parameters. Scope is NOT taken from the original run: it is re-evaluated from the
// current program definition in the store (fail closed if the program is gone or the scope is
// invalid), then goes through enqueueScan so the scope guard, rate limiter, and egress
// are exactly the same as an ordinary scan. It replies with the Scanning processes panel.
func (s *Server) handleRunRerun(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	run, ok := s.queue.Get(id)
	if !ok {
		s.renderScansLive(w, r, "Run not found; the run history is lost when the server restarts.")
		return
	}
	if run.Status == jobs.Queued || run.Status == jobs.Running {
		s.renderScansLive(w, r, "The run is still running. Stop it first or wait for it to finish.")
		return
	}
	sp, ok := s.specFor(id)
	if !ok {
		s.renderScansLive(w, r, "This run's parameters are no longer stored. Run it from the Scan menu.")
		return
	}
	me, _ := s.currentUser(r)
	reason := ""
	var guard *scope.Guard
	if prog, err := s.store.GetProgram(r.Context(), run.Program); err != nil {
		reason = "the program has no saved scope"
	} else if g, errs := scope.New(prog.InScope, prog.OutScope); len(errs) > 0 {
		reason = "invalid program scope: " + errs[0].Error()
	} else {
		guard = g
	}
	if guard == nil {
		s.auditAppend(r.Context(), audit.Event{Kind: "run.rerun", Program: run.Program, RunID: id, Allowed: false,
			Reason: reason, Message: fmt.Sprintf("%s: rerun denied", me)})
		s.renderScansLive(w, r, "Rerun denied: "+reason+".")
		return
	}
	newID := s.enqueueScan(run.Program, guard, sp)
	s.auditAppend(r.Context(), audit.Event{Kind: "run.rerun", Program: run.Program, RunID: newID, Allowed: true,
		Message: fmt.Sprintf("%s reran %s", me, id)})
	s.renderScansLive(w, r, "")
}

// handleRunDelete drops one FINISHED run from the Scanning processes
// panel (the in-memory queue history + the rerun spec). It only clears the
// monitoring entry — findings already saved in the store are NOT removed (that
// goes through Dashboard ▸ delete findings). An active run must be Stopped first so the engine is
// not orphaned. operator+ & CSRF through middleware. It replies with the Scanning processes panel.
func (s *Server) handleRunDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	run, ok := s.queue.Get(id)
	if !ok {
		s.renderScansLive(w, r, "Run not found; it may already be deleted or lost when the server restarts.")
		return
	}
	if run.Status == jobs.Queued || run.Status == jobs.Running {
		s.renderScansLive(w, r, "The run is still running. Stop it first, then delete it from the list.")
		return
	}
	if s.queue.Remove(id) {
		s.forgetSpec(id)
		me, _ := s.currentUser(r)
		s.auditAppend(r.Context(), audit.Event{Kind: "run.delete", Program: run.Program, RunID: id, Allowed: true,
			Message: fmt.Sprintf("%s removed the run entry (%s) from the monitor; findings stay", me, run.Status)})
	}
	s.renderScansLive(w, r, "")
}

// canControl: operator+ (or auth off) may Stop / Rerun; a viewer
// only watches. The real gate is still the authorize() middleware.
func (s *Server) canControl(r *http.Request) bool {
	return s.authDisabled || auth.CanWrite(s.roleOf(r))
}

func (s *Server) runViewFor(r *http.Request, run *jobs.Run) runView {
	v := toRunView(run)
	v.CanControl = s.canControl(r)
	return v
}

type runView struct {
	ID         string
	Program    string
	Status     string
	Label      string
	Err        string
	Active     bool
	Stopping   bool // Stop requested, the engine is being stopped
	CanControl bool // the role may Stop
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
		Stopping:   r.Stopping,
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
	// the active filter (to repopulate the controls & keep it in the query).
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

type priorityPage struct {
	Nav      string
	Title    string
	Program  string
	CSRF     string
	Programs []string
	Scored   []triage.Scored
	Total    int // number of program findings before the prefilter ("N of M" context)
}

// handlePriority shows the "verification priority" ranking (SAW/DSS) of a
// program's findings — the same as the MCP `rank` tool, computed in-process (the
// triage package). Read-only: it does not touch the target, does not change the store.
func (s *Server) handlePriority(w http.ResponseWriter, r *http.Request) {
	program := strings.TrimSpace(r.URL.Query().Get("program"))
	progs := s.programNames(r.Context())
	if program == "" && len(progs) > 0 {
		program = progs[0]
	}
	var all []*finding.Finding
	if program != "" {
		all, _ = s.store.List(r.Context(), store.Query{Program: program})
	}
	page := priorityPage{
		Nav: "priority", Title: "Priority", Program: program, CSRF: s.csrfToken(r),
		Programs: progs, Scored: triage.Rank(all), Total: len(all),
	}
	s.render(w, r, "priority", "base", page)
}

func (s *Server) handleBulkTriage(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	status := finding.Status(strings.TrimSpace(r.FormValue("status")))
	switch status {
	case finding.StatusConfirmed, finding.StatusFalsePositive, finding.StatusIgnored, finding.StatusNew:
	default:
		http.Error(w, "triage status not allowed", http.StatusBadRequest)
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
		http.Error(w, "finding not found", http.StatusNotFound)
		return
	}
	s.renderPartial(w, r, "findings", "finding_detail", f)
}

func (s *Server) handleTriage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	status := finding.Status(strings.TrimSpace(r.FormValue("status")))
	verifiedBy := strings.TrimSpace(r.FormValue("verified_by"))

	// Manual triage may not set duplicate (that is the store's dedup path).
	switch status {
	case finding.StatusConfirmed, finding.StatusFalsePositive, finding.StatusIgnored, finding.StatusNew:
	default:
		http.Error(w, "triage status not allowed", http.StatusBadRequest)
		return
	}

	if err := s.store.SetStatus(r.Context(), id, status, verifiedBy); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f, err := s.store.Get(r.Context(), id)
	if err != nil {
		http.Error(w, "finding not found", http.StatusNotFound)
		return
	}
	s.renderPartial(w, r, "findings", "finding_detail", f)
}

// handleFindingEdit saves the narrative report fields (description, reproduction
// steps, impact) that the hunter completes during triage, so the draft report &
// platform export are complete (principle: the report is always a draft, completed+verified
// manually before submitting). It does not change status/severity/dedup.
func (s *Server) handleFindingEdit(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
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
		http.Error(w, "finding not found", http.StatusNotFound)
		return
	}
	me, _ := s.currentUser(r)
	s.auditAppend(r.Context(), audit.Event{Kind: "finding.edit", Program: f.Program, Allowed: true,
		Message: fmt.Sprintf("%s completed the draft of finding %s (description/steps/impact)", me, id)})
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
		http.Error(w, "program required", http.StatusBadRequest)
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
		http.Error(w, "program required", http.StatusBadRequest)
		return
	}
	findings, _ := s.store.List(r.Context(), store.Query{Program: program})
	rep := report.Build(program, findings, time.Now())
	s.render(w, r, "report_print", "report_print", rep)
}

// handleReportExport downloads the draft formatted to a platform template (HackerOne /
// Bugcrowd). With ?id= -> one confirmed finding; without id -> the whole
// report. It only produces a file to copy/submit MANUALLY — no
// auto-submit, no outbound connection.
func (s *Server) handleReportExport(w http.ResponseWriter, r *http.Request) {
	program := strings.TrimSpace(r.URL.Query().Get("program"))
	platform := report.Platform(strings.TrimSpace(r.URL.Query().Get("platform")))
	if program == "" {
		http.Error(w, "program required", http.StatusBadRequest)
		return
	}
	if !platform.Valid() {
		http.Error(w, "export platform not supported", http.StatusBadRequest)
		return
	}

	var md, fname string
	if id := strings.TrimSpace(r.URL.Query().Get("id")); id != "" {
		f, err := s.store.Get(r.Context(), id)
		if err != nil || f.Program != program {
			http.Error(w, "finding not found", http.StatusNotFound)
			return
		}
		if f.Status != finding.StatusConfirmed {
			http.Error(w, "only confirmed findings can be exported", http.StatusBadRequest)
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
	Note     string // flash after an action (e.g. delete)
	Programs []*store.Program
}

func (s *Server) handlePrograms(w http.ResponseWriter, r *http.Request) {
	progs, _ := s.store.ListPrograms(r.Context())
	note := ""
	if r.URL.Query().Get("ok") == "deleted" {
		note = "Program deleted (findings & audit stay saved)."
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

	PlatformData string        // the pasted platform data, kept when an import is held
	Import       *importReport // the import summary to review; nil when there is none
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
		http.Error(w, "invalid form", http.StatusBadRequest)
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
		page.Errors = append(page.Errors, "The program name is required.")
	}
	// Fail-closed: refuse to save when there is an unparsed scope entry (especially out-of-scope).
	if _, errs := scope.New(inScope, outScope); len(errs) > 0 {
		for _, e := range errs {
			page.Errors = append(page.Errors, "Invalid scope: "+e.Error())
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
		Message: fmt.Sprintf("%s saved the scope: %d in-scope, %d out-of-scope", me, len(inScope), len(outScope))})
	http.Redirect(w, r, "/programs", http.StatusSeeOther)
}

// importReport is the import summary reviewed in the scope editor.
type importReport struct {
	scope.ImportResult
	Held     bool     // held: Unresolved not yet agreed, the form is not filled
	Replaced []string // old in-scope entries in the form replaced by the import
}

// handleProgramImport converts platform scope data, then fills the scope editor
// form to review. This handler does NOT save anything: new entries take effect
// only after the user presses Save, through the fail-closed handleProgramSave.
//
// Merging follows the same safe direction as the importer: in-scope is REPLACED
// (old entries may be assets the program has dropped), out-of-scope is MERGED
// (an exclusion the user wrote must not be lost to the import).
//
// When an exclusion cannot be represented, the form is not filled until the user agrees
// to the list. The agreement is bound to the Digest, so it does not apply to other data.
func (s *Server) handleProgramImport(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
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
		page.Errors = append(page.Errors, "Import failed: "+err.Error())
		s.auditAppend(r.Context(), audit.Event{Kind: "program.import", Program: name, Allowed: false,
			Reason: err.Error(), Message: me + " failed to import platform scope"})
		s.render(w, r, "program_edit", "base", page)
		return
	}

	summary := fmt.Sprintf("%s · %d in-scope, %d out-of-scope, %d unrepresented exclusions · sha256 %s",
		res.Format, len(res.InScope), len(res.OutScope), len(res.Unresolved), res.Digest)
	report := &importReport{ImportResult: res}
	page.Import = report
	if len(res.Unresolved) > 0 && r.FormValue("ack_unresolved") != res.Digest {
		report.Held = true
		s.auditAppend(r.Context(), audit.Event{Kind: "program.import", Program: name, Allowed: false,
			Reason: "unrepresented exclusions not yet agreed", Message: me + " · " + summary})
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

// appendMissingLines adds the entries not yet present to the textarea content, without
// changing lines the user already wrote (including comments).
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

// handleProgramDelete deletes a program's scope definition. Only the program
// definition is removed (so the list does not pile up); findings stay saved as
// work product and the append-only audit is untouched — this deletion itself is
// RECORDED in the audit. State-changing → needs operator+ & CSRF (authorize middleware).
func (s *Server) handleProgramDelete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		http.Redirect(w, r, "/programs", http.StatusSeeOther)
		return
	}
	me, _ := s.currentUser(r)
	err := s.store.DeleteProgram(r.Context(), name)
	if err != nil && err != store.ErrNotFound { // idempotent: already gone = silent success
		http.Error(w, "could not delete the program: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err == nil {
		s.auditAppend(r.Context(), audit.Event{Kind: "program.delete", Program: name, Allowed: true, Message: fmt.Sprintf("%s deleted the program definition (findings & audit stay)", me)})
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
		http.Error(w, "invalid form", http.StatusBadRequest)
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
	Supported  bool // the store supports the catalog
	CanRefresh bool // there are sources & an operator-or-above role
	HasSources bool
	Sources    []payload.SourceInfo
	Stats      store.CatalogStats
	Entries    []payload.Entry

	// the active filter (to repopulate the form)
	Q, Engine, Trust, Severity, Tag, Enabled string

	// pagination
	Total, Page, Pages, From, To int
	HasPrev, HasNext             bool
	PrevURL, NextURL             string

	Flash string // banner after a refresh
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
			page.Flash = "Catalog updated — " + t + " templates cataloged."
		} else {
			page.Flash = "Catalog updated."
		}
	}
	s.render(w, r, "payloads", "base", page)
}

func (s *Server) handlePayloadsRefresh(w http.ResponseWriter, r *http.Request) {
	if s.catalog == nil {
		http.Error(w, "the catalog is not supported by this store", http.StatusServiceUnavailable)
		return
	}
	if len(s.payloadSources) == 0 {
		http.Error(w, "no payload sources configured (set -nuclei-templates / -custom-templates)", http.StatusServiceUnavailable)
		return
	}
	ctx := r.Context()
	before, _ := s.catalog.CatalogStats(ctx)
	// Build scans the sources' local files (no network), then ReplaceCatalog
	// swaps the catalog atomically.
	cat := payload.Build(ctx, s.payloadSources)
	if err := s.catalog.ReplaceCatalog(ctx, cat); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	user, _ := s.currentUser(r)
	s.auditAppend(ctx, audit.Event{
		Kind:    "catalog.refresh",
		Allowed: true,
		Message: fmt.Sprintf("payload bank refreshed by %s: %d templates from %d sources (previously %d)",
			firstNonEmptyStr(user, "system"), len(cat.Entries), len(cat.Sources), before.Total),
	})
	v := url.Values{}
	v.Set("refreshed", "1")
	v.Set("total", strconv.Itoa(len(cat.Entries)))
	http.Redirect(w, r, "/payloads?"+v.Encode(), http.StatusSeeOther)
}

// payloadFilterQuery builds the filter query string (without page) for the pagination links.
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
	Severities  []dashSev // ordered critical..info (including 0 for column alignment)
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
	Note           string // flash after an action (e.g. delete findings)
	Rows           []dashRow
	TotalPrograms  int
	TotalFindings  int
	TotalConfirmed int
	TotalNew       int
	TotalRuns      int
	SevTotals      []dashSev    // total per severity across programs (for the summary bar)
	SevDonut       template.CSS // conic-gradient of the severity composition (safe: template.CSS)
}

var dashSevOrder = []finding.Severity{
	finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium,
	finding.SeverityLow, finding.SeverityInfo,
}

// handleDashboard shows the cross-program summary (counts from the store;
// read-only, no network). Duplicates are excluded (List default).
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	page := dashboardPage{Nav: "dashboard", Title: "Dashboard", CSRF: s.csrfToken(r)}
	if r.URL.Query().Get("ok") == "findings-deleted" {
		prog := strings.TrimSpace(r.URL.Query().Get("program"))
		n := strings.TrimSpace(r.URL.Query().Get("n"))
		page.Note = fmt.Sprintf("%s findings of program %q deleted. The scope definition & audit stay.", n, prog)
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

	// Most recently active on top; those with no activity below (ordered by name).
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

// handleDashboardDeleteFindings deletes ALL findings of a program (the action from
// a "Findings per program" row). As chosen: findings ONLY — the program scope
// definition stays (managed in the Programs menu) and the append-only audit is untouched;
// this deletion itself is recorded (findings.delete). State-changing → operator+
// & CSRF via the authorize() middleware. Idempotent: a program with no findings → 0, 303.
func (s *Server) handleDashboardDeleteFindings(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
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
		http.Error(w, "could not delete the findings: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Drop this program's AI analysis cache so no orphan rows
	// pile up. Best-effort: the findings are already deleted, a cleanup failure must
	// not fail the request. The count is recorded so the audit stays intact.
	aiPurged := 0
	if s.aistore != nil {
		aiPurged, _ = s.aistore.DeleteAIAnalysisByProgram(r.Context(), program)
	}
	// Also drop the program's FINISHED run history (in-memory + store) so it does not
	// become an orphan after its findings are gone. Active runs are skipped (stop them first).
	runsPurged := s.queue.RemoveByProgram(program)
	s.auditAppend(r.Context(), audit.Event{Kind: "findings.delete", Program: program, Allowed: true,
		Message: fmt.Sprintf("%s deleted %d program findings + %d AI cache + %d run history (the scope definition stays)", me, n, aiPurged, runsPurged)})
	http.Redirect(w, r, fmt.Sprintf("/dashboard?ok=findings-deleted&program=%s&n=%d", url.QueryEscape(program), n), http.StatusSeeOther)
}

// ---- Monitor scan live (dashboard) ----

type scanLiveRow struct {
	ID          string
	Program     string
	Label       string
	Status      string
	Active      bool
	Stopping    bool
	Done        bool
	Failed      bool
	Cancelled   bool
	CanRerun    bool // the run finished & its parameters are still remembered
	Saved       int
	Scanned     int
	Discovered  int
	DeniedCount int
	Err         string
	Elapsed     string
}

type scansLivePage struct {
	Rows           []scanLiveRow
	ActiveCount    int
	QueuedCount    int
	DoneCount      int
	CancelledCount int
	Total          int
	HasAny         bool
	Interval       string // HTMX polling interval (adaptive)
	UpdatedAt      string
	CanControl     bool   // show the Stop / Rerun buttons (operator+)
	Notice         string // a Stop/Rerun action message (e.g. the reason for a denial)
}

const scansLiveLimit = 12

// handleDashboardScans renders the "Scanning processes" panel (live) from the in-process
// job queue — read-only, no network & no store query (cheap for
// polling). HTMX calls it repeatedly (a self-chained trigger) so the run status
// looks like it changes in real time: queued → running → done/failed/stopped,
// with the duration.
func (s *Server) handleDashboardScans(w http.ResponseWriter, r *http.Request) {
	s.renderScansLive(w, r, "")
}

// renderScansLive renders the Scanning processes panel; notice (optional) shows up
// as an info line, used by the Stop/Rerun action.
func (s *Server) renderScansLive(w http.ResponseWriter, r *http.Request, notice string) {
	now := time.Now()
	runs := s.queue.List("") // all, newest first
	page := scansLivePage{Total: len(runs), UpdatedAt: now.Format("15:04:05"), CanControl: s.canControl(r), Notice: notice}
	for _, rn := range runs {
		switch rn.Status {
		case jobs.Queued:
			page.QueuedCount++
		case jobs.Running:
			page.ActiveCount++
		case jobs.Done:
			page.DoneCount++
		case jobs.Cancelled:
			page.CancelledCount++
		}
		if len(page.Rows) >= scansLiveLimit {
			continue
		}
		v := toRunView(rn)
		_, hasSpec := s.specFor(rn.ID)
		page.Rows = append(page.Rows, scanLiveRow{
			ID: v.ID, Program: v.Program, Label: rn.Label,
			Status:      string(rn.Status),
			Active:      v.Active,
			Stopping:    rn.Stopping,
			Done:        rn.Status == jobs.Done,
			Failed:      rn.Status == jobs.Failed,
			Cancelled:   rn.Status == jobs.Cancelled,
			CanRerun:    !v.Active && hasSpec,
			Saved:       v.Saved,
			Scanned:     v.Scanned,
			Discovered:  v.Discovered,
			DeniedCount: len(v.Denied),
			Err:         v.Err,
			Elapsed:     runElapsed(rn, now),
		})
	}
	page.HasAny = len(page.Rows) > 0
	// Adaptive polling: 2 s when there is an active/queued scan, 6 s when idle (still
	// watching for a new scan) — cheap because it only reads the in-memory queue.
	page.Interval = "6s"
	if page.ActiveCount > 0 || page.QueuedCount > 0 {
		page.Interval = "2s"
	}
	s.renderPartial(w, r, "dashboard", "scans_live", page)
}

// runElapsed: running = since start; finished = total runtime; queued = wait.
// A run stopped while queued has no StartedAt → "—".
func runElapsed(r *jobs.Run, now time.Time) string {
	switch r.Status {
	case jobs.Queued:
		return "queued"
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

// humanDur formats a compact duration: "<1s", "9s", "1m 05s", "2h 10m".
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

// handleSASTRun runs one SAST adapter on a subpath INSIDE sastRoot.
// The path scope is enforced by sast.Resolve (default-deny); analysis is local, it does not
// touch the network. Findings enter the store & Findings like any other engine.
func (s *Server) handleSASTRun(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	page := s.sastBasePage()
	page.CSRF = s.csrfToken(r)
	page.Program = strings.TrimSpace(r.FormValue("program"))
	page.Subpath = strings.TrimSpace(r.FormValue("subpath"))
	page.Engine = strings.TrimSpace(r.FormValue("engine"))

	if !page.Enabled {
		page.Error = "SAST is disabled. Run the server with -sast-root <dir>."
		s.render(w, r, "sast", "base", page)
		return
	}
	if page.Program == "" {
		page.Error = "The program is required."
		s.render(w, r, "sast", "base", page)
		return
	}
	eng, ok := sast.Lookup(page.Engine)
	if !ok {
		page.Error = "Unknown SAST adapter: " + page.Engine
		s.render(w, r, "sast", "base", page)
		return
	}

	dir, err := sast.Resolve(s.sastRoot, page.Subpath)
	if err != nil {
		// Boundary denied — record it to the audit (like a DAST scope denial).
		if s.audit != nil {
			_, _ = s.audit.Append(r.Context(), audit.Event{
				Kind: "sast.scope", Program: page.Program, Target: page.Subpath,
				Allowed: false, Reason: err.Error(), Layer: "path",
			})
		}
		page.Error = "Path denied: " + err.Error()
		s.render(w, r, "sast", "base", page)
		return
	}

	runID := fmt.Sprintf("sast-%d", time.Now().UnixNano())
	res, err := sast.Run(r.Context(), dir, page.Subpath, page.Program, runID, []sast.Engine{eng}, s.store, s.audit)
	if err != nil {
		page.Error = "Analysis failed: " + err.Error()
		s.render(w, r, "sast", "base", page)
		return
	}
	page.Result = &sastResult{Engine: eng.Name(), Path: page.Subpath, Saved: res.Saved, Duplicates: res.Duplicates}
	s.render(w, r, "sast", "base", page)
}

// ---- gRPC (enumeration) ----

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

// handleGRPCRun enumerates gRPC targets (host:port) via reflection. Each host
// MUST pass the program scope guard (grpcurl cannot be proxied; scope is enforced
// upstream). Findings enter the store & Findings like any other engine.
func (s *Server) handleGRPCRun(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
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
		page.Error = "The program and at least one host:port target are required."
		s.render(w, r, "grpc", "base", page)
		return
	}
	prog, err := s.store.GetProgram(r.Context(), page.Program)
	if err != nil {
		page.Error = "The program has no saved scope yet — save its scope first on the Programs page."
		s.render(w, r, "grpc", "base", page)
		return
	}
	guard, errs := scope.New(prog.InScope, prog.OutScope)
	if len(errs) > 0 {
		page.Error = "Invalid program scope: " + errs[0].Error()
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
			page.Error = "Enumeration failed for " + tgt + ": " + serr.Error()
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

// ---- Proxy / Egress check (proxy chain & exit IP diagnostics) ----

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
	// Offline geolocation of the egress IP (empty when the GeoIP DB is not loaded). GeoLoaded
	// marks whether the country column needs to be shown at all.
	GeoLoaded          bool
	SourceGeo, ExitGeo geoip.Info
}

// handleProxyForm shows the proxy diagnostic menu.
func (s *Server) handleProxyForm(w http.ResponseWriter, r *http.Request) {
	program := strings.TrimSpace(r.URL.Query().Get("program"))
	s.render(w, r, "proxy", "base", proxyPage{
		Nav: "proxy", Title: "Proxy", Program: program, CSRF: s.csrfToken(r),
		Programs: s.programNames(r.Context()),
	})
}

// burpPage: the Burp integration onboarding page (see burp.html). Purely
// informational — it shows the read-only API endpoints + how to build/load the extension.
type burpPage struct {
	Nav, Title, Program, CSRF string
	BaseURL                   string   // scheme+host from the request, for the command examples
	User                      string   // login username, for the curl -u example
	Programs                  []string // programs that have findings, to pick an example
	SampleProgram             string   // the program used in the command examples
}

// handleBurp shows the Burp integration page: the UI entry point for the read-only
// API + extension. It does not run Burp; purely onboarding.
func (s *Server) handleBurp(w http.ResponseWriter, r *http.Request) {
	program := strings.TrimSpace(r.URL.Query().Get("program"))
	user, _ := s.currentUser(r)
	if user == "" {
		user = "admin" // auth off / just an example
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
			sample = "program-name"
		}
	}
	s.render(w, r, "burp", "base", burpPage{
		Nav: "burp", Title: "Burp integration", Program: program, CSRF: s.csrfToken(r),
		BaseURL: scheme + "://" + r.Host, User: user, Programs: progs, SampleProgram: sample,
	})
}

// handleProxyCheck validates & tests the proxy chain, then (optionally) measures
// the IP the target sees directly vs through the chain using an echo endpoint that
// MUST pass the program scope guard (default-deny). State-changing → operator+
// (authorize middleware). The proxy credentials are never shown/logged.
func (s *Server) handleProxyCheck(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	program := strings.TrimSpace(r.FormValue("program"))
	echo := strings.TrimSpace(r.FormValue("echo_url"))
	chainLines := splitLines(r.FormValue("upstream_proxy"))

	res := &proxyCheckResult{}
	hops, err := egress.ParseChain(chainLines)
	if err != nil {
		res.Error = "Invalid chain: " + err.Error()
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
		Message: fmt.Sprintf("%s tested the proxy: %d/%d hops reachable, echo=%t, ip-changed=%t", me, reachable, len(res.Hops), echo != "", changed),
	})
	s.renderPartial(w, r, "proxy", "proxy_result", res)
}

// proxyEchoCheck measures the IP the target sees: one direct GET and one
// through the chain, to the same echo endpoint. The echo MUST pass the program scope guard
// (default-deny — Principle #2). It returns the result + a note when it cannot.
func (s *Server) proxyEchoCheck(r *http.Request, program string, chain []string, echo string) (*proxyEchoResult, string) {
	if program == "" {
		return nil, "Pick a program first so the echo endpoint is checked by the scope guard (default-deny)."
	}
	prog, err := s.store.GetProgram(r.Context(), program)
	if err != nil {
		return nil, "The program has no saved scope yet — save it first on the Programs page."
	}
	guard, errs := scope.New(prog.InScope, prog.OutScope)
	if len(errs) > 0 {
		return nil, "Invalid program scope: " + errs[0].Error()
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
		GeoLoaded:    s.geo.Loaded(),
	}
	out.SourceGeo = s.geo.Resolve(out.SourceIP)
	if !direct.Allowed {
		return out, ""
	}
	chained := egress.New(guard, auditSink)
	if err := chained.SetUpstream(chain...); err != nil {
		out.ExitErr = "the chain could not be built: " + err.Error()
		return out, ""
	}
	exit := chained.Fetch(r.Context(), echo, timeout)
	out.ExitIP, out.ExitStatus, out.ExitErr = egress.ExtractClientIP(exit.Body), exit.Status, exit.Err
	out.ExitGeo = s.geo.Resolve(out.ExitIP)
	out.Changed = out.SourceIP != "" && out.ExitIP != "" && out.SourceIP != out.ExitIP
	return out, ""
}

// ---- Capture (recording reverse proxy) ----

// captureSession is one active reverse-proxy gateway for a program.
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

// delCapture removes the session from the map and returns it (nil when there is none).
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
		page.Note = fmt.Sprintf("%s endpoints promoted to scan %s — see Findings/Audit.", r.URL.Query().Get("n"), run)
	}
	s.render(w, r, "capture", "base", page)
}

// handleCaptureStart opens a reverse-proxy gateway to one in-scope target. The target
// MUST pass the program scope guard (fail closed); the gateway uses the scope-guarded
// egress transport so only in-scope hosts are forwarded.
func (s *Server) handleCaptureStart(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	program := strings.TrimSpace(r.FormValue("program"))
	target := strings.TrimSpace(r.FormValue("target"))
	rps := parseRPS(r.FormValue("rps"))

	page := s.capturePageFor(r, program)
	page.Target = target
	page.RPS = r.FormValue("rps")

	if program == "" || target == "" {
		page.Error = "The program and target are required."
		s.render(w, r, "capture", "base", page)
		return
	}
	if s.getCapture(program) != nil {
		page.Error = "A capture session for this program is already running — stop it first."
		s.render(w, r, "capture", "base", page)
		return
	}
	prog, err := s.store.GetProgram(r.Context(), program)
	if err != nil {
		page.Error = "The program has no saved scope yet — save its scope first on the Programs page."
		s.render(w, r, "capture", "base", page)
		return
	}
	guard, errs := scope.New(prog.InScope, prog.OutScope)
	if len(errs) > 0 {
		page.Error = "Invalid program scope: " + errs[0].Error()
		s.render(w, r, "capture", "base", page)
		return
	}

	// Audit a gateway egress denial (an out-of-scope host while browsing). It uses
	// context.Background because the gateway lives beyond this request.
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
		page.Error = "Could not start the gateway: " + err.Error()
		s.render(w, r, "capture", "base", page)
		return
	}
	addr, stop, err := gw.Listen("127.0.0.1:0")
	if err != nil {
		page.Error = "Could not open the listener: " + err.Error()
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
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	program := strings.TrimSpace(r.FormValue("program"))
	if sess := s.delCapture(program); sess != nil {
		if sess.stop != nil {
			_ = sess.stop()
		}
		s.auditAppend(r.Context(), audit.Event{Kind: "capture.stop", Program: program, Target: sess.Target, Allowed: true, Message: fmt.Sprintf("%d candidates", len(sess.gw.Records()))})
	}
	http.Redirect(w, r, "/capture?program="+url.QueryEscape(program), http.StatusSeeOther)
}

// handleCapturePromote turns the selected endpoints into a scan. The endpoints STILL
// go through the scope guard + rate limiter + egress (the same scan path) — no
// shortcut. No auto-submit.
func (s *Server) handleCapturePromote(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	program := strings.TrimSpace(r.FormValue("program"))
	targets := r.Form["url"]
	rps := parseRPS(r.FormValue("rps"))

	if program == "" || len(targets) == 0 {
		page := s.capturePageFor(r, program)
		page.Error = "Pick at least one endpoint to promote."
		s.render(w, r, "capture", "base", page)
		return
	}
	prog, err := s.store.GetProgram(r.Context(), program)
	if err != nil {
		page := s.capturePageFor(r, program)
		page.Error = "The program has no saved scope yet."
		s.render(w, r, "capture", "base", page)
		return
	}
	guard, errs := scope.New(prog.InScope, prog.OutScope)
	if len(errs) > 0 {
		page := s.capturePageFor(r, program)
		page.Error = "Invalid program scope: " + errs[0].Error()
		s.render(w, r, "capture", "base", page)
		return
	}
	runID := s.enqueueScan(program, guard, scanSpec{targets: targets, rps: rps})
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
		http.Error(w, "vault not configured", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	scope := normScope(r.FormValue("scope"))
	name := strings.TrimSpace(r.FormValue("name"))
	value := r.FormValue("value")
	if name == "" || value == "" {
		http.Error(w, "name & value required", http.StatusBadRequest)
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
		http.Error(w, "vault not configured", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
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

// programNames merges programs that have saved findings with programs
// whose scope is defined — both persistent across restarts.
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

// shellData wraps the full-page data (rendered through "base") with the
// chrome context: the current user & role for the topbar + admin menu. The content
// template still gets its own data through .Body, so no page struct needs to
// know about auth.
type shellData struct {
	User   string
	Role   string
	AuthOn bool
	Body   any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, page, name string, data any) {
	t := s.pages[page]
	if t == nil {
		http.Error(w, "template missing: "+page, http.StatusInternalServerError)
		return
	}
	// Only full pages (base) are wrapped; HTMX partials & standalone pages
	// (login, report_print) get their data directly.
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

// splitLines splits a textarea into a list of entries: trim, drop empty lines and
// comments (#).
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

// splitList splits a comma- or space-separated list (e.g. the template selection
// tags input) into non-empty tokens. Used for the tags field on the scan form.
func splitList(raw string) []string {
	return strings.Fields(strings.ReplaceAll(raw, ",", " "))
}

// scanSeverities is the set of severities valid for the nuclei template selection
// (-severity). The order = the checkbox display priority on the scan form.
var scanSeverities = []string{"critical", "high", "medium", "low", "info"}

// filterSeverities normalizes the selection severity input: lowercase, drop duplicates,
// and keep only known values (form checkboxes are always valid, but the query
// ?severity= from an external link can be anything — do not pass junk to the engine).
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

// parseRPS reads the rate from the form; an empty/invalid value => 10 req/s (the limiter
// still clamps it to its safe range).
func parseRPS(s string) float64 {
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || v <= 0 {
		return 10
	}
	return v
}

// stealthScanRPS clamps the scan rate to low-and-slow mode when stealth is on:
// it never exceeds stealthScanMax (a minimal footprint). It can only LOWER the rate,
// never raise it — the rate limiter stays required & is not turned off.
const stealthScanMax = 3.0

func stealthScanRPS(rps float64) float64 {
	if rps <= 0 || rps > stealthScanMax {
		return stealthScanMax
	}
	return rps
}

// safeFilename filters a program name into a safe file name.
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

// engineLabel is the sidebar footer text from the engines actually
// configured. A ProxyAware engine touches the network (through the scope-guard egress
// proxy), the same criterion as the orchestrator; none of them means mock.
func engineLabel(engines []engine.Engine) string {
	names := make([]string, 0, len(engines))
	network := false
	for _, e := range engines {
		names = append(names, e.Name())
		if _, ok := e.(engine.ProxyAware); ok {
			network = true
		}
	}
	if !network {
		return "engine: mock (no network)"
	}
	return "engine: real (" + strings.Join(names, ", ") + ")"
}

// reconLabel is the seed column caption on the scan form from the recon actually
// configured, by the same criterion: a ProxyAware recon touches the network.
// The tool chain comes from Name() so it does not go stale when the pipeline changes.
func reconLabel(rec recon.Engine) string {
	if rec == nil {
		return "recon not active on this instance: seeds ignored"
	}
	chain := rec.Name()
	if i, j := strings.IndexByte(chain, '('), strings.LastIndexByte(chain, ')'); i >= 0 && j > i {
		chain = chain[i+1 : j]
	}
	mode := "recon mock, no network"
	if _, ok := rec.(engine.ProxyAware); ok {
		mode = "recon real"
	}
	return mode + ": " + chain + ", the results are still filtered by the scope guard"
}

func parseTemplates(version, engineLbl, reconLbl string) (map[string]*template.Template, error) {
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
		"appVersion":  func() string { return version },
		"engineLabel": func() string { return engineLbl },
		"reconLabel":  func() string { return reconLbl },
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
		"priority":     {"templates/base.html", "templates/priority.html"},
		"report":       {"templates/base.html", "templates/report.html"},
		"report_print": {"templates/report_print.html"},
		"settings":     {"templates/base.html", "templates/settings.html"},
		"ai":           {"templates/base.html", "templates/ai.html", "templates/ai_card.html"},
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
