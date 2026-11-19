// Command bughound runs the bughound web application.
//
// It binds to localhost by default: this is an offensive tool, so do not expose
// it by accident. The default engine set is a mock (no network connections).
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"bughound/internal/audit"
	"bughound/internal/auth"
	"bughound/internal/engine"
	"bughound/internal/engine/dalfox"
	"bughound/internal/engine/ffuf"
	"bughound/internal/engine/nuclei"
	"bughound/internal/engine/retire"
	"bughound/internal/engine/zap"
	"bughound/internal/geoip"
	"bughound/internal/payload"
	"bughound/internal/recon"
	"bughound/internal/secret"
	"bughound/internal/store"
	"bughound/internal/web"
)

// version is injected at build time with -ldflags "-X main.version=...".
// It defaults to "dev" for local builds (go build/go run).
var version = "dev"

func main() {
	// CLI subcommand: `bughound templates update|list` manages the Payload Bank
	// (BH-SPEC-PAYLOAD) without starting the server.
	if len(os.Args) > 1 && os.Args[1] == "templates" {
		runTemplates(os.Args[2:])
		return
	}
	// `bughound eval` scores scan output against a ground-truth baseline (recall
	// over the DAST-detectable classes). It works offline and starts no server.
	if len(os.Args) > 1 && os.Args[1] == "eval" {
		runEval(os.Args[2:])
		return
	}

	addr := flag.String("addr", "127.0.0.1:8787", "bind address (localhost only by default)")
	showVersion := flag.Bool("version", false, "print the version and exit")
	dbPath := flag.String("db", "bughound.db", "path to the SQLite file (empty = in-memory, ephemeral)")
	engineMode := flag.String("engine", "mock", "engine set: mock (mock nuclei+ffuf, no network) | real (real nuclei + subfinder/httpx/katana through the egress proxy)")
	keyPath := flag.String("key", "bughound.key", "path to the master key file used to encrypt secrets (or set env BUGHOUND_MASTER_KEY)")
	adminUser := flag.String("admin-user", "", "initial admin username at bootstrap (or env BUGHOUND_ADMIN_USER; default \"admin\")")
	adminPass := flag.String("admin-password", "", "initial admin password (or env BUGHOUND_ADMIN_PASSWORD); empty = create the first admin interactively at /setup on first run")
	noAuth := flag.Bool("no-auth", false, "DISABLE login and RBAC (open access); only for a trusted localhost or tests")
	rotateKey := flag.Bool("rotate-key", false, "rotate the master key: re-encrypt every secret with a new key, then exit")
	sastRoot := flag.String("sast-root", "", "code root for SAST (empty = off); static analysis is confined to this dir")
	ffufWordlist := flag.String("ffuf-wordlist", "", "wordlist path for the real ffuf engine (empty = built-in wordlist)")
	zapMode := flag.String("zap-mode", "quick", "real ZAP engine mode: quick|baseline (spider + passive, NO attacks) | full (+ active scan)")
	grpcMode := flag.String("grpc", "mock", "gRPC enumeration engine: mock | real (grpcurl, needs the binary)")
	grpcPlaintext := flag.Bool("grpc-plaintext", false, "gRPC without TLS (-plaintext) for the real gRPC engine")
	nucleiTemplates := flag.String("nuclei-templates", "", "nuclei-templates dir for the Payload Bank (empty = auto: env NUCLEI_TEMPLATES_DIR / $HOME/nuclei-templates)")
	customTemplates := flag.String("custom-templates", "", "custom template dir for the Payload Bank (optional; or env BUGHOUND_CUSTOM_TEMPLATES)")
	flag.Parse()

	if *showVersion {
		fmt.Println("bughound", version)
		return
	}

	if *noAuth && !isLocalhost(*addr) {
		log.Printf("WARNING: -no-auth with a non-localhost bind (%s): the UI is OPEN without credentials. Do not expose it to a network.", *addr)
	}

	var st store.Store
	if *dbPath == "" {
		st = store.NewMem()
		log.Printf("store: in-memory (ephemeral)")
	} else {
		sq, err := store.OpenSQLite(*dbPath)
		if err != nil {
			log.Fatalf("bughound: cannot open database %q: %v", *dbPath, err)
		}
		defer sq.Close()
		st = sq
		log.Printf("store: sqlite (%s)", *dbPath)
	}

	// Master key + secret vault (encrypted at rest, isolated from findings).
	kr, src, err := secret.LoadKeyring(*keyPath)
	if err != nil {
		log.Fatalf("bughound: master key: %v", err)
	}
	switch src {
	case secret.SourceGenerated:
		log.Printf("secret: NEW master key created at %s (0600); keep it safe and do NOT commit it", *keyPath)
	case secret.SourceEphemeral:
		log.Printf("secret: ephemeral master key (not persisted); set env %s or -key so secrets survive a restart", secret.EnvKey)
	default:
		log.Printf("secret: master key from %s (key-id %s)", src, kr.ActiveID())
	}

	var vault secret.Vault
	if *dbPath == "" {
		vault = secret.NewMemVault(kr)
	} else {
		vpath := strings.TrimSuffix(*dbPath, ".db") + "-secrets.db"
		vv, verr := secret.OpenSQLiteVault(vpath, kr)
		if verr != nil {
			log.Fatalf("bughound: vault secret: %v", verr)
		}
		defer vv.Close()
		vault = vv
		log.Printf("secret: vault %s (separate from findings)", vpath)
	}

	if *rotateKey {
		if src == secret.SourceEnv {
			log.Fatalf("bughound: rotation needs a file-based key (not env %s)", secret.EnvKey)
		}
		if *keyPath == "" {
			log.Fatalf("bughound: rotation needs -key")
		}
		oldID := kr.ActiveID()
		newKey, nerr := secret.NewRandomKey()
		if nerr != nil {
			log.Fatalf("bughound: %v", nerr)
		}
		// 1) save the new key plus ALL old keys (a safe transition: if the process
		//    dies, every secret can still be decrypted and the rotation can be rerun).
		if werr := secret.WriteKeyFile(*keyPath, append([]secret.Key{newKey}, kr.AllKeys()...)...); werr != nil {
			log.Fatalf("bughound: write key: %v", werr)
		}
		kr.Rotate(newKey)
		n, rerr := vault.Rotate(context.Background())
		if rerr != nil {
			log.Fatalf("bughound: vault rotation failed (the old keys are still saved, safe to rerun): %v", rerr)
		}
		// 2) re-encryption is done: keep only the new key.
		if werr := secret.WriteKeyFile(*keyPath, newKey); werr != nil {
			log.Fatalf("bughound: finalize key: %v", werr)
		}
		log.Printf("rotation done: %d secrets re-encrypted; key-id %s -> %s (%s)", n, oldID, newKey.ID(), *keyPath)
		return
	}

	// The audit key (HMAC) is SEPARATE from the master key, so rotating the master
	// key does not break the existing audit chain.
	var auditKey []byte
	if *dbPath == "" {
		ak, _ := secret.NewRandomKey()
		auditKey = secret.NewKeyring(ak).Subkey("hmac")
	} else {
		akPath := strings.TrimSuffix(*keyPath, ".key") + ".audit.key"
		akr, _, aerr := secret.LoadKeyring(akPath)
		if aerr != nil {
			log.Fatalf("bughound: audit key: %v", aerr)
		}
		auditKey = akr.Subkey("hmac")
	}

	var auditLog audit.Log
	if *dbPath == "" {
		auditLog = audit.NewMemLog(auditKey)
	} else {
		apath := strings.TrimSuffix(*dbPath, ".db") + "-audit.db"
		anchorPath := strings.TrimSuffix(*dbPath, ".db") + "-audit.anchor"
		al, aerr := audit.OpenSQLiteLog(apath, auditKey, audit.WithAnchorer(audit.NewFileAnchorer(anchorPath, auditKey)))
		if aerr != nil {
			log.Fatalf("bughound: audit log: %v", aerr)
		}
		defer al.Close()
		auditLog = al
		log.Printf("audit: trail %s + anchor %s (append-only, HMAC chain + external attestation)", apath, anchorPath)
	}

	// Record secret access (Reveal) in the audit trail (without the value).
	vault.SetRevealHook(func(scope, name string) {
		_, _ = auditLog.Append(context.Background(), audit.Event{Kind: "secret.reveal", Program: scope, Message: "secret: " + name})
	})

	var engines []engine.Engine
	var rec recon.Engine
	var engineFactory func(rps float64, sel web.Selection) ([]engine.Engine, recon.Engine)
	names, useMock := parseEngineMode(*engineMode)
	// Custom detection template dir for the Payload Bank (flag → env
	// BUGHOUND_CUSTOM_TEMPLATES). The "nuclei-custom" runner (roster) and
	// DefaultSources (catalog) share it so both point at the same directory.
	// Empty = no custom runner.
	customDir := strings.TrimSpace(*customTemplates)
	if customDir == "" {
		customDir = strings.TrimSpace(os.Getenv("BUGHOUND_CUSTOM_TEMPLATES"))
	}
	if useMock {
		engines = []engine.Engine{nuclei.Mock{}, ffuf.Mock{}, zap.Mock{}}
		rec = recon.MockPipeline{}
		log.Printf("engine: mock (nuclei + ffuf + zap), no network connections")
	} else {
		// Factory: build NEW engines + recon per scan, with the request rate clamped
		// to the scan rps (per-engine throttle, in the execution path). The web layer
		// calls it for every run so each run has its own engines and egress proxy.
		engineFactory = func(rps float64, sel web.Selection) ([]engine.Engine, recon.Engine) {
			rate := engineRate(rps)
			var es []engine.Engine
			for _, n := range names {
				switch n {
				case "nuclei":
					// Template selection (tags/severity) applies to nuclei only: -tags/-severity
					// pick a subset of the installed templates.
					es = append(es, &nuclei.Runner{RateLimit: rate, Tags: sel.Tags, Severity: sel.Severity})
				case "ffuf":
					es = append(es, &ffuf.Runner{Wordlist: *ffufWordlist, RateLimit: rate, APIRoutes: sel.APIRoutes})
				case "zap":
					es = append(es, &zap.Runner{Mode: *zapMode, RateLimit: rate})
				case "retire":
					// retire.js: SCA for client-side JS libraries. Its egress (fetch the HTML,
					// download same-origin JS) goes through the same scope guard proxy; without
					// a proxy it fetches nothing (fail-safe in the Runner).
					es = append(es, &retire.Runner{RateLimit: rate})
				case "nuclei-dast":
					// ACTIVE DAST (nuclei fuzzing): katana crawls, then parameters are fuzzed
					// with payloads (SQLi/XSS/etc.). Crawl and fuzz egress goes through the
					// same scope guard proxy; volume is limited by the rate and the 'low'
					// aggression level; without a proxy there are no connections (fail-safe).
					// Findings are candidates (draft -> verify). Safety profile:
					// non-destructive is always on; stealth comes from the scan form.
					es = append(es, &nuclei.DASTRunner{RateLimit: rate, Safety: nuclei.Safety{Stealth: sel.Stealth}})
				case "dalfox":
					// ACTIVE DAST for XSS only: send XSS payloads to the target's parameters
					// and normalize each PoC into a finding. Egress goes through the same scope
					// guard proxy; volume is limited by workers + delay; without a proxy there
					// are no connections (fail-safe). Non-destructive; findings are candidates
					// (draft → verify).
					es = append(es, &dalfox.Runner{RateLimit: rate, Stealth: sel.Stealth})
				case "nuclei-custom":
					// A nuclei runner ONLY for the Payload Bank's custom detection templates
					// (BH-SPEC-PAYLOAD): `-t <customDir>` runs just your own read-only
					// templates, SEPARATE from the official "nuclei" runner that runs the full
					// built-in set. buildArgs still forces non-destructive mode. Without
					// customDir (empty flag/env) the runner is skipped silently. It
					// deliberately ignores sel.Tags/Severity: the custom dir is small and
					// curated, so every custom template should run and the main scan
					// selection (e.g. the user picking the "sqli" tag for nuclei) must not
					// trim it.
					if customDir != "" {
						es = append(es, &nuclei.Runner{RateLimit: rate, TemplatesDir: customDir})
					}
				}
			}
			if sel.Stealth {
				log.Printf("scan: STEALTH low-and-slow profile is on (scan and DAST rate clamped, browser UA) + non-destructive")
			}
			return es, recon.NewRealPipelineRate(rate)
		}
		engines, rec = engineFactory(0, web.Selection{}) // representative instance (default rate, all templates) for validation and fallback
		if len(engines) == 0 {
			log.Fatalf("bughound: -engine %q names no known engine (choose: mock | real | a list of: nuclei,ffuf,zap,retire,nuclei-dast,dalfox,nuclei-custom)", *engineMode)
		}
		// Build the recon chain from the pipeline's Name() so the log does not go stale when its stages change.
		log.Printf("engine: REAL (%s) + %s; HTTP egress goes through the scope guard proxy; naabu (direct TCP) only reaches in-scope hosts · per-engine throttle is on (rate from the scan rps, default %d/s)", strings.Join(names, ", "), rec.Name(), engineRate(0))
		log.Printf("WARNING: only scan authorized targets (in scope / lab / explicit permission)")
		for _, n := range names {
			if n == "ffuf" && strings.TrimSpace(*ffufWordlist) == "" {
				log.Printf("ffuf: -ffuf-wordlist is empty, using the built-in wordlist")
			}
			if n == "nuclei-custom" {
				if customDir == "" {
					log.Printf("nuclei-custom: ON in the roster but the custom template dir is empty (set -custom-templates / BUGHOUND_CUSTOM_TEMPLATES); the runner is skipped and nothing runs")
				} else {
					log.Printf("nuclei-custom: running ONLY the read-only custom templates from %q (separate from the full nuclei set); non-destructive mode is forced", customDir)
				}
			}
			if n == "zap" {
				m := strings.ToLower(strings.TrimSpace(*zapMode))
				if m == "full" {
					log.Printf("zap: mode %q: spider + ACTIVE scan (sends attack payloads)", m)
				} else {
					log.Printf("zap: mode %q: spider + passive scan (no attacks; use -zap-mode full for active)", m)
				}
			}
		}
	}

	// SAST is on when -sast-root or env BUGHOUND_SAST_ROOT is set. The image
	// declares BUGHOUND_SAST_ROOT=/data/sast, so SAST works right after a deploy
	// with no extra flag; resolveSASTRoot makes sure the dir exists (an empty
	// volume bound over /data can hide the image's built-in dir).
	sastRootEff, sastLog := resolveSASTRoot(*sastRoot, os.Getenv("BUGHOUND_SAST_ROOT"))
	if sastLog != "" {
		log.Print(sastLog)
	}

	grpcReal := strings.EqualFold(*grpcMode, "real") || strings.EqualFold(*grpcMode, "grpcurl")
	if grpcReal {
		log.Printf("grpc: REAL enumeration via grpcurl (plaintext=%t)", *grpcPlaintext)
	}

	// RBAC: the store provides user accounts. Login is REQUIRED by default;
	// -no-auth opens it up (only for a trusted localhost or tests).
	webUsers, ok := st.(store.UserStore)
	if !ok {
		log.Fatalf("bughound: the store does not support user management")
	}
	if *noAuth {
		log.Printf("auth: DISABLED (-no-auth): open access with no login and no RBAC")
	} else {
		au := firstNonEmpty(*adminUser, os.Getenv("BUGHOUND_ADMIN_USER"), "admin")
		ap := firstNonEmpty(*adminPass, os.Getenv("BUGHOUND_ADMIN_PASSWORD"))
		created, berr := bootstrapAdmin(context.Background(), webUsers, au, ap)
		if berr != nil {
			log.Fatalf("bughound: bootstrap admin: %v", berr)
		}
		switch {
		case created:
			log.Printf("auth: admin %q created from -admin-password/env", au)
		default:
			if n, _ := webUsers.CountUsers(context.Background()); n == 0 {
				log.Printf("auth: login REQUIRED; no account yet, create the first admin at /setup on first visit")
			} else {
				log.Printf("auth: login REQUIRED (an account already exists; manage accounts on the Users page)")
			}
		}
	}

	// Payload Bank (BH-SPEC-PAYLOAD): the template sources scanned on a catalog
	// refresh. It only reads local files (no network), so it is safe in any mode.
	payloadSources := payload.DefaultSources(*nucleiTemplates, customDir)
	if len(payloadSources) > 0 {
		var ids []string
		for _, ps := range payloadSources {
			ids = append(ids, fmt.Sprintf("%s(%s,%s)", ps.ID, ps.Engine, ps.Trust))
		}
		log.Printf("payload bank: %d sources [%s]; refresh via /payloads or `bughound templates update`", len(payloadSources), strings.Join(ids, ", "))
	}

	// GeoIP (optional): labels the egress IP on the Proxy page with a country and
	// ASN from a LOCAL GeoLite2 database. It is fully OFFLINE and never calls a
	// third-party geolocation service (this keeps egress isolation, Principle #2).
	// It is off when the env is not set; if the DB cannot be opened the feature
	// degrades cleanly (the Proxy page still shows the IP without a country). The
	// server closes the DB on shutdown.
	var geoResolver geoip.Resolver = geoip.Nop{}
	if gdb, gerr := geoip.Open(os.Getenv("BUGHOUND_GEOIP_COUNTRY_DB"), os.Getenv("BUGHOUND_GEOIP_ASN_DB")); gerr != nil {
		log.Printf("geoip: DB not loaded (%v); the Proxy page still shows the IP without a country", gerr)
	} else if gdb != nil {
		geoResolver = gdb
		log.Printf("geoip: on; egress IP country/ASN labels come from the local GeoLite2 DB (offline)")
	}

	srv, err := web.NewServer(web.Config{Store: st, Engines: engines, Recon: rec, NewEngines: engineFactory, Vault: vault, Audit: auditLog, Users: webUsers, AuthDisabled: *noAuth, Version: version, SASTRoot: sastRootEff, GRPCReal: grpcReal, GRPCPlaintext: *grpcPlaintext, PayloadSources: payloadSources, GeoIP: geoResolver})
	if err != nil {
		log.Fatalf("bughound: initialization failed: %v", err)
	}
	defer srv.Close()

	log.Printf("bughound listening on http://%s", *addr)
	log.Printf("scope guard on · rate limiter required · no auto-submit")

	httpSrv := &http.Server{Addr: *addr, Handler: srv, ReadHeaderTimeout: 10 * time.Second}
	if err := httpSrv.ListenAndServe(); err != nil {
		log.Fatalf("bughound: server stopped: %v", err)
	}
}

// bootstrapAdmin creates the first admin account ONLY when a password is
// configured (-admin-password / BUGHOUND_ADMIN_PASSWORD), for headless or
// automated deploys. With no password and an empty store it creates nothing:
// the first admin is then created interactively through the /setup page on the
// first visit. It reports whether an account was created.
func bootstrapAdmin(ctx context.Context, users store.UserStore, user, pass string) (created bool, err error) {
	n, err := users.CountUsers(ctx)
	if err != nil {
		return false, err
	}
	if n > 0 || pass == "" {
		return false, nil // an account already exists, or defer to first-run /setup
	}
	if user == "" {
		user = "admin"
	}
	hash, err := auth.HashPassword(pass)
	if err != nil {
		return false, err
	}
	if err := users.CreateUser(ctx, store.User{Username: user, Role: string(auth.RoleAdmin), PassHash: hash}); err != nil {
		return false, err
	}
	return true, nil
}

// firstNonEmpty returns the first non-empty (trimmed) argument.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

// resolveSASTRoot picks the effective SAST root: the -sast-root flag, then env
// BUGHOUND_SAST_ROOT. When one is set, it makes sure the directory exists
// (creating it if needed) so sast.Resolve's path scoping does not fail on a
// root that is not there yet. This matters because the image declares
// BUGHOUND_SAST_ROOT=/data/sast while an empty volume bound over /data hides
// the image's built-in dir. It returns the effective root ("" = SAST off) and
// one log line for the caller to print. Failing to prepare the dir is NOT
// fatal: SAST is disabled so the orchestrator keeps running (a SAST
// misconfiguration does not take the other features down).
func resolveSASTRoot(flagVal, envVal string) (root, logMsg string) {
	root = firstNonEmpty(flagVal, envVal)
	if root == "" {
		return "", ""
	}
	if err := os.MkdirAll(root, 0o750); err != nil {
		return "", fmt.Sprintf("sast: root %q cannot be prepared (%v); SAST is disabled", root, err)
	}
	return root, fmt.Sprintf("sast: enabled, confined to root %q (local static analysis, no network)", root)
}

// parseEngineMode interprets the -engine flag. "" / "mock" -> mock engines
// (mock is exclusive). Anything else is a comma-separated list: "real" is an
// alias for nuclei; known names (nuclei, ffuf, zap, retire, nuclei-dast,
// dalfox) build real Runners. Unknown names are ignored (the caller rejects
// the flag when nothing is recognized). Deduplicated, in input order.
func parseEngineMode(mode string) (names []string, mock bool) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		return nil, true
	}
	seen := map[string]bool{}
	add := func(n string) {
		if !seen[n] {
			names = append(names, n)
			seen[n] = true
		}
	}
	for _, tok := range strings.Split(mode, ",") {
		switch strings.TrimSpace(tok) {
		case "":
			// skip
		case "mock":
			return nil, true // mock overrides the rest
		case "real", "nuclei":
			add("nuclei")
		case "ffuf":
			add("ffuf")
		case "zap":
			add("zap")
		case "retire":
			add("retire")
		case "nuclei-dast":
			add("nuclei-dast")
		case "dalfox":
			add("dalfox")
		case "nuclei-custom":
			// Read-only nuclei runner for custom detection templates only (Payload Bank).
			// It is active only when a custom dir is configured (flag/env); see the roster.
			add("nuclei-custom")
		}
	}
	return names, false
}

// engineRate derives the per-engine request rate (req/s) from the scan rps. A
// zero or negative value → the safe default; the result is clamped to
// maxEngineRate so it is never "practically unlimited". This matches the
// clamping in package ratelimit, so the throttle is always in the execution
// path and input cannot turn it off.
func engineRate(rps float64) int {
	const defaultEngineRate, maxEngineRate = 20, 50
	r := rps
	if r <= 0 {
		r = defaultEngineRate
	}
	if r > maxEngineRate {
		r = maxEngineRate
	}
	return int(r)
}

// splitSubcommand strips the subcommand verb (the first non-flag argument) from
// args so the flags after it can still be parsed. It returns def when the first
// argument is a flag or args is empty.
func splitSubcommand(args []string, def string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return def, args
}

// runTemplates runs the `bughound templates <update|list>` subcommand that
// manages the Payload Bank (BH-SPEC-PAYLOAD): it scans the sources and
// refreshes the catalog stored in SQLite. It only reads local files (no network).
func runTemplates(args []string) {
	// Take the subcommand verb first: the flag package stops parsing at the first
	// non-flag argument, so the verb has to come off before Parse for the flags
	// AFTER it (e.g. `templates update -db ...`) to be read.
	sub, args := splitSubcommand(args, "update")

	fs := flag.NewFlagSet("templates", flag.ExitOnError)
	db := fs.String("db", "bughound.db", "path to the SQLite file where the catalog is stored")
	nucleiDir := fs.String("nuclei-templates", "", "nuclei-templates dir (empty = auto: env NUCLEI_TEMPLATES_DIR / $HOME/nuclei-templates)")
	customDir := fs.String("custom-templates", "", "custom template dir (optional; or env BUGHOUND_CUSTOM_TEMPLATES)")
	_ = fs.Parse(args)
	if *db == "" {
		log.Fatalf("templates: -db (SQLite) is required to store the catalog")
	}
	st, err := store.OpenSQLite(*db)
	if err != nil {
		log.Fatalf("templates: open database %q: %v", *db, err)
	}
	defer st.Close()
	ctx := context.Background()

	switch sub {
	case "update", "refresh":
		sources := payload.DefaultSources(*nucleiDir, *customDir)
		if len(sources) == 0 {
			log.Fatalf("templates: no sources (set -nuclei-templates / -custom-templates or the env)")
		}
		before, _ := st.CatalogStats(ctx)
		cat := payload.Build(ctx, sources)
		if err := st.ReplaceCatalog(ctx, cat); err != nil {
			log.Fatalf("templates: save catalog: %v", err)
		}
		fmt.Printf("catalog updated: %d templates from %d sources (previously %d)\n", len(cat.Entries), len(cat.Sources), before.Total)
		for _, s := range cat.Sources {
			status := "available"
			if !s.Available {
				status = "UNAVAILABLE"
			}
			fmt.Printf("  - %-16s %-7s trust=%-9s %6d templates (%d active) [%s] %s\n",
				s.ID, s.Engine, s.Trust, s.Count, s.Enabled, status, s.Path)
			if s.Note != "" {
				fmt.Printf("      note: %s\n", s.Note)
			}
		}
	case "list":
		entries, total, err := st.ListCatalog(ctx, store.CatalogQuery{Limit: 50})
		if err != nil {
			log.Fatalf("templates: list: %v", err)
		}
		fmt.Printf("%d templates in the catalog (showing %d):\n", total, len(entries))
		for _, e := range entries {
			en := "off"
			if e.Enabled {
				en = "on "
			}
			fmt.Printf("  [%s] %-44s %-7s %-8s %s\n", en, e.TemplateID, e.Engine, e.SeverityDefault, e.Trust)
		}
	default:
		log.Fatalf("templates: unknown subcommand %q (use: update | list)", sub)
	}
}

func isLocalhost(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	switch strings.ToLower(host) {
	case "127.0.0.1", "localhost", "::1", "":
		return true
	}
	return strings.HasPrefix(host, "127.")
}
