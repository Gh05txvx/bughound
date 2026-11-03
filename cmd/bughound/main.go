// Command bughound menjalankan aplikasi web bughound (M0).
//
// Default bind ke localhost saja: ini tool offensive, jangan diekspos tanpa
// sadar. Engine di M0 adalah mock (tanpa koneksi jaringan).
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"bughound/internal/audit"
	"bughound/internal/auth"
	"bughound/internal/engine"
	"bughound/internal/engine/ffuf"
	"bughound/internal/engine/nuclei"
	"bughound/internal/engine/retire"
	"bughound/internal/engine/zap"
	"bughound/internal/payload"
	"bughound/internal/recon"
	"bughound/internal/secret"
	"bughound/internal/store"
	"bughound/internal/web"
)

// version di-inject saat build lewat -ldflags "-X main.version=...".
// Default "dev" untuk build lokal (go build/go run).
var version = "dev"

func main() {
	// Subperintah CLI: `bughound templates update|list` mengelola Bank Payload
	// (BH-SPEC-PAYLOAD) tanpa menjalankan server.
	if len(os.Args) > 1 && os.Args[1] == "templates" {
		runTemplates(os.Args[2:])
		return
	}

	addr := flag.String("addr", "127.0.0.1:8787", "alamat bind (default localhost saja)")
	showVersion := flag.Bool("version", false, "cetak versi lalu keluar")
	dbPath := flag.String("db", "bughound.db", "path file SQLite (kosongkan untuk in-memory/ephemeral)")
	engineMode := flag.String("engine", "mock", "set engine: mock (nuclei+ffuf mock, tanpa jaringan) | real (nuclei + subfinder/httpx/katana nyata lewat proxy egress)")
	keyPath := flag.String("key", "bughound.key", "path file kunci master untuk enkripsi secret (atau set env BUGHOUND_MASTER_KEY)")
	adminUser := flag.String("admin-user", "", "username admin awal saat bootstrap (atau env BUGHOUND_ADMIN_USER; default \"admin\")")
	adminPass := flag.String("admin-password", "", "kata sandi admin awal (atau env BUGHOUND_ADMIN_PASSWORD); kosong = dibuat acak & dicetak ke konsol sekali")
	noAuth := flag.Bool("no-auth", false, "NONAKTIFKAN login & RBAC (akses terbuka) — hanya untuk localhost tepercaya / test")
	rotateKey := flag.Bool("rotate-key", false, "rotasi kunci master: re-enkripsi semua secret ke kunci baru lalu keluar")
	sastRoot := flag.String("sast-root", "", "root kode untuk SAST (kosong = nonaktif); analisis statis dikurung ke dir ini")
	ffufWordlist := flag.String("ffuf-wordlist", "", "path wordlist untuk engine ffuf nyata (kosong = wordlist bawaan)")
	zapMode := flag.String("zap-mode", "quick", "mode engine ZAP nyata: quick | baseline | full (full = spider + active scan)")
	grpcMode := flag.String("grpc", "mock", "engine enumerasi gRPC: mock | real (grpcurl, butuh binary)")
	grpcPlaintext := flag.Bool("grpc-plaintext", false, "gRPC tanpa TLS (-plaintext) untuk engine gRPC nyata")
	nucleiTemplates := flag.String("nuclei-templates", "", "dir nuclei-templates untuk Bank Payload (kosong = auto: env NUCLEI_TEMPLATES_DIR / $HOME/nuclei-templates)")
	customTemplates := flag.String("custom-templates", "", "dir template custom untuk Bank Payload (opsional; atau env BUGHOUND_CUSTOM_TEMPLATES)")
	flag.Parse()

	if *showVersion {
		fmt.Println("bughound", version)
		return
	}

	if *noAuth && !isLocalhost(*addr) {
		log.Printf("PERINGATAN: -no-auth + bind non-localhost (%s) — UI TERBUKA tanpa kredensial. Jangan ekspos ke jaringan.", *addr)
	}

	var st store.Store
	if *dbPath == "" {
		st = store.NewMem()
		log.Printf("store: in-memory (ephemeral)")
	} else {
		sq, err := store.OpenSQLite(*dbPath)
		if err != nil {
			log.Fatalf("bughound: gagal buka database %q: %v", *dbPath, err)
		}
		defer sq.Close()
		st = sq
		log.Printf("store: sqlite (%s)", *dbPath)
	}

	// Kunci master + vault secret (enkripsi saat disimpan, terisolasi dari temuan).
	kr, src, err := secret.LoadKeyring(*keyPath)
	if err != nil {
		log.Fatalf("bughound: kunci master: %v", err)
	}
	switch src {
	case secret.SourceGenerated:
		log.Printf("secret: kunci master BARU dibuat di %s (0600) — amankan & JANGAN commit", *keyPath)
	case secret.SourceEphemeral:
		log.Printf("secret: kunci master ephemeral (tak dipersist); set env %s atau -key agar secret bertahan", secret.EnvKey)
	default:
		log.Printf("secret: kunci master dari %s (key-id %s)", src, kr.ActiveID())
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
		log.Printf("secret: vault %s (terpisah dari temuan)", vpath)
	}

	if *rotateKey {
		if src == secret.SourceEnv {
			log.Fatalf("bughound: rotasi butuh kunci berbasis file (bukan env %s)", secret.EnvKey)
		}
		if *keyPath == "" {
			log.Fatalf("bughound: rotasi butuh -key")
		}
		oldID := kr.ActiveID()
		newKey, nerr := secret.NewRandomKey()
		if nerr != nil {
			log.Fatalf("bughound: %v", nerr)
		}
		// 1) simpan kunci baru + SEMUA kunci lama (transisi aman: bila proses
		//    mati, semua secret tetap bisa didekripsi dan rotasi bisa diulang).
		if werr := secret.WriteKeyFile(*keyPath, append([]secret.Key{newKey}, kr.AllKeys()...)...); werr != nil {
			log.Fatalf("bughound: tulis kunci: %v", werr)
		}
		kr.Rotate(newKey)
		n, rerr := vault.Rotate(context.Background())
		if rerr != nil {
			log.Fatalf("bughound: rotasi vault gagal (kunci lama masih tersimpan, aman diulang): %v", rerr)
		}
		// 2) re-enkripsi selesai: simpan hanya kunci baru.
		if werr := secret.WriteKeyFile(*keyPath, newKey); werr != nil {
			log.Fatalf("bughound: finalisasi kunci: %v", werr)
		}
		log.Printf("rotasi selesai: %d secret di-re-enkripsi; key-id %s -> %s (%s)", n, oldID, newKey.ID(), *keyPath)
		return
	}

	// Kunci audit (HMAC) TERPISAH dari master, agar rotasi master tak memutus
	// rantai audit yang sudah ada.
	var auditKey []byte
	if *dbPath == "" {
		ak, _ := secret.NewRandomKey()
		auditKey = secret.NewKeyring(ak).Subkey("hmac")
	} else {
		akPath := strings.TrimSuffix(*keyPath, ".key") + ".audit.key"
		akr, _, aerr := secret.LoadKeyring(akPath)
		if aerr != nil {
			log.Fatalf("bughound: kunci audit: %v", aerr)
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
		log.Printf("audit: trail %s + anchor %s (append-only, rantai HMAC + attestation eksternal)", apath, anchorPath)
	}

	// Catat akses secret (Reveal) ke audit trail (tanpa nilai).
	vault.SetRevealHook(func(scope, name string) {
		_, _ = auditLog.Append(context.Background(), audit.Event{Kind: "secret.reveal", Program: scope, Message: "secret: " + name})
	})

	var engines []engine.Engine
	var rec recon.Engine
	var engineFactory func(rps float64, sel web.Selection) ([]engine.Engine, recon.Engine)
	names, useMock := parseEngineMode(*engineMode)
	if useMock {
		engines = []engine.Engine{nuclei.Mock{}, ffuf.Mock{}, zap.Mock{}}
		rec = recon.MockPipeline{}
		log.Printf("engine: mock (nuclei + ffuf + zap) — tanpa koneksi jaringan")
	} else {
		// Factory: bangun engine + recon BARU per scan dengan laju request dijepit
		// ke rps scan (throttle per-engine, di jalur eksekusi). Web memanggilnya
		// untuk tiap run agar tiap run punya engine & proxy egress sendiri.
		engineFactory = func(rps float64, sel web.Selection) ([]engine.Engine, recon.Engine) {
			rate := engineRate(rps)
			var es []engine.Engine
			for _, n := range names {
				switch n {
				case "nuclei":
					// Seleksi template (tags/severity) hanya berlaku untuk nuclei —
					// -tags/-severity memilih subset dari templates terpasang.
					es = append(es, &nuclei.Runner{RateLimit: rate, Tags: sel.Tags, Severity: sel.Severity})
				case "ffuf":
					es = append(es, &ffuf.Runner{Wordlist: *ffufWordlist, RateLimit: rate})
				case "zap":
					es = append(es, &zap.Runner{Mode: *zapMode, RateLimit: rate})
				case "retire":
					// retire.js: SCA library JS klien. Egress (fetch HTML + unduh JS
					// same-origin) lewat proxy scope guard yang sama; tanpa proxy = tak
					// fetch (fail-safe di Runner).
					es = append(es, &retire.Runner{RateLimit: rate})
				case "nuclei-dast":
					// DAST AKTIF (nuclei fuzzing): crawl katana → fuzz parameter dgn
					// payload (SQLi/XSS/dst.). Egress crawl+fuzz lewat proxy scope guard
					// yang sama; volume dibatasi rate + agresi 'low'; tanpa proxy = tak
					// ada koneksi (fail-safe). Temuan = kandidat (draft->verify).
					// Profil keamanan: non-destruktif selalu aktif; stealth dari form scan.
					es = append(es, &nuclei.DASTRunner{RateLimit: rate, Safety: nuclei.Safety{Stealth: sel.Stealth}})
				}
			}
			if sel.Stealth {
				log.Printf("scan: profil STEALTH low-and-slow aktif (laju scan & DAST dijepit, UA browser) + non-destruktif")
			}
			return es, recon.NewRealPipelineRate(rate)
		}
		engines, rec = engineFactory(0, web.Selection{}) // instance representatif (laju default, semua template) utk validasi & fallback
		if len(engines) == 0 {
			log.Fatalf("bughound: -engine %q tak mengenali engine apa pun (pilih: mock | real | daftar: nuclei,ffuf,zap,retire,nuclei-dast)", *engineMode)
		}
		log.Printf("engine: NYATA (%s + recon subfinder/httpx/katana) — egress lewat proxy scope guard · throttle per-engine aktif (laju dari rps scan, default %d/dtk)", strings.Join(names, ", "), engineRate(0))
		log.Printf("PERINGATAN: hanya scan target yang sah (in-scope / lab / izin eksplisit)")
		for _, n := range names {
			if n == "ffuf" && strings.TrimSpace(*ffufWordlist) == "" {
				log.Printf("ffuf: -ffuf-wordlist kosong, memakai wordlist bawaan")
			}
			if n == "zap" {
				log.Printf("zap: mode %q", strings.ToLower(strings.TrimSpace(*zapMode)))
			}
		}
	}

	if *sastRoot != "" {
		log.Printf("sast: aktif, dikurung ke root %q (analisis statis lokal, tanpa jaringan)", *sastRoot)
	}

	grpcReal := strings.EqualFold(*grpcMode, "real") || strings.EqualFold(*grpcMode, "grpcurl")
	if grpcReal {
		log.Printf("grpc: enumerasi NYATA via grpcurl (plaintext=%t)", *grpcPlaintext)
	}

	// RBAC: store menyediakan akun pengguna. Login WAJIB secara default; -no-auth
	// membukanya (hanya untuk localhost tepercaya / test).
	webUsers, ok := st.(store.UserStore)
	if !ok {
		log.Fatalf("bughound: store tidak mendukung manajemen pengguna")
	}
	if *noAuth {
		log.Printf("auth: DINONAKTIFKAN (-no-auth) — akses terbuka tanpa login & tanpa RBAC")
	} else {
		au := firstNonEmpty(*adminUser, os.Getenv("BUGHOUND_ADMIN_USER"), "admin")
		ap := firstNonEmpty(*adminPass, os.Getenv("BUGHOUND_ADMIN_PASSWORD"))
		created, generated, pw, berr := bootstrapAdmin(context.Background(), webUsers, au, ap)
		if berr != nil {
			log.Fatalf("bughound: bootstrap admin: %v", berr)
		}
		switch {
		case created && generated:
			log.Printf("auth: admin %q dibuat — kata sandi: %s", au, pw)
			log.Printf("auth: SIMPAN kata sandi di atas; tak akan ditampilkan lagi. Ganti via halaman Users.")
		case created:
			log.Printf("auth: admin %q dibuat dari -admin-password/env", au)
		default:
			log.Printf("auth: login WAJIB (akun sudah ada; kelola via halaman Users)")
		}
	}

	// Bank Payload (BH-SPEC-PAYLOAD): sumber template yang di-scan saat refresh
	// katalog. Hanya membaca berkas lokal (tanpa jaringan); aman di mode apa pun.
	payloadSources := payload.DefaultSources(*nucleiTemplates, *customTemplates)
	if len(payloadSources) > 0 {
		var ids []string
		for _, ps := range payloadSources {
			ids = append(ids, fmt.Sprintf("%s(%s,%s)", ps.ID, ps.Engine, ps.Trust))
		}
		log.Printf("bank payload: %d sumber [%s] — refresh via /payloads atau `bughound templates update`", len(payloadSources), strings.Join(ids, ", "))
	}

	srv, err := web.NewServer(web.Config{Store: st, Engines: engines, Recon: rec, NewEngines: engineFactory, Vault: vault, Audit: auditLog, Users: webUsers, AuthDisabled: *noAuth, Version: version, SASTRoot: *sastRoot, GRPCReal: grpcReal, GRPCPlaintext: *grpcPlaintext, PayloadSources: payloadSources})
	if err != nil {
		log.Fatalf("bughound: gagal inisialisasi: %v", err)
	}
	defer srv.Close()

	log.Printf("bughound di http://%s", *addr)
	log.Printf("scope guard aktif · rate limiter wajib · tanpa auto-submit")

	httpSrv := &http.Server{Addr: *addr, Handler: srv}
	if err := httpSrv.ListenAndServe(); err != nil {
		log.Fatalf("bughound: server berhenti: %v", err)
	}
}

// bootstrapAdmin membuat akun admin pertama bila store belum punya pengguna.
// Mengembalikan apakah user dibuat, apakah kata sandinya dibuat acak, dan kata
// sandi tersebut (hanya terisi bila acak — agar bisa dicetak sekali ke konsol).
func bootstrapAdmin(ctx context.Context, users store.UserStore, user, pass string) (created, generated bool, pw string, err error) {
	n, err := users.CountUsers(ctx)
	if err != nil {
		return false, false, "", err
	}
	if n > 0 {
		return false, false, "", nil // sudah ada akun; jangan bootstrap ulang
	}
	if user == "" {
		user = "admin"
	}
	pw = pass
	if pw == "" {
		if pw, err = randomPassword(); err != nil {
			return false, false, "", err
		}
		generated = true
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		return false, false, "", err
	}
	if err := users.CreateUser(ctx, store.User{Username: user, Role: string(auth.RoleAdmin), PassHash: hash}); err != nil {
		return false, false, "", err
	}
	return true, generated, pw, nil
}

// randomPassword menghasilkan kata sandi acak url-safe (~16 karakter).
func randomPassword() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// firstNonEmpty mengembalikan argumen non-kosong (ter-trim) pertama.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

// parseEngineMode menafsirkan flag -engine. "" / "mock" -> engine mock (mock
// eksklusif). Selain itu daftar dipisah koma: "real" = alias nuclei; nama yang
// dikenal (nuclei, ffuf, zap, retire, nuclei-dast) membangun Runner nyata. Nama
// tak dikenal diabaikan (pemanggil menolak bila tak ada yang dikenali).
// Ter-dedup, urut input.
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
			// lewati
		case "mock":
			return nil, true // mock mengalahkan sisanya
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
		}
	}
	return names, false
}

// engineRate menurunkan laju request per-engine (req/dtk) dari rps scan. Nilai
// 0/negatif → default aman; dijepit ≤ maxEngineRate agar tak pernah "praktis
// tanpa batas" — senada dengan penjepitan di paket ratelimit, sehingga throttle
// selalu ada di jalur eksekusi dan tak bisa dimatikan lewat input.
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

// splitSubcommand melepas verb subperintah (argumen non-flag pertama) dari args
// sehingga flag setelahnya tetap bisa diurai. Mengembalikan def bila argumen
// pertama adalah flag atau args kosong.
func splitSubcommand(args []string, def string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return def, args
}

// runTemplates menjalankan subperintah `bughound templates <update|list>` untuk
// mengelola Bank Payload (BH-SPEC-PAYLOAD): men-scan sumber lalu me-refresh
// katalog yang tersimpan di SQLite. Hanya membaca berkas lokal (tanpa jaringan).
func runTemplates(args []string) {
	// Ambil verb subperintah lebih dulu: flag package berhenti mengurai begitu
	// menemui argumen non-flag, jadi verb harus dilepas sebelum Parse agar flag
	// SETELAH verb (mis. `templates update -db ...`) tetap terbaca.
	sub, args := splitSubcommand(args, "update")

	fs := flag.NewFlagSet("templates", flag.ExitOnError)
	db := fs.String("db", "bughound.db", "path file SQLite tempat katalog disimpan")
	nucleiDir := fs.String("nuclei-templates", "", "dir nuclei-templates (kosong = auto: env NUCLEI_TEMPLATES_DIR / $HOME/nuclei-templates)")
	customDir := fs.String("custom-templates", "", "dir template custom (opsional; atau env BUGHOUND_CUSTOM_TEMPLATES)")
	_ = fs.Parse(args)
	if *db == "" {
		log.Fatalf("templates: butuh -db (SQLite) untuk menyimpan katalog")
	}
	st, err := store.OpenSQLite(*db)
	if err != nil {
		log.Fatalf("templates: buka database %q: %v", *db, err)
	}
	defer st.Close()
	ctx := context.Background()

	switch sub {
	case "update", "refresh":
		sources := payload.DefaultSources(*nucleiDir, *customDir)
		if len(sources) == 0 {
			log.Fatalf("templates: tak ada sumber (set -nuclei-templates / -custom-templates atau env)")
		}
		before, _ := st.CatalogStats(ctx)
		cat := payload.Build(ctx, sources)
		if err := st.ReplaceCatalog(ctx, cat); err != nil {
			log.Fatalf("templates: simpan katalog: %v", err)
		}
		fmt.Printf("katalog diperbarui: %d template dari %d sumber (sebelumnya %d)\n", len(cat.Entries), len(cat.Sources), before.Total)
		for _, s := range cat.Sources {
			status := "tersedia"
			if !s.Available {
				status = "TAK TERSEDIA"
			}
			fmt.Printf("  - %-16s %-7s trust=%-9s %6d template (%d aktif) [%s] %s\n",
				s.ID, s.Engine, s.Trust, s.Count, s.Enabled, status, s.Path)
			if s.Note != "" {
				fmt.Printf("      catatan: %s\n", s.Note)
			}
		}
	case "list":
		entries, total, err := st.ListCatalog(ctx, store.CatalogQuery{Limit: 50})
		if err != nil {
			log.Fatalf("templates: list: %v", err)
		}
		fmt.Printf("%d template di katalog (menampilkan %d):\n", total, len(entries))
		for _, e := range entries {
			en := "off"
			if e.Enabled {
				en = "on "
			}
			fmt.Printf("  [%s] %-44s %-7s %-8s %s\n", en, e.TemplateID, e.Engine, e.SeverityDefault, e.Trust)
		}
	default:
		log.Fatalf("templates: subperintah tak dikenal %q (pakai: update | list)", sub)
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
