// Command bughound menjalankan aplikasi web bughound (M0).
//
// Default bind ke localhost saja: ini tool offensive, jangan diekspos tanpa
// sadar. Engine di M0 adalah mock (tanpa koneksi jaringan).
package main

import (
	"flag"
	"log"
	"net/http"
	"strings"

	"bughound/internal/audit"
	"bughound/internal/engine"
	"bughound/internal/engine/ffuf"
	"bughound/internal/engine/nuclei"
	"bughound/internal/recon"
	"bughound/internal/secret"
	"bughound/internal/store"
	"bughound/internal/web"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8787", "alamat bind (default localhost saja)")
	dbPath := flag.String("db", "bughound.db", "path file SQLite (kosongkan untuk in-memory/ephemeral)")
	engineMode := flag.String("engine", "mock", "set engine: mock (nuclei+ffuf mock, tanpa jaringan) | real (nuclei + subfinder/httpx/katana nyata lewat proxy egress)")
	keyPath := flag.String("key", "bughound.key", "path file kunci master untuk enkripsi secret (atau set env BUGHOUND_MASTER_KEY)")
	flag.Parse()

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

	var auditLog audit.Log
	if *dbPath == "" {
		auditLog = audit.NewMemLog(kr.Subkey("audit"))
	} else {
		apath := strings.TrimSuffix(*dbPath, ".db") + "-audit.db"
		al, aerr := audit.OpenSQLiteLog(apath, kr.Subkey("audit"))
		if aerr != nil {
			log.Fatalf("bughound: audit log: %v", aerr)
		}
		defer al.Close()
		auditLog = al
		log.Printf("audit: trail %s (append-only, rantai HMAC)", apath)
	}

	var engines []engine.Engine
	var rec recon.Engine
	switch strings.ToLower(*engineMode) {
	case "real", "nuclei":
		engines = []engine.Engine{&nuclei.Runner{}}
		rec = recon.NewRealPipeline()
		log.Printf("engine: NYATA (nuclei + subfinder/httpx/katana) — egress lewat proxy scope guard")
		log.Printf("PERINGATAN: hanya scan target yang sah (in-scope / lab / izin eksplisit)")
	default:
		engines = []engine.Engine{nuclei.Mock{}, ffuf.Mock{}}
		rec = recon.MockPipeline{}
		log.Printf("engine: mock (nuclei + ffuf) — tanpa koneksi jaringan")
	}

	srv, err := web.NewServer(web.Config{Store: st, Engines: engines, Recon: rec, Vault: vault, Audit: auditLog})
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
