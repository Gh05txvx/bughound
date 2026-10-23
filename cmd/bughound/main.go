// Command bughound menjalankan aplikasi web bughound (M0).
//
// Default bind ke localhost saja: ini tool offensive, jangan diekspos tanpa
// sadar. Engine di M0 adalah mock (tanpa koneksi jaringan).
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

	"bughound/internal/audit"
	"bughound/internal/engine"
	"bughound/internal/engine/ffuf"
	"bughound/internal/engine/nuclei"
	"bughound/internal/engine/zap"
	"bughound/internal/recon"
	"bughound/internal/secret"
	"bughound/internal/store"
	"bughound/internal/web"
)

// version di-inject saat build lewat -ldflags "-X main.version=...".
// Default "dev" untuk build lokal (go build/go run).
var version = "dev"

func main() {
	addr := flag.String("addr", "127.0.0.1:8787", "alamat bind (default localhost saja)")
	showVersion := flag.Bool("version", false, "cetak versi lalu keluar")
	dbPath := flag.String("db", "bughound.db", "path file SQLite (kosongkan untuk in-memory/ephemeral)")
	engineMode := flag.String("engine", "mock", "set engine: mock (nuclei+ffuf mock, tanpa jaringan) | real (nuclei + subfinder/httpx/katana nyata lewat proxy egress)")
	keyPath := flag.String("key", "bughound.key", "path file kunci master untuk enkripsi secret (atau set env BUGHOUND_MASTER_KEY)")
	authFlag := flag.String("auth", "", "password HTTP Basic auth (atau env BUGHOUND_AUTH); kosong = tanpa auth (hanya aman untuk localhost)")
	rotateKey := flag.Bool("rotate-key", false, "rotasi kunci master: re-enkripsi semua secret ke kunci baru lalu keluar")
	sastRoot := flag.String("sast-root", "", "root kode untuk SAST (kosong = nonaktif); analisis statis dikurung ke dir ini")
	ffufWordlist := flag.String("ffuf-wordlist", "", "path wordlist untuk engine ffuf nyata (kosong = wordlist bawaan)")
	zapMode := flag.String("zap-mode", "quick", "mode engine ZAP nyata: quick | baseline | full (full = spider + active scan)")
	grpcMode := flag.String("grpc", "mock", "engine enumerasi gRPC: mock | real (grpcurl, butuh binary)")
	grpcPlaintext := flag.Bool("grpc-plaintext", false, "gRPC tanpa TLS (-plaintext) untuk engine gRPC nyata")
	flag.Parse()

	if *showVersion {
		fmt.Println("bughound", version)
		return
	}

	authSecret := *authFlag
	if authSecret == "" {
		authSecret = strings.TrimSpace(os.Getenv("BUGHOUND_AUTH"))
	}
	if authSecret == "" && !isLocalhost(*addr) {
		log.Printf("PERINGATAN: bind non-localhost (%s) TANPA -auth — UI terbuka tanpa kredensial. Set -auth atau BUGHOUND_AUTH.", *addr)
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
	names, useMock := parseEngineMode(*engineMode)
	if useMock {
		engines = []engine.Engine{nuclei.Mock{}, ffuf.Mock{}, zap.Mock{}}
		rec = recon.MockPipeline{}
		log.Printf("engine: mock (nuclei + ffuf + zap) — tanpa koneksi jaringan")
	} else {
		for _, n := range names {
			switch n {
			case "nuclei":
				engines = append(engines, &nuclei.Runner{})
			case "ffuf":
				engines = append(engines, &ffuf.Runner{Wordlist: *ffufWordlist})
			case "zap":
				engines = append(engines, &zap.Runner{Mode: *zapMode})
			}
		}
		if len(engines) == 0 {
			log.Fatalf("bughound: -engine %q tak mengenali engine apa pun (pilih: mock | real | daftar: nuclei,ffuf,zap)", *engineMode)
		}
		rec = recon.NewRealPipeline()
		log.Printf("engine: NYATA (%s + recon subfinder/httpx/katana) — egress lewat proxy scope guard", strings.Join(names, ", "))
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

	srv, err := web.NewServer(web.Config{Store: st, Engines: engines, Recon: rec, Vault: vault, Audit: auditLog, AuthSecret: authSecret, Version: version, SASTRoot: *sastRoot, GRPCReal: grpcReal, GRPCPlaintext: *grpcPlaintext})
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

// parseEngineMode menafsirkan flag -engine. "" / "mock" -> engine mock (mock
// eksklusif). Selain itu daftar dipisah koma: "real" = alias nuclei; nama yang
// dikenal (nuclei, ffuf, zap) membangun Runner nyata. Nama tak dikenal diabaikan
// (pemanggil menolak bila tak ada yang dikenali). Hasil ter-dedup, urut input.
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
		}
	}
	return names, false
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
