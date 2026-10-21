// Command bughound menjalankan aplikasi web bughound (M0).
//
// Default bind ke localhost saja: ini tool offensive, jangan diekspos tanpa
// sadar. Engine di M0 adalah mock (tanpa koneksi jaringan).
package main

import (
	"flag"
	"log"
	"net/http"

	"bughound/internal/engine/nuclei"
	"bughound/internal/store"
	"bughound/internal/web"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8787", "alamat bind (default localhost saja)")
	dbPath := flag.String("db", "bughound.db", "path file SQLite (kosongkan untuk in-memory/ephemeral)")
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

	eng := nuclei.Mock{}

	srv, err := web.NewServer(st, eng)
	if err != nil {
		log.Fatalf("bughound: gagal inisialisasi: %v", err)
	}

	log.Printf("bughound (M0) di http://%s — engine: %s", *addr, eng.Name())
	log.Printf("scope guard aktif · tanpa auto-submit · tanpa koneksi ke aset nyata")

	httpSrv := &http.Server{Addr: *addr, Handler: srv}
	if err := httpSrv.ListenAndServe(); err != nil {
		log.Fatalf("bughound: server berhenti: %v", err)
	}
}
