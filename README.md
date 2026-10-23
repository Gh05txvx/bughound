# bughound

**Bug Bounty DAST Orchestrator** — bukan scanner, melainkan *orchestrator* yang menyatukan engine recon & DAST yang sudah matang (nuclei, httpx, subfinder, ZAP, dll), menormalkan hasilnya ke satu skema temuan seragam, lalu membantu triase dan menghasilkan draft report yang siap diverifikasi manual sebelum disubmit.

> ⚠️ **Hanya untuk pengujian yang sah.** bughound adalah tool offensive (DAST). Gunakan hanya terhadap aset yang berada dalam scope program bounty, lab milik sendiri, atau sistem dengan izin eksplisit. **Scope guard default-deny** menolak target yang tidak terbukti in-scope, dan **tidak ada auto-submit** — report selalu berakhir sebagai draft.

## Status

**M0 — Fondasi: selesai.** Gate M0 terpenuhi: satu temuan mengalir *scan → normalisasi → tersimpan*; scope guard menolak target di luar scope (lapis input **dan** egress); nol koneksi ke aset nyata.

**M1 & M2 berjalan** (dengan engine mock/target dummy): rate limiter di jalur eksekusi, pipeline recon, multi-engine (nuclei + ffuf), modul report (draft), job queue, vault secret terenkripsi, audit trail berantai, serta triase (aksi massal + filter) dan scope per-program yang persisten. Roadmap M3 ada di PRD.

## Prinsip yang mengikat

Keamanan adalah batas struktural, bukan tambahan:

- **Scope guard** sebagai satu titik penegakan wajib (default-deny, out-of-scope menang, fail-closed), ditegakkan dua lapis (input + egress).
- **Tidak ada auto-submit** — report selalu draft, dikirim manual oleh pengguna.
- **Secret disensor** dari evidence dan raw sebelum disimpan; tidak pernah bocor ke store/log/report.
- **Satu skema temuan seragam** sebagai fondasi; semua engine menulis ke sana.

## Fitur M0

- Skema Temuan Seragam (`BH-SPEC-FINDING`): format JSON berversi, `dedup_key` deterministik.
- Scope Guard (`BH-SPEC-SCOPE`): domain/wildcard/URL/IP/CIDR, normalisasi punycode & IP, kebijakan port, penegakan dua lapis.
- Findings store: in-memory & SQLite (persisten), dedup per-program, triase, query terurut severity.
- Adapter nuclei (JSONL → skema) + engine mock (tanpa jaringan).
- Orchestrator in-process: scope guard → scan → normalisasi → store + audit trail.
- UI web (Go + HTMX): input scope, jalankan scan, triase temuan. Binary tunggal.

## Build & jalankan

Butuh Go 1.26+.

```bash
go test ./...                 # jalankan seluruh test
go run ./cmd/bughound         # jalankan (simpan ke ./bughound.db)
go run ./cmd/bughound -db ""  # mode in-memory (ephemeral)
```

Buka http://127.0.0.1:8787 — isi scope & target, jalankan scan, lalu triase di halaman **Findings**. Form sudah terisi contoh (`demo.test` in-scope, `evil.test` di luar scope) untuk mendemokan scope guard.

Flag:

- `-addr` — alamat bind (default `127.0.0.1:8787`, localhost saja).
- `-db` — path file SQLite (default `bughound.db`; kosongkan untuk in-memory).
- `-engine` — `mock` (default, tanpa jaringan) atau `real` (engine nyata via proxy scope guard).
- `-auth` — password HTTP Basic (atau env `BUGHOUND_AUTH`); kosong = tanpa auth (hanya aman di localhost).
- `-key` — path kunci master enkripsi secret (atau env `BUGHOUND_MASTER_KEY`); `-rotate-key` merotasinya.
- `-sast-root` — root kode untuk SAST (kosong = nonaktif); analisis statis dikurung ke dir ini (path scope, default-deny).
- `-ffuf-wordlist` — wordlist untuk engine ffuf nyata (kosong = wordlist bawaan).
- `-zap-mode` — mode ZAP nyata: `quick` (default) · `baseline` · `full` (spider + active scan via Automation Framework).
- `-grpc` — engine enumerasi gRPC: `mock` (default) · `real` (grpcurl). `-grpc-plaintext` untuk gRPC tanpa TLS.
- `-version` — cetak versi build lalu keluar.

## Rilis (single binary)

Seluruh aset (template + static + HTMX) di-embed lewat `go:embed` dan SQLite-nya pure-Go, jadi tiap rilis adalah **satu binary** tanpa dependensi runtime (CGO off, cross-compile bersih).

```bash
make build                    # binary lokal -> bin/bughound (versi dari git describe)
make release                  # cross-compile semua target -> dist/ (+ checksum)
make release VERSION=v0.1.0   # override versi yang di-embed
```

`make release` menghasilkan arsip untuk `linux/{amd64,arm64}`, `darwin/{amd64,arm64}`, dan `windows/amd64` beserta `SHA256SUMS.txt`. Versi di-inject ke binary (`-ldflags -X main.version`) dan tampil di footer UI serta `bughound -version`.

**Tag & GitHub Release.** Push tag `vX.Y.Z` memicu workflow [`release.yml`](.github/workflows/release.yml) yang menjalankan test, membangun semua target, lalu membuat GitHub Release berisi arsip + checksum:

```bash
git tag -a v0.1.0 -m "bughound v0.1.0"
git push origin v0.1.0
```

## Engine yang didukung & cara pasang

bughound adalah **orchestrator**, bukan scanner: engine recon/DAST/SAST **tidak di-bundle** ke dalam binary. Untuk scan nyata, pasang sendiri tool-nya, lalu bughound memanggilnya sebagai subprocess dan menegakkan scope guard, rate limiter, serta egress (koneksi keluar engine dipaksa lewat proxy scope-guard bughound). **Default `-engine mock`** tak butuh tool apa pun dan tak menyentuh jaringan.

| Engine | Peran | Adapter | Pasang |
| --- | --- | --- | --- |
| **nuclei** | DAST (template) | mock + nyata | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| **subfinder → httpx → katana** | recon (subdomain → probe → crawl) | mock + nyata | `go install github.com/projectdiscovery/{subfinder/v2/cmd/subfinder,httpx/cmd/httpx,katana/cmd/katana}@latest` |
| **gau** | recon (URL historis, pasif) | mock + nyata | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| **dnsx** | recon (resolusi/validasi DNS) | mock + nyata | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| **naabu** | recon (port scan TCP) | mock + nyata | `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` (butuh libpcap) |
| **ffuf** | DAST (content discovery) | mock + nyata | `go install github.com/ffuf/ffuf/v2@latest` · wordlist bawaan (override `-ffuf-wordlist`) |
| **ZAP** | DAST (proxy scanner) | mock + nyata | [OWASP ZAP](https://www.zaproxy.org/download/) (`zap.sh` di PATH) · `-zap-mode quick\|baseline\|full` |
| **semgrep** | SAST | mock + nyata | `pipx install semgrep` · aktif via `-sast-root` |
| **grpcurl** | gRPC (enumerasi reflection) | mock + nyata | `go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest` · `-grpc real` |

Mengaktifkan engine nyata lewat flag `-engine` (daftar dipisah koma):

```bash
go run ./cmd/bughound -engine real                       # nuclei + recon nyata
go run ./cmd/bughound -engine nuclei,ffuf                # ffuf pakai wordlist bawaan
go run ./cmd/bughound -engine nuclei,ffuf -ffuf-wordlist /path/wordlist.txt
go run ./cmd/bughound -engine nuclei,zap -zap-mode full  # + ZAP spider & active scan
go run ./cmd/bughound -sast-root /path/ke/repo           # aktifkan SAST (semgrep)
```

`mock` (default) menjalankan versi mock semua engine (tanpa jaringan). Menambah engine baru = menulis **satu adapter** (bangun argumen → subprocess `ProxyAware` → `Parse` ke skema temuan), lihat `internal/engine/*` dan `internal/sast`.

## Scan ter-arah OpenAPI/Swagger (API/backend)

Di form **Scan**, tempel spec **OpenAPI 3 / Swagger 2** (JSON atau YAML) pada kolom *OpenAPI/Swagger spec*. Tiap endpoint di `paths` diperluas jadi target konkret (param `{id}` → `1`, base dari `servers`/`host` atau target pertama), lalu **masing-masing tetap melewati scope guard** sebelum di-scan engine. Ini membuat scan menjangkau seluruh endpoint API yang didokumentasikan, bukan hanya hasil crawling.

> Catatan cakupan: ini memperluas endpoint sebagai target (probe + template engine). Fuzzing per-method/body yang lebih dalam (mis. `nuclei -im openapi`) belum didukung. Untuk **gRPC**, lihat halaman **gRPC** (enumerasi layanan/metode via reflection; fuzzing invokasi belum).

## Docker (engine ikut di dalam image)

Karena engine nyata tidak di-bundle ke binary, cara termudah menjalankan scan nyata **tanpa memasang tool di host** adalah image Docker yang menyatukan bughound + engine (nuclei, subfinder, httpx, katana, ffuf, semgrep; ZAP opsional). Di dalam container semua engine ada di `PATH`, jadi `-engine real`/`nuclei,ffuf,zap` langsung jalan.

```bash
docker build -t bughound .                                 # lean (tanpa ZAP)
docker build --build-arg WITH_ZAP=true -t bughound:zap .   # + OWASP ZAP (berat, +JRE)

# default: engine mock (aman), UI di http://127.0.0.1:8787
docker run --rm -p 127.0.0.1:8787:8787 -v bughound-data:/data bughound

# scan nyata (engine sudah ada di image) + auth
docker run --rm -p 127.0.0.1:8787:8787 -v bughound-data:/data -e BUGHOUND_AUTH=rahasia \
  bughound -addr 0.0.0.0:8787 -db /data/bughound.db -engine nuclei,ffuf -auth rahasia
```

Atau `docker compose up --build` (lihat `docker-compose.yml`; port sudah ke localhost, data di volume).

**Image rilis (GHCR).** Setiap tag `vX.Y.Z` memicu workflow [`docker.yml`](.github/workflows/docker.yml) yang mem-build & push image gabungan ke GitHub Container Registry, jadi tak perlu build sendiri:

```bash
docker pull ghcr.io/gh05txvx/bughound:latest     # tag versi: :0.2.2, :0.2
docker run --rm -p 127.0.0.1:8787:8787 -v bughound-data:/data ghcr.io/gh05txvx/bughound:latest
```

(Image GHCR = varian lean tanpa ZAP; untuk ZAP build lokal dengan `--build-arg WITH_ZAP=true`.)

> **Visibilitas:** paket GHCR default **privat** saat pertama terbit. Agar bisa `docker pull` tanpa login, set paket `bughound` ke **Public** di GitHub → Packages → bughound → *Package settings* → *Change visibility*. Atau tetap privat dan `docker login ghcr.io` dulu.

**Keamanan:** petakan port ke `127.0.0.1` saja dan set `-auth`/`BUGHOUND_AUTH` bila diakses dari luar localhost. Default container tetap `-engine mock` (tak ada scan nyata) sampai engine dipilih eksplisit.

## Struktur

```
cmd/bughound/        entry point (web server)
internal/
  finding/           skema temuan seragam
  scope/             scope guard
  store/             persistensi (interface + Mem + SQLite)
  engine/            kontrak engine + adapter nuclei (+ mock)
  sast/              analisis statis sebagai plugin (registry + mock + semgrep)
  orchestrator/      alur scan dengan penegakan scope dua lapis
  web/               UI (Go + HTMX + template, aset di-embed)
docs/                spesifikasi, PRD, design spec, persona (lihat docs/README.md)
```

## Dokumentasi

Spesifikasi fondasi dan dokumen produk ada di [`docs/`](docs/README.md): skema temuan, scope guard, bank payload, PRD, design spec, dan persona kerja.

## Lisensi

[MIT](LICENSE) © 2026 Gh05t
