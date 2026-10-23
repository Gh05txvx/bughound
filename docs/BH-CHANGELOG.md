# BH-CHANGELOG — Catatan perkembangan implementasi

Log rekayasa: **apa yang sudah dibangun** di repo (pelengkap spec/PRD yang menyatakan apa yang *seharusnya* dibangun). Sumber kebenaran detail tetap git history + CI; dokumen ini peta ringkasnya. Tanggal relatif dikonversi ke milestone/rilis.

## Status ringkas

Fondasi **M0**, MVP **M1**, triase & multi-engine **M2**: **selesai**. **M3** (pengerasan & rilis) berjalan: audit pre-launch lolos + diremediasi, export platform, dashboard, SAST plugin, adapter engine nyata (ffuf, ZAP). Empat rilis publik: **v0.1.0 → v0.2.0**.

## Rilis

| Tag | Isi inti |
| --- | --- |
| `v0.2.0` | SAST sebagai plugin (analisis statis lokal; minor bump) |
| `v0.1.2` | Export report ke template HackerOne/Bugcrowd + Dashboard |
| `v0.1.1` | Perbaikan CSRF (Origin: null) + anchoring audit (BH-F06) |
| `v0.1.0` | Fondasi + M1 + packaging single-binary |

Tiap rilis = single binary lintas-platform (linux/darwin/windows) + `SHA256SUMS.txt`, dibangun workflow `release.yml` saat tag `v*` dipush.

## Fondasi & pipeline (M0–M1)

- **Skema Temuan Seragam** (`BH-SPEC-FINDING`): format berversi, `dedup_key` deterministik, evidence tersensor.
- **Scope Guard** (`BH-SPEC-SCOPE`): domain/wildcard/URL/IP/CIDR, normalisasi punycode & IP, default-deny, penegakan **dua lapis** (input + egress).
- **Store**: in-memory & SQLite (pure-Go), dedup per-program, triase, query terurut severity, program+scope persisten.
- **Orchestrator**: recon → scope (input) → scan rate-limited → egress re-check → store + audit.
- **Web UI**: Go + HTMX + `html/template`, aset di-`go:embed` (single binary).
- **Rate limiter** wajib di jalur eksekusi (config dijepit, tak bisa dimatikan).
- **Recon**: pipeline mock + nyata (subfinder → httpx → katana).
- **Job queue** async (worker pool), **report module** (draft Markdown + PDF), **egress proxy** (HTTP+CONNECT, per-koneksi scope) + `nuclei.Runner` nyata.

## Triase & scope (M2)

- **Aksi massal** di Findings: konfirmasi / false-positive / abaikan sekaligus (fail-closed status, CSRF).
- **Filter** severity | status | type | run.
- **Program & scope persisten** + **scope editor** dengan pratinjau izin/tolak (tanpa menyentuh jaringan).

## Keamanan

7 prinsip mengikat diimplementasikan & diuji:

1. Scope guard default-deny, satu titik penegakan, tahan bypass (homoglyph/IP-obfuscation/userinfo/suffix/encoding).
2. Tak pernah menyentuh out-of-scope — input + egress + proxy per-koneksi; dialer anti-SSRF/anti-rebinding (resolve + tolak IP internal + pin IP).
3. Tanpa auto-submit — report selalu draft; export hanya memformat untuk submit manual.
4. Rate limiter di jalur eksekusi.
5. Secret AES-256-GCM, keyring + rotasi, tersensor dari log/store/report.
6. Audit trail HMAC-chain append-only + **anchoring eksternal** (BH-F06): trunkasi/rollback/penghapusan total store terdeteksi.
7. Satu skema temuan seragam untuk semua engine.

**Audit pre-launch (`BH-P03-APPSEC`)** — laporan di `audit/BH-AUDIT-M2-pre-launch.md`. Semua temuan **High/Medium/Low** diremediasi (BH-F01 CSRF+auth, BH-F02 rebinding, BH-F04 parser, BH-F05 reveal-audit, BH-F06 anchoring, BH-F07 rotasi; BH-F03 dimitigasi Opsi C + ADR). Tersisa: Info (F08/F09), BH-F03 (defense-in-depth), Option A (allowlist OS). Perbaikan tambahan dari E2E: CSRF menerima `Origin: null` (form non-HTMX same-origin di Chromium) tanpa melemahkan pertahanan (token + Sec-Fetch-Site).

## Rilis & CI

- **Packaging**: single binary (`go:embed` + SQLite pure-Go, CGO off), versi via `-ldflags -X main.version`, footer UI + `-version`.
- **Tooling**: `Makefile`, `scripts/build-release.sh` (cross-compile + arsip + checksum).
- **Workflow**: `ci.yml` (Go test), `e2e.yml` (Playwright), `release.yml` (tag `v*` → GitHub Release).

## E2E (`BH-P05`)

Suite Playwright di `e2e/`: 5 skenario (2 kritis: scope-guard & no-auto-submit; + scan-flow, triage, program-scope). Engine mock, store/kunci ephemeral, bind localhost, **egress diblok dua lapis** (env proxy mati + pengaman browser). Page Object Model, selector peran/teks, auto-wait.

## Report & export (M3)

- Draft report dari temuan **terkonfirmasi** (Markdown, unduh/cetak-PDF).
- **Export** ke template **HackerOne** & **Bugcrowd** (per-temuan atau seluruh report) — tetap draft, submit **manual**, tanpa koneksi keluar; pemetaan severity/CWE/CVSS + bagian khas tiap platform.

## Dashboard (M3)

Halaman landing `/dashboard`: KPI lintas-program (program/temuan/terkonfirmasi/run) + tabel per program (breakdown severity, konfirmasi, run, aktivitas terakhir, tautan cepat).

## SAST sebagai plugin (M3)

`internal/sast`: analisis statis sebagai **plugin** (registry adapter) yang menulis ke skema temuan yang sama, membaca **kode lokal**. Boundary = **path scope** (`sast.Resolve`: confine ke satu root, default-deny, tolak traversal/symlink-escape). Adapter: **Mock** (offline) + **semgrep Runner**. Diaktifkan `-sast-root`; temuan muncul di Findings/Dashboard.

## Status adapter engine

| Engine | Peran | Adapter |
| --- | --- | --- |
| nuclei | DAST | mock + nyata (`-proxy`) |
| subfinder → httpx → katana | recon | mock + nyata (httpx/katana via proxy) |
| gau | recon (URL historis, pasif) | mock + nyata |
| dnsx | recon (resolusi DNS) | mock + nyata |
| naabu | recon (port scan TCP) | mock + nyata (TCP mentah; hanya dipindai pada host in-scope hasil httpx) |
| ffuf | DAST (content discovery) | mock + nyata (wordlist bawaan ter-embed; override `-ffuf-wordlist`) |
| ZAP | DAST (proxy scanner) | mock + nyata (mode `-zap-mode` quick/baseline/full; full = spider + active scan via Automation Framework; upstream proxy config) |
| semgrep | SAST | mock + nyata (opt-in via `-sast-root`) |

Pemilihan engine: `-engine mock` (default, semua mock, tanpa jaringan) · `-engine real` (nuclei + recon nyata) · daftar koma `-engine nuclei,ffuf,zap`. Semua engine nyata = subprocess tool eksternal yang **tidak di-bundle**; lihat README "Engine yang didukung & cara pasang".

## Scan ter-arah OpenAPI/Swagger (API)

`internal/openapi`: `Endpoints(spec, fallbackBase)` mem-parse OpenAPI 3 / Swagger 2 (JSON atau YAML via gopkg.in/yaml.v3, fallback encoding/json) → daftar URL endpoint absolut unik (base dari `servers`/`host`+`basePath`+`schemes` atau fallback target; param path `{id}`→`1`). Form Scan dapat kolom *OpenAPI/Swagger spec*: endpoint hasil ekspansi ditambahkan ke target dan **tetap lewat scope guard** (spec tak memintas batas). Menjangkau seluruh endpoint API terdokumentasi, bukan hanya crawling. Batas: belum fuzzing per-method/body (nuclei `-im openapi`) & belum gRPC. Uji `openapi/openapi_test.go` + `web/openapi_scan_test.go`.

## Docker (engine ikut di image)

`Dockerfile` multi-stage + `docker-compose.yml` + `.dockerignore`: image gabungan **bughound + engine** (nuclei/subfinder/httpx/katana/ffuf via `go install`, semgrep via pip; **ZAP opsional** `--build-arg WITH_ZAP=true`). Di dalam container engine ada di `PATH` → `-engine real` jalan tanpa pasang tool di host. Non-root, data di `/data`, default `-engine mock` (aman); port dipetakan ke localhost + `-auth` untuk akses non-lokal. Divalidasi `docker build --check` (bersih; base image resolve). Cocok untuk mesin tanpa engine terpasang tapi punya Docker. Workflow `docker.yml`: saat tag `v*`, build & push image ke **GitHub Container Registry** (`ghcr.io/<owner>/bughound`, varian lean) dengan cache GHA → `docker pull ghcr.io/…:latest`. Lihat README "Docker".

## Catatan pola

Menambah engine = menulis **satu adapter**: bangun argumen → subprocess (`ProxyAware` agar egress ditegakkan) → `Parse` output ke skema temuan. Contoh: `internal/engine/{nuclei,ffuf,zap}`, `internal/sast`. Triase/report/store/dashboard tak perlu disentuh.
