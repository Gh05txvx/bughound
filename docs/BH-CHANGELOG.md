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
| grpcurl | gRPC (enumerasi + fuzz invokasi) | mock + nyata (`-grpc real`) |

Pemilihan engine: `-engine mock` (default, semua mock, tanpa jaringan) · `-engine real` (nuclei + recon nyata) · daftar koma `-engine nuclei,ffuf,zap`. Semua engine nyata = subprocess tool eksternal yang **tidak di-bundle**; lihat README "Engine yang didukung & cara pasang".

## Scan ter-arah OpenAPI/Swagger (API)

`internal/openapi`: `Endpoints(spec, fallbackBase)` mem-parse OpenAPI 3 / Swagger 2 (JSON atau YAML via gopkg.in/yaml.v3, fallback encoding/json) → daftar URL endpoint absolut unik (base dari `servers`/`host`+`basePath`+`schemes` atau fallback target; param path `{id}`→`1`). Form Scan dapat kolom *OpenAPI/Swagger spec*: endpoint hasil ekspansi ditambahkan ke target dan **tetap lewat scope guard** (spec tak memintas batas). Menjangkau seluruh endpoint API terdokumentasi, bukan hanya crawling. Batas: belum fuzzing per-method/body (nuclei `-im openapi`) & belum gRPC. Uji `openapi/openapi_test.go` + `web/openapi_scan_test.go`.

## gRPC — enumerasi via reflection

`internal/engine/grpc`: `Mock` + `Runner` (grpcurl) + `buildFindings`. Memakai gRPC Server Reflection untuk mengenumerasi layanan & metode → temuan: `grpc-reflection-enabled` (Medium, CWE-200), `grpc-service-exposed`, `grpc-method-exposed` (Info); layanan infra (reflection/health/channelz) disaring. Halaman web **gRPC** (`GET /grpc`, `POST /grpc/run`): target `host:port`, tiap host **wajib lolos scope guard program** (grpcurl tak bisa diproxy → scope ditegakkan di hulu; penolakan dicatat audit `grpc.scope`). Engine: mock default, `-grpc real` (+ `-grpc-plaintext`) memakai grpcurl; ditambahkan ke image Docker. **Fuzz invokasi** (opt-in, checkbox di halaman gRPC): `Scanner.Fuzz` menginvoke metode yang terlihat **read-only** (Get/List/Query/… — metode mutasi Create/Delete/… dilewati demi keamanan) dengan payload kosong, lalu mengklasifikasi status gRPC → temuan `grpc-method-callable-unauth` (Medium, CWE-306, respons OK tanpa kredensial) / `grpc-method-reachable-unauth` (Low, InvalidArgument); Unauthenticated/PermissionDenied = terproteksi (tak dilaporkan). Uji `engine/grpc/grpc_test` (+ classify/readOnly/fuzz) + `web/grpc_test` (+ fuzz).

## Proxy upstream & rantai (meneruskan egress)

`egress.Proxy.SetUpstream(urls...)` + `internal/egress/upstream.go` (`buildChainDialer`): koneksi akhir (ke IP yang SUDAH di-scope-check & di-pin) diteruskan lewat **satu proxy atau rantai multi-hop**. Skema tiap hop: **http/https** (CONNECT, TLS untuk https, Proxy-Authorization Basic), **socks5/socks5h** (via `golang.org/x/net/proxy`, Tor-friendly); kredensial `user:pass@host`. Rantai dibangun dengan fold: tiap hop jadi `proxy.Dialer` yang me-reach dirinya lewat hop sebelumnya (`httpProxyDialer`/SOCKS5, semuanya `ContextDialer` sehingga ctx & pin IP terjaga). `orchestrator.ScanRequest.ProxyChain []string` (fail-closed bila ada hop tak valid); form Scan punya kolom **Upstream proxy / rantai** (satu hop per baris). Keamanan tetap: scope guard + IP-pinning (anti-SSRF/rebinding) berjalan sebelum diteruskan — rantai hanya mengganti jalur ke IP yang sudah dicek. Uji `egress/upstream_test` (tunnel 1-hop & **2-hop** via proxy palsu + echo, skema salah, hop kedua salah, rantai kosong, socks5 construct, SetUpstream). Reverse proxy: lihat bagian berikut (capture gateway).

## Reverse proxy — capture gateway (browsing manual → scan)

"Reverse proxy" diwujudkan sebagai **capture gateway**, dikendalikan penuh dari UI web (bukan CLI). `internal/egress/capture.go` (`Gateway` + `httputil.ReverseProxy`): bughound berdiri sebagai reverse proxy ke **satu target in-scope**; hunter mengarahkan browser ke listener lokal (`http://127.0.0.1:<port>/`) dan browsing target seperti biasa. Tiap request yang lewat **direkam** (dedup per `method+URL`, dengan status & hitungan) sebagai kandidat endpoint, lalu bisa **di-promote jadi scan** lewat jalur scan yang sama (`enqueueScan` → orchestrator → scope guard + rate limiter + egress). **Keamanan**: gateway memakai ulang transport egress ter-guard (`Proxy.transport`: resolve → tolak IP internal → pin IP, plus rantai upstream bila diset), target divalidasi scope guard saat start (**fail closed**, default-deny), dan tiap penerusan di-**scope-check ulang** + **rate-limited** → hanya host in-scope yang pernah diteruskan, bahkan saat browsing manual. Listener lokal bicara HTTP biasa di loopback; re-originasi ke target HTTPS ditangani transport (SNI = host target, IP di-pin) sehingga **tanpa pasang CA cert** di browser. Tanpa auto-submit (promote hanya membuat scan draft). Audit: `capture.start` / `capture.stop` / `capture.promote` / `capture.egress` (penolakan). Halaman web **Capture** (`GET /capture`, `POST /capture/{start,stop,promote}`). Uji `egress/capture_test` (teruskan+rekam, dedup, tolak target out-of-scope, rate-limited) + `web/capture_test` (start/listener, promote→scan selesai, stop, wajib scope program).

## Branding & halaman login (UI)

Logo **bughound** (maskot beagle-detektif) dipasang di UI: sidebar brand + favicon (`internal/web/static/bughound-logo.png`, ikut `go:embed`), dan maskot di header README. **Halaman login ber-logo** menggantikan popup HTTP Basic untuk browser **saat `-auth`/`BUGHOUND_AUTH` diset**: `GET/POST /login` + `POST /logout`, template standalone `login.html`. Auth berbasis **sesi cookie** (`bh_session`, `HttpOnly`+`SameSite=Strict`, `Secure` bila TLS, TTL 12 jam, invalidasi server-side saat logout); perbandingan password **constant-time**; **CSRF tetap berlaku** pada `POST /login`. **HTTP Basic tetap didukung** sebagai jalur otomasi/CLI (kredensial eksplisit yang gagal → 401; browser tanpa sesi → redirect `/login`). Tanpa `-auth`, perilaku lama: akses terbuka (hanya aman di localhost), `/login` mengalihkan ke `/dashboard`. `enqueueScan`/jalur lain tak berubah. Audit `auth.login` (sukses/gagal) + `auth.logout`. Uji `web/login_test` (alur sesi, CSRF wajib, mode tanpa-auth) + `web/security_test` (Basic auth diperbarui: tanpa kredensial → redirect login).

## Pembaruan UI/UX (design system — BH-P02-DESIGN)

Poles tampilan agar konsisten dengan design spec: padat, flat, gelap, status-forward, aksen tunggal, fokus terlihat. `internal/web/static/app.css` diperbarui menyeluruh (semua kelas lama dipertahankan): token surface berlapis + radius/transisi/focus-ring; **`select` & checkbox kini ter-style** (sebelumnya default browser yang kontras di tema gelap); filter & bulk-bar dirapikan; tabel zebra + header uppercase; **nav aktif pakai bar aksen kiri**; scrollbar tipis; `:focus-visible` (aksesibilitas); tombol/kartu/badge/pill dipoles; halaman login lebih premium (backdrop radial + logo berpendar). `base.html`: topbar kini menampilkan status **"scope guard: default-deny"** yang selalu terlihat + program sebagai chip (prinsip "status & scope selalu tampak"). Hanya CSS + satu perubahan markup header; `go test ./...` hijau, seluruh halaman render 200.

## Docker (engine ikut di image)

`Dockerfile` multi-stage + `docker-compose.yml` + `.dockerignore`: image gabungan **bughound + engine** (nuclei/subfinder/httpx/katana/ffuf via `go install`, semgrep via pip; **ZAP opsional** `--build-arg WITH_ZAP=true`). Di dalam container engine ada di `PATH` → `-engine real` jalan tanpa pasang tool di host. Non-root, data di `/data`, default `-engine mock` (aman); port dipetakan ke localhost + `-auth` untuk akses non-lokal. Divalidasi `docker build --check` (bersih; base image resolve). Cocok untuk mesin tanpa engine terpasang tapi punya Docker. Workflow `docker.yml`: saat tag `v*`, build & push image ke **GitHub Container Registry** (`ghcr.io/<owner>/bughound`, varian lean) dengan cache GHA → `docker pull ghcr.io/…:latest`. Lihat README "Docker".

## Catatan pola

Menambah engine = menulis **satu adapter**: bangun argumen → subprocess (`ProxyAware` agar egress ditegakkan) → `Parse` output ke skema temuan. Contoh: `internal/engine/{nuclei,ffuf,zap}`, `internal/sast`. Triase/report/store/dashboard tak perlu disentuh.
