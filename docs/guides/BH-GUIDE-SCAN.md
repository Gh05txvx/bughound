# BH-GUIDE-SCAN — Mekanisme fitur & kebutuhan scan per skenario

> Panduan operasional: **bagaimana tiap fitur bekerja** dan **apa yang perlu kamu isi untuk scan tertentu**. Ditulis sesuai implementasi (`cmd/bughound`, `internal/web`, `internal/engine`, `internal/sast`, `internal/egress`, `internal/recon`). Terakhir diperbarui: 2026-11-09.
>
> Pelengkap: [`BH-GUIDE-PROXY`](BH-GUIDE-PROXY.md) (menu Proxy & rantai), [`BH-SPEC-SCOPE`](../specs/BH-SPEC-SCOPE-scope-guard.md) (aturan scope), [`BH-SPEC-FINDING`](../specs/BH-SPEC-FINDING-skema-temuan.md) (skema temuan).

---

## 0. Baca ini dulu (batas yang tidak bisa dimatikan)

BugHound adalah **orchestrator**, bukan scanner tunggal: ia menyatukan engine recon/DAST/SAST matang ke satu skema temuan, lalu membantu triase & draft report. Empat batas struktural berlaku di **setiap** scan:

1. **Scope guard default-deny.** Target yang tidak terbukti **in-scope ditolak**. Tidak ada jalur samping. Kamu *wajib* mendaftarkan target di `in_scope`.
2. **Egress terkunci.** Hanya engine worker yang menjangkau jaringan, dan hanya ke IP in-scope yang sudah di-*pin* (anti-SSRF/rebinding). IP privat ditolak saat dial kecuali eksplisit in-scope.
3. **Rate limiter di jalur eksekusi.** Tiap engine dijepit ke `rps` scan. Tidak mudah dimatikan.
4. **Tanpa auto-submit.** Report selalu draft; pengiriman ke platform dilakukan manual olehmu.

> ⚠️ Scope guard menegakkan **DI MANA** kamu boleh scan, bukan **APAKAH** otomasi diizinkan. Untuk target bug bounty nyata, membaca Rules of Engagement program (apakah scanner/otomasi boleh, batas rate, header penanda) tetap tanggung jawabmu — lihat §4 skenario J.

---

## 1. Peta pipeline — di mana tiap fitur berdiri

```
Web UI  →  Orchestrator (SCOPE GUARD)  →  Job queue  →  Engine workers (adapter + rate limiter)  →  Normalisasi → Triase → Store
                     │                                          │
              default-deny,                            egress lewat proxy BugHound
              out-of-scope menang                      (pin IP → rantai proxy → target)
```

- **Input** diperiksa scope guard **sebelum** job dibuat (lapis 1).
- **Egress** tiap request diperiksa lagi di proxy (lapis 2) — fail-closed.
- Tiap engine menulis ke **satu skema temuan** (`BH-SPEC-FINDING`) → dedup, triase, report seragam lintas engine.

---

## 2. Mekanisme fitur

### 2.1 Scope guard (boundary wajib)

| Aspek | Perilaku |
| --- | --- |
| Default | **Deny** — tak terbukti in-scope = ditolak. |
| Konflik | **Out-of-scope menang** atas in-scope. |
| Format entri | host (`example.com`), wildcard (`*.example.com`), CIDR, atau host:port. Port tak disebut = semua port, kecuali entri sebut eksplisit. |
| Dua lapis | (1) input form, (2) egress tiap koneksi. Keduanya fail-closed. |
| IP privat | Ditolak saat **dial** kecuali eksplisit in-scope (mis. lab `172.30.0.10`). |

### 2.2 Egress, IP-pinning & rantai proxy

Tiap request engine keluar lewat **proxy egress in-app**. Alur:

```
engine → proxy egress BugHound (scope guard + pin IP) → hop1 → hop2 → … → target
```

- Target di-resolve & **di-pin** di sisi BugHound sebelum diteruskan → DNS-rebinding/SSRF diblok.
- **Rantai proxy** (field *Upstream proxy / rantai* di form Scan): **satu hop per baris, urut**. Skema didukung: `http://`, `https://`, `socks5://` (`socks5h://` juga). Kredensial `user:pass@host` — **disensor** dari log/UI/audit. Hop tak valid = fail-closed.
- Uji rantai lebih dulu di menu **Proxy** (`/proxy`) sebelum dipakai scan — lihat [`BH-GUIDE-PROXY`](BH-GUIDE-PROXY.md).

### 2.3 Rate limiter & stealth

- `rps` form → laju request per engine (throttle di jalur eksekusi).
- Checkbox **stealth** → mode *low-and-slow* (jitter/agresi rendah) untuk engine aktif; recall tetap utuh, lebih sopan ke target.
- Profil **non-destruktif selalu aktif** untuk engine injeksi (payload bedah, bukan merusak).

### 2.4 Engine DAST — apa yang tiap engine kerjakan & apa yang memicunya

Roster engine ditetapkan **saat startup** lewat flag `-engine` (daftar dipisah koma). Per-scan kamu **menyaring** (tags/severity/stealth/api_routes), bukan memilih engine.

| Engine | Peran | Input yang memicu temuan | Catatan |
| --- | --- | --- | --- |
| `nuclei` | Template matcher (exposures, misconfig, CVE server-side, header hilang) | `targets`/`seeds` (URL/host) | Disaring oleh `tags` + `severity`. |
| `ffuf` | Content discovery (brute path) | base URL di `targets` | Centang **api_routes** → wordlist Assetnote `apiroutes` (bagus untuk `/api`, `/openapi.json`). Kalibrasi dinding 401/403/500. |
| `zap` | Spider + aturan ZAP | base URL | **`quick`/`baseline` = PASIF saja** (header, info leak). **Aktif (inject) hanya bila startup `-zap-mode full`.** |
| `nuclei-dast` | **DAST aktif**: crawl katana → fuzz parameter (SQLi/injeksi) | URL **ber-parameter** (`/search?q=`) atau hasil crawl | Non-destruktif + throttle. Temuan = kandidat draft→verify. |
| `dalfox` | **DAST aktif khusus XSS** | URL **ber-parameter** (`/greet?name=`) | Normalkan PoC → temuan. |
| `retire` | SCA library JS klien (CVE sisi-klien) | halaman yang memuat JS | **Opt-in**: image harus di-build `WITH_RETIRE=true` + `retire` ada di roster. |

> **OpenAPI body-fuzz:** field **openapi** menerima **ISI dokumen** spec (JSON/YAML), **bukan URL**. Base URL diambil dari baris pertama `targets`. Endpoint di spec (termasuk `POST`) di-discover & di-fuzz body-nya.

### 2.5 Recon (mode engine nyata)

Pipeline nyata: **subfinder → httpx → katana**. Dari satu domain/host seed: enumerasi subdomain → probe yang hidup → crawl URL. Hasil crawl memperkaya `targets` — **tetapi hanya yang in-scope yang di-scan**.

### 2.6 SAST — analisis statis kode

Kode **tidak** keluar jaringan. Dikurung ke root yang diset `-sast-root` (default: nonaktif). Dropdown `/sast` **pilih satu engine per run**.

| Engine | Bahasa/target | Temuan |
| --- | --- | --- |
| `semgrep` | multi-bahasa (`p/default`, **offline** pre-baked) | pola luas (eval, subprocess, injeksi, dll.) |
| `bandit` | Python | kode `B###` (B324 md5, B307 eval, B602 shell=True, B608 SQL, …) |
| `gitleaks` | semua teks | secret — **nilai ter-redaksi** (tak pernah bocor ke temuan/log) |
| `findsecbugs` | bytecode JVM | **opt-in** `WITH_FINDSECBUGS=true`; butuh kelas/jar terkompilasi |

Output SARIF (mis. CodeQL) dinormalkan via `NormalizeSARIF` → skema temuan seragam.

### 2.6b Men-stage kode untuk SAST (lokal, OSS, atau diberi program)

SAST **butuh kode**, bukan URL. Target yang hanya memberi URL HTTPS **tak bisa di-SAST** — itu wilayah DAST (lihat §4.J). SAST berlaku saat kodenya tersedia untukmu: kodebase sendiri, open-source (GitHub/GitLab), atau source yang program berikan. BugHound **tidak** mengunduh/meng-clone otomatis (tak ada jaringan di SAST) dan **tak punya upload kode via GUI** — **kamu** yang menaruh kode di bawah `-sast-root`.

**Cara a — bind-mount folder host (disarankan: sekali setup, tanpa `cp` berulang).**
Mount folder host *read-only* ke dalam sast-root saat menjalankan container:
```bash
docker run ... \
  -e BUGHOUND_SAST_ROOT=/data/sast \
  -v C:/path/ke/sast-ext:/data/sast/ext:ro \
  ...
```
Lalu `git clone`/salin repo ke `C:/path/ke/sast-ext/<nama>` di host → langsung terbaca container. Di `/sast`, **Subpath** = `ext/<nama>`. Read-only karena SAST tak pernah menulis ke kode.

**Cara b — `docker cp` (tanpa recreate container).**
```bash
git clone --depth 1 https://github.com/org/app /tmp/app
docker cp /tmp/app bughound:/data/sast/app
MSYS_NO_PATHCONV=1 docker exec -u root bughound chown -R bh:bh /data/sast/app
```
**Subpath** = `app`.

> Path-scope tetap berlaku: apa pun di luar `-sast-root` ditolak (default-deny; `..`/symlink escape diblok). Secret di kode tetap ter-redaksi pada temuan.

### 2.7 Normalisasi, dedup & triase

- Semua engine → satu skema (`BH-SPEC-FINDING`): severity/status/confidence/evidence/`owasp`.
- **Dedup** per `(program, dedup_key)` dengan `duplicate_of`; dedup_key memasukkan metode HTTP (GET≠POST), kolaps site-wide (abaikan path/port).
- Triase di `/findings`: set status (confirmed/false-positive/…), lengkapi `impact` + langkah repro → mengisi report & export.

### 2.8 Report & export (tanpa auto-submit)

Report generator menyusun **draft** dari temuan terkonfirmasi; export format **HackerOne / Bugcrowd** terisi (repro + dampak), **bukan** placeholder. Pengiriman tetap manual.

### 2.9 Integrasi Burp

- API baca-saja `GET /api/v1/findings` (reuse HTTP Basic) — tarik temuan ke tooling.
- Extension Montoya (`burp-ext/`) — muat temuan + **Send-to-Repeater** untuk verifikasi manual. Halaman onboarding di `/burp`.

**Setia vs fallback.** Hanya temuan engine **aktif** (`nuclei-dast`, `dalfox`) yang membawa `evidence.request` (request mentah; header sensitif → `[REDACTED]`); extension mengirimnya utuh (method/path/body) ke Repeater. Temuan **pasif** (ZAP/ffuf/retire) tak punya request mentah → fallback **`GET` polos** dari `location.url`. Karena itu validasi IDOR/BAC tetap manual di Burp.

**Uji handoff (end-to-end):**

1. Scan target **ber-parameter** dengan roster memuat `dalfox`/`nuclei-dast` — mis. lab `http://<ip-lab>/greet?name=hunter` (XSS refleksi) dan `/search?q=hound` (SQLi error). `in_scope` memuat IP/CIDR lab.
2. Di `/findings`: pastikan temuan XSS (`dalfox`) / SQLi (`nuclei-dast`) punya **request mentah** — tombol **Salin request** muncul = `evidence.request` terisi.
3. Extension Burp: isi URL/user/pass + nama program → **Muat temuan** → pilih temuan **aktif** → **Kirim ke Repeater**.
4. Verifikasi di Repeater: request **setia** (bukan `GET /` polos), host/port benar, header sensitif `[REDACTED]`. Pembanding: pilih temuan **pasif** → muncul `GET` polos.

### 2.10 gRPC (opsional)

Form `/grpc`: `program`, `targets`, checkbox `fuzz`. Engine nyata `grpcurl` (startup `-grpc real`, `-grpc-plaintext` untuk tanpa TLS). Enumerasi service/method via reflection.

### 2.11 Stop & Run ulang

- **Stop** (Dashboard ▸ Proses scanning, atau status run di `/scan`) menghentikan satu run: engine yang sedang jalan dibunuh, run lain tak terganggu. Temuan yang sudah tersimpan tetap ada.
- **Run ulang** menjalankan lagi run yang sudah berakhir dengan parameter yang sama. Scope dinilai ulang dari definisi program **saat ini**.
- Keduanya butuh peran operator/admin dan tercatat di audit (`run.stop`, `run.rerun`). Riwayat run disimpan di memori, jadi hilang saat server di-restart.

---

## 3. Referensi field form **Scan** (`/scan`)

| Field | Wajib? | Isi | Catatan |
| --- | --- | --- | --- |
| `program` | ✅ | nama program | kunci temuan/report & preset. |
| `in_scope` | ✅ | satu entri per baris | host/wildcard/CIDR. **Target harus ada di sini** (default-deny). |
| `out_scope` | – | satu per baris | menang atas in-scope. |
| `targets` | ✅ | satu URL/host per baris | baris pertama = base untuk OpenAPI. Sertakan URL **ber-parameter** agar injeksi/XSS kena. |
| `seeds` | – | satu per baris | titik awal recon/crawl. |
| `rps` | – | angka | laju per engine; kecilkan untuk target nyata. |
| `upstream_proxy` | – | **satu hop per baris** | `http/https/socks5`, `user:pass@host`. |
| `tags` | – | daftar dipisah koma | filter template nuclei. |
| `severity[]` | – | checkbox | saring severity. |
| `stealth` | – | checkbox | low-and-slow. |
| `api_routes` | – | checkbox | wordlist Assetnote `apiroutes` untuk ffuf. |
| `openapi` | – | **isi spec** JSON/YAML | **BUKAN URL** — URL = fail-closed `cannot unmarshal`. |
| `save_preset` | – | checkbox | simpan seleksi (tags/severity/stealth) sebagai preset program. |

## 3b. Referensi form **SAST** (`/sast`)

| Field | Isi |
| --- | --- |
| `program` | nama program |
| `subpath` | subdirektori relatif di dalam `-sast-root` (mis. `lab`) |
| `engine` | **satu**: `semgrep` \| `bandit` \| `gitleaks` \| `findsecbugs` |

## 3c. Flag startup (CLI) yang menentukan kapabilitas

| Flag / env | Default | Efek |
| --- | --- | --- |
| `-addr` | `127.0.0.1:8787` | bind loopback. |
| `-engine` | `mock` | `mock` \| daftar nyata dipisah koma: `nuclei,ffuf,zap,dalfox,nuclei-dast,retire`. |
| `-zap-mode` | `quick` | `quick`\|`baseline`\|`full` (**full = spider + active scan**). |
| `-sast-root` | kosong (nonaktif) | root kode SAST; analisis dikurung ke sini. |
| `-grpc` / `-grpc-plaintext` | `mock` / off | engine gRPC nyata (`grpcurl`). |
| `-ffuf-wordlist` | bawaan | wordlist ffuf nyata. |
| `-key` / `BUGHOUND_MASTER_KEY` | `bughound.key` | kunci enkripsi secret. |
| `BUGHOUND_SAST_ROOT` | – | alternatif env untuk `-sast-root`. |
| build arg `WITH_FINDSECBUGS` / `WITH_RETIRE` | `false` | sertakan toolchain FindSecBugs / retire.js di image. |

---

## 4. Kebutuhan untuk scan apa saja — skenario → input minimal

Tiap skenario: **engine yang bekerja**, **input yang kamu isi**, dan **prasyarat** (jika ada).

### A. Web app DAST menyeluruh (kamu punya URL)
- **Engine:** nuclei + ffuf + zap(pasif) + nuclei-dast + dalfox.
- **Isi:** `program`; `in_scope` = host target; `targets` = URL + endpoint ber-parameter; `rps` secukupnya; centang `api_routes`.
- **Prasyarat:** roster `-engine nuclei,ffuf,zap,dalfox,nuclei-dast`. Untuk ZAP active tambah `-zap-mode full`.

### B. Fokus XSS
- **Engine:** `dalfox` (+ nuclei-dast).
- **Isi:** `targets` berisi URL ber-parameter reflektif (`/greet?name=test`).

### C. Injeksi aktif (SQLi/dsb.)
- **Engine:** `nuclei-dast` (crawl→fuzz). ZAP active (jika `-zap-mode full`) melengkapi.
- **Isi:** `targets`/`seeds` dengan URL ber-parameter (`/search?q=test`); boleh andalkan crawl katana dari seed.

### D. Content / secret discovery
- **Engine:** `ffuf` (+ nuclei exposures).
- **Isi:** base URL di `targets`; centang `api_routes` untuk permukaan `/api`. Membongkar `/admin`, `/backup.zip`, `.env`, `.git/config`.

### E. API via OpenAPI/Swagger
- **Engine:** OpenAPI discovery → body-fuzz (+ nuclei/nuclei-dast).
- **Isi:** `targets` baris pertama = base URL; tempel **ISI spec** di `openapi` (bukan URL).

### F. Recon / attack surface dari domain atau wildcard
- **Engine:** recon subfinder→httpx→katana, lalu DAST pada yang hidup.
- **Isi:** `in_scope` = `*.example.com` (**hanya bila RoE/scope mengizinkan wildcard**); `seeds` = domain apex. Hanya subdomain in-scope yang di-scan.

### G. SAST kode sumber (termasuk target OSS/eksternal)
- **Engine:** semgrep / bandit / gitleaks / findsecbugs (satu per run).
- **Butuh kode, bukan URL.** Untuk target eksternal, SAST hanya berlaku bila kodenya tersedia (OSS atau diberi program); target URL-only → pakai DAST (§4.J).
- **Isi:** stage kode di bawah `-sast-root` (**bind-mount** atau `docker cp` — lihat §2.6b); di `/sast` isi `program`, `subpath`, pilih `engine`. Jalankan beberapa kali untuk beberapa engine.
- **Alur bila target OSS:** SAST repo → temukan sink kandidat → buktikan live via DAST/Burp (pakai `program` yang sama agar temuan gabung).
- **Prasyarat:** server jalan dengan `-sast-root`/`BUGHOUND_SAST_ROOT`. FindSecBugs butuh image `WITH_FINDSECBUGS=true` + bytecode.

### H. Scan lewat Burp / proxy (lihat & rekam trafik, suntik header penanda)
- **Isi:** di `upstream_proxy` taruh proxy Burp. **Dari container Docker gunakan `http://host.docker.internal:8080`** (bukan `127.0.0.1:8080` — itu loopback container). Validasi dulu di menu Proxy.
- **Catatan:** scope guard + pin IP tetap jalan **sebelum** diteruskan ke proxy. Burp Match/Replace bisa menambah header/User-Agent penanda yang diminta program.

### I. gRPC
- **Isi:** `/grpc` → `program`, `targets`, centang `fuzz`.
- **Prasyarat:** `-grpc real` (+ `-grpc-plaintext` bila tanpa TLS).

### J. Target bug bounty nyata (program hanya kasih URL HTTPS)
1. **Pra-terbang:** baca policy — pastikan URL in-scope; catat bentuk scope persis (host saja? wildcard?); konfirmasi **RoE mengizinkan otomasi** + batas rate; catat header penanda wajib (bila ada).
2. **Scope:** `in_scope` = **hanya** aset dari policy; isi `out_scope` untuk pengecualian.
3. **Scan:** `targets` = URL HTTPS; `rps` **konservatif (5–10)** dan/atau centang `stealth`; mulai dari satu endpoint.
4. **Proxy (opsional, disarankan):** route lewat Burp (`http://host.docker.internal:8080`) untuk audit + suntik header penanda.
5. **Triase → Report:** verifikasi manual (Burp Repeater), export draft H1/Bugcrowd. **Submit manual.**

> IP publik in-scope **boleh** dijangkau; yang ditolak adalah out-of-scope & IP privat (kecuali eksplisit). Roster agresif (`nuclei-dast`, `ffuf`) mengirim banyak request — untuk target nyata pertimbangkan roster lebih ringan + stealth.

---

## 5. Troubleshooting cepat

| Gejala | Sebab & perbaikan |
| --- | --- |
| "out of scope" / ditolak | Target tidak ada di `in_scope` (default-deny). Tambahkan host/IP-nya. |
| OpenAPI `cannot unmarshal !!str http://...` | Kamu isi **URL** di field `openapi`; isi **ISI spec** atau kosongkan. |
| SQLi/XSS tak muncul | Tak ada URL ber-parameter di `targets`/`seeds`, atau `nuclei-dast`/`dalfox` tak di roster. |
| ZAP tak menemukan injeksi | Mode `quick` = pasif; butuh startup `-zap-mode full`. |
| SAST "dinonaktifkan" | Server jalan tanpa `-sast-root`; set root + pakai `subpath` yang benar. |
| Proxy ke Burp gagal dari container | Pakai `host.docker.internal:8080`, bukan `127.0.0.1:8080`. |
| retire/findsecbugs tak ada | Image di-build tanpa `WITH_RETIRE`/`WITH_FINDSECBUGS`; rebuild + tambah ke roster. |
| Scan kelamaan / salah target | Tekan **Stop** di Dashboard ▸ Proses scanning. Tak perlu restart container (restart menghentikan semua run). |
