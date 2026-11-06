# BugHound — Extension Burp Suite (Montoya)

Extension kecil yang menarik **temuan** dari BugHound langsung ke dalam Burp
Suite, lalu **mengirim request-nya ke Repeater** untuk kamu validasi manual —
tanpa pindah-pindah tool.

Alurnya searah dan sengaja dibatasi:

```
BugHound  ──(GET /api/v1/findings, HTTP Basic)──▶  Extension Burp  ──▶  Repeater (Send manual oleh kamu)
```

- Extension **hanya membaca** dari BugHound (tidak pernah menulis/mengubah).
- **Tidak ada auto-submit / auto-scan.** Mengirim request ke target tetap aksi
  manual kamu lewat tombol **Send** di Repeater.
- Password tidak disimpan ke disk — isi ulang per sesi Burp.

---

## 1. Prasyarat

- **JDK 17+** (Burp modern berjalan di Java 17+).
- **Gradle 8+** terpasang, _atau_ buat wrapper dengan `gradle wrapper` lalu
  pakai `./gradlew`.
- **Burp Suite** (Community atau Professional) yang mendukung Montoya API.
- BugHound berjalan dengan API aktif (lihat bagian **API** di bawah).

## 2. Build

Dari folder `burp-ext/`:

```bash
gradle shadowJar        # atau: ./gradlew shadowJar
```

Hasil: **`build/libs/bughound-burp.jar`** (Gson sudah dibundel di dalamnya;
Montoya API tidak — itu disediakan Burp saat runtime).

> Jika resolusi dependency gagal, buka `build.gradle` dan sesuaikan versi
> `montoya-api` ke rilis terbaru di Maven Central. API inti yang dipakai
> extension ini (`registerSuiteTab`, `HttpService`, `HttpRequest`,
> `repeater().sendToRepeater`) stabil lintas versi.

## 3. Load ke Burp

`Extensions` → `Installed` → `Add` → Extension type: **Java** → pilih
`build/libs/bughound-burp.jar` → `Next`.

Di tab **Output** akan muncul: `bughound: extension dimuat — buka tab 'BugHound'.`
dan muncul tab baru bernama **BugHound**.

## 4. Pakai

Di tab **BugHound**:

1. Isi **BugHound URL** (default `http://127.0.0.1:8787`), **user**, **pass**
   (akun BugHound-mu), dan **program** (nama program persis seperti di BugHound,
   mis. `juice-lab-v4`).
2. Klik **Muat temuan** → tabel terisi (Severity, Type, Title, Method, URL).
3. Pilih satu baris → **Kirim ke Repeater**. Request-nya (dari
   `evidence.request` bila ada; kalau tidak, GET ke URL lokasi) muncul sebagai
   tab Repeater baru `bh:<judul singkat>`.
4. Di Repeater, tekan **Send** sendiri untuk memvalidasi. Dari titik ini kamu
   bekerja seperti biasa di Burp.

## 5. API BugHound yang dikonsumsi (read-only)

Extension memakai API JSON baca-saja BugHound (lihat `internal/web/api.go`).
Berguna juga untuk skrip/otomasi lain:

| Endpoint | Keterangan |
| --- | --- |
| `GET /api/v1/findings?program=<nama>` | Daftar temuan satu program (JSON). Opsi: `run_id`, `status`, `severity` (dipisah koma), `include_duplicates=1`. |
| `GET /api/v1/findings/{id}` | Satu temuan lengkap (skema seragam, termasuk `evidence.request`). |

Autentikasi: **HTTP Basic** dengan akun BugHound (jalur otomasi yang sudah ada;
GET tidak perlu CSRF). Tanpa kredensial → `401`. Contoh:

```bash
curl -u admin:ubah-saya-2026 \
  'http://127.0.0.1:8787/api/v1/findings?program=juice-lab-v4'
```

## 6. Catatan keamanan

- **Read-only & tanpa auto-submit**: API BugHound yang dipakai hanya `GET`;
  extension tidak mengubah data BugHound dan tidak pernah mengirim request ke
  target secara otomatis. Egress/scope guard/rate limiter BugHound tetap
  mengatur scan BugHound sendiri; extension ini di luar jalur itu (hanya
  handoff baca → Repeater).
- **Scope**: Repeater mengirim ke host apa pun yang kamu tekan **Send**. Pastikan
  target in-scope program bug bounty-mu — ini tanggung jawabmu di Burp, sama
  seperti Repeater biasa.
- **Kredensial**: user/pass BugHound hanya ada di memori UI extension; tidak
  dipersist. Pakai akun berperan baca bila cukup.
- **Transport**: untuk BugHound non-lokal, taruh di belakang TLS (mis. reverse
  proxy) agar Basic auth tidak lewat polos.

## 7. Struktur

```
burp-ext/
  build.gradle, settings.gradle   # build (shadow jar, montoya compileOnly, gson)
  src/main/java/bughound/burp/
    BughoundExtension.java         # entry point (BurpExtension)
    BughoundPanel.java             # UI tab + aksi kirim-ke-Repeater
    ApiClient.java                 # klien HTTP Basic ke API BugHound (GET saja)
    Models.java                    # model JSON (Finding/Location/Evidence)
```
