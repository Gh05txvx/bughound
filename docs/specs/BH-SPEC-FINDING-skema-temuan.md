# Spesifikasi — Skema Temuan Seragam (BugHound)

Oct 21, 2026 · @Gh05t

Skema temuan seragam adalah fondasi BugHound: satu format tunggal yang menjadi tujuan normalisasi semua engine (recon & DAST), dan sumber data untuk triase serta report. Dokumen ini mendefinisikan field, tipe, enum, struktur bukti, kunci dedup, dan aturan versioning secara pasti, agar semua komponen (engine adapter, store, triase, report, UI) sepakat pada satu bentuk data. ID: `BH-SPEC-FINDING`.

## Ringkasan & peran

Setiap engine (nuclei, httpx, ZAP, dll) menghasilkan output dengan bentuk berbeda. **Temuan** adalah satu catatan ternormalisasi: satu isu keamanan pada satu lokasi, dalam bentuk yang sama apa pun engine asalnya.

Skema ini jadi titik temu semua komponen:

- **Engine adapter** menulis ke skema (menormalkan output mentah).
- **Store** menyimpan temuan dalam bentuk skema.
- **Triase** membaca skema untuk dedup, skoring, dan prioritas.
- **Report generator** menyusun draft dari field skema.
- **Web UI** menampilkan dan memfilter berdasarkan field skema.

Karena itu, perubahan pada skema berdampak ke semua komponen. Skema harus stabil, berversi, dan cukup kaya untuk triase dan report tanpa harus kembali ke output mentah engine.

## Prinsip desain skema

1. **Netral terhadap engine.** Tidak ada field yang khusus satu engine. Detail khas engine disimpan di `raw` (lihat field), bukan mengotori skema inti.
2. **Cukup untuk triase dan report.** Field dipilih agar triase (dedup, severity, prioritas) dan report (judul, langkah, dampak, bukti) bisa jalan tanpa membuka output mentah.
3. **Stabil dan berversi.** Skema punya `schema_version`. Field baru ditambah secara aditif; field lama tidak dihapus sembarangan (lihat Versioning).
4. **Identitas stabil.** Tiap temuan punya `id` unik dan `dedup_key` deterministik, agar duplikat lintas scan/engine bisa digabung dengan andal.
5. **Aman secara bawaan.** Skema tidak pernah menyimpan secret mentah; bukti dibersihkan sebelum masuk (sejalan prinsip keamanan BugHound).
6. **Format pertukaran: JSON.** Representasi kanonik adalah JSON (UTF-8). Penyimpanan boleh apa pun (DB relasional/dokumen) selama bisa memetakan ke bentuk JSON ini.
7. **Waktu dalam UTC ISO 8601.** Semua timestamp memakai format `YYYY-MM-DDThh:mm:ssZ`.

## Field inti skema

Satu temuan adalah objek JSON dengan field berikut. "Wajib" berarti harus ada di setiap temuan yang tersimpan.

| Field | Tipe | Wajib | Keterangan |
| --- | --- | --- | --- |
| schema\_version | string | ya | Versi skema, mis. `"1.0"` |
| id | string (UUID) | ya | Identitas unik temuan |
| dedup\_key | string | ya | Kunci deterministik untuk menggabung duplikat |
| program | string | ya | Program bounty terkait |
| run\_id | string | ya | Run yang menghasilkan temuan |
| target | string | ya | Aset yang diuji (URL/host); wajib in-scope |
| type | string | ya | Jenis kerentanan, slug stabil (mis. `xss`, `ssrf`, `info-disclosure`) |
| title | string | ya | Judul ringkas temuan |
| description | string | tidak | Penjelasan isu |
| severity | enum | ya | `info` / `low` / `medium` / `high` / `critical` |
| confidence | enum | ya | `low` / `medium` / `high` (keyakinan otomatis, sebelum verifikasi manual) |
| cvss | object | tidak | `{ version, vector, score }` bila ada |
| cwe | string\[\] | tidak | Daftar id CWE, mis. `["CWE-79"]` |
| tags | string\[\] | tidak | Label bebas untuk filter |
| owasp | string | tidak | Kategori OWASP Top 10 2021 (mis. `A03:2021`); aditif, hasil klasifikasi best-effort dari cwe/tags/type. `type` native tetap sumber presisi & basis dedup |
| location | object | ya | Lokasi spesifik temuan (lihat bagian Struktur) |
| evidence | object | tidak | Bukti: request/response, payload, referensi screenshot |
| reproduction | string\[\] | tidak | Langkah reproduksi terurut |
| impact | string | tidak | Dampak konkret untuk report; diisi saat triase/lengkapi-draft |
| source\_engine | string | ya | Engine asal, mis. `nuclei`, `zap` |
| source\_template | string | tidak | Id template/rule asal (mis. id template nuclei) |
| references | string\[\] | tidak | Tautan referensi (CVE, dokumentasi) |
| raw | object | tidak | Payload mentah khas engine, tidak dinormalkan |
| status | enum | ya | `new` / `confirmed` / `duplicate` / `false_positive` / `ignored` |
| duplicate\_of | string | tidak | `id` temuan utama bila `status = duplicate` |
| in\_report | boolean | tidak | Apakah sudah ditambahkan ke report (default `false`) |
| verified\_by | string | tidak | Anggota tim yang mengonfirmasi |
| created\_at | datetime | ya | Waktu temuan dihasilkan (UTC ISO 8601) |
| updated\_at | datetime | tidak | Waktu perubahan terakhir |

Field yang tidak diisi dihilangkan dari JSON (bukan diisi `null`), kecuali di mana `null` punya makna eksplisit.

## Enum

Nilai enum bersifat tertutup: hanya nilai di bawah yang sah. Menambah nilai baru memerlukan kenaikan `schema_version` (lihat Versioning).

**severity** (tingkat keparahan):

| Nilai | Arti |
| --- | --- |
| critical | Dampak sangat berat; diprioritaskan paling atas |
| high | Dampak berat |
| medium | Dampak sedang |
| low | Dampak kecil |
| info | Informasional; bukan kerentanan langsung |

**status** (status triase):

| Nilai | Arti |
| --- | --- |
| new | Baru, belum ditriase |
| confirmed | Terverifikasi manual; layak masuk report |
| duplicate | Duplikat dari temuan lain (`duplicate_of` diisi) |
| false\_positive | Dinilai bukan temuan nyata |
| ignored | Sengaja diabaikan (mis. accepted risk, di luar minat) |

**confidence** (keyakinan otomatis sebelum verifikasi manual):

| Nilai | Arti |
| --- | --- |
| high | Engine sangat yakin (mis. match pasti) |
| medium | Perlu pemeriksaan |
| low | Indikasi lemah; rawan false positive |

Severity berasal dari engine/template atau skoring CVSS; confidence berasal dari engine. Keduanya boleh ditimpa manual saat triase, dan perubahannya tercatat di audit trail.

## Struktur evidence & lokasi

**location** menunjuk di mana persisnya temuan berada. Bentuk objek:

```json
{
  "url": "https://api.acme.io/fetch",
  "method": "POST",
  "parameter": "url",
  "param_location": "body"
}
```

- `url` (wajib di dalam location): URL spesifik yang terdampak.
- `method` (opsional): metode HTTP bila relevan.
- `parameter` (opsional): nama parameter yang jadi titik masuk.
- `param_location` (opsional): `query` / `body` / `header` / `cookie` / `path`.

**evidence** menyimpan bukti yang sudah dibersihkan dari secret. Bentuk objek:

```json
{
  "request": "POST /fetch HTTP/1.1\nHost: api.acme.io\n...",
  "response_excerpt": "HTTP/1.1 200 OK\n...",
  "payload": "http://169.254.169.254/latest/meta-data/",
  "matched": "ami-id",
  "screenshot_ref": "blob://findings/abc123/1.png"
}
```

- Semua sub-field opsional, tapi minimal satu sebaiknya ada agar temuan bisa diverifikasi.
- `request` / `response_excerpt`: potongan HTTP, dipangkas dan dibersihkan dari kredensial.
- `payload`: payload yang memicu temuan.
- `matched`: bagian respons yang cocok dengan pola.
- `screenshot_ref`: rujukan ke bukti biner di store (bukan data inline), agar skema tetap ringan.

Aturan keamanan: sebelum masuk `evidence`, nilai header otentikasi, token, dan kredensial **wajib disensor**. Skema tidak pernah menyimpan secret mentah.

## Kunci dedup

`dedup_key` membuat dua temuan yang "pada dasarnya sama" punya kunci identik, sehingga triase bisa menggabungkannya. Kunci dihitung deterministik dari field yang menentukan identitas sebuah isu, bukan dari detail yang berubah tiap scan.

Resep default v1:

```text
dedup_key = sha256( lower(type) + "|" + host(target) + "|" + path(location.url) + "|" + upper(location.method) + "|" + (location.parameter | "") )
```

- `type`: jenis kerentanan (bukan judul bebas).
- `host(target)`: host dari target, tanpa skema dan **tanpa port** (port sengaja dikecualikan dari kunci).
- `path(location.url)`: path URL, tanpa query string (nilai query berubah-ubah).
- `location.method`: metode HTTP, dinormalkan huruf besar; kosong bila tak relevan (mis. ffuf/retire/SAST). Memisahkan mis. `GET` vs `POST` pada path+parameter yang sama agar tak salah gabung.
- `location.parameter`: nama parameter bila ada, string kosong bila tidak.

Untuk tipe **site-wide** (isu tingkat origin: header keamanan absen, CSP, CORS, dll. — lihat `siteWide()` di `internal/finding/dedup.go`), `path` **dan** `method` diabaikan (identitas = origin), sehingga kemunculan di banyak URL mengolaps jadi satu.

Yang **tidak** masuk kunci: `run_id`, `source_engine`, timestamp, payload spesifik, nilai query, dan port target. Dengan begitu, isu XSS yang sama pada parameter yang sama tetap satu temuan walau ditemukan dua engine berbeda atau di dua run berbeda.

Saat dedup terjadi, temuan baru diberi `status = duplicate` dan `duplicate_of` menunjuk temuan utama; atau implementasi boleh menyimpan satu temuan dengan daftar kemunculan. Keputusan penyimpanan itu ada di spec store, tapi kunci dan maknanya tetap sesuai dokumen ini.

Catatan: resep tetap sengaja sederhana. Penyempurnaan `method` (agar `GET` vs `POST` tak salah gabung) dan kolaps site-wide **sudah diterapkan** di `internal/finding/dedup.go` (lihat checklist "Pertanyaan terbuka" di bawah).

## Contoh temuan

Satu record lengkap:

```json
{
  "schema_version": "1.0",
  "id": "f1a2b3c4-5d6e-7f80-9a1b-2c3d4e5f6071",
  "dedup_key": "9f2c...e41a",
  "program": "acme-public",
  "run_id": "run_20261021_0912",
  "target": "https://api.acme.io",
  "type": "ssrf",
  "title": "SSRF pada parameter url di /fetch",
  "description": "Endpoint /fetch mengambil URL dari parameter tanpa validasi, memungkinkan permintaan ke jaringan internal.",
  "severity": "critical",
  "confidence": "medium",
  "cvss": { "version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:L", "score": 9.3 },
  "cwe": ["CWE-918"],
  "tags": ["ssrf", "cloud-metadata"],
  "location": {
    "url": "https://api.acme.io/fetch",
    "method": "POST",
    "parameter": "url",
    "param_location": "body"
  },
  "evidence": {
    "request": "POST /fetch HTTP/1.1\nHost: api.acme.io\nAuthorization: [REDACTED]\n\nurl=http://169.254.169.254/latest/meta-data/",
    "response_excerpt": "HTTP/1.1 200 OK\n...\nami-id\n...",
    "payload": "http://169.254.169.254/latest/meta-data/",
    "matched": "ami-id",
    "screenshot_ref": "blob://findings/f1a2b3c4/1.png"
  },
  "reproduction": [
    "Kirim POST ke /fetch dengan body url=http://169.254.169.254/latest/meta-data/",
    "Amati respons memuat metadata instance"
  ],
  "source_engine": "nuclei",
  "source_template": "ssrf-via-fetch",
  "references": ["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
  "status": "new",
  "in_report": false,
  "created_at": "2026-10-21T09:14:03Z"
}
```

Perhatikan header `Authorization` disensor menjadi `[REDACTED]` di `evidence.request`, sesuai aturan keamanan.

## Versioning & ekstensi

Skema diberi versi `MAYOR.MINOR` lewat `schema_version`.

- **Perubahan MINOR (aditif, kompatibel):** menambah field opsional baru, atau menambah nilai enum. Konsumen lama tetap bisa membaca. Naikkan MINOR (mis. `1.0` → `1.1`).
- **Perubahan MAYOR (merusak):** menghapus/mengganti nama field, mengubah tipe, membuat field opsional jadi wajib, atau menghapus nilai enum. Naikkan MAYOR (mis. `1.x` → `2.0`) dan sediakan migrasi.

Aturan praktis:

- Tambah dulu secara aditif; hindari perubahan MAYOR kecuali benar-benar perlu.
- Jangan pakai ulang nama field lama untuk makna berbeda.
- Detail khas engine tidak pernah jadi field inti; taruh di `raw`.
- Setiap kenaikan versi dicatat (changelog singkat), karena store, triase, report, dan UI mengandalkan kontrak ini.

Store harus menyimpan `schema_version` per temuan agar data lama tetap terbaca setelah skema naik versi.

### Riwayat versi

- `1.0` — skema awal (M0).
- `1.1` — tambah `impact` (dampak konkret untuk report; aditif).
- `1.2` — tambah `owasp` (kategori OWASP Top 10 2021; aditif, hasil klasifikasi best-effort).

## Pemetaan engine ke skema

Setiap engine punya satu adapter yang mengubah output mentahnya menjadi temuan skema. Adapter bertanggung jawab mengisi field wajib; sisanya diisi bila tersedia.

Contoh pemetaan (ilustratif, bukan final):

| Field skema | Dari nuclei | Dari ZAP |
| --- | --- | --- |
| type | `template-id` / `classification` | `pluginid` / alert name → slug |
| title | `info.name` | `alert` |
| severity | `info.severity` (dipetakan ke enum) | `risk` (dipetakan ke enum) |
| confidence | dari tipe match | `confidence` |
| cwe | `info.classification.cwe-id` | `cweid` |
| location.url | `matched-at` | `url` |
| location.parameter | dari match bila ada | `param` |
| evidence | request/response match | `evidence`, `attack`, `other` |
| source\_template | `template-id` | `pluginid` |
| references | `info.reference` | `reference` |
| raw | seluruh objek hasil nuclei | seluruh objek alert ZAP |

Tanggung jawab adapter:

- Memetakan severity/confidence engine ke enum skema (bukan menyalin mentah).
- Menyensor secret dari evidence sebelum menulis.
- Menghitung `dedup_key` sesuai resep di dokumen ini.
- Mengisi `source_engine` dan `schema_version`.

Karena semua engine bertemu di satu skema, menambah engine baru = menambah satu adapter, tanpa menyentuh triase, report, atau UI.

## Pertanyaan terbuka

> Direkonsiliasi dengan implementasi 2026-11-04. `[x]` = sudah diputuskan/diimplementasi (dengan bukti), `[~]` = sebagian, `[ ]` = masih terbuka.

- [x] Penyempurnaan `dedup_key`: kunci kini `sha256(lower(type)|host|path|method|parameter)` (`internal/finding/dedup.go`) — **metode HTTP ikut** agar GET vs POST pada path+parameter sama tak salah gabung; method dinormalkan huruf besar, kosong (ffuf/retire/SAST) tetap kosong, dan untuk tipe site-wide path+method diabaikan (identitas = origin). Port tetap sengaja dikecualikan.
- [x] Taksonomi `type`: **tetap slug native per-engine** (template-id nuclei, slug alert ZAP, dll) sebagai sumber presisi + basis dedup; **tidak** dibuat daftar kanonik tunggal. Korelasi lintas-engine ditangani field **aditif** `owasp` (OWASP Top 10 2021) hasil classifier best-effort (CWE → kata kunci tag/type) di `Finalize` — lihat `internal/finding/owasp.go`; tampil di finding detail, report, & export H1/Bugcrowd. Peta WASC sengaja tak dibuat (OWASP dipilih sebagai standar tunggal).
- [x] Severity: **sumber utama dari engine**, dipetakan per-adapter ke enum skema (`mapSeverity`/`mapRisk` di tiap `internal/engine/*/parse.go`). Tidak dihitung ulang dari CVSS.
- [x] Model penyimpanan dedup: **record terpisah dengan `duplicate_of`** menunjuk temuan utama; duplikat disembunyikan dari hitungan/report tetapi tersimpan utuh untuk audit. Ditegakkan per `(program, dedup_key)` di `internal/store` (Mem & SQLite), plus kolaps site-wide untuk isu origin-level.
- [x] Ukuran `evidence`: **batas inline diterapkan** — tiap sub-field tekstual dipotong di `Finding.Finalize` pada batas rune (maks 32 KiB/field) dengan penanda jumlah byte yang dibuang; `screenshot_ref` (referensi, bukan konten) tak dipotong. Batas longgar agar request tetap bisa diputar ulang (mis. ke Burp). Lihat `internal/finding/finding.go` (`clampFields`/`clampText`).
- [~] `program`/`run_id` vs `workspace`/`tenant`: multi-user hadir lewat **RBAC** (admin/operator/viewer, `internal/auth`) di atas **satu workspace bersama**; `program`+`run_id` tetap pembatas data. Partisi `workspace`/`tenant` sengaja belum ditambah (cukup untuk tim kecil).

Catatan: fondasi skema sudah tegak sejak M0; sisa item di atas adalah penyempurnaan, bukan penghambat.
