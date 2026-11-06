# Spesifikasi — Bank Payload & Template (bughound)

Oct 21, 2026 · @Gh05t

Bank payload adalah tempat semua template/payload yang dijalankan engine hidup, diatur, diperbarui, dan ditambah. Tujuannya: payload mudah di-update dan ditambah tanpa menyentuh kode bughound, sambil tetap aman dan tertelusur. Dokumen ini memilih modelnya (hibrida condong tipis: payload tetap dalam format asli engine, dengan satu lapisan katalog netral di atasnya), lalu mendefinisikan struktur bank, metadata, format, mekanisme update, dan aturan keamanan. ID: `BH-SPEC-PAYLOAD`.

## Ringkasan & peran

Engine (nuclei, ZAP, dll) tidak tahu apa yang harus dicek sampai diberi **template/payload**: aturan yang mendefinisikan satu pengujian. Bank payload adalah tempat semua template itu hidup, diatur, diperbarui, dan ditambah.

Bank ini menjembatani tiga hal:

- **Sumber** tempat template berasal (repo komunitas nuclei, direktori custom milik sendiri, feed eksternal).
- **Engine workers** yang menjalankan template saat scan.
- **Skema temuan** (`BH-SPEC-FINDING`): saat sebuah template menghasilkan temuan, id-nya terbawa ke field `source_template`, sehingga temuan bisa dilacak balik ke payload asalnya.

Nilai utama bank: payload bisa di-update dan ditambah tanpa menyentuh kode bughound, tetap aman (sumber luar diperlakukan tak tepercaya), dan tertelusur (tiap scan mencatat versi template yang dipakai).

## Prinsip desain

1. **Simpan dalam format asli engine.** Isi payload tidak diterjemahkan ke format sendiri. Template nuclei tetap YAML nuclei. Ini menghindari membangun ulang ekosistem yang sudah matang.
2. **Satu lapisan katalog netral di atasnya.** Bughound hanya menambahkan manifest metadata seragam yang mengatalogkan semua template, apa pun engine-nya, tanpa menyentuh isinya.
3. **Sumber bersifat pluggable.** Bank adalah kumpulan sumber yang bisa ditambah/dihapus lewat konfigurasi, bukan satu folder tetap.
4. **Payload adalah data, bukan kode.** Template tidak pernah ditanam di dalam kode bughound; ia dibaca dari sumber saat runtime, sehingga update = perbarui sumber, bukan rebuild.
5. **Aman secara bawaan.** Template dari luar diperlakukan tak tepercaya dan divalidasi sebelum dijalankan.
6. **Tertelusur.** Setiap scan mencatat sumber dan versi template yang dipakai, agar hasil bisa direproduksi dan diaudit.
7. **Mudah ditambah.** Menambah payload = menaruh satu file di sumber + metadata minimal, tanpa mengubah komponen lain.

## Model yang dipilih

Dipilih: **hibrida yang condong tipis.** Payload tetap native engine; bughound menambahkan katalog netral (metadata), bukan format payload baru.

Perbandingan tiga opsi:

| Model | Kelebihan | Kekurangan | Verdict |
| --- | --- | --- | --- |
| Tipis di atas engine | Paling cepat; ikut ekosistem nuclei | Fleksibilitas terikat format nuclei; sulit lintas engine | Terlalu sempit |
| Format payload netral sendiri | Portabel lintas engine | Harus bangun penerjemah + rawan membangun ulang nuclei | Over-engineering untuk tim kecil |
| **Hibrida condong tipis (dipilih)** | Payload native (murah) + katalog seragam (fleksibel update/tambah/aman) | Perlu disiplin menjaga metadata | Paling pas |

Alasan: isi payload yang diterjemahkan adalah pekerjaan besar dan rawan salah, sementara yang benar-benar kita butuhkan untuk "fleksibel update dan tambah" cukup di level katalog (metadata, sumber, update, keamanan). Format payload netral sendiri baru diperkenalkan nanti, hanya untuk cek yang tidak bisa diungkapkan engine mana pun, dan itu dicatat sebagai pertanyaan terbuka, bukan dibangun sekarang.

## Struktur bank & sumber

Bank bukan satu folder, melainkan kumpulan **sumber** yang didaftarkan di konfigurasi. Tiap sumber adalah repo/direktori berisi template dalam format native-nya. Di atas semua sumber, bughound membangun satu **katalog** (manifest) yang menyeragamkan metadata tiap template tanpa menyentuh isinya.

> _Diagram: struktur bank · sumber native → katalog netral → engine — tersedia di versi Claude Docs (tidak terbawa ke ekspor Markdown)._

Tiap sumber punya: lokasi (path atau URL repo), tipe engine, tingkat kepercayaan, dan cara update-nya. Menambah sumber = menambah satu entri konfigurasi. Katalog menyimpan untuk tiap template: id, sumber asal, engine, versi, dan metadata (severity default, tag, referensi). Engine workers memilih dan menjalankan template lewat katalog, bukan langsung menyentuh sumber. Feed eksternal yang tak tepercaya wajib melewati validasi sebelum masuk katalog (lihat Keamanan).

## Metadata katalog

Untuk tiap template, katalog menyimpan metadata seragam berikut, apa pun engine asalnya. Metadata inilah yang membuat bank bisa difilter, diprioritaskan, diperbarui, dan dilacak balik.

| Field | Tipe | Wajib | Keterangan |
| --- | --- | --- | --- |
| template\_id | string | ya | Id stabil unik di seluruh bank (mis. `nuclei:ssrf-via-fetch`) |
| source | string | ya | Id sumber asal (mis. `nuclei-community`, `custom`) |
| engine | string | ya | Engine yang menjalankan (mis. `nuclei`, `zap`) |
| native\_ref | string | ya | Lokasi/id template dalam format native-nya di sumber |
| name | string | ya | Nama ringkas yang terbaca manusia |
| type | string | tidak | Jenis kerentanan, selaras taksonomi `type` di skema temuan |
| severity\_default | enum | tidak | Severity bawaan (sesuai enum skema temuan) |
| tags | string\[\] | tidak | Label untuk seleksi (mis. `ssrf`, `cve`, `fast`) |
| references | string\[\] | tidak | Tautan referensi |
| trust | enum | ya | `trusted` / `review` / `untrusted` (menentukan perlakuan keamanan) |
| version | string | ya | Versi template (hash isi atau versi sumber) |
| enabled | boolean | ya | Apakah ikut dijalankan secara default |
| added\_at | datetime | tidak | Waktu masuk katalog |

`template_id` di sini adalah nilai yang terbawa ke `source_template` pada temuan, sehingga tiap temuan bisa dilacak balik ke payload dan versinya.

## Format satu template/payload

Satu template = **body native** (tidak disentuh) + **metadata**. Ada dua cara metadata disediakan:

1. **Diturunkan dari body native.** Untuk engine yang template-nya sudah memuat metadata (nuclei punya blok `info:` dengan name, severity, tags, reference), katalog mengekstraknya otomatis. Tidak perlu file tambahan.
2. **Sidecar.** Untuk payload yang format native-nya tidak membawa metadata, sediakan satu file sidecar `<nama>.meta.yaml` di sebelahnya yang mengisi field metadata katalog.

Contoh template nuclei (body native, metadata diturunkan dari `info:`):

```yaml
id: ssrf-via-fetch
info:
  name: SSRF via fetch parameter
  severity: high
  tags: [ssrf, cloud-metadata]
  reference:
    - https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
# ... bagian requests/matchers native nuclei di bawah ...
```

Contoh sidecar untuk payload non-nuclei (`myscan.meta.yaml`):

```yaml
template_id: custom:open-redirect-logout
engine: custom
name: Open redirect pada parameter logout
type: open-redirect
severity_default: medium
tags: [open-redirect, custom]
trust: trusted
```

Aturan: body native tidak pernah diedit oleh bughound. Bila metadata tidak lengkap dan tidak bisa diturunkan, template tetap masuk katalog tapi ditandai perlu dilengkapi, bukan diam-diam dipakai dengan metadata kosong.

## Mekanisme update & penambahan

**Update (memperbarui yang ada):**

- Tiap sumber punya cara update sendiri yang dipanggil bughound: `git pull` untuk repo, perintah update bawaan nuclei untuk template nuclei, unduh untuk feed.
- Perintah `bughound templates update` menjalankan update semua sumber (atau satu sumber), lalu me-refresh katalog.
- Perubahan isi terdeteksi lewat `version` (hash), sehingga katalog tahu apa yang berubah.

**Penambahan (menambah payload baru):**

- Tambah template native ke direktori sumber (mis. taruh file `.yaml` di direktori custom), lengkapi metadata (dari `info:` atau sidecar), lalu refresh katalog. Tidak perlu mengubah kode bughound.
- Menambah **sumber** baru = menambah satu entri konfigurasi (lokasi, engine, trust, cara update).

**Reproducibility & pinning:**

- Setiap run mencatat versi tiap template yang dipakai (snapshot katalog), agar hasil scan bisa direproduksi.
- Sumber bisa dipatok (pin) ke versi/commit tertentu, supaya update tidak mengubah perilaku tanpa sengaja. Update menjadi tindakan sadar, bukan kejutan.

**Seleksi:**

- Scan memilih template lewat metadata katalog (berdasarkan `tags`, `type`, `severity_default`, `enabled`), bukan menjalankan semua secara buta.

## Keamanan template tak tepercaya

Template adalah instruksi yang dieksekusi engine, jadi template berbahaya bisa membuat permintaan tak diinginkan, termasuk ke target di luar scope. Karena itu template dari luar diperlakukan tak tepercaya.

Aturan:

- **Tingkat trust eksplisit.** Tiap sumber ditandai `trusted` / `review` / `untrusted`. Hanya sumber `trusted` yang boleh jalan otomatis.
- **Review sebelum aktif.** Template dari sumber `review`/`untrusted` masuk katalog dalam keadaan `enabled = false` sampai ditinjau dan dinaikkan trust-nya secara sadar.
- **Scope guard tetap mengikat.** Apa pun yang diminta template, setiap koneksi keluar tetap melewati scope guard (`BH-SPEC-SCOPE`). Template tidak bisa memintas scope.
- **Validasi bentuk.** Template divalidasi terhadap skema format engine sebelum dipakai; yang tidak valid ditolak, bukan dijalankan.
- **Batasi kemampuan berbahaya.** Fitur template yang bisa mengeksekusi perintah lokal atau membaca file sistem (bila engine mendukungnya) dinonaktifkan atau dibatasi untuk template non-`trusted`.
- **Integritas sumber.** Update sumber dilakukan lewat kanal yang terverifikasi (mis. repo yang dikenal); perubahan tercatat lewat `version`.

Untuk pemakaian pribadi di awal, cukup pakai sumber yang kamu percaya (repo nuclei resmi + direktori custom milik sendiri). Aturan trust penuh menjadi penting saat bank menerima template dari luar atau tool dipakai orang lain.

## Integrasi

**Ke engine adapter.** Saat scan, orchestrator memilih template dari katalog (berdasarkan metadata), lalu menyerahkan `native_ref` ke engine adapter yang sesuai. Adapter menjalankan template dalam format native-nya; bank tidak menerjemahkan isi payload. Ini menjaga pemisahan: bank mengatur *apa yang tersedia dan dipilih*, adapter mengatur *bagaimana dijalankan*.

**Ke skema temuan.** Saat sebuah template menghasilkan temuan, adapter mengisi `source_template` di temuan dengan `template_id` dari katalog (`BH-SPEC-FINDING`). Dengan begitu setiap temuan bisa dilacak balik ke payload dan versinya, dan triase bisa, misalnya, meredam seluruh temuan dari satu template yang ternyata berisik.

**Ke config.** Daftar sumber, tingkat trust, pin versi, dan profil seleksi disimpan di konfigurasi bughound (modul Config di PRD), bukan di kode.

Hasilnya, menambah kemampuan deteksi baru = menambah template ke bank (atau menambah sumber), bukan menulis kode, selama engine-nya sudah didukung.

## Pertanyaan terbuka

> Direkonsiliasi dengan implementasi 2026-11-04. `[x]` = sudah diputuskan/diimplementasi, `[~]` = sebagian, `[ ]` = masih terbuka.

- [ ] Format payload netral sendiri: **masih sengaja ditunda** (hanya untuk cek yang tak bisa diungkapkan engine mana pun). Belum diperkenalkan.
- [x] `template_id` global: skema **`<engine>:<native-id>`** diterapkan (`internal/payload/payload.go`, `source.go`), unik dan stabil lintas sumber (yang pertama menang saat tabrakan id).
- [x] Metadata minimum untuk boleh `enabled`: diterapkan lewat `hasMinMeta`/`canEnable` — sebuah template hanya `enabled` otomatis bila dari sumber **trusted** DAN metadata minimumnya terpenuhi.
- [x] Pemetaan severity/tag native → seragam: dilakukan per-adapter engine saat normalisasi ke skema temuan (`mapSeverity` di tiap `internal/engine/*/parse.go`); katalog payload menyimpan `type`/severity selaras skema.
- [x] Profil seleksi ("jalankan tag X, severity >= Y" per program): **diimplementasi** sebagai preset per-program — `store.ScanPreset{Tags,Severity,Stealth}` pada `Program` (kolom `preset` di tabel `programs`, migrasi additif idempoten untuk DB lama), mem-prefill form scan saat program dipilih. Disimpan hanya bila pengguna mencentang "simpan preset" (scan biasa TIDAK menimpanya). Seleksi per-scan tetap lewat tags/severity + `enabled`/tingkat trust sumber; kosong = semua template. Preset tak menyentuh scope guard/egress/rate/secret.
- [~] Validasi keamanan template: **model trust diterapkan** (hanya sumber trusted yang auto-`enabled`) dengan scope guard sebagai jaring pengaman runtime utama; **sandbox eksekusi template lebih dalam ditunda** sesuai rencana v1.
- [x] Storage katalog: **snapshot dibangun saat runtime dari sumber direktori template pluggable** (`nuclei-dir`, `custom-dir` via `DefaultSources`/`Build`) — bukan di store temuan, dan tidak perlu manifest terpisah.

Catatan: yang paling mendesak (skema `template_id` dan metadata minimum) sudah terjawab karena keduanya mengikat ke `source_template` di skema temuan.
