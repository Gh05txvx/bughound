# Spesifikasi — Scope Guard (bughound)

Oct 21, 2026 · @Gh05t

Scope guard adalah kontrol keamanan paling kritis di bughound: satu titik penegakan yang memastikan hanya target in-scope yang boleh disentuh, dan menolak sisanya secara default. Karena bughound adalah tool offensive, kegagalan scope guard berdampak hukum dan reputasi. Dokumen ini mendefinisikan format scope, normalisasi, algoritma keputusan, presedensi, kasus tepi, dan titik penegakan secara pasti, agar implementasi, audit (BH-P03-APPSEC), dan test (BH-P05-E2E) sepakat pada definisi yang sama. ID: `BH-SPEC-SCOPE`.

## Ringkasan & peran

Scope guard menjawab satu pertanyaan untuk setiap target: **boleh disentuh atau tidak?** Jawabannya mengikat seluruh aktivitas scan. Bila guard salah meloloskan satu target, bughound bisa memindai aset yang tidak diizinkan, dan itu konsekuensi hukum, bukan sekadar bug.

Karena itu guard dirancang dengan sikap paling konservatif: **default deny**. Target hanya diizinkan bila terbukti in-scope dan tidak terbukti out-of-scope. Semua keraguan berujung tolak.

Guard ini dirujuk oleh tiga pihak yang harus sepakat pada definisi yang sama:

- **Implementasi** menegakkannya di jalur eksekusi.
- **Audit (BH-P03-APPSEC)** mengujinya paling keras, mencari cara membypass.
- **E2E (BH-P05-E2E)** mengetesnya paling awal, memastikan target luar scope ditolak di UI.

## Prinsip

1. **Default deny.** Bila tidak terbukti in-scope, tolak. Tidak ada "mungkin boleh".
2. **Out-of-scope menang.** Bila sebuah target cocok in-scope sekaligus out-of-scope, hasilnya tolak. Pengecualian selalu mengalahkan izin.
3. **Satu titik penegakan.** Keputusan diambil di satu modul (scope guard). Tidak ada komponen lain yang punya logika scope sendiri.
4. **Tak bisa dilewati.** Tidak ada jalur eksekusi scan yang bisa mencapai target tanpa melewati guard. Ini sifat struktural, bukan konvensi.
5. **Deterministik.** Input yang sama selalu memberi keputusan yang sama; tidak bergantung waktu atau urutan.
6. **Fail closed.** Bila guard error atau scope tidak bisa diurai, hasilnya tolak, bukan loloskan.
7. **Keputusan tercatat.** Setiap penolakan (dan izin, minimal ringkas) masuk audit trail.

## Format input scope

Sebuah program punya dua daftar: **in-scope** dan **out-of-scope**. Tiap entri memakai salah satu bentuk berikut.

| Bentuk | Contoh | Cocok dengan |
| --- | --- | --- |
| Domain eksak | `app.acme.io` | Host itu saja |
| Wildcard subdomain | `*.acme.io` | Semua subdomain acme.io (lihat aturan wildcard) |
| URL / prefix path | `https://acme.io/api/` | URL di bawah prefix itu |
| Alamat IP | `203.0.113.10` | IP itu saja |
| Rentang CIDR | `203.0.113.0/24` | Semua IP dalam rentang |

Aturan:

- Daftar out-of-scope memakai bentuk yang sama dan dievaluasi dengan presedensi lebih tinggi.
- Entri yang tidak bisa diurai ditolak saat input (guard fail closed), dan pengguna diberi tahu, bukan diam-diam diabaikan.
- Skema input disimpan apa adanya untuk audit; pencocokan dilakukan pada bentuk ternormalisasi (bagian berikutnya).
- Bentuk yang tidak didukung di v1 (mis. regex bebas) ditolak, bukan ditebak maknanya.

## Normalisasi target & scope

Sebelum dibandingkan, target dan entri scope dinormalkan ke bentuk kanonik yang sama. Normalisasi mencegah bypass lewat variasi penulisan.

Langkah normalisasi host:

- **Huruf kecil** seluruh host.
- **Buang skema** (`https://`, `http://`) dan kredensial userinfo (`user:pass@`).
- **IDN ke punycode** (`xn--`), lalu bandingkan dalam bentuk punycode. Ini menutup bypass lewat homoglyph/unicode.
- **Buang titik akhir** (trailing dot) pada FQDN.
- **Port**: pisahkan host dan port. Kebijakan port default v1: scope berbasis host mencakup semua port kecuali entri menyebut port eksplisit (pertanyaan terbuka bila perlu lebih ketat).
- **Path**: untuk entri URL, bandingkan path setelah dinormalkan (resolusi `.`/`..`, decoding persen yang aman, hilangkan slash ganda).

Langkah normalisasi IP:

- Normalkan representasi (mis. IPv6 dikompres konsisten; tolak atau normalkan bentuk desimal/oktal yang menyesatkan seperti `0x7f.0.0.1`).
- Bandingkan IP sebagai nilai numerik dalam rentang CIDR, bukan sebagai string.

Setelah normalisasi, target direpresentasikan sebagai pasangan (host-atau-IP ternormalkan, port, path) yang dipakai algoritma keputusan.

## Algoritma keputusan

Untuk setiap target, guard menjalankan langkah berurutan berikut. Urutannya penting: out-of-scope diperiksa lebih dulu agar selalu menang, dan default-nya tolak.

> _Diagram: keputusan scope guard · out-of-scope menang, default deny — tersedia di versi Claude Docs (tidak terbawa ke ekspor Markdown)._

Dibaca sebagai aturan: **tolak bila cocok out-of-scope; jika tidak, izinkan hanya bila cocok in-scope; selain itu tolak.** Normalisasi selalu dijalankan lebih dulu agar perbandingan adil. Bila normalisasi atau pencocokan gagal/error, hasilnya tolak (fail closed).

## Presedensi & aturan pencocokan

**Presedensi:** out-of-scope selalu menang. Sebuah target yang cocok dengan entri in-scope *dan* entri out-of-scope diperlakukan sebagai out-of-scope (tolak). Ini memungkinkan pola umum "izinkan `*.acme.io` kecuali `admin.acme.io`".

**Aturan wildcard (`*.domain`):**

- `*.acme.io` cocok dengan subdomain seperti `app.acme.io` dan `a.b.acme.io`.
- Secara default `*.acme.io` **tidak** mencakup apex `acme.io` itu sendiri; bila apex juga in-scope, ia harus didaftarkan terpisah. (Kebijakan ini dinyatakan eksplisit agar audit dan test sepakat.)
- Wildcard hanya di posisi subdomain paling kiri; bentuk seperti `a.*.io` tidak didukung di v1.

**Pencocokan host:** perbandingan dilakukan pada label domain yang sudah dinormalkan (punycode, huruf kecil), bukan substring. `notacme.io` tidak cocok dengan entri `acme.io`, dan `acme.io.evil.com` tidak cocok dengan `acme.io`.

**Pencocokan IP/CIDR:** IP target diuji keanggotaannya dalam rentang CIDR secara numerik.

**Pencocokan URL/path:** entri prefix path cocok bila host sama dan path target berada di bawah prefix (batas segmen), bukan sekadar awalan string.

## Kasus tepi

Kasus yang sering jadi celah bypass dan cara guard menanganinya:

| Kasus | Risiko | Kebijakan guard |
| --- | --- | --- |
| Redirect saat scan | Scan diarahkan ke host luar scope | Host tujuan redirect dievaluasi ulang; di luar scope = berhenti, tidak diikuti |
| IP privat / metadata | SSRF ke 169.254.169.254, 10.0.0.0/8, dll | Rentang privat/link-local ditolak kecuali eksplisit in-scope (default deny lebih ketat di sini) |
| Homoglyph / IDN | `аcme.io` (huruf Cyrillic) menyamar | Dinormalkan ke punycode sebelum dibandingkan |
| IP menyesatkan | `0x7f.0.0.1`, desimal, oktal | Dinormalkan ke bentuk kanonik atau ditolak |
| Port tak terduga | Target di port lain | Sesuai kebijakan port (lihat Normalisasi); bila ketat, port di luar daftar ditolak |
| Apex vs wildcard | `acme.io` lolos lewat `*.acme.io` | Apex tidak tercakup wildcard kecuali didaftarkan |
| Case & trailing dot | `ACME.io`, `acme.io.` | Dinormalkan sebelum dibandingkan |
| Credential di URL | `user:pass@acme.io` | Userinfo dibuang saat normalisasi; host tetap diuji |
| Out-of-scope tumpang in-scope | `admin.acme.io` dalam `*.acme.io` | Out-of-scope menang, tolak |

Setiap kasus di tabel ini sebaiknya punya test E2E atau unit tersendiri, karena inilah yang paling mungkin diserang saat audit.

## Penegakan di runtime

Memeriksa scope hanya saat input tidak cukup. Target bisa berubah di tengah jalan (redirect, URL baru dari crawling, permintaan yang dibuat engine). Karena itu guard ditegakkan di **dua lapis**:

1. **Saat input/perencanaan.** Semua target awal (dari scope, recon, crawling) disaring sebelum masuk antrean scan. Yang di luar scope dibuang di sini.
2. **Saat egress, tepat sebelum koneksi keluar.** Setiap permintaan yang akan dikirim engine worker ke jaringan diperiksa ulang terhadap guard. Ini menutup target yang muncul di runtime (redirect, link baru) yang tidak terlihat saat perencanaan.

Lapis kedua adalah yang membuat jaminan "tidak pernah menyentuh aset luar scope" benar-benar struktural: sekalipun ada bug di tahap sebelumnya, koneksi keluar tetap dihadang. Idealnya diperkuat lagi dengan pembatasan jaringan di level lingkungan (allowlist egress), sebagai pertahanan berlapis.

Guard tidak boleh bisa dinonaktifkan lewat konfigurasi biasa. Tidak ada flag "lewati scope guard" untuk kenyamanan; mematikannya (bila ada, untuk pengujian internal) harus jelas, tercatat, dan tidak mungkin aktif di jalur produksi.

## Logging & audit

Setiap keputusan guard yang menolak dicatat ke audit trail dengan: waktu, target (ternormalkan), program, run\_id, alasan (out-of-scope / tidak in-scope / gagal urai), dan entri scope yang memicu (bila penolakan karena out-of-scope).

- Penolakan di lapis egress diperlakukan sebagai sinyal penting: bila sering terjadi, itu bisa menandakan bug di tahap perencanaan atau upaya penyalahgunaan.
- Audit trail scope tidak boleh bisa dihapus diam-diam (sejalan prinsip audit trail bughound).
- Target yang diizinkan boleh dicatat ringkas (minimal jumlah/agregat) agar jejak lengkap tersedia untuk audit (BH-P03-APPSEC), tanpa membebani log.

Log ini adalah bukti utama saat audit pre-launch menilai apakah scope guard benar-benar menegakkan batas.

## Pertanyaan terbuka

> Direkonsiliasi dengan implementasi 2026-11-04. `[x]` = sudah diputuskan/diimplementasi, `[ ]` = masih terbuka.

- [x] Kebijakan port: **default v1 = scope berbasis host mencakup semua port**, kecuali entri menyebut port eksplisit (lihat §Format di atas). Pengetatan ke 80/443-saja tetap opsi masa depan bila dibutuhkan.
- [x] Apex + wildcard: **tetap dipisah** — `*.domain` hanya mencakup subdomain (wildcard di posisi paling kiri), apex harus didaftarkan sebagai entri sendiri (`internal/scope/entry.go`). Pilihan yang lebih ketat dan aman.
- [x] IP privat/metadata: **tolak saat connect kecuali eksplisit in-scope** (IP/CIDR). Dialer egress menolak loopback/privat/link-local/metadata lalu me-*pin* IP yang sudah dicek (anti-rebinding). Lihat `BH-AUDIT-M2` BH-F02, `internal/egress/ssrf_test.go`.
- [ ] Format scope platform: **importer HackerOne/Bugcrowd belum dibuat**; scope dimasukkan dalam bentuk kanonik dokumen ini. (Ekspor report ke format platform sudah ada; impor scope belum.)
- [x] Penegakan egress: **di aplikasi (proxy paksa)** — engine aktif dipaksa lewat `-proxy` + env `HTTP(S)_PROXY`/`ALL_PROXY`. Allowlist jaringan / kontainer per scan = hardening opt-in; residual egress non-HTTP diterima untuk threat model saat ini (ADR `BH-ADR-egress-isolation`, BH-F03).
- [x] Resolusi DNS: **ya, ditolak** — hostname in-scope yang resolve ke IP out-of-scope/privat ditolak saat connect dengan IP-pinning (mencegah DNS rebinding). Lihat BH-F02.

Catatan: jawaban condong ke lebih ketat seperti diarahkan; scope guard tetap default-deny.
