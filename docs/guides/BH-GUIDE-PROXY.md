# BH-GUIDE-PROXY — Proxy chain, endpoint echo IP & upstream proxy

> Panduan operasional menu **Proxy** (`/proxy`, nav *Pengujian*): menguji rantai upstream proxy sebelum dipakai scan, dan memverifikasi apakah IP yang dilihat target benar-benar berubah. Ditulis sesuai implementasi (`internal/egress`, `internal/web`). Terakhir diperbarui: 2026-11-03.

Menu ini **diagnostik**, bukan jalur scan. Rantai yang kamu masukkan di sini tidak otomatis dipakai scan — scan tetap mengambil rantai dari field **Upstream proxy / rantai** di form **Scan**. Gunakan menu Proxy untuk *membuktikan rantai bekerja & IP berubah*, lalu salin rantai yang terbukti ke form Scan.

---

## 1. Apa yang dilakukan menu Proxy

| Bagian | Selalu jalan? | Menyentuh target? | Keterangan |
| --- | --- | --- | --- |
| Validasi rantai | ya | tidak | Cek skema & format tiap hop. |
| Uji konektivitas hop | ya | **tidak** | Tiap hop di-reach berurutan (`hop_i` lewat `hop_1..hop_{i-1}`); hanya menyentuh **infrastruktur proxy milikmu**, bukan target scan. Melaporkan reachable + latensi + IP hasil-resolve. |
| Cek IP egress | opsional | ya (ke **echo**) | Dua GET ke endpoint echo — **langsung** vs **lewat rantai** — lalu bandingkan IP yang dilihat server echo → badge **"IP berubah"**. |

**Batas keamanan (tak bisa dimatikan dari menu ini):**

- **Echo tunduk scope guard program** (default-deny, `BH-SPEC-SCOPE`). Host echo yang tidak terbukti in-scope **ditolak** — sama seperti engine nyata.
- **Kredensial proxy** (`user:pass@`) **disensor** dari UI, pesan error, dan audit (`egress.check`). Tak pernah bocor.
- **IP-pinning / anti-SSRF**: target di-resolve & di-*pin* di host bughound sebelum rantai; IP privat/internal ditolak kecuali eksplisit in-scope.
- **Bounded**: diagnostik ini sekali-jalan (timeout 8 dtk/hop, 10 dtk/echo) — bukan flood. Rate limiter wajib berlaku di **scan**, diatur di form Scan.

---

## 2. Rantai proxy (upstream chain)

**Format:** satu hop per baris, **urut** (hop pertama di atas). Alur:

```
engine/bughound → hop1 → hop2 → … → hopN → target
```

**Skema yang didukung** (hop tak valid = *fail-closed*, scan/diagnostik tak jalan):

| Skema | Transport | Catatan |
| --- | --- | --- |
| `http://` | HTTP `CONNECT` | proxy HTTP biasa (Burp, Squid, dll). Host-level (tanpa MITM) → tak perlu pasang CA cert. |
| `https://` | HTTP `CONNECT` over TLS | koneksi ke proxy-nya terenkripsi. |
| `socks5://` | SOCKS5 | DNS di-resolve sisi bughound (lihat §6). |
| `socks5h://` | SOCKS5 | sama; resolusi target tetap di-pin di hulu. |

**Kredensial:** sematkan di URL → `skema://user:pass@host:port`. Didukung untuk HTTP (`Proxy-Authorization: Basic`) dan SOCKS5 (auth user/pass). **Ditampilkan tersensor** menjadi `skema://host:port`.

**Contoh rantai:**

```text
# satu hop (Burp)
http://127.0.0.1:8080

# satu hop SOCKS5 berkredensial (proxy komersial)
socks5://user:pass@gw.provider.example:1080

# multi-hop: lewat Burp lalu keluar via Tor
http://127.0.0.1:8080
socks5://127.0.0.1:9050
```

---

## 3. Upstream proxy — apa saja yang bisa dipakai

| Kategori | Contoh URL | Kapan dipakai |
| --- | --- | --- |
| **Burp Suite** (Proxy) | `http://127.0.0.1:8080` | melihat/merekam & memanipulasi traffic di Burp. |
| **OWASP ZAP** | `http://127.0.0.1:8080` | idem, lewat ZAP. |
| **mitmproxy** | `http://127.0.0.1:8080` | inspeksi/scripting traffic. |
| **Tor** | `socks5://127.0.0.1:9050` | keluar lewat jaringan Tor (anonimitas; hindari untuk program yang melarang Tor). |
| **SSH dynamic SOCKS** | `socks5://127.0.0.1:1080` (via `ssh -D 1080 user@jump`) | keluar lewat IP server lompatan (jump box / VPS). |
| **Proxy korporat / Squid** | `http://proxy.corp.local:3128` | wajib di jaringan kantor. |
| **Proxy komersial (residential/datacenter)** | `socks5://user:pass@host:port` atau `http://...` | **exit IP statis** yang di-allowlist program bug bounty. |

> **Catatan:** bughound hanya meneruskan egress HTTP/HTTPS lewat proxy (CONNECT/SOCKS). Egress non-HTTP (mis. DNS mentah engine) tidak lewat sini — itu urusan lapis OS (pertahanan berlapis).

---

## 4. Endpoint echo IP

**Tujuan:** sebuah URL yang membalas **IP klien yang dilihat server**. bughound mengambil token IP pertama dari body (teks polos atau JSON). Dengan membandingkan echo *langsung* vs *lewat rantai*, kamu tahu IP exit benar berubah.

**Requirement wajib:** host echo **harus in-scope** di program (default-deny). Kalau tidak, echo **ditolak scope guard** — itu disengaja (Prinsip #2: bughound tak menyentuh aset di luar scope, bahkan untuk diagnostik). Jadi:

> Endpoint echo adalah **infrastruktur diagnostikmu**, bukan bagian target. Untuk memakainya, **tambahkan host echo ke daftar in-scope** program secara sadar.

**Opsi endpoint echo:**

| Opsi | Contoh | Catatan |
| --- | --- | --- |
| **Echo milik sendiri** (disarankan) | VPS/lab kamu: `http://echo.lab.kamu/ip` | paling bersih; kamu kontrol penuh. Contoh nginx: `location / { return 200 "$remote_addr"; }`. |
| **Layanan publik** | `https://api.ipify.org`, `https://ifconfig.me/ip`, `https://icanhazip.com`, `https://checkip.amazonaws.com`, `https://ipinfo.io/ip` | hanya jika **kamu tambahkan ke in-scope** program. Pilih yang membalas IP sebagai teks polos agar parsing bersih. |

**Format body yang dikenali:** `203.0.113.9`, `{"ip":"203.0.113.9"}`, `your ip is 203.0.113.9` — token IPv4/IPv6 pertama diambil. Kosong bila tak ada IP.

---

## 5. Pakai untuk program bug bounty di luar (requirement)

Banyak program menuntut traffic datang dari **IP statis terdaftar** (VPN program, atau IP yang kamu declare di profil). Menu Proxy adalah cara memverifikasinya **sebelum** scan sungguhan.

**Requirement & langkah:**

1. **Exit IP statis** — siapkan upstream proxy yang IP keluarnya = IP yang di-allowlist program (VPS/jump box via `ssh -D`, atau proxy komersial statis). Rantai Tor/residential-rotating **tidak cocok** untuk program yang mewajibkan IP tetap.
2. **Scope presisi** — isi in-scope program dengan target resmi program (domain/wildcard/CIDR). Kalau mau verifikasi IP, **tambahkan host echo** (mis. `api.ipify.org`) ke in-scope juga.
3. **Verifikasi IP (menu Proxy)** — Program = program itu, Rantai = proxymu, Echo = endpoint in-scope → **Uji proxy**. Pastikan **IP exit** = IP yang didaftarkan program. Kalau "IP sama" / tak berubah, rantai belum efektif.
4. **Rate limit** — set di form **Scan** sesuai aturan program (bughound menjepit per-engine, maks 50/dtk).
5. **Auth proxy** — pakai `user:pass@` bila proxy komersial butuh (tersensor otomatis).
6. **Scan** — baru jalankan scan dengan rantai yang sama di form Scan. Report tetap **draft** (tanpa auto-submit).

**Checklist cepat sebelum scan program eksternal:**

- [ ] Exit IP proxy = IP terdaftar program (dibuktikan lewat menu Proxy).
- [ ] Target program sudah in-scope; out-of-scope diisi bila ada.
- [ ] Host echo (bila dipakai) ditambahkan in-scope.
- [ ] Rate limit sesuai aturan program.
- [ ] Rantai yang terbukti disalin ke form **Scan**.

---

## 6. Catatan teknis & batasan

- **Resolusi & IP-pin di hulu.** Target di-resolve ke IP di host bughound lalu di-*pin* (anti DNS-rebinding), baru koneksi ke IP itu diteruskan lewat rantai. Jadi `socks5` vs `socks5h` tak mengubah resolusi target (sudah di-pin); DNS target terjadi di sisi bughound, bukan di exit node.
- **Host-level pada HTTPS.** Untuk target HTTPS (tunnel CONNECT), scope guard menegakkan di level host:port (tanpa membongkar TLS). Tak perlu CA cert.
- **Hop = infra, bukan target.** Konektivitas hop tidak di-scope-check (hop memang proxy milikmu, sering loopback seperti Burp/Tor). Hanya **target & echo** yang melewati scope guard.
- **Fail-closed.** Hop/skema tak valid, atau echo out-of-scope → ditolak; tak ada koneksi diam-diam.
- **Audit.** Tiap uji tercatat `egress.check` (ringkasan hop, echo?, ip-berubah?); penolakan echo dicatat dengan alasan. Tanpa kredensial.

---

## 7. Resep uji-coba lokal (lab milik sendiri)

Membuktikan "IP berubah" butuh echo + proxy pada **IP berbeda** di jaringan lab sendiri (keduanya in-scope). Contoh pada `bughound-lab` (`172.30.0.0/24`):

```bash
# Echo: balas IP klien apa adanya
docker run -d --name lab-echo --network bughound-lab --ip 172.30.0.40 nginx:alpine
docker exec lab-echo sh -c 'printf "server { listen 80; location / { default_type text/plain; return 200 \"\$remote_addr\n\"; } }\n" > /etc/nginx/conf.d/default.conf && nginx -s reload'

# Proxy SOCKS5 (butuh kredensial, atau pakai -e REQUIRE_AUTH=false)
docker run -d --name lab-proxy --network bughound-lab --ip 172.30.0.50 \
  -e PROXY_USER=labuser -e PROXY_PASSWORD=labpass serjs/go-socks5-proxy
```

Di menu Proxy: Program dengan in-scope `172.30.0.0/24`, Rantai `socks5://labuser:labpass@172.30.0.50:1080`, Echo `http://172.30.0.40/`.
Harapan: hop **reachable** (kredensial tersensor), **IP sumber** (IP lab bughound) → **IP exit** `172.30.0.50`, **"IP berubah ✓"**.

Bersihkan: hapus program lewat endpoint ter-audit, lalu `docker rm -f lab-echo lab-proxy`.
