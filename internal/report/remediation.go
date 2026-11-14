package report

import (
	"strings"

	"bughound/internal/finding"
)

// remediationFor mengembalikan panduan remediasi actionable untuk draft report,
// dipilih dari KELAS temuan (type/title/CWE, lalu kategori OWASP sebagai
// fallback). Urutan tiap entri: perbaikan akar → pertahanan berlapis → deteksi
// (selaras metodologi pelaporan: remediasi spesifik & ber-urutan, bukan
// "validasi input" generik). Konten defensif murni — bukan langkah eksploitasi;
// hunter boleh menyunting sebelum submit MANUAL (tanpa auto-submit).
//
// Deterministik & offline: tak memanggil jaringan/LLM, cocok untuk draft yang
// reproducible. Selalu mengembalikan minimal satu butir.
func remediationFor(f *finding.Finding) []string {
	// Normalkan tanda hubung→spasi agar type ber-hyphen ("file-upload",
	// "os-command-injection") cocok dengan kata kunci berspasi.
	hay := strings.ReplaceAll(strings.ToLower(f.Type+" "+f.Title), "-", " ")
	cwe := strings.ToUpper(strings.Join(f.CWE, " "))
	has := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(hay, s) {
				return true
			}
		}
		return false
	}
	hasCWE := func(ids ...string) bool {
		for _, id := range ids {
			if strings.Contains(cwe, id) {
				return true
			}
		}
		return false
	}

	switch {
	case has("sqli", "sql-injection", "sql injection", "nosql") || hasCWE("CWE-89", "CWE-943"):
		return []string{
			"Pakai prepared statement / parameterized query (atau ORM yang aman); jangan merangkai query dari input pengguna.",
			"Terapkan akun DB least-privilege dan matikan primitif berbahaya (xp_cmdshell, LOAD_FILE/INTO OUTFILE, COPY … PROGRAM) bila tak dibutuhkan.",
			"Alert pada pola anomali (UNION/SLEEP/komentar) di log query untuk deteksi dini.",
		}
	case has("xss", "cross-site scripting", "cross site scripting") || hasCWE("CWE-79"):
		return []string{
			"Encode output sesuai konteks (HTML/atribut/JS/URL); utamakan framework dengan auto-escaping.",
			"Pasang Content-Security-Policy ketat (tanpa unsafe-inline) sebagai pertahanan berlapis + sanitasi rich-text dengan allowlist.",
			"Set cookie sesi HttpOnly+Secure+SameSite agar dampak pencurian sesi berkurang.",
		}
	case has("ssrf", "server-side request forgery") || hasCWE("CWE-918"):
		return []string{
			"Validasi URL tujuan dengan allowlist host/skema; tolak IP privat/link-local (169.254.0.0/16, 10/8, 127/8) & endpoint metadata cloud.",
			"Fetch lewat egress proxy terkontrol, matikan redirect tak perlu, dan pin DNS→IP untuk cegah rebinding.",
			"Log tujuan outbound dari komponen server untuk deteksi akses internal mencurigakan.",
		}
	case has("ssti", "template injection") || hasCWE("CWE-1336"):
		return []string{
			"Jangan susun template dari input pengguna; perlakukan input sebagai DATA (variabel konteks), bukan sumber template.",
			"Pakai engine template ter-sandbox / logic-less dan nonaktifkan eval maupun akses atribut berbahaya.",
		}
	case has("xxe", "xml external entity") || hasCWE("CWE-611"):
		return []string{
			"Nonaktifkan resolusi external entity & DTD di parser XML (FEATURE_SECURE_PROCESSING / disallow-doctype-decl).",
			"Utamakan format less-kompleks (JSON) bila memungkinkan; validasi skema XML yang diterima.",
		}
	case has("deserial") || hasCWE("CWE-502"):
		return []string{
			"Hindari deserialisasi native atas data tak tepercaya; pakai format data murni (JSON) dengan skema ketat.",
			"Bila harus, terapkan allowlist tipe/kelas dan integrity-check (signature) pada objek terserialisasi.",
		}
	case has("command inject", "os command", "rce", "remote code execution") || hasCWE("CWE-77", "CWE-78"):
		return []string{
			"Jangan panggil shell dengan input pengguna; pakai API ber-argumen array (tanpa shell) + validasi allowlist ketat.",
			"Jalankan komponen dengan hak minimal dan isolasi (container/seccomp) untuk membatasi dampak.",
			"Monitor proses anak tak wajar yang dilahirkan layanan web.",
		}
	case has("idor", "bola", "broken access", "access control", "authorization", "privilege") || hasCWE("CWE-639", "CWE-284", "CWE-285", "CWE-862"):
		return []string{
			"Tegakkan otorisasi tingkat-objek di sisi server untuk SETIAP request (bandingkan pemilik resource vs identitas sesi); default-deny.",
			"Pakai identifier tak-tertebak (UUID) sebagai pelengkap, bukan pengganti, kontrol akses.",
			"Log akses lintas-objek/akun yang gagal untuk deteksi enumerasi.",
		}
	case has("open redirect", "open-redirect") || hasCWE("CWE-601"):
		return []string{
			"Validasi tujuan redirect dengan allowlist path/host relatif; tolak URL absolut eksternal.",
			"Bila redirect eksternal diperlukan, tampilkan interstitial konfirmasi.",
		}
	case has("file upload", "unrestricted upload", "arbitrary file") || hasCWE("CWE-434"):
		return []string{
			"Validasi tipe konten nyata (magic bytes) + allowlist ekstensi; pakai nama file yang di-generate server.",
			"Simpan di luar webroot / storage non-eksekusi dan sajikan lewat handler terpisah; matikan eksekusi di direktori upload.",
		}
	case has("request smuggling", "smuggling") || hasCWE("CWE-444"):
		return []string{
			"Normalkan parsing Content-Length vs Transfer-Encoding di semua hop; tolak request dengan header panjang ambigu.",
			"Selaraskan front-end & back-end (HTTP/2 end-to-end bila bisa) dan matikan connection reuse yang rawan.",
		}
	case has("parameter pollution", "hpp") || hasCWE("CWE-235"):
		return []string{
			"Kanonikalisasi parameter duplikat secara eksplisit (ambil first/last konsisten) di seluruh stack.",
			"Validasi tipe & jumlah parameter yang diharapkan; tolak yang berlebih.",
		}
	case has("cors") || hasCWE("CWE-942"):
		return []string{
			"Pakai allowlist origin ketat; jangan pantulkan Origin sembarang dan jangan gabungkan ACAO:* dengan credentials.",
			"Batasi method & header yang diizinkan seminimal mungkin.",
		}
	case has("jwt", "json web token") || hasCWE("CWE-347"):
		return []string{
			"Verifikasi signature dengan algoritma tetap dari sisi server; TOLAK alg \"none\" dan pergantian algoritma (mis. RS→HS).",
			"Pakai kunci/secret kuat + rotasi; validasi klaim exp/aud/iss.",
		}
	case has("oauth", "openid", "sso"):
		return []string{
			"Validasi redirect_uri dengan exact-match allowlist; wajibkan & verifikasi parameter state (anti-CSRF) + PKCE.",
			"Jangan bocorkan token lewat URL/Referer; pakai response_mode yang aman.",
		}
	case has("csrf", "cross-site request forgery") || hasCWE("CWE-352"):
		return []string{
			"Wajibkan anti-CSRF token per-sesi pada aksi state-changing; set cookie SameSite=Lax/Strict.",
			"Verifikasi Origin/Referer untuk request sensitif sebagai pertahanan berlapis.",
		}
	case has("exposed", "disclosure", "information leak", "info leak", "directory listing", "debug", "exposure") || hasCWE("CWE-200", "CWE-538"):
		return []string{
			"Hapus/retriksi akses ke path & artefak sensitif (.env, backup, .git, endpoint debug); kembalikan 404/403.",
			"Matikan mode debug/verbose error di produksi dan review header yang membocorkan versi.",
		}
	}

	// Fallback per kategori OWASP 2021 (kasar tapi tetap actionable).
	switch f.OWASP {
	case finding.A01:
		return []string{"Tegakkan otorisasi server-side yang konsisten untuk setiap aksi & objek; default-deny."}
	case finding.A02:
		return []string{"Pakai kriptografi & TLS kuat (hindari algoritma lemah/kunci statis); lindungi data sensitif saat transit & istirahat."}
	case finding.A03:
		return []string{"Perlakukan semua input sebagai tak tepercaya: parameterisasi/escape sesuai konteks interpreter (SQL/HTML/OS/template)."}
	case finding.A04:
		return []string{"Perbaiki akar desain: terapkan kontrol keamanan di alur bisnis (rate-limit, validasi state, batas kuota)."}
	case finding.A05:
		return []string{"Perketat konfigurasi: matikan fitur/endpoint tak terpakai, debug off, header aman, default yang aman."}
	case finding.A06:
		return []string{"Perbarui komponen/dependensi ke versi tanpa kerentanan; pantau advisory & kelola SBOM."}
	case finding.A07:
		return []string{"Perkuat autentikasi & sesi: MFA, kebijakan kredensial, invalidasi sesi, lindungi token."}
	case finding.A08:
		return []string{"Pastikan integritas data/kode: verifikasi signature update/paket; hindari deserialisasi tak tepercaya."}
	case finding.A09:
		return []string{"Tambah logging & monitoring untuk event keamanan dan pastikan alerting berjalan."}
	case finding.A10:
		return []string{"Batasi request server-side dengan allowlist tujuan; blok rentang internal & endpoint metadata."}
	}

	return []string{"Perbaiki akar penyebab di sisi server; validasi & encoding sesuai konteks interpreter; tambahkan logging/deteksi yang relevan."}
}
