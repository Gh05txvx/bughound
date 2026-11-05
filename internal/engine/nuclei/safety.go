package nuclei

import (
	"fmt"
	"strconv"
	"strings"
)

// Safety mengatur profil keamanan eksekusi engine DAST aktif (nuclei fuzzing).
//
// Dua lapis, sesuai kebutuhan bug bounty (menemukan kandidat bug untuk
// diverifikasi manual — BUKAN mengeksploitasi sampai merusak):
//
//  1. Non-destruktif — SELALU aktif, struktural (bukan opsi yang bisa dimatikan
//     lewat input). Engine tak pernah mengirim payload yang menolak layanan
//     (tag `dos`) dan tak memakai callback blind/OAST ke pihak ketiga
//     (`-no-interactsh`) — sejalan dengan proxy egress yang memang memblok
//     tujuan di luar scope. Fuzzing dijaga `-fuzz-aggression low`.
//  2. Stealth (opsional) — low-and-slow: laju sangat rendah, satu koneksi,
//     User-Agent browser wajar, cakupan URL dikecilkan. Tujuannya menekan jejak
//     agar pekerjaan sah tak disalahartikan sebagai serangan oleh pemantauan
//     target (SOC). Ini MENGURANGI gangguan & risiko insiden palsu — bukan
//     jaminan "tak terdeteksi", dan tak menyentuh audit trail bughound sendiri.
type Safety struct {
	Stealth bool
}

const (
	stealthRateLimit   = 3  // req/dtk maksimum saat stealth (low-and-slow)
	stealthConcurrency = 1  // -c saat stealth (satu koneksi)
	stealthTimeout     = 20 // -timeout (dtk) saat stealth (sabar, tak memborong)
	stealthMaxURLs     = 40 // cap URL fuzz saat stealth (< default maxDASTURLs)

	// browserUA: User-Agent browser wajar agar request tak langsung menonjol
	// sebagai pemindai otomatis. Bukan penyamaran untuk tujuan jahat — konteksnya
	// pengujian yang sah dengan jejak minimal.
	browserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

// destructiveExcludeTags adalah tag nuclei yang TIDAK PERNAH dikirim engine
// bughound: payload yang berpotensi merusak/menurunkan layanan target atau
// membajak request pengguna lain. dos = denial-of-service; smuggling = request
// smuggling/desync. Daftar sengaja konservatif; non-destruktif ini struktural.
var destructiveExcludeTags = []string{"dos", "smuggling"}

// destructiveExcludeIDs adalah template unsafe individual yang mengubah keadaan
// target (unggah/tulis) sehingga tak non-destruktif, tapi tak tertangkap tag di
// atas. CVE-2021-30118: unggah webshell .aspx (Kaseya). CVE-2023-46747: smuggling
// AJP F5 yang membuat admin lalu menjalankan perintah. Dikecualikan per-ID, bukan
// via tag intrusive, agar ratusan template intrusive non-destruktif lain tetap jalan.
var destructiveExcludeIDs = []string{"CVE-2021-30118", "CVE-2023-46747"}

// nonDestructiveArgs mengembalikan argumen nuclei yang menolak template/payload
// destruktif. Dipakai jalur plain runner maupun -dast agar kebijakan ini satu
// sumber dan tak bisa lepas di salah satu jalur.
func nonDestructiveArgs() []string {
	var a []string
	if len(destructiveExcludeTags) > 0 {
		a = append(a, "-exclude-tags", strings.Join(destructiveExcludeTags, ","))
	}
	if len(destructiveExcludeIDs) > 0 {
		a = append(a, "-exclude-id", strings.Join(destructiveExcludeIDs, ","))
	}
	return a
}

// nucleiExtraArgs mengembalikan argumen keamanan untuk `nuclei -dast`. Non-
// destruktif selalu disertakan; argumen stealth hanya saat Stealth aktif.
func (s Safety) nucleiExtraArgs() []string {
	args := append([]string{
		"-no-interactsh", // tanpa callback blind/OAST ke pihak ketiga
	}, nonDestructiveArgs()...)
	if s.Stealth {
		args = append(args,
			"-c", strconv.Itoa(stealthConcurrency),
			"-timeout", strconv.Itoa(stealthTimeout),
			"-H", "User-Agent: "+browserUA,
		)
	}
	return args
}

// katanaExtraArgs mengembalikan argumen stealth untuk crawl katana (nil bila
// tidak stealth — crawl default sudah ringan).
func (s Safety) katanaExtraArgs() []string {
	if !s.Stealth {
		return nil
	}
	return []string{
		"-c", strconv.Itoa(stealthConcurrency),
		"-H", "User-Agent: " + browserUA,
	}
}

// rate menjepit laju (req/dtk) ke profil: saat stealth, tak pernah melebihi
// stealthRateLimit; selain itu memakai base apa adanya (base<=0 = biarkan engine
// memakai default-nya).
func (s Safety) rate(base int) int {
	if s.Stealth && (base <= 0 || base > stealthRateLimit) {
		return stealthRateLimit
	}
	return base
}

// maxURLs mengembalikan cap jumlah URL yang difuzz sesuai profil.
func (s Safety) maxURLs() int {
	if s.Stealth {
		return stealthMaxURLs
	}
	return maxDASTURLs
}

// Describe meringkas profil untuk log/audit (tanpa data sensitif).
func (s Safety) Describe() string {
	mode := "standar"
	if s.Stealth {
		mode = fmt.Sprintf("stealth(rate≤%d,c%d,UA-browser)", stealthRateLimit, stealthConcurrency)
	}
	return fmt.Sprintf("non-destruktif[no-interactsh,exclude-tags=%s,exclude-id=%d,aggression=low] + %s",
		strings.Join(destructiveExcludeTags, ","), len(destructiveExcludeIDs), mode)
}
