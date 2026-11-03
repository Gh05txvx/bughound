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

// destructiveExcludeTags adalah tag nuclei yang TIDAK PERNAH dikirim engine DAST
// bughound: payload yang berpotensi merusak atau menurunkan layanan target.
// Daftar sengaja konservatif dan bisa diperluas; non-destruktif ini struktural.
var destructiveExcludeTags = []string{"dos"}

// nucleiExtraArgs mengembalikan argumen keamanan untuk `nuclei -dast`. Non-
// destruktif selalu disertakan; argumen stealth hanya saat Stealth aktif.
func (s Safety) nucleiExtraArgs() []string {
	args := []string{
		"-no-interactsh", // tanpa callback blind/OAST ke pihak ketiga
		"-exclude-tags", strings.Join(destructiveExcludeTags, ","),
	}
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
	return fmt.Sprintf("non-destruktif[no-interactsh,exclude=%s,aggression=low] + %s",
		strings.Join(destructiveExcludeTags, ","), mode)
}
