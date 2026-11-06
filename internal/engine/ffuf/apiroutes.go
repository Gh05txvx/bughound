package ffuf

import (
	"os"
	"strings"
)

// Enrichment route API. Selain wordlist direktori umum, banyak temuan bernilai
// tinggi hidup di endpoint API yang tak tertaut/terdaftar (mis. /api/v1/...,
// /rest/..., /graphql). Assetnote merilis "apiroutes" — daftar path API nyata
// yang paling sering diamati di web (terurut frekuensi), ideal sebagai kamus
// brute path API. bughound membundlenya saat build (lihat Dockerfile) lalu
// mengumpankannya ke engine ffuf yang SUDAH ter-proxy, sehingga tiap probe path
// API pun ditegakkan scope guard (sama seperti wordlist bawaan/robots/spec).
//
// Opt-in: hanya aktif bila APIRoutes diset (per-scan dari form, atau preset
// program). Volume besar (~ribuan path) → sengaja tidak default.

const (
	// defaultAPIWordlist adalah lokasi wordlist route API ter-bundle di image.
	// Bisa ditimpa env BUGHOUND_API_WORDLIST (power user: tunjuk wordlist sendiri).
	defaultAPIWordlist = "/usr/local/share/bughound/wordlists/apiroutes.txt"
	// maxAPIRoutePaths membatasi jumlah path yang dibaca (pagar pengaman bila env
	// menunjuk berkas raksasa). Bundle bawaan sudah dipangkas lebih kecil dari ini.
	maxAPIRoutePaths = 20000
)

// apiRoutePaths mengembalikan path route API ter-bundle dalam bentuk FUZZ (tanpa
// slash tepi) untuk di-merge ke wordlist ffuf. Hanya aktif bila APIRoutes=true.
//
// Keamanan: di-gate pada proxyAddr (seperti robotsPaths/specPaths). Pembacaan
// berkas ini MURNI lokal (tanpa jaringan), tetapi amplifikasi ~ribuan path hanya
// boleh terjadi lewat proxy egress yang scope-enforced — tanpa proxy, tak ada
// enrichment, jadi tak pernah ada brute path API yang memintas scope guard.
// Bundle absen (mis. dev lokal tanpa image) → nil (best-effort, bukan error).
func (r *Runner) apiRoutePaths() []string {
	if !r.APIRoutes || r.proxyAddr == "" {
		return nil
	}
	path := strings.TrimSpace(os.Getenv("BUGHOUND_API_WORDLIST"))
	if path == "" {
		path = defaultAPIWordlist
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil // bundle/berkas absen → tanpa enrichment (bukan error)
	}
	return normalizeAPIRoutes(data, maxAPIRoutePaths)
}

// normalizeAPIRoutes mengubah isi wordlist route API menjadi path bentuk FUZZ:
// satu path per baris, slash tepi dibuang (buildArgs menyusun target + "/" +
// FUZZ), query dibuang, baris kosong/komentar/wildcard/ber-spasi dilewati,
// ter-dedup, dibatasi max. Tahan terhadap berkas mentah Assetnote (path
// ber-leading-slash) maupun yang sudah dinormalkan saat build.
func normalizeAPIRoutes(data []byte, max int) []string {
	var out []string
	seen := map[string]bool{}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.SplitN(line, "?", 2)[0] // buang query
		line = strings.Trim(line, "/")         // bentuk FUZZ (tanpa slash tepi)
		if line == "" || strings.ContainsAny(line, " \t") || strings.ContainsAny(line, "*$") {
			continue // kosong / ber-spasi / pola wildcard — bukan path probe literal
		}
		if seen[line] {
			continue
		}
		seen[line] = true
		out = append(out, line)
		if len(out) >= max {
			break
		}
	}
	return out
}
