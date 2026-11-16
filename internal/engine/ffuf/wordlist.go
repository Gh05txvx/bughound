package ffuf

import (
	"bytes"
	_ "embed"
	"os"
	"strings"

	"bughound/internal/engine"
)

//go:embed default-wordlist.txt
var defaultWordlist []byte

// resolveWordlist mengembalikan path wordlist siap pakai. Bila Wordlist diisi,
// dipakai apa adanya (cleanup no-op). Bila kosong, wordlist bawaan ditulis ke
// berkas sementara dan cleanup menghapusnya.
func (r *Runner) resolveWordlist() (path string, cleanup func(), err error) {
	if strings.TrimSpace(r.Wordlist) != "" {
		return r.Wordlist, func() {}, nil
	}
	return tempWordlist("ffuf-wl-*.txt", defaultWordlist)
}

// withoutLogout menulis salinan wordlist tanpa baris route logout
// (engine.IsLogoutPath) — untuk scan berlogin: satu GET ke route logout mematikan
// sesi (wordlist bawaan memuat "logout"; robots.txt sering men-Disallow-nya).
func withoutLogout(basePath string) (string, func(), error) {
	base, err := os.ReadFile(basePath)
	if err != nil {
		return "", nil, err
	}
	var buf bytes.Buffer
	for _, ln := range strings.SplitAfter(string(base), "\n") {
		if !engine.IsLogoutPath(ln) {
			buf.WriteString(ln)
		}
	}
	return tempWordlist("ffuf-wl-auth-*.txt", buf.Bytes())
}

// tempWordlist menulis data ke berkas wordlist sementara; cleanup menghapusnya.
func tempWordlist(pattern string, data []byte) (string, func(), error) {
	tmp, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", nil, err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", nil, err
	}
	tmp.Close()
	return tmp.Name(), func() { os.Remove(tmp.Name()) }, nil
}
