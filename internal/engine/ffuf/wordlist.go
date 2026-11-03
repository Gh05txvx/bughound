package ffuf

import (
	_ "embed"
	"os"
	"strings"
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
	tmp, err := os.CreateTemp("", "ffuf-wl-*.txt")
	if err != nil {
		return "", nil, err
	}
	if _, err := tmp.Write(defaultWordlist); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", nil, err
	}
	tmp.Close()
	return tmp.Name(), func() { os.Remove(tmp.Name()) }, nil
}
