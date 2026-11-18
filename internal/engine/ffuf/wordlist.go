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

// resolveWordlist returns a ready-to-use wordlist path. When Wordlist is set, it
// is used as-is (cleanup is a no-op). When empty, the built-in wordlist is
// written to a temp file and cleanup removes it.
func (r *Runner) resolveWordlist() (path string, cleanup func(), err error) {
	if strings.TrimSpace(r.Wordlist) != "" {
		return r.Wordlist, func() {}, nil
	}
	return tempWordlist("ffuf-wl-*.txt", defaultWordlist)
}

// withoutLogout writes a copy of the wordlist without logout route lines
// (engine.IsLogoutPath), for an authenticated scan: one GET to a logout route
// kills the session (the built-in wordlist holds "logout"; robots.txt often Disallows it).
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

// tempWordlist writes data to a temp wordlist file; cleanup removes it.
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
