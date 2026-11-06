package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func eqStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestParseEngineMode(t *testing.T) {
	cases := []struct {
		in    string
		names []string
		mock  bool
	}{
		{"", nil, true},
		{"mock", nil, true},
		{"real", []string{"nuclei"}, false},
		{"nuclei,ffuf,zap", []string{"nuclei", "ffuf", "zap"}, false},
		{"nuclei,dalfox", []string{"nuclei", "dalfox"}, false},
		{"real,zap", []string{"nuclei", "zap"}, false},
		{"nuclei,nuclei", []string{"nuclei"}, false},
		{"NUCLEI, FFUF", []string{"nuclei", "ffuf"}, false},
		{"nuclei,mock", nil, true}, // mock eksklusif
		{"tak-dikenal", nil, false}, // tak ada yang dikenali
	}
	for _, c := range cases {
		names, mock := parseEngineMode(c.in)
		if mock != c.mock || !eqStrings(names, c.names) {
			t.Errorf("parseEngineMode(%q) = %v,%v; ingin %v,%v", c.in, names, mock, c.names, c.mock)
		}
	}
}

func TestResolveSASTRoot(t *testing.T) {
	// Kosong di flag & env = SAST nonaktif, tanpa log.
	if root, msg := resolveSASTRoot("", ""); root != "" || msg != "" {
		t.Errorf("kosong: dapat root=%q msg=%q; ingin nonaktif tanpa log", root, msg)
	}

	// Flag diset → root dibuat & aktif.
	base := t.TempDir()
	fromFlag := filepath.Join(base, "flagroot")
	if root, msg := resolveSASTRoot(fromFlag, ""); root != fromFlag || !strings.Contains(msg, "aktif") {
		t.Errorf("flag: dapat root=%q msg=%q; ingin root=%q & 'aktif'", root, msg, fromFlag)
	}
	if fi, err := os.Stat(fromFlag); err != nil || !fi.IsDir() {
		t.Errorf("flag: dir %q harus dibuat; err=%v", fromFlag, err)
	}

	// Env dipakai bila flag kosong.
	fromEnv := filepath.Join(base, "envroot")
	if root, _ := resolveSASTRoot("", fromEnv); root != fromEnv {
		t.Errorf("env: dapat root=%q; ingin %q", root, fromEnv)
	}

	// Flag menang atas env.
	if root, _ := resolveSASTRoot(fromFlag, fromEnv); root != fromFlag {
		t.Errorf("precedence: dapat root=%q; ingin flag %q menang", root, fromFlag)
	}

	// Gagal menyiapkan dir (parent berupa file) → nonaktif, non-fatal, log jelas.
	fileParent := filepath.Join(base, "afile")
	if err := os.WriteFile(fileParent, []byte("x"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	badRoot := filepath.Join(fileParent, "child") // parent bukan direktori → MkdirAll gagal
	if root, msg := resolveSASTRoot(badRoot, ""); root != "" || !strings.Contains(msg, "dinonaktifkan") {
		t.Errorf("gagal-mkdir: dapat root=%q msg=%q; ingin nonaktif & 'dinonaktifkan'", root, msg)
	}
}

func TestSplitSubcommand(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		wantSub  string
		wantRest []string
	}{
		{"verb lalu flag", []string{"update", "-db", "x.db"}, "update", []string{"-db", "x.db"}},
		{"verb saja", []string{"list"}, "list", nil},
		{"tanpa verb (langsung flag) pakai default", []string{"-db", "x.db"}, "update", []string{"-db", "x.db"}},
		{"kosong pakai default", nil, "update", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sub, rest := splitSubcommand(c.args, "update")
			if sub != c.wantSub {
				t.Errorf("sub=%q, ingin %q", sub, c.wantSub)
			}
			if !eqStrings(rest, c.wantRest) {
				t.Errorf("rest=%v, ingin %v", rest, c.wantRest)
			}
		})
	}
}
