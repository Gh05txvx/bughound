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
		{"nuclei,mock", nil, true}, // mock is exclusive
		{"unknown-name", nil, false}, // nothing recognized
	}
	for _, c := range cases {
		names, mock := parseEngineMode(c.in)
		if mock != c.mock || !eqStrings(names, c.names) {
			t.Errorf("parseEngineMode(%q) = %v,%v; want %v,%v", c.in, names, mock, c.names, c.mock)
		}
	}
}

func TestResolveSASTRoot(t *testing.T) {
	// Empty flag and env = SAST off, with no log line.
	if root, msg := resolveSASTRoot("", ""); root != "" || msg != "" {
		t.Errorf("empty: got root=%q msg=%q; want off with no log line", root, msg)
	}

	// Flag set → the root is created and SAST is on.
	base := t.TempDir()
	fromFlag := filepath.Join(base, "flagroot")
	if root, msg := resolveSASTRoot(fromFlag, ""); root != fromFlag || !strings.Contains(msg, "enabled") {
		t.Errorf("flag: got root=%q msg=%q; want root=%q and 'enabled'", root, msg, fromFlag)
	}
	if fi, err := os.Stat(fromFlag); err != nil || !fi.IsDir() {
		t.Errorf("flag: dir %q must be created; err=%v", fromFlag, err)
	}

	// The env is used when the flag is empty.
	fromEnv := filepath.Join(base, "envroot")
	if root, _ := resolveSASTRoot("", fromEnv); root != fromEnv {
		t.Errorf("env: got root=%q; want %q", root, fromEnv)
	}

	// The flag wins over the env.
	if root, _ := resolveSASTRoot(fromFlag, fromEnv); root != fromFlag {
		t.Errorf("precedence: got root=%q; want flag %q to win", root, fromFlag)
	}

	// Failing to prepare the dir (the parent is a file) → off, non-fatal, with a clear log line.
	fileParent := filepath.Join(base, "afile")
	if err := os.WriteFile(fileParent, []byte("x"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	badRoot := filepath.Join(fileParent, "child") // the parent is not a directory, so MkdirAll fails
	if root, msg := resolveSASTRoot(badRoot, ""); root != "" || !strings.Contains(msg, "disabled") {
		t.Errorf("mkdir-fails: got root=%q msg=%q; want off and 'disabled'", root, msg)
	}
}

func TestSplitSubcommand(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		wantSub  string
		wantRest []string
	}{
		{"verb then flags", []string{"update", "-db", "x.db"}, "update", []string{"-db", "x.db"}},
		{"verb only", []string{"list"}, "list", nil},
		{"no verb (flags first) uses the default", []string{"-db", "x.db"}, "update", []string{"-db", "x.db"}},
		{"empty uses the default", nil, "update", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sub, rest := splitSubcommand(c.args, "update")
			if sub != c.wantSub {
				t.Errorf("sub=%q, want %q", sub, c.wantSub)
			}
			if !eqStrings(rest, c.wantRest) {
				t.Errorf("rest=%v, want %v", rest, c.wantRest)
			}
		})
	}
}
