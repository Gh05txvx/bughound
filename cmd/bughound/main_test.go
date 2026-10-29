package main

import "testing"

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
