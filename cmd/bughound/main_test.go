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
