package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestScanPresetSavePrefillPreserve proves the full per-program preset cycle
// through the HTTP surface: (1) a scan with "save preset" stores the selection to
// the program; (2) opening the scan form for that program prefills tags/severity/stealth
// from the preset; (3) a later scan WITHOUT ticking "save preset" does NOT overwrite
// the preset — an ordinary scan must not change it silently.
func TestScanPresetSavePrefillPreserve(t *testing.T) {
	srv, _, _ := newSelectionServer(t)

	// 1) Save the preset.
	rec := do(t, srv, "POST", "/scan", url.Values{
		"program": {"acme"}, "in_scope": {"acme.io"}, "targets": {"acme.io"},
		"tags": {"cve, exposure"}, "severity": {"critical", "high"}, "stealth": {"1"}, "api_routes": {"1"},
		"save_preset": {"1"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST save preset = %d", rec.Code)
	}
	waitRunDone(t, srv, runIDFrom(t, rec.Body.String()))

	// 2) The scan form for that program must be prefilled from the preset.
	body := do(t, srv, "GET", "/scan?program=acme", nil).Body.String()
	if !strings.Contains(body, `value="cve,exposure"`) {
		t.Errorf("tags not prefilled from the preset")
	}
	if !strings.Contains(body, `value="critical" checked`) || !strings.Contains(body, `value="high" checked`) {
		t.Errorf("the preset severity is not checked in the form")
	}
	if !strings.Contains(body, `name="stealth" value="1" checked`) {
		t.Errorf("the preset stealth is not checked in the form")
	}
	if !strings.Contains(body, `name="api_routes" value="1" checked`) {
		t.Errorf("the preset API routes is not checked in the form")
	}

	// 3) Scan again with a different selection but WITHOUT opting in to save → the preset stays.
	rec3 := do(t, srv, "POST", "/scan", url.Values{
		"program": {"acme"}, "in_scope": {"acme.io"}, "targets": {"acme.io"},
		"tags": {"sqli"},
	})
	if rec3.Code != http.StatusOK {
		t.Fatalf("POST without save = %d", rec3.Code)
	}
	waitRunDone(t, srv, runIDFrom(t, rec3.Body.String()))

	body2 := do(t, srv, "GET", "/scan?program=acme", nil).Body.String()
	if !strings.Contains(body2, `value="cve,exposure"`) {
		t.Errorf("the preset must be kept without opt-in (tags still cve,exposure)")
	}
	if strings.Contains(body2, `value="sqli"`) {
		t.Errorf("a scan without opt-in must not overwrite the program preset")
	}
}
