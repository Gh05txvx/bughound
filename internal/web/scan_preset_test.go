package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestScanPresetSavePrefillPreserve membuktikan siklus penuh preset per-program
// lewat permukaan HTTP: (1) scan dengan "simpan preset" menyimpan seleksi ke
// program; (2) membuka form scan untuk program itu mengisi tags/severity/stealth
// dari preset; (3) scan berikutnya TANPA mencentang "simpan preset" TIDAK menimpa
// preset — scan biasa tak boleh diam-diam mengubahnya.
func TestScanPresetSavePrefillPreserve(t *testing.T) {
	srv, _, _ := newSelectionServer(t)

	// 1) Simpan preset.
	rec := do(t, srv, "POST", "/scan", url.Values{
		"program": {"acme"}, "in_scope": {"acme.io"}, "targets": {"acme.io"},
		"tags": {"cve, exposure"}, "severity": {"critical", "high"}, "stealth": {"1"},
		"save_preset": {"1"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST simpan preset = %d", rec.Code)
	}
	waitRunDone(t, srv, runIDFrom(t, rec.Body.String()))

	// 2) Form scan program itu harus ter-prefill dari preset.
	body := do(t, srv, "GET", "/scan?program=acme", nil).Body.String()
	if !strings.Contains(body, `value="cve,exposure"`) {
		t.Errorf("tags tak ter-prefill dari preset")
	}
	if !strings.Contains(body, `value="critical" checked`) || !strings.Contains(body, `value="high" checked`) {
		t.Errorf("severity preset tak tercentang di form")
	}
	if !strings.Contains(body, `name="stealth" value="1" checked`) {
		t.Errorf("stealth preset tak tercentang di form")
	}

	// 3) Scan lagi dengan seleksi beda tapi TANPA opt-in simpan → preset tetap.
	rec3 := do(t, srv, "POST", "/scan", url.Values{
		"program": {"acme"}, "in_scope": {"acme.io"}, "targets": {"acme.io"},
		"tags": {"sqli"},
	})
	if rec3.Code != http.StatusOK {
		t.Fatalf("POST tanpa simpan = %d", rec3.Code)
	}
	waitRunDone(t, srv, runIDFrom(t, rec3.Body.String()))

	body2 := do(t, srv, "GET", "/scan?program=acme", nil).Body.String()
	if !strings.Contains(body2, `value="cve,exposure"`) {
		t.Errorf("preset harus dipertahankan tanpa opt-in (tags masih cve,exposure)")
	}
	if strings.Contains(body2, `value="sqli"`) {
		t.Errorf("scan tanpa opt-in tak boleh menimpa preset program")
	}
}
