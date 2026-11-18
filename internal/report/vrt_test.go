package report

import (
	"strings"
	"testing"

	"bughound/internal/finding"
)

func TestBugcrowdVRTFromCWE(t *testing.T) {
	cases := map[string]string{
		"CWE-89":   "server_side_injection.sql_injection",
		"CWE-79":   "cross_site_scripting_xss.reflected",
		"CWE-918":  "server_security_misconfiguration.server_side_request_forgery_ssrf",
		"CWE-601":  "unvalidated_redirects_and_forwards.open_redirect",
		"CWE-352":  "cross_site_request_forgery_csrf",
		"CWE-942":  "server_security_misconfiguration.unsafe_cross_origin_resource_sharing",
		"CWE-540":  "sensitive_data_exposure",
		"CWE-538":  "sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset",
		"CWE-548":  "server_security_misconfiguration.directory_listing_enabled",
		"CWE-1021": "server_security_misconfiguration.clickjacking",
		"CWE-319":  "insecure_data_transport.cleartext_transmission_of_sensitive_data",
	}
	for cwe, want := range cases {
		f := &finding.Finding{Type: "unmapped-type", CWE: []string{cwe}}
		if got := bugcrowdVRT(f); got != want {
			t.Errorf("CWE %s → %q, want %q", cwe, got, want)
		}
	}
}

func TestBugcrowdVRTFromKeywords(t *testing.T) {
	// Alert types that commonly have no mapped CWE (e.g. ZAP/nuclei).
	cases := map[string]string{
		"cross-domain-misconfiguration":          "server_security_misconfiguration.unsafe_cross_origin_resource_sharing",
		"content-security-policy-header-not-set": "server_security_misconfiguration.lack_of_security_headers.content_security_policy",
		"x-frame-options-header-missing":         "server_security_misconfiguration.clickjacking",
		"strict-transport-security-not-set":      "server_security_misconfiguration.lack_of_security_headers.strict_transport_security",
		"directory-listing":                      "server_security_misconfiguration.directory_listing_enabled",
		"fingerprinthub-web-fingerprints":        "server_security_misconfiguration.fingerprinting_banner_disclosure",
		"prometheus-metrics":                     "sensitive_data_exposure",
		"exposed-source-map":                     "sensitive_data_exposure",
		"sql-injection":                          "server_side_injection.sql_injection",
		"open-redirect":                          "unvalidated_redirects_and_forwards.open_redirect",
	}
	for typ, want := range cases {
		f := &finding.Finding{Type: typ}
		if got := bugcrowdVRT(f); got != want {
			t.Errorf("type %q → %q, want %q", typ, got, want)
		}
	}
}

func TestBugcrowdVRTCWEBeatsKeyword(t *testing.T) {
	// The type contains the keyword "redirect" but the CWE is SQLi → the CWE wins.
	f := &finding.Finding{Type: "weird-redirect-thing", CWE: []string{"CWE-89"}}
	if got := bugcrowdVRT(f); got != "server_side_injection.sql_injection" {
		t.Errorf("CWE must win over keywords; got %q", got)
	}
}

func TestBugcrowdVRTUnknownEmpty(t *testing.T) {
	if got := bugcrowdVRT(&finding.Finding{Type: "business-logic-flaw"}); got != "" {
		t.Errorf("an unknown type must be empty; got %q", got)
	}
	// Regression: "brute-force" contains the substring "rce" and must NOT become RCE.
	if got := bugcrowdVRT(&finding.Finding{Type: "brute-force-login"}); strings.Contains(got, "remote_code_execution") {
		t.Errorf("brute-force must not map to RCE; got %q", got)
	}
}

func TestExportBugcrowdCarriesVRT(t *testing.T) {
	f := mk("Permissive CORS at /api", finding.SeverityMedium, finding.StatusConfirmed)
	f.CWE = []string{"CWE-942"}
	md := ExportFinding(f, PlatformBugcrowd)
	for _, want := range []string{
		"VRT (candidate",
		"server_security_misconfiguration.unsafe_cross_origin_resource_sharing",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("the Bugcrowd export must contain %q\n---\n%s", want, md)
		}
	}
	// No mapped class: the VRT line does not appear (do not guess).
	// (mk() uses Type "ssrf", which is mapped, so set a neutral type.)
	nf := mk("neutral", finding.SeverityLow, finding.StatusConfirmed)
	nf.Type = "business-logic-flaw"
	if md := ExportFinding(nf, PlatformBugcrowd); strings.Contains(md, "VRT (candidate") {
		t.Errorf("without a mapped class, the VRT line must not appear:\n%s", md)
	}
}
