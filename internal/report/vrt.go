package report

import (
	"strings"

	"bughound/internal/finding"
)

// bugcrowdVRT returns a CANDIDATE Bugcrowd VRT (Vulnerability Rating Taxonomy)
// category for a finding, best effort. The aim is to guide the hunter to the
// right VRT node in the draft export, so the form does not fall back to a
// default that often auto-downgrades the priority (e.g. P4 for something that
// should be P3).
//
// CWE is stronger than keywords (as in ClassifyOWASP). It returns "" when it is
// not confident enough. The IDs follow the official
// bugcrowd/vulnerability-rating-taxonomy; because the VRT changes between
// versions and each program can use a subset/override, the hunter MUST check
// against the program's VRT before submitting (the export marks it as a
// "candidate").
func bugcrowdVRT(f *finding.Finding) string {
	for _, raw := range f.CWE {
		n := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(raw)), "CWE-")
		if v, ok := cweVRT[n]; ok {
			return v
		}
	}
	return vrtFromKeywords(strings.ToLower(strings.Join(f.Tags, " ") + " " + f.Type))
}

// cweVRT maps the CWEs that adapters actually emit → a VRT category. Curated
// (not every CWE), parallel to cweOWASP in internal/finding.
var cweVRT = map[string]string{
	// server_side_injection
	"89":  "server_side_injection.sql_injection",
	"77":  "server_side_injection.remote_code_execution_rce",
	"78":  "server_side_injection.remote_code_execution_rce",
	"94":  "server_side_injection.remote_code_execution_rce",
	"95":  "server_side_injection.remote_code_execution_rce",
	"917": "server_side_injection.ssti",
	"90":  "server_side_injection.ldap_injection",
	"611": "server_side_injection.xml_external_entity_injection_xxe",
	"22":  "server_side_injection.file_inclusion.local",
	"23":  "server_side_injection.file_inclusion.local",
	"35":  "server_side_injection.file_inclusion.local",
	"98":  "server_side_injection.file_inclusion.local",
	// xss
	"79": "cross_site_scripting_xss.reflected",
	"80": "cross_site_scripting_xss.reflected",
	// csrf / redirect / ssrf / access control
	"352": "cross_site_request_forgery_csrf",
	"601": "unvalidated_redirects_and_forwards.open_redirect",
	"918": "server_security_misconfiguration.server_side_request_forgery_ssrf",
	"639": "broken_access_control.idor",
	// cors / clickjacking / security headers
	"942":  "server_security_misconfiguration.unsafe_cross_origin_resource_sharing",
	"1021": "server_security_misconfiguration.clickjacking",
	"693":  "server_security_misconfiguration.lack_of_security_headers",
	// transport / crypto
	"319": "insecure_data_transport.cleartext_transmission_of_sensitive_data",
	"326": "cryptographic_weakness",
	"327": "cryptographic_weakness",
	"328": "cryptographic_weakness",
	// exposure
	"200": "sensitive_data_exposure",
	"538": "sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset",
	"540": "sensitive_data_exposure",
	"548": "server_security_misconfiguration.directory_listing_enabled",
	// outdated components
	"937":  "using_components_with_known_vulnerabilities.outdated_software_version",
	"1035": "using_components_with_known_vulnerabilities.outdated_software_version",
	"1104": "using_components_with_known_vulnerabilities.outdated_software_version",
}

// vrtFromKeywords matches a string (tags+type, lowercase) to a VRT category,
// from the most specific to the most general (best effort). It is used for
// findings without a mapped CWE (e.g. ZAP alert types). It deliberately does
// NOT use a bare "rce" (a false match with "force" in "brute-force").
func vrtFromKeywords(hay string) string {
	has := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(hay, s) {
				return true
			}
		}
		return false
	}
	switch {
	case has("sql-injection", "sqli"):
		return "server_side_injection.sql_injection"
	case has("os-command", "command-injection"):
		return "server_side_injection.remote_code_execution_rce"
	case has("ssti", "template-injection"):
		return "server_side_injection.ssti"
	case has("ldap-injection"):
		return "server_side_injection.ldap_injection"
	case has("xxe", "xml-external"):
		return "server_side_injection.xml_external_entity_injection_xxe"
	case has("lfi", "file-inclusion", "traversal"):
		return "server_side_injection.file_inclusion.local"
	case has("ssrf"):
		return "server_security_misconfiguration.server_side_request_forgery_ssrf"
	case has("open-redirect", "redirect"):
		return "unvalidated_redirects_and_forwards.open_redirect"
	case has("idor"):
		return "broken_access_control.idor"
	case has("xss", "cross-site-scripting"):
		return "cross_site_scripting_xss.reflected"
	case has("csrf", "cross-site-request-forgery"):
		return "cross_site_request_forgery_csrf"
	case has("cors", "cross-domain", "cross-origin"):
		return "server_security_misconfiguration.unsafe_cross_origin_resource_sharing"
	case has("clickjack", "x-frame"):
		return "server_security_misconfiguration.clickjacking"
	case has("content-security-policy", "csp"):
		return "server_security_misconfiguration.lack_of_security_headers.content_security_policy"
	case has("strict-transport", "hsts"):
		return "server_security_misconfiguration.lack_of_security_headers.strict_transport_security"
	case has("x-content-type"):
		return "server_security_misconfiguration.lack_of_security_headers.x_content_type_options"
	case has("security-header", "missing-header", "missing-security"):
		return "server_security_misconfiguration.lack_of_security_headers"
	case has("directory-listing", "directory listing", "dir-listing"):
		return "server_security_misconfiguration.directory_listing_enabled"
	case has("cleartext"):
		return "insecure_data_transport.cleartext_transmission_of_sensitive_data"
	case has("cipher", "insecure-ssl", "weak-tls", "weak-cipher"):
		return "server_security_misconfiguration.insecure_ssl.insecure_cipher_suite"
	case has("outdated", "vulnerable-dependency", "known-vuln"):
		return "using_components_with_known_vulnerabilities.outdated_software_version"
	case has("retire", "javascript-librar", "js-librar"):
		return "using_components_with_known_vulnerabilities.unpatched_javascript_libraries"
	case has("fingerprint", "tech-detect", "banner", "version-detect"):
		return "server_security_misconfiguration.fingerprinting_banner_disclosure"
	case has("git-config", "env-file", "exposed-secret", "secret", "credential"):
		return "sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset"
	case has("source-map", "sourcemap", "source-leak", "source-code"):
		return "sensitive_data_exposure"
	case has("exposed", "exposure", "disclosure", "metrics", "swagger", "info-leak"):
		return "sensitive_data_exposure"
	}
	return ""
}
