package finding

import "strings"

// OWASP adalah kategori OWASP Top 10 2021 hasil klasifikasi sebuah temuan.
// Field ini ADITIF terhadap `type` native (yang tetap lebih presisi dan jadi
// basis dedup); tujuannya pengelompokan/korelasi lintas-engine untuk report
// yang siap-submit. Klasifikasi bersifat BEST-EFFORT (sinyal berurut: CWE, lalu
// kata kunci di tags/type) — bukan penilaian otoritatif; verifikator berhak
// menimpanya.
type OWASP string

const (
	OWASPNone OWASP = ""         // belum/tak terklasifikasi
	A01       OWASP = "A01:2021" // Broken Access Control
	A02       OWASP = "A02:2021" // Cryptographic Failures
	A03       OWASP = "A03:2021" // Injection
	A04       OWASP = "A04:2021" // Insecure Design
	A05       OWASP = "A05:2021" // Security Misconfiguration
	A06       OWASP = "A06:2021" // Vulnerable and Outdated Components
	A07       OWASP = "A07:2021" // Identification and Authentication Failures
	A08       OWASP = "A08:2021" // Software and Data Integrity Failures
	A09       OWASP = "A09:2021" // Security Logging and Monitoring Failures
	A10       OWASP = "A10:2021" // Server-Side Request Forgery (SSRF)
)

var owaspTitle = map[OWASP]string{
	A01: "Broken Access Control",
	A02: "Cryptographic Failures",
	A03: "Injection",
	A04: "Insecure Design",
	A05: "Security Misconfiguration",
	A06: "Vulnerable and Outdated Components",
	A07: "Identification and Authentication Failures",
	A08: "Software and Data Integrity Failures",
	A09: "Security Logging and Monitoring Failures",
	A10: "Server-Side Request Forgery (SSRF)",
}

// Title mengembalikan judul kategori (kosong bila OWASPNone/tak dikenal).
func (o OWASP) Title() string { return owaspTitle[o] }

// Label mengembalikan "A05:2021 Security Misconfiguration" untuk ditampilkan;
// kosong bila OWASPNone.
func (o OWASP) Label() string {
	if o == OWASPNone {
		return ""
	}
	if t := owaspTitle[o]; t != "" {
		return string(o) + " " + t
	}
	return string(o)
}

// Valid melaporkan apakah o kategori yang dikenal (atau kosong).
func (o OWASP) Valid() bool { return o == OWASPNone || owaspTitle[o] != "" }

// ClassifyOWASP menebak kategori OWASP 2021 sebuah temuan dari sinyal yang ada,
// berurutan: (1) CWE (paling kuat), (2) kata kunci di tags lalu type. Best-effort:
// mengembalikan OWASPNone bila tak ada yang cocok.
func ClassifyOWASP(f *Finding) OWASP {
	if c := owaspFromCWE(f.CWE); c != OWASPNone {
		return c
	}
	hay := strings.ToLower(strings.Join(f.Tags, " ") + " " + f.Type)
	return owaspFromKeywords(hay)
}

// owaspFromCWE memetakan CWE umum (yang benar-benar dipancarkan adapter) ke
// kategori OWASP 2021. Kuratif (bukan 900+ CWE), berdasar pemetaan resmi OWASP.
func owaspFromCWE(cwes []string) OWASP {
	for _, raw := range cwes {
		n := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(raw)), "CWE-")
		if c, ok := cweOWASP[n]; ok {
			return c
		}
	}
	return OWASPNone
}

var cweOWASP = map[string]OWASP{
	// A01 Broken Access Control
	"22": A01, "23": A01, "35": A01, "59": A01, "200": A01, "201": A01,
	"219": A01, "275": A01, "284": A01, "285": A01, "352": A01, "425": A01,
	"538": A01, "548": A01, "639": A01, "862": A01, "863": A01,
	// A02 Cryptographic Failures
	"261": A02, "296": A02, "310": A02, "319": A02, "321": A02, "326": A02,
	"327": A02, "328": A02, "329": A02, "331": A02, "523": A02, "720": A02, "757": A02,
	// A03 Injection
	"74": A03, "77": A03, "78": A03, "79": A03, "80": A03, "83": A03, "87": A03,
	"88": A03, "89": A03, "90": A03, "91": A03, "93": A03, "94": A03, "95": A03,
	"97": A03, "116": A03, "564": A03, "643": A03, "652": A03, "917": A03,
	// A04 Insecure Design
	"209": A04, "256": A04, "501": A04, "522": A04,
	// A05 Security Misconfiguration
	"16": A05, "260": A05, "315": A05, "520": A05, "526": A05, "537": A05,
	"541": A05, "611": A05, "614": A05, "693": A05, "756": A05, "776": A05,
	"942": A05, "1004": A05, "1021": A05, "1032": A05, "1174": A05, "1275": A05,
	// A06 Vulnerable and Outdated Components
	"937": A06, "1035": A06, "1104": A06,
	// A07 Identification and Authentication Failures
	"255": A07, "259": A07, "287": A07, "288": A07, "290": A07, "294": A07,
	"295": A07, "297": A07, "300": A07, "302": A07, "304": A07, "306": A07,
	"307": A07, "346": A07, "384": A07, "521": A07, "613": A07, "620": A07,
	"640": A07, "798": A07,
	// A08 Software and Data Integrity Failures
	"345": A08, "353": A08, "426": A08, "494": A08, "502": A08, "565": A08,
	"784": A08, "829": A08, "830": A08, "915": A08,
	// A09 Security Logging and Monitoring Failures
	"117": A09, "223": A09, "532": A09, "778": A09,
	// A10 Server-Side Request Forgery
	"918": A10,
}

// owaspFromKeywords memindai string (gabungan tags+type, huruf kecil) untuk kata
// kunci kelas kerentanan, dari yang paling spesifik ke paling umum (misconfig
// paling akhir karena paling luas). Best-effort.
func owaspFromKeywords(hay string) OWASP {
	has := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(hay, s) {
				return true
			}
		}
		return false
	}
	switch {
	case has("ssrf"):
		return A10
	case has("sqli", "sql-injection", "xss", "cross-site-scripting", "rce",
		"command-injection", "os-command", "code-injection", "ssti",
		"template-injection", "ldap-injection", "xpath-injection", "crlf",
		"host-header-injection", "injection"):
		return A03
	case has("deserialization", "pickle", "untrusted-data", "integrity"):
		return A08
	case has("cleartext", "weak-cipher", "insecure-cipher", "weak-tls",
		"sweet32", "heartbleed", "crypto-"):
		return A02
	case has("vulnerable-dependency", "outdated", "retirejs", "known-vuln",
		"cve-", " cve", "sca"):
		return A06
	case has("default-login", "default-credential", "weak-password",
		"auth-bypass", "jwt", "session-fixation", "authentication"):
		return A07
	case has("traversal", "lfi", "local-file-inclusion", "idor", "broken-access",
		"access-control", "information-disclosure", "info-disclosure",
		"disclosure", "suspicious-comments", "sensitive", "listing",
		"directory-brows"):
		return A01
	case has("misconfig", "header", "csp", "cors", "cross-domain", "x-frame",
		"x-content", "clickjacking", "hsts", "exposed", "exposure",
		"content-discovery", "modern-web-application", "user-agent-fuzzer",
		"metrics", "swagger", "api-docs", "default-page", "debug", "config"):
		return A05
	}
	return OWASPNone
}
