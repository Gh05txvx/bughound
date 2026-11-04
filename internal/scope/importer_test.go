package scope

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const h1Header = "identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission," +
	"availability_requirement,confidentiality_requirement,integrity_requirement,max_severity,system_tags,created_at,updated_at\n"

// h1Row menulis satu baris CSV HackerOne; submit = kolom eligible_for_submission.
func h1Row(id, assetType, submit string) string {
	return id + "," + assetType + ",,true," + submit + ",,,,critical,,2024-01-01 00:00:00 UTC,2024-01-01 00:00:00 UTC\n"
}

func mustImport(t *testing.T, raw string) ImportResult {
	t.Helper()
	res, err := ImportPlatform(raw)
	if err != nil {
		t.Fatalf("ImportPlatform: %v", err)
	}
	return res
}

func assets(items []ImportItem) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.Asset)
	}
	return out
}

func TestConvertInNarrowsOrKeeps(t *testing.T) {
	cases := []struct {
		raw  string
		want []string
	}{
		{"acme.io", []string{"acme.io"}},
		{"ACME.io.", []string{"acme.io"}},
		{" https://acme.io/\t", []string{"acme.io"}},
		{"https://acme.io/*", []string{"acme.io"}},
		{"https://acme.io/api/*", []string{"acme.io/api"}},
		{"https://acme.io:8443/app/", []string{"acme.io:8443/app"}},
		{"*.acme.io", []string{"*.acme.io"}},
		{"https://*.acme.io/", []string{"*.acme.io"}},
		{"*.acme.io/*", []string{"*.acme.io"}},
		{"203.0.113.10", []string{"203.0.113.10"}},
		{"203.0.113.10:8080", []string{"203.0.113.10:8080"}},
		{"http://203.0.113.10:8080/", []string{"203.0.113.10:8080"}},
		{"203.0.113.7/24", []string{"203.0.113.0/24"}},
		{"203.0.113.10.", []string{"203.0.113.10"}},
		{"bücher.de", []string{"xn--bcher-kva.de"}},
		{"a.acme.io, b.acme.io", []string{"a.acme.io", "b.acme.io"}},
		{"https://a.acme.io,https://b.acme.io/", []string{"a.acme.io", "b.acme.io"}},
		// Koma pada path bukan pemisah: tetap satu prefix, bukan host baru y.acme.io.
		{"https://a.acme.io/x,y.acme.io", []string{"a.acme.io/x,y.acme.io"}},
	}
	for _, c := range cases {
		got, err := convertIn(c.raw)
		if err != nil {
			t.Errorf("convertIn(%q): %v", c.raw, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("convertIn(%q) = %v, ingin %v", c.raw, got, c.want)
		}
	}
}

// Invarian utama: yang tak bisa diwakili tanpa melebar tak boleh masuk in-scope.
func TestConvertInRefusesWhatWouldWiden(t *testing.T) {
	cases := []struct{ raw, why string }{
		{"*.com", "seluruh TLD"},
		{"*.co.uk", "suffix publik multi-label"},
		{"*.github.io", "suffix publik privat"},
		{"0.0.0.0/0", "seluruh IPv4"},
		{"::/0", "seluruh IPv6"},
		{"203.0.0.0/7", "lebih lebar dari /8"},
		{"10.0.0.0/8", "jaringan privat"},
		{"169.0.0.0/8", "memuat metadata cloud"},
		{"169.254.169.254", "metadata cloud"},
		{"http://169.254.169.254/", "metadata cloud via URL"},
		// Bentuk IP tersamar tetap IP.
		{"169.254.169.254.", "titik akhir menyamarkan metadata"},
		{"169.254.169.254.:80", "titik akhir + port"},
		{"127.0.0.1.", "titik akhir menyamarkan loopback"},
		{"１２７.０.０.１", "digit fullwidth dipetakan idna jadi loopback"},
		{"*.169.254.169.254", "wildcard di atas bentuk IP"},
		{"127.0.0.1", "loopback"},
		{"::1", "loopback IPv6"},
		{"fe80::1%eth0", "link-local ber-zone"},
		{"::ffff:169.254.169.254", "IPv4-mapped menyamarkan metadata"},
		{"::ffff:169.254.0.0/112", "rentang IPv4-mapped"},
		{"api.*.acme.io", "wildcard tengah"},
		{"*-dev.acme.io", "wildcard parsial"},
		{"*.acme.*", "wildcard TLD"},
		{"*.acme.io/api", "wildcard + path"},
		{"https://acme.io/*/x", "pola tengah path"},
		{"https://acme.io/a%20b", "path ter-encode"},
		{"https://acme.io/app?x=1", "query akan melebar ke seluruh path"},
		{"https://acme.io/#/dash", "fragment akan melebar ke seluruh host"},
		{"https://user:pw@acme.io/", "userinfo"},
		{"https://acme.io\\@evil.com/", "backslash parser-differential"},
		{"ftp://acme.io/", "skema non-web"},
		{"wss://acme.io", "skema non-web"},
		{"mailto:a@acme.io", "bukan host"},
		{"acme.io:abc", "port bukan angka"},
		{"http://acme.io:99999/", "port di luar rentang"},
		{"10.0.0.1-50", "rentang IP"},
		{"all", "teks bebas tanpa spasi"},
		{"localhost", "bukan domain publik"},
		{"app.internal", "TLD tak dikenal"},
		{".acme.io", "label kosong: entri semu"},
		{"acme..io", "label kosong: entri semu"},
		{"Any other subdomain of acme.io", "teks bebas"},
		{"██████", "disensor"},
		{"https://203.0.113.10/app", "path pada host IP"},
		{"", "kosong"},
	}
	for _, c := range cases {
		if got, err := convertIn(c.raw); err == nil {
			t.Errorf("convertIn(%q) = %v, ingin ditolak (%s)", c.raw, got, c.why)
		}
	}
}

func TestConvertOutOnlyWidens(t *testing.T) {
	cases := []struct {
		raw     string
		want    []string
		apexes  []string
		widened bool
	}{
		{"admin.acme.io", []string{"admin.acme.io"}, nil, false},
		{"https://admin.acme.io/", []string{"admin.acme.io"}, nil, false},
		{"https://acme.io/admin", []string{"acme.io/admin"}, nil, false},
		{"https://acme.io/admin/*", []string{"acme.io/admin"}, nil, false},
		{"https://acme.io:8443/admin", []string{"acme.io/admin"}, nil, true},
		{"https://acme.io/admin?x=1", []string{"acme.io/admin"}, nil, true},
		{"https://acme.io/a*b/c", []string{"acme.io"}, nil, true},
		{"https://acme.io/x/a%20b", []string{"acme.io/x"}, nil, true},
		{"*.dev.acme.io", []string{"*.dev.acme.io"}, []string{"dev.acme.io"}, false},
		{".dev.acme.io", []string{"*.dev.acme.io"}, []string{"dev.acme.io"}, false},
		{"https://*.dev.acme.io/admin", []string{"*.dev.acme.io"}, []string{"dev.acme.io"}, true},
		{"api.*.acme.io", []string{"*.acme.io"}, nil, true},
		{"a*.acme.io", []string{"*.acme.io"}, nil, true},
		{"203.0.113.10", []string{"203.0.113.10"}, nil, false},
		{"203.0.113.10.", []string{"203.0.113.10"}, nil, false},
		{"203.0.113.10:443", []string{"203.0.113.10"}, nil, true},
		{"http://203.0.113.10/", []string{"203.0.113.10"}, nil, false},
		{"https://203.0.113.10/admin", []string{"203.0.113.10"}, nil, true},
		{"10.0.0.0/8", []string{"10.0.0.0/8"}, nil, false},
		{"0.0.0.0/0", []string{"0.0.0.0/0"}, nil, false},
		{"https://a.acme.io/x/*,https://b.acme.io/y", []string{"a.acme.io/x", "b.acme.io/y"}, nil, false},
	}
	for _, c := range cases {
		got, err := convertOut(c.raw)
		if err != nil {
			t.Errorf("convertOut(%q): %v", c.raw, err)
			continue
		}
		if !reflect.DeepEqual(got.entries, c.want) || !reflect.DeepEqual(got.apexes, c.apexes) || got.widened != c.widened {
			t.Errorf("convertOut(%q) = %+v, ingin entries=%v apexes=%v widened=%v", c.raw, got, c.want, c.apexes, c.widened)
		}
	}
}

// Eksklusi tanpa superset yang masuk akal wajib ditolak agar ditinjau manusia.
func TestConvertOutRefusesWithoutSuperset(t *testing.T) {
	for _, raw := range []string{
		"support.acme.*", "*", "https://*/arcgis/*", "*acme.com", "www.acme*.com", "/self-service-*",
		"10.0.0.1-50", "107.167.127.4{0,1}", "all", "██████", "Other subdomains of acme.io",
		"a.acme.io,Other subdomains", ",", "",
		// CIDR rusak tak boleh menyusut jadi satu IP.
		"203.0.113.0/24:443", "203.0.113.0/33", "203.0.113.10/x",
		// Label kosong menghasilkan entri yang tak pernah cocok.
		"acme..io", "*..acme.io", "acme.io..",
	} {
		if got, err := convertOut(raw); err == nil {
			t.Errorf("convertOut(%q) = %+v, ingin ditolak", raw, got)
		}
	}
}

// Bukti utama: eksklusi hasil impor benar-benar dihadang Guard.
func TestImportedExclusionsAreEnforcedByGuard(t *testing.T) {
	data := h1Header +
		h1Row("*.acme.io", "WILDCARD", "true") +
		h1Row("acme.io", "URL", "true") +
		h1Row("203.0.113.0/24", "CIDR", "true") +
		h1Row("https://acme.io:443/admin", "URL", "false") +
		h1Row("203.0.113.10:443", "IP_ADDRESS", "false") +
		h1Row("https://203.0.113.20/admin", "URL", "false") +
		h1Row("*.dev.acme.io", "WILDCARD", "false") +
		h1Row(".stage.acme.io", "URL", "false") +
		h1Row("api.*.corp.acme.io", "WILDCARD", "false") +
		h1Row(`"https://acme.io/a/*,https://acme.io/b"`, "URL", "false")
	res := mustImport(t, data)
	g := mustGuard(t, res.InScope, res.OutScope)

	for _, target := range []string{
		"https://acme.io/admin", "https://acme.io:443/admin", "https://acme.io:8443/admin/x",
		"https://203.0.113.10/", "203.0.113.10", "http://203.0.113.10:8080/",
		"https://203.0.113.20/admin/x", "203.0.113.20",
		"dev.acme.io", "x.dev.acme.io", "stage.acme.io", "x.stage.acme.io",
		"api.eu.corp.acme.io", "other.corp.acme.io",
		"https://acme.io/a/1", "https://acme.io/b",
	} {
		if r := g.Evaluate(target); r.Allowed {
			t.Errorf("eksklusi bocor: %q diizinkan via %q", target, r.MatchedEntry)
		}
	}
	for _, target := range []string{"https://acme.io/shop", "app.acme.io", "203.0.113.11"} {
		if r := g.Evaluate(target); !r.Allowed {
			t.Errorf("%q seharusnya tetap diizinkan (%s)", target, r.Reason)
		}
	}
}

func TestApexDerivedOnlyWhenNotExplicitlyInScope(t *testing.T) {
	res := mustImport(t, h1Header+
		h1Row("acme.io", "URL", "true")+
		h1Row("*.acme.io", "WILDCARD", "false")+
		h1Row("*.other.io", "WILDCARD", "false"))
	want := []string{"*.acme.io", "*.other.io", "other.io"}
	if !reflect.DeepEqual(res.OutScope, want) {
		t.Fatalf("OutScope = %v, ingin %v", res.OutScope, want)
	}
	if !mustGuard(t, res.InScope, res.OutScope).Evaluate("acme.io").Allowed {
		t.Error("apex yang eksplisit in-scope tak boleh tertimpa eksklusi turunan")
	}
}

func TestShadowedInScopeIsReported(t *testing.T) {
	res := mustImport(t, h1Header+
		h1Row("www.acme.io", "URL", "true")+
		h1Row("acme.io/app", "URL", "true")+
		h1Row("shop.other.io", "URL", "true")+
		h1Row("*.acme.io", "WILDCARD", "false"))
	if got, want := assets(res.Shadowed), []string{"www.acme.io"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Shadowed = %v, ingin %v", got, want)
	}
	if !strings.Contains(res.Shadowed[0].Detail, "*.acme.io") {
		t.Errorf("harus menyebut eksklusi pemicu: %q", res.Shadowed[0].Detail)
	}
}

func TestUnresolvedAndWidenedAreReported(t *testing.T) {
	res := mustImport(t, h1Header+
		h1Row("app.acme.io", "URL", "true")+
		h1Row("support.acme.*", "WILDCARD", "false")+
		h1Row("All other assets", "OTHER", "false")+
		h1Row("blog.acme.io", "OTHER", "false")+
		h1Row("com.acme.app", "GOOGLE_PLAY_APP_ID", "false")+
		h1Row("https://acme.io:8443/x", "URL", "false"))

	if got, want := assets(res.Unresolved), []string{"support.acme.*", "All other assets"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Unresolved = %v, ingin %v", got, want)
	}
	if got, want := assets(res.Widened), []string{"https://acme.io:8443/x"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Widened = %v, ingin %v", got, want)
	}
	if got, want := assets(res.Skipped), []string{"com.acme.app"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Skipped = %v, ingin %v", got, want)
	}
	// Tipe OTHER tetap dipakai sebagai eksklusi: menambah eksklusi selalu aman.
	if want := []string{"blog.acme.io", "acme.io/x"}; !reflect.DeepEqual(res.OutScope, want) {
		t.Errorf("OutScope = %v, ingin %v", res.OutScope, want)
	}
}

func TestInScopeOtherAndNonWebNeverImported(t *testing.T) {
	res := mustImport(t, h1Header+
		h1Row("*.vpn.acme.io", "OTHER", "true")+
		h1Row("https://github.com/acme/app", "SOURCE_CODE", "true")+
		h1Row("com.acme.android", "GOOGLE_PLAY_APP_ID", "true")+
		h1Row("https://acme.io", "SOMETHING_NEW", "true"))
	if len(res.InScope) != 0 {
		t.Errorf("tipe tak dikenal/non-web masuk in-scope: %v", res.InScope)
	}
	if len(res.Skipped) != 4 {
		t.Errorf("Skipped = %v, ingin 4 aset dilaporkan", assets(res.Skipped))
	}
}

func TestParseHackerOneCSV(t *testing.T) {
	data := "\xef\xbb\xbf" + h1Header + // BOM dari spreadsheet
		"app.acme.io,URL,\"Uji dengan akun sendiri.\nJangan lebih dari 5 rps\",true,true,,,,critical,,,\n" +
		h1Row("vdp.acme.io", "URL", "true") +
		h1Row("support.acme.io", "URL", "false") +
		h1Row("unknown.acme.io", "URL", "")
	res := mustImport(t, data)
	if res.Format != "HackerOne CSV" {
		t.Errorf("Format = %q", res.Format)
	}
	if want := []string{"app.acme.io", "vdp.acme.io"}; !reflect.DeepEqual(res.InScope, want) {
		t.Errorf("InScope = %v, ingin %v", res.InScope, want)
	}
	// Status eligible kosong bukan izin: diperlakukan sebagai eksklusi.
	if want := []string{"support.acme.io", "unknown.acme.io"}; !reflect.DeepEqual(res.OutScope, want) {
		t.Errorf("OutScope = %v, ingin %v", res.OutScope, want)
	}
	if len(res.Notes) != 1 || !strings.Contains(res.Notes[0].Detail, "5 rps") {
		t.Errorf("instruksi program hilang: %+v", res.Notes)
	}
}

func TestParseHackerOneAPI(t *testing.T) {
	res := mustImport(t, `{"data":[
		{"id":"1","type":"structured-scope","attributes":{"asset_type":"URL","asset_identifier":"https://api.acme.io","eligible_for_submission":true,"instruction":"API kami"}},
		{"id":"2","type":"structured-scope","attributes":{"asset_type":"URL","asset_identifier":"old.acme.io","eligible_for_submission":false}},
		{"id":"3","type":"structured-scope","attributes":{"asset_type":"URL","asset_identifier":"flagless.acme.io"}}
	],"links":{"self":"https://api.hackerone.com/v1/x"}}`)
	if res.Format != "HackerOne API JSON" {
		t.Errorf("Format = %q", res.Format)
	}
	if want := []string{"api.acme.io"}; !reflect.DeepEqual(res.InScope, want) {
		t.Errorf("InScope = %v, ingin %v", res.InScope, want)
	}
	if want := []string{"old.acme.io", "flagless.acme.io"}; !reflect.DeepEqual(res.OutScope, want) {
		t.Errorf("OutScope = %v, ingin %v (tanpa flag bukan izin)", res.OutScope, want)
	}
}

func TestParseBugcrowdBrief(t *testing.T) {
	res := mustImport(t, `{"data":{"brief":{"name":"Acme"},"scope":[
		{"name":"In Scope Targets","inScope":true,"targets":[
			{"name":"Aplikasi utama","uri":"https://app.acme.io/","category":"website","ipAddress":null},
			{"name":"api.acme.io","uri":"","category":"api"},
			{"name":"Acme iOS","uri":"","category":"ios"}]},
		{"name":"Out of Scope","inScope":false,"targets":[
			{"name":"Blog","uri":"https://blog.acme.io","category":"website"}]},
		{"name":"Tanpa flag","targets":[
			{"name":"flagless.acme.io","uri":"","category":"website"}]}
	]}}`)
	if res.Format != "Bugcrowd brief JSON" {
		t.Errorf("Format = %q", res.Format)
	}
	if want := []string{"app.acme.io", "api.acme.io"}; !reflect.DeepEqual(res.InScope, want) {
		t.Errorf("InScope = %v, ingin %v", res.InScope, want)
	}
	if want := []string{"blog.acme.io", "flagless.acme.io"}; !reflect.DeepEqual(res.OutScope, want) {
		t.Errorf("OutScope = %v, ingin %v", res.OutScope, want)
	}
}

func TestParseBountyTargetsObject(t *testing.T) {
	h1 := `{"handle":"acme","targets":{
		"in_scope":[
			{"asset_identifier":"*.acme.io","asset_type":"WILDCARD","eligible_for_submission":true},
			{"asset_identifier":"ineligible.acme.io","asset_type":"URL","eligible_for_submission":false}],
		"out_of_scope":[{"asset_identifier":"old.acme.io","asset_type":"URL","eligible_for_submission":false}]}}`
	bc := `[{"name":"Acme","targets":{
		"in_scope":[{"type":"website","target":"https://app.acme.io/","uri":"https://app.acme.io/","name":"App","ipAddress":""}],
		"out_of_scope":[{"type":"website","target":"https://www.acme.io/","uri":"https://www.acme.io/","name":"www","ipAddress":""}]}}]`

	res := mustImport(t, h1)
	if want := []string{"*.acme.io"}; !reflect.DeepEqual(res.InScope, want) {
		t.Errorf("InScope = %v, ingin %v", res.InScope, want)
	}
	if want := []string{"ineligible.acme.io", "old.acme.io"}; !reflect.DeepEqual(res.OutScope, want) {
		t.Errorf("OutScope = %v, ingin %v (flag false mengalahkan daftar)", res.OutScope, want)
	}

	res = mustImport(t, bc)
	if !reflect.DeepEqual(res.InScope, []string{"app.acme.io"}) || !reflect.DeepEqual(res.OutScope, []string{"www.acme.io"}) {
		t.Errorf("Bugcrowd: in=%v out=%v", res.InScope, res.OutScope)
	}
}

// Data yang tak bisa dipercaya sebagai daftar utuh ditolak seluruhnya.
func TestImportRejectsUntrustworthyData(t *testing.T) {
	cases := []struct{ name, raw, want string }{
		{"kosong", "  \n", "kosong"},
		{"terlalu besar", strings.Repeat("x", MaxImportBytes+1), "melebihi batas"},
		{"daftar host polos", "acme.io\n*.acme.io", "format tak dikenali"},
		{"CSV tanpa kolom eligible", "identifier,asset_type\nacme.io,URL\n", "format tak dikenali"},
		{"CSV terpotong", h1Header + "app.acme.io,URL", "CSV tak valid"},
		{"CSV hanya header", h1Header, "tak memuat aset"},
		{"JSON rusak", `{"data":`, "JSON tak valid"},
		{"JSON asing", `{"foo":1}`, "format tak dikenali"},
		{"API terpotong", `{"data":[{"type":"structured-scope","attributes":{"asset_type":"URL","asset_identifier":"a.acme.io","eligible_for_submission":true}}],"links":{"next":"https://api.hackerone.com/x?page=2"}}`, "terpotong"},
		{"API tipe asing", `{"data":[{"type":"report","attributes":{}}]}`, "format tak dikenali"},
		{"brief tanpa scope", `{"data":{"brief":{}}}`, "format tak dikenali"},
		// Respons targets_url Bugcrowd: flag in/out ada di grup, bukan di sini.
		{"target tanpa status in/out", `{"targets":[{"name":"a.acme.io","uri":"https://a.acme.io","category":"website"}]}`, "JSON tak valid"},
		{"banyak program", `[{"targets":{"in_scope":[],"out_of_scope":[]}},{"targets":{"in_scope":[],"out_of_scope":[]}}]`, "2 program"},
		{"array kosong", `[]`, "0 program"},
	}
	for _, c := range cases {
		res, err := ImportPlatform(c.raw)
		if err == nil {
			t.Errorf("%s: ingin ditolak, dapat %+v", c.name, res)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q tak memuat %q", c.name, err, c.want)
		}
	}
}

func TestImportDigestBindsToContent(t *testing.T) {
	data := h1Header + h1Row("app.acme.io", "URL", "true")
	a := mustImport(t, data)
	// Textarea browser mengirim CRLF; sidik jari tak boleh berubah karenanya.
	if b := mustImport(t, strings.ReplaceAll(data, "\n", "\r\n")); a.Digest != b.Digest {
		t.Error("digest berubah hanya karena CRLF")
	}
	if c := mustImport(t, data+h1Row("x.acme.io", "URL", "false")); a.Digest == c.Digest {
		t.Error("digest harus berubah saat isi berubah")
	}
}

func TestImportDedupesAndTruncatesNotes(t *testing.T) {
	long := strings.Repeat("é", maxNote+50)
	raw, err := json.Marshal(map[string]any{"targets": map[string]any{
		"in_scope": []map[string]any{
			{"asset_identifier": "acme.io", "asset_type": "URL", "instruction": long},
			{"asset_identifier": "https://acme.io/", "asset_type": "URL"},
		},
		"out_of_scope": []map[string]any{},
	}})
	if err != nil {
		t.Fatal(err)
	}
	res := mustImport(t, string(raw))
	if want := []string{"acme.io"}; !reflect.DeepEqual(res.InScope, want) {
		t.Errorf("InScope = %v, ingin %v", res.InScope, want)
	}
	if got := []rune(res.Notes[0].Detail); len(got) != maxNote+1 || got[maxNote] != '…' {
		t.Errorf("catatan tak dipotong rune-safe: %d rune", len(got))
	}
}
