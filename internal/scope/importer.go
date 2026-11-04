package scope

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Importer mengonversi data scope platform (HackerOne, Bugcrowd) ke entri
// kanonik BH-SPEC-SCOPE. Ia hanya MENGHASILKAN TEKS: tak mengambil keputusan
// (itu tugas Guard) dan tak menyimpan apa pun — hasilnya mengisi form scope
// editor untuk ditinjau, lalu lewat jalur simpan biasa.
//
// Data platform ditulis pihak ketiga dan bentuknya lebih longgar dari bahasa
// scope bughound. Saat sebuah aset tak bisa diwakili persis, arah pembulatannya
// wajib aman. INVARIAN inti berkas ini:
//
//   - In-scope hanya boleh MENYEMPIT: ragu = tak diimpor; default deny menutupnya.
//   - Out-of-scope hanya boleh MELEBAR: ragu = diperluas. Eksklusi yang tak bisa
//     diwakili sama sekali masuk Unresolved dan menahan impor sampai ditinjau,
//     karena eksklusi yang hilang berarti under-blocking.
//
// "Lolos parseEntry" belum berarti layak dari data pihak ketiga: "all" dan
// "localhost" sah untuk scope tulisan tangan (lab), tapi pada daftar program publik
// itu teks bebas. Karena itu hasil parseEntry diperiksa lagi, lalu keluaran ditulis
// ulang dari field entri ternormalkan, bukan dari string platform.

// MaxImportBytes menjaga sumber daya, bukan menyaring dump platform (itu ditolak
// dari bentuknya). Program besar nyata mencapai ~1,3 MiB (5 ribu aset). Form
// dibatasi 10 MiB oleh net/http dan urlencode melebarkan data ~1,35x, jadi batas
// ini masih muat dalam satu POST.
const MaxImportBytes = 4 << 20

const (
	minBitsV4 = 8  // CIDR in-scope lebih lebar dari ini ditolak (bukan aset satu program)
	minBitsV6 = 32 // setara alokasi RIR umum
	maxNote   = 300
)

// nonPublicPrefixes adalah rentang yang tak boleh masuk in-scope lewat impor.
// Mencerminkan egress.isSpecialIP (IP internal hanya boleh bila EKSPLISIT
// in-scope), ditambah 0.0.0.0/8 dan CGNAT. Data pihak ketiga tak boleh membuka
// metadata cloud atau jaringan internal; bila memang sengaja, pengguna
// menuliskannya sendiri. Paket scope tak bisa mengimpor egress (siklus).
var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// ImportItem adalah satu aset platform yang perlu dilihat pengguna.
type ImportItem struct {
	Asset  string // identifier apa adanya dari platform
	Type   string // tipe aset menurut platform
	Detail string // alasan, hasil konversi, atau instruksi program
}

// ImportResult adalah hasil konversi data platform.
type ImportResult struct {
	Format   string   // format yang terdeteksi
	Digest   string   // sidik jari input; persetujuan Unresolved terikat ke sini
	InScope  []string // entri kanonik
	OutScope []string // entri kanonik

	Unresolved []ImportItem // eksklusi tak terwakili: wajib ditinjau sebelum impor
	Shadowed   []ImportItem // in-scope yang tertimpa eksklusi: guard akan menolaknya
	Widened    []ImportItem // eksklusi yang sengaja diperluas agar tetap efektif
	Skipped    []ImportItem // in-scope yang tak diimpor & aset non-web
	Notes      []ImportItem // instruksi program untuk aset in-scope
}

// ImportPlatform mendeteksi format data lalu mengonversinya. Error berarti data
// tak bisa dipercaya sebagai daftar scope utuh (format tak dikenal, terpotong,
// lebih dari satu program): tak ada hasil parsial, fail closed.
func ImportPlatform(raw string) (ImportResult, error) {
	if len(raw) > MaxImportBytes {
		return ImportResult{}, fmt.Errorf("data melebihi batas %d KiB: tempel satu program saja", MaxImportBytes>>10)
	}
	s := strings.TrimSpace(strings.TrimPrefix(strings.ReplaceAll(raw, "\r\n", "\n"), "\xef\xbb\xbf"))
	if s == "" {
		return ImportResult{}, errors.New("data kosong")
	}
	format, assets, err := parseAssets(s)
	if err != nil {
		return ImportResult{}, err
	}
	if len(assets) == 0 {
		return ImportResult{}, errors.New("data tak memuat aset")
	}
	sum := sha256.Sum256([]byte(s))
	res := ImportResult{Format: format, Digest: hex.EncodeToString(sum[:16])}

	// In-scope lebih dulu: apex turunan eksklusi wildcard perlu tahu host mana
	// yang eksplisit diizinkan program.
	inHosts := map[string]bool{}
	for _, a := range assets {
		if a.inScope {
			res.addIn(a, inHosts)
		}
	}
	for _, a := range assets {
		if !a.inScope {
			res.addOut(a, inHosts)
		}
	}
	res.InScope = dedupe(res.InScope)
	res.OutScope = dedupe(res.OutScope)

	// Gerbang terakhir: keluaran wajib lolos kompilasi guard yang sama.
	g, errs := New(res.InScope, res.OutScope)
	if len(errs) > 0 {
		return ImportResult{}, fmt.Errorf("hasil konversi ditolak guard: %w", errs[0])
	}
	// Pola lazim "www.x in-scope, *.x out-of-scope": out-of-scope menang, jadi
	// entri itu mati. Arahnya aman, tapi pengguna perlu tahu.
	for _, s := range res.InScope {
		if d := g.Evaluate(s); d.Reason == ReasonOutOfScope {
			res.Shadowed = append(res.Shadowed, ImportItem{Asset: s, Detail: "ditolak oleh " + d.MatchedEntry})
		}
	}
	return res, nil
}

func (r *ImportResult) addIn(a platformAsset, inHosts map[string]bool) {
	switch classifyAsset(a.assetType) {
	case classNonWeb:
		r.Skipped = append(r.Skipped, a.item("aset non-web: bukan target DAST"))
		return
	case classOther:
		r.Skipped = append(r.Skipped, a.item("tipe ini tak ditebak; tambahkan manual bila memang aset web"))
		return
	}
	entries, err := convertIn(a.identifier)
	if err != nil {
		r.Skipped = append(r.Skipped, a.item(err.Error()))
		return
	}
	for _, s := range entries {
		if e, err := parseEntry(s); err == nil && e.host != "" {
			inHosts[e.host] = true
		}
	}
	r.InScope = append(r.InScope, entries...)
	if n := truncateNote(a.note); n != "" {
		r.Notes = append(r.Notes, a.item(n))
	}
}

func (r *ImportResult) addOut(a platformAsset, inHosts map[string]bool) {
	if classifyAsset(a.assetType) == classNonWeb {
		r.Skipped = append(r.Skipped, a.item("aset non-web: bukan target DAST"))
		return
	}
	// Tipe OTHER/tak dikenal tetap dicoba: menambah eksklusi selalu arah aman.
	ex, err := convertOut(a.identifier)
	if err != nil {
		r.Unresolved = append(r.Unresolved, a.item(err.Error()))
		return
	}
	// Apex turunan tak boleh menimpa host yang eksplisit diizinkan program
	// (pola sah: "acme.io" in-scope, "*.acme.io" out-of-scope).
	for _, apex := range ex.apexes {
		if !inHosts[apex] {
			ex.entries = append(ex.entries, apex)
			ex.widened = true
		}
	}
	r.OutScope = append(r.OutScope, ex.entries...)
	if ex.widened {
		r.Widened = append(r.Widened, a.item(strings.Join(ex.entries, ", ")))
	}
}

// ---- Klasifikasi tipe aset ----

type assetClass int

const (
	classWeb    assetClass = iota // target jaringan
	classNonWeb                   // mobile, source, hardware: bukan target DAST
	classOther                    // OTHER & tipe tak dikenal: jangan ditebak
)

func classifyAsset(assetType string) assetClass {
	switch strings.ToUpper(strings.TrimSpace(assetType)) {
	case "URL", "WILDCARD", "DOMAIN", "API", "IP_ADDRESS", "CIDR", "WEBSITE", "NETWORK":
		return classWeb
	case "GOOGLE_PLAY_APP_ID", "APPLE_STORE_APP_ID", "OTHER_APK", "OTHER_IPA", "TESTFLIGHT",
		"WINDOWS_APP_STORE_APP_ID", "SOURCE_CODE", "DOWNLOADABLE_EXECUTABLES", "HARDWARE",
		"SMART_CONTRACT", "AI_MODEL", "IOS", "ANDROID", "IOT":
		return classNonWeb
	}
	return classOther
}

// ---- Konversi identifier ----

// ident adalah identifier platform yang dipecah, belum ditafsirkan.
type ident struct {
	scheme string // huruf kecil, "" bila tak ada
	host   string // host[:port], boleh memuat '*'
	path   string // tanpa query/fragment, "" bila tak ada
	extra  bool   // ada userinfo/query/fragment yang tak terwakili entri scope
}

func splitIdent(raw string) (ident, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ident{}, errors.New("identifier kosong")
	}
	if hasSuspiciousChars(s) {
		return ident{}, errors.New("teks bebas, bukan host/URL")
	}
	var id ident
	// Query/fragment dipotong lebih dulu: "://" di dalamnya bukan skema, dan
	// "a.io#@evil.com" harus tetap ber-host a.io seperti tafsir browser.
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s, id.extra = s[:i], true
	}
	if i := strings.Index(s, "://"); i > 0 && !strings.ContainsAny(s[:i], "/.") {
		id.scheme, s = strings.ToLower(s[:i]), s[i+3:]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s, id.path = s[:i], s[i:]
	}
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		s, id.extra = s[i+1:], true
	}
	if s == "" {
		return ident{}, errors.New("identifier tanpa host")
	}
	id.host = s
	return id, nil
}

// splitHostList memecah daftar host dipisah koma ("a.io,b.io") yang lazim di data
// platform. Identifier ber-path tak dipecah: koma di path bukan pemisah, dan
// menebaknya bisa melahirkan host in-scope palsu.
func splitHostList(raw string) []string {
	parts := strings.Split(raw, ",")
	for i, p := range parts {
		id, err := splitIdent(p)
		if err != nil || id.extra || strings.Trim(id.path, "/") != "" {
			return []string{raw}
		}
		parts[i] = strings.TrimSpace(p)
	}
	return parts
}

// convertIn mengonversi aset in-scope. Hanya menyempit: apa pun yang tak bisa
// diwakili tanpa melebar dikembalikan sebagai error.
func convertIn(raw string) ([]string, error) {
	parts := splitHostList(raw)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		s, err := convertOneIn(p)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func convertOneIn(raw string) (string, error) {
	id, err := splitIdent(raw)
	if err != nil {
		return "", err
	}
	if id.extra {
		return "", errors.New("memuat userinfo/query/fragment: mengimpornya berarti memperluas in-scope")
	}
	if id.scheme != "" && id.scheme != "http" && id.scheme != "https" {
		return "", fmt.Errorf("skema %q bukan web", id.scheme)
	}
	// "/x/*" setara prefix "/x"; "*" lain di path tak punya padanan.
	path := strings.TrimSuffix(id.path, "/*")
	if strings.ContainsAny(path, "*%") {
		return "", errors.New("pola/encoding di path tak punya padanan entri scope")
	}
	if path == "/" {
		path = ""
	}
	cand := id.host + path
	if strings.Contains(id.host, "*") {
		if path != "" {
			return "", errors.New("wildcard + path tak punya padanan entri scope")
		}
	} else if id.scheme != "" {
		cand = id.scheme + "://" + cand
	}
	e, err := parseEntry(cand)
	if err != nil {
		return "", errors.New("bentuk tak didukung entri scope")
	}
	// URL ber-host IP disamakan ke entri IP agar cek IP publik berlaku. Path pada
	// host IP tak diimpor: keluaran kanonik tak memuat skema yang diwajibkannya.
	if a, ok := urlHostIP(e); ok {
		if e.path != "/" {
			return "", errors.New("path pada host IP tak punya padanan entri scope")
		}
		e = entry{kind: kindIP, addr: a, port: e.port}
	}
	s, final, err := renderEntry(e)
	if err != nil {
		return "", err
	}
	if err := checkInScope(final); err != nil {
		return "", err
	}
	return s, nil
}

// checkInScope menolak entri yang sah secara sintaks tapi tak layak diterima
// dari data pihak ketiga.
func checkInScope(e entry) error {
	switch e.kind {
	case kindHostExact, kindURLPrefix:
		return checkPublicHost(e.host)
	case kindWildcard:
		if _, err := publicsuffix.EffectiveTLDPlusOne(e.base); err != nil {
			return errors.New("wildcard terlalu lebar: mencakup seluruh suffix publik")
		}
		return checkPublicHost(e.base)
	case kindIP:
		if !publicAddr(e.addr) {
			return errors.New("IP non-publik: tambahkan manual bila memang sengaja")
		}
	case kindCIDR:
		minBits := minBitsV4
		if e.cidr.Addr().Is6() {
			minBits = minBitsV6
		}
		if e.cidr.Bits() < minBits {
			return errors.New("rentang CIDR terlalu lebar")
		}
		if !publicPrefix(e.cidr) {
			return errors.New("rentang non-publik: tambahkan manual bila memang sengaja")
		}
	}
	return nil
}

// exclusion adalah hasil konversi satu aset out-of-scope.
type exclusion struct {
	entries []string
	apexes  []string // apex wildcard, dipakai bila tak eksplisit in-scope
	widened bool     // lebih luas dari aslinya
}

// convertOut mengonversi aset out-of-scope. Hanya melebar: port, query, dan path
// yang tak terwakili dibuang (keluaran mencakup aslinya); error berarti tak ada
// superset yang masuk akal, dan aset itu wajib ditinjau manusia.
func convertOut(raw string) (exclusion, error) {
	// Selalu dipecah per koma, berbeda dari in-scope: bagian yang tak terbaca
	// membuat seluruh aset ditinjau, sedangkan tak memecah berarti bagian
	// sesudah koma hilang diam-diam (under-blocking).
	var ex exclusion
	for _, p := range strings.Split(raw, ",") {
		if strings.TrimSpace(p) == "" {
			continue
		}
		one, err := convertOneOut(p)
		if err != nil {
			return exclusion{}, err
		}
		ex.entries = append(ex.entries, one.entries...)
		ex.apexes = append(ex.apexes, one.apexes...)
		ex.widened = ex.widened || one.widened
	}
	if len(ex.entries) == 0 {
		return exclusion{}, errors.New("identifier kosong")
	}
	return ex, nil
}

func convertOneOut(raw string) (exclusion, error) {
	id, err := splitIdent(raw)
	if err != nil {
		return exclusion{}, err
	}
	// Port dibuang: eksklusi lebih luas selalu aman, dan wildcard tak bisa memuatnya.
	host, port, err := splitHostPort(id.host)
	if err != nil {
		return exclusion{}, errors.New("bentuk tak didukung entri scope")
	}
	ex := exclusion{widened: id.extra || port != ""}
	// ".acme.io" lazim berarti acme.io beserta subdomainnya.
	if strings.HasPrefix(host, ".") {
		host = "*" + host
	}
	if strings.Contains(host, "*") {
		return wildcardExclusion(host, id.path, ex)
	}

	// Path dipotong di batas segmen sebelum pola/encoding: path entri tanpa skema
	// dibandingkan literal, sedangkan path target sudah di-decode.
	path := strings.TrimSuffix(id.path, "/*")
	if i := strings.IndexAny(path, "*%"); i >= 0 {
		path = path[:strings.LastIndexByte(path[:i], '/')+1]
		ex.widened = true
	}
	var e entry
	if a, err := netip.ParseAddr(host); err == nil && id.scheme != "" {
		// Berskema berarti URL: seluruh IP pasti mencakup path-nya.
		ex.widened = ex.widened || strings.Trim(path, "/") != ""
		e = entry{kind: kindIP, addr: a}
	} else {
		// Tanpa skema, IP ber-path bukan URL melainkan CIDR rusak; parseEntry
		// menolaknya, jadi eksklusinya tak diam-diam menyusut jadi satu IP.
		if e, err = parseEntry(host + path); err != nil {
			return exclusion{}, errors.New("bentuk tak didukung entri scope")
		}
		if e.kind == kindHostExact || e.kind == kindURLPrefix {
			if err := checkPublicHost(e.host); err != nil {
				return exclusion{}, err
			}
		}
	}
	s, _, err := renderEntry(e)
	if err != nil {
		return exclusion{}, err
	}
	ex.entries = []string{s}
	return ex, nil
}

// wildcardExclusion memetakan pola host ber-'*' ke wildcard kiri yang pasti
// mencakupnya. Bentuk "*.x" tetap, ditambah apex x: makna platform soal apex
// ambigu, dan arah aman eksklusi adalah melebar. Pola lain ("api.*.x", "a*.x")
// melebar ke "*.x".
func wildcardExclusion(host, path string, ex exclusion) (exclusion, error) {
	rest := host[strings.LastIndexByte(host, '*')+1:]
	dot := strings.IndexByte(rest, '.')
	if dot < 0 || rest[dot+1:] == "" {
		return exclusion{}, errors.New("pola tak punya domain jangkar")
	}
	e, err := parseEntry("*." + rest[dot+1:])
	if err != nil {
		return exclusion{}, errors.New("bentuk tak didukung entri scope")
	}
	exact := strings.HasPrefix(host, "*.") && strings.Count(host, "*") == 1
	if !exact {
		// Tanpa jangkar nyata "*foo.com" akan jadi "*.com": eksklusi semu.
		if _, err := publicsuffix.EffectiveTLDPlusOne(e.base); err != nil {
			return exclusion{}, errors.New("pola tak punya domain jangkar")
		}
		ex.widened = true
	}
	if strings.Trim(strings.TrimSuffix(path, "/*"), "/") != "" {
		ex.widened = true
	}
	s, _, err := renderEntry(e)
	if err != nil {
		return exclusion{}, err
	}
	ex.entries = []string{s}
	if exact {
		ex.apexes = []string{e.base}
	}
	return ex, nil
}

// urlHostIP melaporkan entri URL ber-host IP beserta alamatnya.
func urlHostIP(e entry) (netip.Addr, bool) {
	return e.addr, e.kind == kindURLPrefix && e.addr.IsValid()
}

// renderEntry menulis entri ternormalkan sebagai teks kanonik: yang tersimpan
// persis yang ditegakkan Guard, tanpa skema (Guard tak memakainya), userinfo,
// atau query. Teks yang tak bisa diurai ulang ditolak.
//
// Entri hasil urai ulang ikut dikembalikan karena itulah yang akan dikompilasi
// Guard. Pemeriksaan keamanan memakai entri ini, bukan masukannya.
func renderEntry(e entry) (string, entry, error) {
	var s string
	switch e.kind {
	case kindWildcard:
		s = "*." + e.base
	case kindCIDR:
		s = e.cidr.String()
	case kindIP:
		s = withPort(e.addr.String(), e.port)
	default:
		s = withPort(e.host, e.port)
		if e.path != "" && e.path != "/" {
			s += e.path
		}
	}
	final, err := parseEntry(s)
	if err != nil {
		return "", entry{}, errors.New("bentuk tak didukung entri scope")
	}
	return s, final, nil
}

func withPort(host, port string) string {
	if port == "" {
		return host
	}
	return net.JoinHostPort(host, port)
}

// checkPublicHost menolak nama tanpa TLD nyata ("all", "localhost", "app.internal"):
// sah untuk scope tulisan tangan, tapi pada data program publik itu teks bebas.
func checkPublicHost(host string) error {
	if suffix, icann := publicsuffix.PublicSuffix(host); !icann && !strings.Contains(suffix, ".") {
		return errors.New("bukan domain publik (TLD tak dikenal)")
	}
	return nil
}

func publicAddr(a netip.Addr) bool {
	if a.Is4In6() { // Guard membandingkannya terpisah dari IPv4; jangan diimpor
		return false
	}
	a = a.WithZone("") // Prefix.Contains selalu false untuk alamat ber-zone
	for _, p := range nonPublicPrefixes {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

func publicPrefix(c netip.Prefix) bool {
	if c.Addr().Is4In6() {
		return false
	}
	for _, p := range nonPublicPrefixes {
		if p.Overlaps(c) {
			return false
		}
	}
	return true
}

func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func truncateNote(s string) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > maxNote {
		return string(r[:maxNote]) + "…"
	}
	return s
}

// ---- Parser format ----

// platformAsset adalah satu aset dalam bentuk netral. inScope hanya true bila
// platform menyatakannya eksplisit: status tak jelas tak pernah jadi izin.
type platformAsset struct {
	identifier string
	assetType  string
	inScope    bool
	note       string
}

func (a platformAsset) item(detail string) ImportItem {
	return ImportItem{Asset: a.identifier, Type: a.assetType, Detail: detail}
}

const unknownFormat = "format tak dikenali: gunakan CSV HackerOne (Download CSV), JSON API HackerOne (structured_scopes), JSON brief Bugcrowd, atau satu objek program bounty-targets-data"

func parseAssets(s string) (string, []platformAsset, error) {
	if s[0] == '{' || s[0] == '[' {
		return parsePlatformJSON(s)
	}
	assets, err := parseHackerOneCSV(s)
	return "HackerOne CSV", assets, err
}

func parseHackerOneCSV(s string) ([]platformAsset, error) {
	rows, err := csv.NewReader(strings.NewReader(s)).ReadAll()
	if err != nil {
		return nil, fmt.Errorf("CSV tak valid: %w", err)
	}
	col := map[string]int{}
	for i, h := range rows[0] {
		col[strings.ToLower(strings.TrimSpace(h))] = i
	}
	idCol, ok1 := col["identifier"]
	typeCol, ok2 := col["asset_type"]
	eligCol, ok3 := col["eligible_for_submission"]
	if !ok1 || !ok2 || !ok3 {
		return nil, errors.New(unknownFormat)
	}
	noteCol, hasNote := col["instruction"]
	assets := make([]platformAsset, 0, len(rows)-1)
	for _, row := range rows[1:] {
		a := platformAsset{
			identifier: row[idCol],
			assetType:  row[typeCol],
			inScope:    strings.EqualFold(strings.TrimSpace(row[eligCol]), "true"),
		}
		if hasNote {
			a.note = row[noteCol]
		}
		assets = append(assets, a)
	}
	return assets, nil
}

// platformTarget menampung field target HackerOne dan Bugcrowd sekaligus; hanya
// satu kelompok yang terisi per format.
type platformTarget struct {
	// HackerOne
	AssetIdentifier       string `json:"asset_identifier"`
	AssetType             string `json:"asset_type"`
	EligibleForSubmission *bool  `json:"eligible_for_submission"`
	Instruction           string `json:"instruction"`
	// Bugcrowd
	Target    string `json:"target"`
	URI       string `json:"uri"`
	Name      string `json:"name"`
	IPAddress string `json:"ipAddress"`
	Type      string `json:"type"`
	Category  string `json:"category"`
}

func (t platformTarget) asset(listedIn bool) platformAsset {
	a := platformAsset{inScope: listedIn, note: t.Instruction}
	// HackerOne bisa menandai aset tak layak submit walau tercantum.
	if t.EligibleForSubmission != nil && !*t.EligibleForSubmission {
		a.inScope = false
	}
	for _, v := range []string{t.AssetIdentifier, t.Target, t.URI, t.Name, t.IPAddress} {
		if strings.TrimSpace(v) != "" {
			a.identifier = v
			break
		}
	}
	for _, v := range []string{t.AssetType, t.Type, t.Category} {
		if strings.TrimSpace(v) != "" {
			a.assetType = v
			break
		}
	}
	return a
}

func parsePlatformJSON(s string) (string, []platformAsset, error) {
	data := []byte(s)
	if s[0] == '[' {
		var arr []json.RawMessage
		if err := json.Unmarshal(data, &arr); err != nil {
			return "", nil, fmt.Errorf("JSON tak valid: %w", err)
		}
		if len(arr) != 1 {
			return "", nil, fmt.Errorf("data memuat %d program: tempel tepat satu program", len(arr))
		}
		data = arr[0]
	}
	var doc struct {
		Data  json.RawMessage `json:"data"`
		Links struct {
			Next string `json:"next"`
		} `json:"links"`
		Targets *struct {
			InScope    []platformTarget `json:"in_scope"`
			OutOfScope []platformTarget `json:"out_of_scope"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return "", nil, fmt.Errorf("JSON tak valid: %w", err)
	}
	switch {
	case doc.Targets != nil:
		assets := make([]platformAsset, 0, len(doc.Targets.InScope)+len(doc.Targets.OutOfScope))
		for _, t := range doc.Targets.InScope {
			assets = append(assets, t.asset(true))
		}
		for _, t := range doc.Targets.OutOfScope {
			assets = append(assets, t.asset(false))
		}
		return "bounty-targets-data JSON", assets, nil
	case len(doc.Data) > 0 && doc.Data[0] == '[':
		// Halaman API yang terpotong bisa kehilangan eksklusi.
		if doc.Links.Next != "" {
			return "", nil, errors.New("hasil API terpotong (links.next ada): gabungkan semua halaman atau pakai page[size]=100")
		}
		return parseHackerOneAPI(doc.Data)
	case len(doc.Data) > 0 && doc.Data[0] == '{':
		return parseBugcrowdBrief(doc.Data)
	}
	return "", nil, errors.New(unknownFormat)
}

func parseHackerOneAPI(data json.RawMessage) (string, []platformAsset, error) {
	var items []struct {
		Type       string         `json:"type"`
		Attributes platformTarget `json:"attributes"`
	}
	if err := json.Unmarshal(data, &items); err != nil {
		return "", nil, fmt.Errorf("JSON tak valid: %w", err)
	}
	assets := make([]platformAsset, 0, len(items))
	for _, it := range items {
		if it.Type != "structured-scope" {
			return "", nil, errors.New(unknownFormat)
		}
		// Berbeda dari daftar in_scope: di sini flag inilah satu-satunya bukti.
		elig := it.Attributes.EligibleForSubmission
		assets = append(assets, it.Attributes.asset(elig != nil && *elig))
	}
	return "HackerOne API JSON", assets, nil
}

func parseBugcrowdBrief(data json.RawMessage) (string, []platformAsset, error) {
	var brief struct {
		Scope []struct {
			InScope *bool            `json:"inScope"`
			Targets []platformTarget `json:"targets"`
		} `json:"scope"`
	}
	if err := json.Unmarshal(data, &brief); err != nil {
		return "", nil, fmt.Errorf("JSON tak valid: %w", err)
	}
	if brief.Scope == nil {
		return "", nil, errors.New(unknownFormat)
	}
	var assets []platformAsset
	for _, group := range brief.Scope {
		in := group.InScope != nil && *group.InScope
		for _, t := range group.Targets {
			assets = append(assets, t.asset(in))
		}
	}
	return "Bugcrowd brief JSON", assets, nil
}
