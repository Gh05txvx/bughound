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

// Importer converts platform scope data (HackerOne, Bugcrowd) into canonical
// BH-SPEC-SCOPE entries. It only PRODUCES TEXT: it makes no decision
// (that is the Guard's job) and stores nothing. The result fills the scope
// editor form for review, then goes through the ordinary save path.
//
// Platform data is written by a third party and its form is looser than
// bughound's scope language. When an asset cannot be represented exactly, the
// rounding direction must be safe. The core INVARIANTS of this file:
//
//   - In-scope may only NARROW: in doubt = not imported; default deny covers it.
//   - Out-of-scope may only WIDEN: in doubt = widened. An exclusion that cannot
//     be represented at all goes to Unresolved and holds the import until reviewed,
//     because a missing exclusion means under-blocking.
//
// "Passes parseEntry" does not yet mean acceptable from third-party data: "all" and
// "localhost" are valid for a hand-written scope (a lab), but on a public program
// list they are free text. So the parseEntry result is checked again, then the output
// is rewritten from the normalized entry fields, not from the platform string.

// MaxImportBytes guards resources, it does not filter a platform dump (that is rejected
// by its form). A real large program reaches ~1.3 MiB (5 thousand assets). The form
// is capped at 10 MiB by net/http and urlencode widens the data ~1.35x, so this limit
// still fits in one POST.
const MaxImportBytes = 4 << 20

const (
	minBitsV4 = 8  // an in-scope CIDR wider than this is rejected (not one program's asset)
	minBitsV6 = 32 // matches a common RIR allocation
	maxNote   = 300
)

// nonPublicPrefixes are ranges that must not enter in-scope through an import.
// It mirrors egress.isSpecialIP (an internal IP is allowed only when EXPLICITLY
// in-scope), plus 0.0.0.0/8 and CGNAT. Third-party data must not open cloud
// metadata or an internal network; if it is intentional, the user writes it
// themselves. The scope package cannot import egress (a cycle).
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

// ImportItem is one platform asset the user needs to see.
type ImportItem struct {
	Asset  string // the identifier as-is from the platform
	Type   string // the asset type per the platform
	Detail string // the reason, conversion result, or program instruction
}

// ImportResult is the result of converting platform data.
type ImportResult struct {
	Format   string   // the detected format
	Digest   string   // input fingerprint; the Unresolved agreement is bound to this
	InScope  []string // canonical entries
	OutScope []string // canonical entries

	Unresolved []ImportItem // unrepresentable exclusions: must be reviewed before import
	Shadowed   []ImportItem // in-scope overridden by an exclusion: the guard will deny it
	Widened    []ImportItem // exclusions deliberately widened so they stay effective
	Skipped    []ImportItem // in-scope not imported & non-web assets
	Notes      []ImportItem // program instructions for an in-scope asset
}

// ImportPlatform detects the data format, then converts it. An error means the data
// cannot be trusted as a complete scope list (unknown format, truncated,
// more than one program): no partial result, fail closed.
func ImportPlatform(raw string) (ImportResult, error) {
	if len(raw) > MaxImportBytes {
		return ImportResult{}, fmt.Errorf("data exceeds the %d KiB limit: paste a single program only", MaxImportBytes>>10)
	}
	s := strings.TrimSpace(strings.TrimPrefix(strings.ReplaceAll(raw, "\r\n", "\n"), "\xef\xbb\xbf"))
	if s == "" {
		return ImportResult{}, errors.New("empty data")
	}
	format, assets, err := parseAssets(s)
	if err != nil {
		return ImportResult{}, err
	}
	if len(assets) == 0 {
		return ImportResult{}, errors.New("data holds no assets")
	}
	sum := sha256.Sum256([]byte(s))
	res := ImportResult{Format: format, Digest: hex.EncodeToString(sum[:16])}

	// In-scope first: the derived apex of a wildcard exclusion needs to know which host
	// the program explicitly allows.
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

	// Final gate: the output must pass the same guard compilation.
	g, errs := New(res.InScope, res.OutScope)
	if len(errs) > 0 {
		return ImportResult{}, fmt.Errorf("the conversion result was rejected by the guard: %w", errs[0])
	}
	// The common pattern "www.x in-scope, *.x out-of-scope": out-of-scope wins, so
	// that entry is dead. The direction is safe, but the user needs to know.
	for _, s := range res.InScope {
		if d := g.Evaluate(s); d.Reason == ReasonOutOfScope {
			res.Shadowed = append(res.Shadowed, ImportItem{Asset: s, Detail: "denied by " + d.MatchedEntry})
		}
	}
	return res, nil
}

func (r *ImportResult) addIn(a platformAsset, inHosts map[string]bool) {
	switch classifyAsset(a.assetType) {
	case classNonWeb:
		r.Skipped = append(r.Skipped, a.item("non-web asset: not a DAST target"))
		return
	case classOther:
		r.Skipped = append(r.Skipped, a.item("this type is not guessed; add it manually if it is really a web asset"))
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
		r.Skipped = append(r.Skipped, a.item("non-web asset: not a DAST target"))
		return
	}
	// OTHER/unknown types are still attempted: adding an exclusion is always the safe direction.
	ex, err := convertOut(a.identifier)
	if err != nil {
		r.Unresolved = append(r.Unresolved, a.item(err.Error()))
		return
	}
	// A derived apex must not override a host the program explicitly allows
	// (valid pattern: "acme.io" in-scope, "*.acme.io" out-of-scope).
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

// ---- Asset type classification ----

type assetClass int

const (
	classWeb    assetClass = iota // network target
	classNonWeb                   // mobile, source, hardware: not a DAST target
	classOther                    // OTHER & unknown types: do not guess
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

// ---- Identifier conversion ----

// ident is a split platform identifier, not yet interpreted.
type ident struct {
	scheme string // lowercase, "" if absent
	host   string // host[:port], may contain '*'
	path   string // without query/fragment, "" if absent
	extra  bool   // has userinfo/query/fragment not representable as a scope entry
}

func splitIdent(raw string) (ident, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ident{}, errors.New("empty identifier")
	}
	if hasSuspiciousChars(s) {
		return ident{}, errors.New("free text, not a host/URL")
	}
	var id ident
	// Query/fragment is trimmed first: a "://" inside it is not a scheme, and
	// "a.io#@evil.com" must still have host a.io like a browser reads it.
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
		return ident{}, errors.New("identifier without a host")
	}
	id.host = s
	return id, nil
}

// splitHostList splits a comma-separated host list ("a.io,b.io") common in platform
// data. An identifier with a path is not split: a comma in a path is not a separator, and
// guessing could create a false in-scope host.
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

// convertIn converts an in-scope asset. Narrowing only: anything that cannot
// be represented without widening is returned as an error.
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
		return "", errors.New("holds userinfo/query/fragment: importing it would widen in-scope")
	}
	if id.scheme != "" && id.scheme != "http" && id.scheme != "https" {
		return "", fmt.Errorf("scheme %q is not web", id.scheme)
	}
	// "/x/*" equals prefix "/x"; another "*" in the path has no equivalent.
	path := strings.TrimSuffix(id.path, "/*")
	if strings.ContainsAny(path, "*%") {
		return "", errors.New("a pattern/encoding in the path has no scope-entry equivalent")
	}
	if path == "/" {
		path = ""
	}
	cand := id.host + path
	if strings.Contains(id.host, "*") {
		if path != "" {
			return "", errors.New("wildcard + path has no scope-entry equivalent")
		}
	} else if id.scheme != "" {
		cand = id.scheme + "://" + cand
	}
	e, err := parseEntry(cand)
	if err != nil {
		return "", errors.New("form not supported as a scope entry")
	}
	// A URL with an IP host is treated as an IP entry so the public-IP check applies. A path on
	// an IP host is not imported: the canonical output holds no scheme, which it would require.
	if a, ok := urlHostIP(e); ok {
		if e.path != "/" {
			return "", errors.New("a path on an IP host has no scope-entry equivalent")
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

// checkInScope rejects an entry that is syntactically valid but not acceptable
// from third-party data.
func checkInScope(e entry) error {
	switch e.kind {
	case kindHostExact, kindURLPrefix:
		return checkPublicHost(e.host)
	case kindWildcard:
		if _, err := publicsuffix.EffectiveTLDPlusOne(e.base); err != nil {
			return errors.New("wildcard too wide: covers an entire public suffix")
		}
		return checkPublicHost(e.base)
	case kindIP:
		if !publicAddr(e.addr) {
			return errors.New("non-public IP: add it manually if it is intentional")
		}
	case kindCIDR:
		minBits := minBitsV4
		if e.cidr.Addr().Is6() {
			minBits = minBitsV6
		}
		if e.cidr.Bits() < minBits {
			return errors.New("CIDR range too wide")
		}
		if !publicPrefix(e.cidr) {
			return errors.New("non-public range: add it manually if it is intentional")
		}
	}
	return nil
}

// exclusion is the result of converting one out-of-scope asset.
type exclusion struct {
	entries []string
	apexes  []string // wildcard apex, used when not explicitly in-scope
	widened bool     // wider than the original
}

// convertOut converts an out-of-scope asset. Widening only: a port, query, and path
// that cannot be represented are dropped (the output covers the original); an error means there is no
// sensible superset, and the asset must be reviewed by a human.
func convertOut(raw string) (exclusion, error) {
	// Always split on commas, unlike in-scope: an unreadable part
	// sends the whole asset to review, while not splitting means the part
	// after the comma is lost silently (under-blocking).
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
		return exclusion{}, errors.New("empty identifier")
	}
	return ex, nil
}

func convertOneOut(raw string) (exclusion, error) {
	id, err := splitIdent(raw)
	if err != nil {
		return exclusion{}, err
	}
	// The port is dropped: a wider exclusion is always safe, and a wildcard cannot hold it.
	host, port, err := splitHostPort(id.host)
	if err != nil {
		return exclusion{}, errors.New("form not supported as a scope entry")
	}
	ex := exclusion{widened: id.extra || port != ""}
	// ".acme.io" commonly means acme.io and its subdomains.
	if strings.HasPrefix(host, ".") {
		host = "*" + host
	}
	if strings.Contains(host, "*") {
		return wildcardExclusion(host, id.path, ex)
	}

	// The path is trimmed at the segment boundary before a pattern/encoding: a schemeless entry's path
	// is compared literally, while the target path is already decoded.
	path := strings.TrimSuffix(id.path, "/*")
	if i := strings.IndexAny(path, "*%"); i >= 0 {
		path = path[:strings.LastIndexByte(path[:i], '/')+1]
		ex.widened = true
	}
	var e entry
	if a, err := netip.ParseAddr(host); err == nil && id.scheme != "" {
		// A scheme means a URL: the whole IP surely covers its path.
		ex.widened = ex.widened || strings.Trim(path, "/") != ""
		e = entry{kind: kindIP, addr: a}
	} else {
		// Without a scheme, an IP with a path is not a URL but broken CIDR; parseEntry
		// rejects it, so the exclusion does not silently shrink to a single IP.
		if e, err = parseEntry(host + path); err != nil {
			return exclusion{}, errors.New("form not supported as a scope entry")
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

// wildcardExclusion maps a host pattern with '*' to a left wildcard that surely
// covers it. The form "*.x" stays, plus apex x: the platform's meaning for the apex
// is ambiguous, and the safe direction for an exclusion is to widen. Other patterns ("api.*.x", "a*.x")
// widen to "*.x".
func wildcardExclusion(host, path string, ex exclusion) (exclusion, error) {
	rest := host[strings.LastIndexByte(host, '*')+1:]
	dot := strings.IndexByte(rest, '.')
	if dot < 0 || rest[dot+1:] == "" {
		return exclusion{}, errors.New("the pattern has no anchor domain")
	}
	e, err := parseEntry("*." + rest[dot+1:])
	if err != nil {
		return exclusion{}, errors.New("form not supported as a scope entry")
	}
	exact := strings.HasPrefix(host, "*.") && strings.Count(host, "*") == 1
	if !exact {
		// Without a real anchor "*foo.com" would become "*.com": a sham exclusion.
		if _, err := publicsuffix.EffectiveTLDPlusOne(e.base); err != nil {
			return exclusion{}, errors.New("the pattern has no anchor domain")
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

// urlHostIP reports a URL entry with an IP host and its address.
func urlHostIP(e entry) (netip.Addr, bool) {
	return e.addr, e.kind == kindURLPrefix && e.addr.IsValid()
}

// renderEntry writes a normalized entry as canonical text: what is stored
// is exactly what the Guard enforces, without a scheme (the Guard does not use it), userinfo,
// or query. Text that cannot be re-parsed is rejected.
//
// The re-parsed entry is returned too because that is what the Guard will
// compile. The safety checks use this entry, not its input.
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
		return "", entry{}, errors.New("form not supported as a scope entry")
	}
	return s, final, nil
}

func withPort(host, port string) string {
	if port == "" {
		return host
	}
	return net.JoinHostPort(host, port)
}

// checkPublicHost rejects a name without a real TLD ("all", "localhost", "app.internal"):
// valid for a hand-written scope, but on public program data it is free text.
func checkPublicHost(host string) error {
	if suffix, icann := publicsuffix.PublicSuffix(host); !icann && !strings.Contains(suffix, ".") {
		return errors.New("not a public domain (unknown TLD)")
	}
	return nil
}

func publicAddr(a netip.Addr) bool {
	if a.Is4In6() { // the Guard compares it separately from IPv4; do not import
		return false
	}
	a = a.WithZone("") // Prefix.Contains is always false for a zoned address
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

// platformAsset is one asset in neutral form. inScope is true only when the
// platform states it explicitly: an unclear status never becomes an allow.
type platformAsset struct {
	identifier string
	assetType  string
	inScope    bool
	note       string
}

func (a platformAsset) item(detail string) ImportItem {
	return ImportItem{Asset: a.identifier, Type: a.assetType, Detail: detail}
}

const unknownFormat = "unrecognized format: use HackerOne CSV (Download CSV), HackerOne JSON API (structured_scopes), Bugcrowd brief JSON, or a single bounty-targets-data program object"

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
		return nil, fmt.Errorf("invalid CSV: %w", err)
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

// platformTarget holds the target fields of HackerOne and Bugcrowd together; only
// one group is filled per format.
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
	// HackerOne may mark an asset ineligible for submission even if listed.
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
			return "", nil, fmt.Errorf("invalid JSON: %w", err)
		}
		if len(arr) != 1 {
			return "", nil, fmt.Errorf("data holds %d programs: paste exactly one program", len(arr))
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
		return "", nil, fmt.Errorf("invalid JSON: %w", err)
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
		// A truncated API page can lose exclusions.
		if doc.Links.Next != "" {
			return "", nil, errors.New("the API result is truncated (links.next present): merge all pages or use page[size]=100")
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
		return "", nil, fmt.Errorf("invalid JSON: %w", err)
	}
	assets := make([]platformAsset, 0, len(items))
	for _, it := range items {
		if it.Type != "structured-scope" {
			return "", nil, errors.New(unknownFormat)
		}
		// Unlike the in_scope list: here this flag is the only evidence.
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
		return "", nil, fmt.Errorf("invalid JSON: %w", err)
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
