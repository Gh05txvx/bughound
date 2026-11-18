package nuclei

import (
	"fmt"
	"strconv"
	"strings"
)

// Safety sets the execution safety profile for the active DAST engine (nuclei fuzzing).
//
// Two layers, matching bug bounty needs (finding candidate bugs for manual
// verification, NOT exploiting them to the point of damage):
//
//  1. Non-destructive, ALWAYS on, structural (not an option that input can turn
//     off). The engine never sends a denial-of-service payload (the `dos` tag)
//     and never uses a blind/OAST callback to a third party (`-no-interactsh`),
//     in line with the egress proxy that already blocks out-of-scope
//     destinations. Fuzzing is held to `-fuzz-aggression low`.
//  2. Stealth (optional), low-and-slow: a very low rate, one connection, a
//     reasonable browser User-Agent, a narrowed URL scope. The point is to keep
//     the footprint down so legitimate work is not mistaken for an attack by the
//     target's monitoring (SOC). This REDUCES noise & the risk of a false
//     incident, it is not a guarantee of "undetected", and it does not touch
//     bughound's own audit trail.
type Safety struct {
	Stealth bool
}

const (
	stealthRateLimit   = 3  // max req/s in stealth (low-and-slow)
	stealthConcurrency = 1  // -c in stealth (one connection)
	stealthTimeout     = 20 // -timeout (s) in stealth (patient, not greedy)
	stealthMaxURLs     = 40 // fuzz URL cap in stealth (< default maxDASTURLs)

	// browserUA: a reasonable browser User-Agent so a request does not immediately
	// stand out as an automated scanner. Not a disguise for a malicious purpose; the
	// context is legitimate testing with a minimal footprint.
	browserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

// destructiveExcludeTags are nuclei tags the bughound engine NEVER sends:
// payloads that could damage or degrade the target's service or hijack another
// user's request. dos = denial-of-service; smuggling = request smuggling/desync.
// The list is deliberately conservative; this non-destructive stance is structural.
var destructiveExcludeTags = []string{"dos", "smuggling"}

// destructiveExcludeIDs are individual unsafe templates that change the target's
// state (upload/write) so they are not non-destructive, but are not caught by the
// tags above. CVE-2021-30118: uploads an .aspx webshell (Kaseya). CVE-2023-46747:
// an AJP F5 smuggling that creates an admin and then runs commands. Excluded
// per-ID, not via the intrusive tag, so hundreds of other intrusive non-destructive templates still run.
var destructiveExcludeIDs = []string{"CVE-2021-30118", "CVE-2023-46747"}

// nonDestructiveArgs returns the nuclei arguments that reject destructive
// templates/payloads. Used by both the plain runner and -dast so this policy has
// one source and cannot slip on either path.
func nonDestructiveArgs() []string {
	var a []string
	if len(destructiveExcludeTags) > 0 {
		a = append(a, "-exclude-tags", strings.Join(destructiveExcludeTags, ","))
	}
	if len(destructiveExcludeIDs) > 0 {
		a = append(a, "-exclude-id", strings.Join(destructiveExcludeIDs, ","))
	}
	return a
}

// nucleiExtraArgs returns the safety arguments for `nuclei -dast`. Non-destructive
// is always included; the stealth arguments only when Stealth is active.
func (s Safety) nucleiExtraArgs() []string {
	args := append([]string{
		"-no-interactsh", // no blind/OAST callback to a third party
	}, nonDestructiveArgs()...)
	if s.Stealth {
		args = append(args,
			"-c", strconv.Itoa(stealthConcurrency),
			"-timeout", strconv.Itoa(stealthTimeout),
			"-H", "User-Agent: "+browserUA,
		)
	}
	return args
}

// katanaExtraArgs returns the stealth arguments for the katana crawl (nil when not
// stealth; the default crawl is already light).
func (s Safety) katanaExtraArgs() []string {
	if !s.Stealth {
		return nil
	}
	return []string{
		"-c", strconv.Itoa(stealthConcurrency),
		"-H", "User-Agent: " + browserUA,
	}
}

// rate clamps the rate (req/s) to the profile: in stealth it never exceeds
// stealthRateLimit; otherwise it uses base as-is (base<=0 = let the engine use its default).
func (s Safety) rate(base int) int {
	if s.Stealth && (base <= 0 || base > stealthRateLimit) {
		return stealthRateLimit
	}
	return base
}

// maxURLs returns the cap on the number of URLs fuzzed per the profile.
func (s Safety) maxURLs() int {
	if s.Stealth {
		return stealthMaxURLs
	}
	return maxDASTURLs
}

// Describe summarizes the profile for the log/audit (no sensitive data).
func (s Safety) Describe() string {
	mode := "standard"
	if s.Stealth {
		mode = fmt.Sprintf("stealth(rate≤%d,c%d,UA-browser)", stealthRateLimit, stealthConcurrency)
	}
	return fmt.Sprintf("non-destructive[no-interactsh,exclude-tags=%s,exclude-id=%d,aggression=low] + %s",
		strings.Join(destructiveExcludeTags, ","), len(destructiveExcludeIDs), mode)
}
