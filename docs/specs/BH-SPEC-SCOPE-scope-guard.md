# Spec: Scope Guard (BugHound)

Oct 21, 2026 · @Gh05t

The scope guard is BugHound's most critical security control: one enforcement point that makes sure only in-scope targets can be touched, and denies the rest by default. Because BugHound is an offensive tool, a scope-guard failure has legal and reputational consequences. This document fixes the scope format, normalization, decision algorithm, precedence, edge cases, and enforcement points so the implementation, the audit (BH-P03-APPSEC), and the tests (BH-P05-E2E) agree on the same definition. ID: `BH-SPEC-SCOPE`.

## Summary & role

The scope guard answers one question for every target: **may it be touched or not?** The answer binds all scan activity. If the guard lets one target through by mistake, BugHound could scan an asset that is not authorized, and that is a legal consequence, not just a bug.

So the guard is built with the most conservative stance: **default deny**. A target is allowed only when it is proven in-scope and not proven out-of-scope. All doubt ends in a denial.

This guard is referenced by three parties who must agree on the same definition:

- **The implementation** enforces it in the execution path.
- **The audit (BH-P03-APPSEC)** tests it hardest, looking for a way to bypass it.
- **E2E (BH-P05-E2E)** tests it earliest, making sure an out-of-scope target is denied in the UI.

## Principles

1. **Default deny.** If it is not proven in-scope, deny. There is no "maybe allowed".
2. **Out-of-scope wins.** If a target matches both in-scope and out-of-scope, the result is a denial. An exclusion always beats an allow.
3. **One enforcement point.** The decision is made in one module (the scope guard). No other component has its own scope logic.
4. **Cannot be bypassed.** No scan execution path can reach a target without going through the guard. This is structural, not a convention.
5. **Deterministic.** The same input always gives the same decision; it does not depend on time or order.
6. **Fail closed.** If the guard errors or the scope cannot be parsed, the result is a denial, not an allow.
7. **Decisions are recorded.** Every denial (and allow, at least in summary) goes into the audit trail.

## Scope input format

A program has two lists: **in-scope** and **out-of-scope**. Each entry uses one of the forms below.

| Form | Example | Matches |
| --- | --- | --- |
| Exact domain | `app.acme.io` | That host only |
| Subdomain wildcard | `*.acme.io` | Every subdomain of acme.io (see the wildcard rule) |
| URL / path prefix | `https://acme.io/api/` | URLs under that prefix |
| IP address | `203.0.113.10` | That IP only |
| CIDR range | `203.0.113.0/24` | Every IP in the range |

Rules:

- The out-of-scope list uses the same forms and is evaluated with higher precedence.
- An entry that cannot be parsed is rejected at input (the guard fails closed), and the user is told, it is not quietly ignored.
- The input text is kept as is for audit; matching is done on the normalized form (next section).
- A form not supported in v1 (e.g. a free-form regex) is rejected, not guessed at.
- An entry that parses but can never match a target is also rejected at input: a port outside 1-65535, a host with an empty label (`.acme.io`), and IP range notation (`10.0.0.1-50`, use CIDR). In out-of-scope, such an entry is a dead exclusion with no warning.
- An IP with a path must have a scheme (`http://203.0.113.10/admin`). Without a scheme it is ambiguous with a broken CIDR (`203.0.113.0/33`), so it is rejected.

## Target & scope normalization

Before they are compared, the target and the scope entries are normalized to the same canonical form. Normalization prevents a bypass through a spelling variant.

Host normalization steps:

- **Lowercase** the whole host.
- **Strip the scheme** (`https://`, `http://`) and the userinfo credentials (`user:pass@`).
- **IDN to punycode** (`xn--`), then compare in punycode form. This closes a bypass through a homoglyph/unicode.
- **Strip the trailing dot** on an FQDN.
- **Port**: split the host and port, then write it without leading zeros (`0443` = `443`). The v1 default port policy: host-based scope covers all ports unless an entry states a port explicitly. For an entry with a port, the target port is computed from the scheme when it is not written (`https://x` = 443, `http://x` = 80). If it is still unknown (`x`, or another scheme), the exclusion wins on doubt and no allow is granted.
- **Path**: for a URL entry, compare the path after it is normalized (resolve `.`/`..`, safe percent-decoding, remove double slashes).

IP normalization steps:

- Normalize the representation (e.g. IPv6 compressed consistently; reject or normalize a misleading decimal/octal form like `0x7f.0.0.1`).
- Compare the IP as a numeric value within the CIDR range, not as a string.
- A host that is an IP after normalization (`203.0.113.10.`, fullwidth digits): on an **entry** it is treated as an IP so its exclusion works; on a **target** it is rejected, because the engine still resolves it through DNS, so the destination is not proven to be the IP the guard evaluated.

After normalization, the target is represented as a (normalized host-or-IP, port, path) tuple used by the decision algorithm.

## Decision algorithm

For each target, the guard runs the following ordered steps. The order matters: out-of-scope is checked first so it always wins, and the default is a denial.

> _Diagram: scope guard decision · out-of-scope wins, default deny (available in the Claude Docs version; not carried into the Markdown export)._

Read as a rule: **deny if it matches out-of-scope; otherwise allow only if it matches in-scope; otherwise deny.** Normalization always runs first so the comparison is fair. If normalization or matching fails/errors, the result is a denial (fail closed).

## Precedence & matching rules

**Precedence:** out-of-scope always wins. A target that matches an in-scope entry *and* an out-of-scope entry is treated as out-of-scope (deny). This enables the common pattern "allow `*.acme.io` except `admin.acme.io`".

**Wildcard rule (`*.domain`):**

- `*.acme.io` matches subdomains like `app.acme.io` and `a.b.acme.io`.
- By default `*.acme.io` does **not** cover the apex `acme.io` itself; if the apex is also in-scope, it must be registered separately. (This policy is stated explicitly so the audit and tests agree.)
- A wildcard is only in the leftmost subdomain position; a form like `a.*.io` is not supported in v1.

**Host matching:** the comparison is on normalized domain labels (punycode, lowercase), not a substring. `notacme.io` does not match the entry `acme.io`, and `acme.io.evil.com` does not match `acme.io`.

**IP/CIDR matching:** the target IP is tested for membership in the CIDR range numerically.

**URL/path matching:** a path-prefix entry matches when the host is the same and the target path is under the prefix (at a segment boundary), not merely a string prefix. A URL host may be an IP; it only matches a target with the same IP.

## Edge cases

Cases that often become a bypass gap and how the guard handles them:

| Case | Risk | Guard policy |
| --- | --- | --- |
| Redirect during a scan | The scan is steered to an out-of-scope host | The redirect destination host is re-evaluated; out of scope = stop, not followed |
| Private IP / metadata | SSRF to 169.254.169.254, 10.0.0.0/8, etc. | Private/link-local ranges are denied unless explicitly in-scope (default deny is stricter here) |
| Homoglyph / IDN | `аcme.io` (Cyrillic letter) in disguise | Normalized to punycode before comparison |
| Misleading IP | `0x7f.0.0.1`, decimal, octal | Normalized to the canonical form or rejected |
| Unexpected port | The target is on another port | Per the port policy (see Normalization); when strict, a port not on the list is denied |
| Default port | The exclusion `acme.io:80` is skipped by `http://acme.io/` | The target port is computed from the scheme |
| Unknown port | The target `acme.io` against an entry with a port | The exclusion wins on doubt; no allow is granted |
| Leading-zero port | `https://acme.io:0443/` skips the port-443 exclusion | The port is canonicalized before comparison |
| Disguised IP | `203.0.113.10.`, fullwidth digits | The entry becomes an IP; the target is rejected |
| Path-based exclusion on HTTPS | CONNECT only reveals `host:port`, so `/admin` passes through the tunnel | That `host:port` is opened and each request is evaluated; whatever is not readable as HTTP/1 is closed |
| A name to an excluded IP | `app.acme.io` is in-scope, but resolves to `203.0.113.10` which is out-of-scope | Denied at connect; another IP from the same name is still allowed. A path-based exclusion on an IP does not apply to a request via a name, because the guard does not map the name to an IP when it evaluates the path |
| A port on a private IP | The exclusion `10.0.0.5:8080` closes another port, or a port-based allow does not apply at connect | Evaluated per destination port. An entry with a path grants no allow, because at connect there is no path yet |
| Entry that never matches | A dead exclusion with no warning | Rejected at input (see Scope input format) |
| Apex vs wildcard | `acme.io` passes through `*.acme.io` | The apex is not covered by the wildcard unless registered |
| Case & trailing dot | `ACME.io`, `acme.io.` | Normalized before comparison |
| Credentials in a URL | `user:pass@acme.io` | The userinfo is stripped during normalization; the host is still tested |
| Out-of-scope overlapping in-scope | `admin.acme.io` inside `*.acme.io` | Out-of-scope wins, deny |

Each case in this table should have its own E2E or unit test, because this is what is most likely to be attacked during an audit.

## Runtime enforcement

Checking scope only at input is not enough. A target can change mid-flight (a redirect, a new URL from crawling, a request the engine makes). So the guard is enforced in **two layers**:

1. **At input/planning.** Every initial target (from scope, recon, crawling) is filtered before it enters the scan queue. What is out of scope is dropped here.
2. **At egress, right before the outbound connection.** Every request an engine worker is about to send to the network is re-checked against the guard. This closes a target that appears at runtime (a redirect, a new link) that was not visible at planning.

The second layer is what makes the "never touches an out-of-scope asset" guarantee truly structural: even if there is a bug in an earlier stage, the outbound connection is still blocked. Ideally it is reinforced with a network restriction at the environment level (an egress allowlist), as defense in depth.

On HTTPS, CONNECT only reveals `host:port`, so a blind tunnel cannot enforce a path-based exclusion. So a `host:port` that has a path-based exclusion is opened: the proxy terminates the client connection and evaluates each request through the same gate as plain HTTP. Other hosts stay a blind tunnel. There is no way back: a connection not readable as HTTP/1 is closed, not forwarded. The reasons and limits are in the ADR `BH-ADR-egress-isolation`.

The guard must not be disablable through ordinary configuration. There is no "skip the scope guard" flag for convenience; turning it off (if it exists, for internal testing) must be explicit, recorded, and impossible to enable on the production path.

## Logging & audit

Every denying guard decision is recorded to the audit trail with: the time, the target (normalized), the program, the run\_id, the reason (out-of-scope / not in-scope / parse failure), and the scope entry that triggered it (when the denial is because of out-of-scope).

- A denial at the egress layer is treated as an important signal: if it happens often, it can indicate a bug at the planning stage or an abuse attempt.
- The layer column distinguishes `input` (at planning), `egress` (a request held before the connection is made), and `finding` (an out-of-scope finding dropped after the engine finished). `finding` evaluates a result, so it is not evidence that the connection was blocked. Old entries from before this split stay labeled `egress`.
- The scope audit trail must not be deletable quietly (in line with BugHound's audit-trail principle).
- Allowed targets may be recorded in summary (at least a count/aggregate) so a full trail is available for the audit (BH-P03-APPSEC), without overloading the log.

This log is the main evidence when the pre-launch audit judges whether the scope guard really enforces the boundary.

## Platform format importer

A program's scope can be imported from platform data instead of typed. The importer (`internal/scope/importer.go`) only **produces text**: it makes no decision (that stays the guard's job) and stores nothing. The result fills the scope editor form for review, then goes through the ordinary fail-closed save path. There is no outbound connection: the user loads or pastes the data themselves, one program per import.

| Source | Form | In-scope evidence |
| --- | --- | --- |
| HackerOne, the **Download CSV** button | `identifier,asset_type,…` | `eligible_for_submission` = `true` |
| HackerOne API | `GET /v1/hackers/programs/{handle}/structured_scopes` | `eligible_for_submission` = `true` |
| Bugcrowd, the brief document | `data.scope[].targets[]` | `inScope` = `true` on the group |
| `bounty-targets-data` | one program object | listed in `in_scope` and not marked `eligible_for_submission` = `false` |

The Bugcrowd brief form is not officially documented; it follows what `arkadiyt/bounty-targets` reads. An unclear status is never an allow: an asset without in-scope evidence is treated as out-of-scope.

**The rounding-direction invariant.** Platform data is looser than this scope language. When an asset cannot be represented exactly, in-scope may only **narrow** (doubt = not imported, default deny covers it) and out-of-scope may only **widen** (doubt = widened), because a missing exclusion means under-blocking.

| Case | In-scope | Out-of-scope |
| --- | --- | --- |
| Host, `*.domain`, IP, CIDR | As is, normalized | As is; `*.x` adds the apex `x`, unless `x` is explicitly in-scope |
| Leading dot (`.x`) | Not imported | Same as `*.x` |
| Port | Kept | Dropped |
| Path `/x/*` | Prefix `/x` | Prefix `/x` |
| Another pattern or encoding in the path | Not imported | Trimmed to the segment boundary |
| Query, fragment, userinfo | Not imported | Dropped |
| Middle/partial wildcard (`api.*.x`, `a*.x`) | Not imported | Widened to `*.x` |
| URL with an IP host | Only at the root, so an IP entry | Becomes a whole-IP entry |
| Public suffix (`*.com`, `*.github.io`), CIDR wider than /8 (IPv4) or /32 (IPv6) | Not imported | As is |
| Non-public IP/CIDR (private, loopback, metadata) | Not imported; write it by hand if deliberate | As is |
| A scheme other than http/https | Not imported | Its host is used |
| Mobile, source-code, hardware types | Not imported | Skipped |
| `OTHER` and unknown types | Not imported | Attempted; failure = not represented |
| Unreadable (free text, redacted, `acme.*`) | Not imported | Not represented |

The output is rewritten from the normalized entries, not copied from the platform string, so what is stored is exactly what the guard enforces. The in-scope check is run on the re-parsed output text, that is, the entries the guard actually compiles. Passing the parser is not enough: `all` and `localhost` are valid for hand-written scope (a lab), but on public program data that is free text, so an imported host must have a known TLD.

**An unrepresentable exclusion holds the import.** The form is not filled until the user reads the list and approves it. The approval is bound to the data's fingerprint, so it does not apply to other data. Such an exclusion stays the user's responsibility: the guard does not block it until it is written as an entry.

**Rejected entirely, with no partial result:** an unknown format, truncated data (`links.next` on the API, an incomplete CSV row), more than one program, a target without an in/out status (the Bugcrowd `targets_url` response), and data over 4 MiB.

**Merging with the form contents:** in-scope is **replaced** (old entries could be an asset the program has since dropped, and what is replaced is shown), out-of-scope is **merged** (a hand-written exclusion must not be lost).

**In-scope entries overridden by an exclusion are reported.** The common pattern "`www.x` in-scope, `*.x` out-of-scope" makes that entry dead because out-of-scope wins. The importer does not loosen the exclusion; it names the entry and the exclusion that triggered it so the user decides.

**Audit:** every attempt is recorded as `program.import` (succeeded, held, failed) along with the count and the data fingerprint, without the data contents. A scope save is recorded as `program.save`.

**Limits:** a free-text rule in a program policy is not read, and an in-scope wildcard apex is not added automatically (in line with the wildcard rule above). The hunter must still read the program brief.

## Open questions

> Reconciled with the implementation on 2026-11-04. `[x]` = decided/implemented, `[ ]` = still open.

- [x] Port policy: **v1 default = host-based scope covers all ports**, unless an entry states a port explicitly (see the §Format above). Tightening to 80/443-only stays a future option if needed.
- [x] Apex + wildcard: **kept separate**: `*.domain` only covers subdomains (a wildcard in the leftmost position), the apex must be registered as its own entry (`internal/scope/entry.go`). The stricter, safer choice.
- [x] Private/metadata IP: **deny at connect unless explicitly in-scope** for the destination port (an IP, `IP:port`, CIDR, or a URL with an IP host and no path). The egress dialer rejects loopback/private/link-local/metadata then *pins* the checked IP (anti-rebinding). See `BH-AUDIT-M2` BH-F02, `internal/egress/ssrf_test.go`.
- [x] Platform scope format: **a HackerOne/Bugcrowd importer is built** (see the §Platform format importer). This document's canonical form stays the only one stored and enforced.
- [x] Egress enforcement: **in the application (forced proxy)**: active engines are forced through `-proxy` + the `HTTP(S)_PROXY`/`ALL_PROXY` env. A network/container allowlist per scan = opt-in hardening; residual non-HTTP egress is accepted for the current threat model (ADR `BH-ADR-egress-isolation`, BH-F03).
- [x] DNS resolution: **yes, denied**: an in-scope hostname that resolves to an out-of-scope/private IP is denied at connect with IP-pinning (prevents DNS rebinding). See BH-F02.

Note: the answers lean stricter as directed; the scope guard stays default-deny.
