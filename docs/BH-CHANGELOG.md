# BH-CHANGELOG: implementation progress notes

An engineering log: **what has been built** in the repo (a companion to the spec/PRD, which state what *should* be built). The source of truth for detail stays git history + CI; this document is the summary map. Relative dates are converted to milestones/releases.

## Status at a glance

The **M0** foundation, the **M1** MVP, and **M2** triage & multi-engine: **done**. **M3** (hardening & release) is underway: the pre-launch audit passed + remediated, platform export, the dashboard, the SAST plugin, real engine adapters (ffuf, ZAP, dalfox). Public releases: **v0.1.0 through v0.5.0** (cross-platform + `SHA256SUMS.txt`).

## Releases

| Tag | Core content |
| --- | --- |
| `v0.5.0` | SAST expanded: **Bandit** (Python), **Gitleaks** (secret detection, double redaction), and **FindSecBugs** (JVM bytecode, opt-in) adapters + a generic **SARIF 2.1.0 normalizer** (one normalization path for CodeQL/SpotBugs/gitleaks & other SARIF emitters), all three appearing automatically in the `/sast` dropdown; **multi-target Docker images** `dast`/`sast`/`full`, so the DAST & SAST toolchains can be used separately (their own image), all three variants published to GHCR (`-dast`/`-sast`/main) |
| `v0.4.0` | SAST on by default (the semgrep `p/default` ruleset pre-baked, offline-ready); the **dalfox** XSS engine (adapter + normalization, requests through the scope-enforced egress proxy); **API route brute force** opt-in per scan (the Assetnote `apiroutes` wordlist) + a wall calibration that echoes the path, a 401/403/500 group of the same shape collapses into one record so real routes do not drown |
| `v0.3.2` | The "BugHound" brand unified (UI/docs/report); HackerOne/Bugcrowd scope import; a per-program template preset; OWASP 2021 category + HTTP method & evidence size clamp on findings; several egress/scope hardenings |
| `v0.3.1` | Secret hardening (redacting the master key & proxy-chain credentials, wrapping the master key with Secret); dead-code removal (BH-P06); a shorter README intro |
| `v0.3.0` | A big release: RBAC + required login, a UI redesign, the Payload Bank + template selection, per-engine rate throttling; the dashboard (live scan monitor, delete findings/program); ffuf quality (SPA catch-all calibration + site-wide dedup + robots.txt/OpenAPI enrichment); the retire.js (client SCA) & nuclei-dast (active fuzzing) adapters; Burp integration (a read-only API + extension); M3 draft completion; the Proxy menu |
| `v0.2.7` | Capture: a recording reverse proxy (manual browsing -> scan) |
| `v0.2.6` | Upstream proxy & egress chains |
| `v0.2.5` | gRPC fuzzing of read-only method invocations (detect access without auth) |
| `v0.2.4` | OpenAPI/Swagger-directed scan + gRPC enumeration |
| `v0.2.3` | Recon naabu + gau + dnsx (the 9-engine GHCR image) |
| `v0.2.2` | Docker (engines inside the image) + pushing the image to GHCR |
| `v0.2.1` | Real ffuf + ZAP engine adapters (scan mode & built-in wordlist) |
| `v0.2.0` | SAST as a plugin (local static analysis; a minor bump) |
| `v0.1.2` | Report export to the HackerOne/Bugcrowd templates + the Dashboard |
| `v0.1.1` | A CSRF fix (Origin: null) + audit anchoring (BH-F06) |
| `v0.1.0` | The foundation + M1 + single-binary packaging |

Each release = a cross-platform single binary (linux/darwin/windows) + `SHA256SUMS.txt`, built by the `release.yml` workflow when a `v*` tag is pushed.

## Foundation & pipeline (M0-M1)

- **The Unified Finding Schema** (`BH-SPEC-FINDING`): a versioned format, a deterministic `dedup_key`, redacted evidence.
- **The Scope Guard** (`BH-SPEC-SCOPE`): domain/wildcard/URL/IP/CIDR, punycode & IP normalization, default-deny, **two-layer** enforcement (input + egress).
- **The store**: in-memory & SQLite (pure-Go), per-program dedup, triage, severity-ordered queries, persistent programs+scope.
- **The orchestrator**: recon → scope (input) → rate-limited scan → egress re-check → store + audit.
- **The web UI**: Go + HTMX + `html/template`, assets `go:embed`-ed (single binary).
- **The rate limiter**, mandatory in the execution path (the config is clamped, it cannot be turned off).
- **Recon**: a mock + real pipeline (subfinder → httpx → katana).
- An async **job queue** (worker pool), a **report module** (Markdown draft + PDF), an **egress proxy** (HTTP+CONNECT, per-connection scope) + the real `nuclei.Runner`.

## Triage & scope (M2)

- **Bulk actions** on Findings: confirm / false-positive / ignore at once (fail-closed status, CSRF).
- **Filters** by severity | status | type | run.
- **Persistent programs & scope** + a **scope editor** with an allow/deny preview (without touching the network).

## Security

The 7 binding principles are implemented & tested:

1. Default-deny scope guard, one enforcement point, bypass-resistant (homoglyph/IP-obfuscation/userinfo/suffix/encoding).
2. Never touches out-of-scope, input + egress + per-connection proxy; an anti-SSRF/anti-rebinding dialer (resolve + reject internal IPs + pin the IP).
3. No auto-submit, a report is always a draft; export only formats it for manual submission.
4. The rate limiter is in the execution path.
5. Secrets are AES-256-GCM, a keyring + rotation, redacted from the log/store/report.
6. An append-only HMAC-chain audit trail + **external anchoring** (BH-F06): a truncation/rollback/whole-store deletion is detected.
7. One unified finding schema for every engine.

**The pre-launch audit (`BH-P03-APPSEC`)**: the audit report is managed internally (not included in the public repo). Every **High/Medium/Low** finding is remediated (BH-F01 CSRF+auth, BH-F02 rebinding, BH-F04 parser, BH-F05 reveal-audit, BH-F06 anchoring, BH-F07 rotation; BH-F03 mitigated with Option C + an ADR). Remaining: Info (F08/F09), BH-F03 (defense in depth), Option A (an OS allowlist). An extra fix from E2E: CSRF accepts `Origin: null` (a non-HTMX same-origin form in Chromium) without weakening the defense (token + Sec-Fetch-Site).

## Release & CI

- **Packaging**: a single binary (`go:embed` + pure-Go SQLite, CGO off), the version via `-ldflags -X main.version`, the UI footer + `-version`.
- **Tooling**: `Makefile`, `scripts/build-release.sh` (cross-compile + archive + checksum).
- **Workflows**: `ci.yml` (Go test), `e2e.yml` (Playwright), `release.yml` (a `v*` tag -> a GitHub Release).

## E2E (`BH-P05`)

A Playwright suite in `e2e/`: 5 scenarios (2 critical: scope-guard & no-auto-submit; + scan-flow, triage, program-scope). Mock engines, an ephemeral store/key, localhost bind, **egress blocked in two layers** (a dead proxy env + a browser guard). Page Object Model, role/text selectors, auto-wait.

## Report & export (M3)

- A draft report from **confirmed** findings (Markdown, download/print-PDF).
- **Export** to the **HackerOne** & **Bugcrowd** templates (per finding or the whole report), still a draft, **manual** submission, no outbound connection; a severity/CWE/CVSS mapping + each platform's own sections.

## Dashboard (M3)

The `/dashboard` landing page: cross-program KPIs (programs/findings/confirmed/runs) + a per-program table (severity breakdown, confirmations, runs, last activity, quick links).

## SAST as a plugin (M3)

`internal/sast`: static analysis as a **plugin** (an adapter registry) that writes to the same finding schema, reading **local code**. The boundary = a **path scope** (`sast.Resolve`: confine to one root, default-deny, reject traversal/symlink-escape). Adapters: **Mock** (offline) + the **semgrep Runner**. Enabled with `-sast-root`; findings appear in Findings/Dashboard.

## Engine adapter status

| Engine | Role | Adapter |
| --- | --- | --- |
| nuclei | DAST | mock + real (`-proxy`) |
| subfinder → httpx → katana | recon | mock + real (httpx/katana through the proxy) |
| gau | recon (historical URLs, passive) | mock + real |
| dnsx | recon (DNS resolution) | mock + real |
| naabu | recon (TCP port scan) | mock + real (raw TCP; only scanned on in-scope hosts from httpx) |
| ffuf | DAST (content discovery) | mock + real (the built-in wordlist embedded; override with `-ffuf-wordlist`) |
| ZAP | DAST (proxy scanner) | mock + real (`-zap-mode` quick/baseline/full; full = spider + active scan via the Automation Framework; upstream proxy config) |
| semgrep | SAST | mock + real (opt-in via `-sast-root`) |
| grpcurl | gRPC (enumeration + invocation fuzzing) | mock + real (`-grpc real`) |

Engine selection: `-engine mock` (default, all mock, no network) · `-engine real` (real nuclei + recon) · a comma list `-engine nuclei,ffuf,zap`. Every real engine = an external tool subprocess that is **not bundled**; see the README "DAST & recon engines" (install instructions there).

## OpenAPI/Swagger-directed scan (API)

`internal/openapi`: `Endpoints(spec, fallbackBase)` parses OpenAPI 3 / Swagger 2 (JSON or YAML via gopkg.in/yaml.v3, falling back to encoding/json) → a list of unique absolute endpoint URLs (the base from `servers`/`host`+`basePath`+`schemes` or the fallback target; a path param `{id}`→`1`). The Scan form has an *OpenAPI/Swagger spec* field: the expanded endpoints are added as targets and **still pass the scope guard** (a spec does not bypass the boundary). It reaches every documented API endpoint, not just what crawling found. Limits: no per-method/body fuzzing yet (nuclei `-im openapi`) & no gRPC yet. Tests `openapi/openapi_test.go` + `web/openapi_scan_test.go`.

## gRPC: enumeration via reflection

`internal/engine/grpc`: `Mock` + `Runner` (grpcurl) + `buildFindings`. It uses gRPC Server Reflection to enumerate services & methods → findings: `grpc-reflection-enabled` (Medium, CWE-200), `grpc-service-exposed`, `grpc-method-exposed` (Info); infra services (reflection/health/channelz) are filtered out. The **gRPC** web page (`GET /grpc`, `POST /grpc/run`): `host:port` targets, each host **must pass the program's scope guard** (grpcurl cannot be proxied → scope is enforced upstream; a denial is recorded as `grpc.scope`). Engine: mock by default, `-grpc real` (+ `-grpc-plaintext`) uses grpcurl; added to the Docker image. **Invocation fuzzing** (opt-in, a checkbox on the gRPC page): `Scanner.Fuzz` invokes methods that look **read-only** (Get/List/Query/…, mutating methods Create/Delete/… are skipped for safety) with an empty payload, then classifies the gRPC status → findings `grpc-method-callable-unauth` (Medium, CWE-306, an OK response without credentials) / `grpc-method-reachable-unauth` (Low, InvalidArgument); Unauthenticated/PermissionDenied = protected (not reported). Tests `engine/grpc/grpc_test` (+ classify/readOnly/fuzz) + `web/grpc_test` (+ fuzz).

## Upstream proxy & chains (forwarding egress)

`egress.Proxy.SetUpstream(urls...)` + `internal/egress/upstream.go` (`buildChainDialer`): the final connection (to the IP already scope-checked & pinned) is forwarded through **one proxy or a multi-hop chain**. Each hop scheme: **http/https** (CONNECT, TLS for https, Proxy-Authorization Basic), **socks5/socks5h** (via `golang.org/x/net/proxy`, Tor-friendly); credentials `user:pass@host`. The chain is built with a fold: each hop becomes a `proxy.Dialer` that reaches itself through the previous hop (`httpProxyDialer`/SOCKS5, all `ContextDialer` so the ctx & pinned IP are kept). `orchestrator.ScanRequest.ProxyChain []string` (fail-closed if a hop is invalid); the Scan form has an **Upstream proxy / chain** field (one hop per line). Security holds: the scope guard + IP-pinning (anti-SSRF/rebinding) run before forwarding, the chain only changes the route to an already-checked IP. Tests `egress/upstream_test` (a 1-hop & **2-hop** tunnel via a fake proxy + echo, a wrong scheme, a wrong second hop, an empty chain, socks5 construct, SetUpstream). Reverse proxy: see the next section (the capture gateway).

## Reverse proxy: the capture gateway (manual browsing -> scan)

The "reverse proxy" is realized as a **capture gateway**, driven entirely from the web UI (not the CLI). `internal/egress/capture.go` (`Gateway` + `httputil.ReverseProxy`): BugHound stands as a reverse proxy to **one in-scope target**; the hunter points a browser at the local listener (`http://127.0.0.1:<port>/`) and browses the target as usual. Each request that passes through is **recorded** (deduplicated per `method+URL`, with a status & count) as an endpoint candidate, then can be **promoted into a scan** through the same scan path (`enqueueScan` → orchestrator → scope guard + rate limiter + egress). **Security**: the gateway reuses the guarded egress transport (`Proxy.transport`: resolve → reject internal IPs → pin the IP, plus the upstream chain if set), the target is validated by the scope guard at start (**fail closed**, default-deny), and each forward is **re-scope-checked** + **rate-limited** → only in-scope hosts are ever forwarded, even during manual browsing. The local listener speaks plain HTTP on loopback; re-origination to an HTTPS target is handled by the transport (SNI = target host, IP pinned) so **no CA cert** is installed in the browser. No auto-submit (promoting only creates a draft scan). Audit: `capture.start` / `capture.stop` / `capture.promote` / `capture.egress` (denials). The **Capture** web page (`GET /capture`, `POST /capture/{start,stop,promote}`). Tests `egress/capture_test` (forward+record, dedup, reject an out-of-scope target, rate-limited) + `web/capture_test` (start/listener, promote→scan done, stop, program scope required).

## Branding & the login page (UI)

The **BugHound** logo (a detective-beagle mascot) is placed in the UI: the brand sidebar + favicon (`internal/web/static/bughound-logo.png`, part of `go:embed`), and the mascot in the README header. A **logo'd login page** replaces the HTTP Basic popup for the browser **when `-auth`/`BUGHOUND_AUTH` is set**: `GET/POST /login` + `POST /logout`, a standalone `login.html` template. Auth is **cookie-session** based (`bh_session`, `HttpOnly`+`SameSite=Strict`, `Secure` under TLS, a 12-hour TTL, server-side invalidation on logout); the password comparison is **constant-time**; **CSRF still applies** on `POST /login`. **HTTP Basic is still supported** as the automation/CLI path (explicit credentials that fail → 401; a browser without a session → redirect to `/login`). Without `-auth`, the old behavior: open access (safe on localhost only), `/login` redirects to `/dashboard`. `enqueueScan`/other paths are unchanged. Audit `auth.login` (success/failure) + `auth.logout`. Tests `web/login_test` (the session flow, CSRF required, the no-auth mode) + `web/security_test` (Basic auth updated: no credentials → login redirect).

## UI/UX updates (design system: BH-P02-DESIGN)

A visual polish to match the design spec: dense, flat, dark, status-forward, a single accent, visible focus. `internal/web/static/app.css` updated throughout (every old class kept): layered surface tokens + radius/transition/focus-ring; **`select` & checkboxes are now styled** (previously the browser default, which clashed on the dark theme); filters & the bulk bar tidied; zebra tables + uppercase headers; **active nav uses a left accent bar**; a thin scrollbar; `:focus-visible` (accessibility); buttons/cards/badges/pills polished; the login page more premium (a radial backdrop + a glowing logo). `base.html`: the topbar now shows an always-visible **"scope guard: default-deny"** status + the program as a chip (the "status & scope always visible" principle). CSS only + one header markup change; `go test ./...` green, every page renders 200.

## RBAC & required authentication (login by default)

Login is now **required by default** on `go run ./cmd/bughound` (no flag needed). A new `internal/auth` package: three **roles**, `admin` > `operator` > `viewer`, with rights helpers (`CanRead`/`CanWrite`/`CanAdmin`) and **PBKDF2-HMAC-SHA256 password hashing** from the standard library (`crypto/pbkdf2`, Go 1.24+; **no new dependency**): a random 16-byte salt, 210k iterations, a self-describing format, constant-time verification. Accounts are kept in the store (`store.UserStore` on **Mem & SQLite**, the `users` table); the raw password is never stored/logged.

**Bootstrap**: if there is no account yet, `admin` is created automatically with a **random password printed to the console once** (override via `-admin-user`/`-admin-password` or the env `BUGHOUND_ADMIN_USER`/`BUGHOUND_ADMIN_PASSWORD`). **Login** (`username`+`password`) uses a cookie session (`bh_session`, `HttpOnly`+`SameSite=Strict`, `Secure` under TLS, a 12-hour TTL, server-side invalidation on logout); **HTTP Basic** (the account's username+password) stays for automation/CLI; constant-time verification + a dummy hash to level the timing on an unknown username (anti-enumeration). **RBAC authorization** at one point (`ServeHTTP` → `authorize`): the `/users` area is admin only, a state-changing action (other than `/logout`) needs operator or above, GET is for every valid role, **default-deny** when the role is not enough. The **Users** page (admin): add/delete/reset-password; a self-lockout guard (cannot delete your own account / the last admin). The identity + role show in the topbar; a **Sign out** button in the sidebar; the **Users** menu is admin only. Audit `auth.login`/`auth.logout`/`user.create`/`user.delete`/`user.password`.

`-no-auth` disables login & RBAC (open access) **only** for a trusted localhost / tests; used by the E2E harness (the product flow is tested directly; login & RBAC are unit-tested in Go). Full-page templates are now wrapped in `shellData` (chrome: user/role) so no page struct needs to know about auth. Tests: `internal/auth` (hash/verify/roles), `store` (user CRUD Mem+SQLite), `web/login_test` (the session flow, an unknown username, CSRF), `web/rbac_test` (viewer read-only, operator without admin, admin manages users, self-delete protection).

## Docker (engines included in the image)

A multi-stage `Dockerfile` + `docker-compose.yml` + `.dockerignore`: a combined **BugHound + engines** image (nuclei/subfinder/httpx/katana/ffuf via `go install`, semgrep via pip; **ZAP optional** `--build-arg WITH_ZAP=true`). Inside the container the engines are on `PATH` → `-engine real` runs without installing tools on the host. Non-root, data in `/data`, default `-engine mock` (safe); the port is mapped to localhost + `-auth` for non-local access. Validated with `docker build --check` (clean; base image resolves). A fit for a machine with no engines installed but with Docker. The `docker.yml` workflow: on a `v*` tag, build & push the image to the **GitHub Container Registry** (`ghcr.io/<owner>/bughound`, lean variant) with GHA cache → `docker pull ghcr.io/…:latest`. See the README "Run with Docker".

## A note on the pattern

Adding an engine = writing **one adapter**: build the arguments → subprocess (`ProxyAware` so egress is enforced) → `Parse` the output into the finding schema. Examples: `internal/engine/{nuclei,ffuf,zap}`, `internal/sast`. Triage/report/store/dashboard do not need to be touched.
