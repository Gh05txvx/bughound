# BH-GUIDE-SCAN: feature mechanics & what each scan scenario needs

> An operational guide: **how each feature works** and **what you fill in for a given scan**. Written to match the implementation (`cmd/bughound`, `internal/web`, `internal/engine`, `internal/sast`, `internal/egress`, `internal/recon`). Last updated: 2026-11-09.
>
> Companion reading: [`BH-GUIDE-PROXY`](BH-GUIDE-PROXY.md) (the Proxy menu & chains), [`BH-SPEC-SCOPE`](../specs/BH-SPEC-SCOPE-scope-guard.md) (scope rules), [`BH-SPEC-FINDING`](../specs/BH-SPEC-FINDING-finding-schema.md) (finding schema).

---

## 0. Read this first (limits that cannot be turned off)

BugHound is an **orchestrator**, not a single scanner: it brings mature recon/DAST/SAST engines into one finding schema, then helps you triage & draft a report. Four structural limits apply to **every** scan:

1. **Default-deny scope guard.** A target not proven **in-scope is rejected**. No side path. You *must* register the target under `in_scope`.
2. **Locked egress.** Only engine workers reach the network, and only to a *pinned* in-scope IP (anti-SSRF/rebinding). A private IP is rejected at dial time unless it is explicitly in-scope.
3. **Rate limiter in the execution path.** Each engine is clamped to the scan's `rps`. Not easy to turn off.
4. **No auto-submit.** A report is always a draft; submission to a platform is done by you by hand.

> ⚠️ The scope guard enforces **WHERE** you may scan, not **WHETHER** automation is allowed. For a real bug bounty target, reading the program's Rules of Engagement (is a scanner/automation allowed, the rate limit, a marker header) is still your responsibility. See §4 scenario J.

---

## 1. Pipeline map: where each feature sits

```
Web UI  →  Orchestrator (SCOPE GUARD)  →  Job queue  →  Engine workers (adapter + rate limiter)  →  Normalize → Triage → Store
                     │                                          │
              default-deny,                            egress through BugHound's proxy
              out-of-scope wins                        (pin IP → proxy chain → target)
```

- **Input** is checked by the scope guard **before** a job is created (layer 1).
- **Egress** for each request is checked again at the proxy (layer 2), fail-closed.
- Every engine writes to **one finding schema** (`BH-SPEC-FINDING`), so dedup, triage, and reporting are uniform across engines.

---

## 2. Feature mechanics

### 2.1 Scope guard (the mandatory boundary)

| Aspect | Behavior |
| --- | --- |
| Default | **Deny**: not proven in-scope = rejected. |
| Conflict | **Out-of-scope wins** over in-scope. |
| Entry format | host (`example.com`), wildcard (`*.example.com`), CIDR, or host:port. No port stated = all ports, unless an entry states one explicitly. |
| Two layers | (1) the input form, (2) egress on each connection. Both fail-closed. |
| Private IP | Rejected at **dial** unless explicitly in-scope (e.g. the lab `172.30.0.10`). |

### 2.2 Egress, IP-pinning & proxy chains

Each engine request leaves through the **in-app egress proxy**. The flow:

```
engine → BugHound egress proxy (scope guard + pin IP) → hop1 → hop2 → … → target
```

- The target is resolved & **pinned** on BugHound's side before it is forwarded, so DNS-rebinding/SSRF is blocked.
- **The proxy chain** (the *Upstream proxy / chain* field in the Scan form): **one hop per line, in order**. Supported schemes: `http://`, `https://`, `socks5://` (`socks5h://` too). Credentials `user:pass@host` are **redacted** from the log/UI/audit. An invalid hop = fail-closed.
- Test the chain first in the **Proxy** menu (`/proxy`) before using it in a scan. See [`BH-GUIDE-PROXY`](BH-GUIDE-PROXY.md).

### 2.3 Rate limiter & stealth

- The form's `rps` sets the request rate per engine (throttled in the execution path).
- The **stealth** checkbox turns on *low-and-slow* mode (low jitter/aggression) for active engines; recall stays intact and it is gentler on the target.
- A **non-destructive profile is always on** for injection engines (surgical payloads, not damaging ones).

### 2.4 DAST engines: what each one does & what triggers it

The engine roster is set **at startup** via the `-engine` flag (a comma-separated list). Per scan you **filter** (tags/severity/stealth/api_routes); you do not pick engines.

| Engine | Role | Input that triggers a finding | Notes |
| --- | --- | --- | --- |
| `nuclei` | Template matcher (exposures, misconfig, server-side CVEs, missing headers) | `targets`/`seeds` (URL/host) | Filtered by `tags` + `severity`. |
| `ffuf` | Content discovery (path brute force) | base URL in `targets` | Tick **api_routes** for the Assetnote `apiroutes` wordlist (good for `/api`, `/openapi.json`). Calibrates against the 401/403/500 wall. |
| `zap` | Spider + ZAP rules | base URL | **`quick`/`baseline` = spider + passive scan** (headers, version/info leaks, exposed files, **without sending attack payloads**). **Active scan (injection) only when started with `-zap-mode full`.** |
| `nuclei-dast` | **Active DAST**: katana crawl → parameter fuzzing (SQLi/injection) | **parameterized** URLs (`/search?q=`) or crawl results | Non-destructive + throttled. A finding is a draft candidate to verify. |
| `dalfox` | **Active DAST, XSS only** | **parameterized** URLs (`/greet?name=`) | Normalizes the PoC into a finding. |
| `retire` | Client-side JS library SCA (client-side CVEs) | pages that load JS | **Opt-in**: the image must be built with `WITH_RETIRE=true` and `retire` must be in the roster. |

> **OpenAPI body-fuzz:** the **openapi** field takes the **document contents** of the spec (JSON/YAML), **not a URL**. The base URL is taken from the first line of `targets`. Endpoints in the spec (including `POST`) are discovered and their body is fuzzed.

### 2.5 Recon (real-engine mode)

The real pipeline: **subfinder → httpx → katana**. From one seed domain/host: enumerate subdomains → probe the live ones → crawl URLs. Crawl results enrich `targets`, but **only in-scope entries are scanned**.

### 2.6 SAST: static code analysis

Code **never** leaves the network. It is fenced to the root set by `-sast-root` (default: off). The `/sast` dropdown **picks one engine per run**.

| Engine | Language/target | Findings |
| --- | --- | --- |
| `semgrep` | many languages (`p/default`, **offline** pre-baked) | broad patterns (eval, subprocess, injection, etc.) |
| `bandit` | Python | `B###` codes (B324 md5, B307 eval, B602 shell=True, B608 SQL, …) |
| `gitleaks` | all text | secrets, with the **value redacted** (it never leaks to a finding/log) |
| `findsecbugs` | JVM bytecode | **opt-in** `WITH_FINDSECBUGS=true`; needs compiled classes/jars |

SARIF output (e.g. CodeQL) is normalized via `NormalizeSARIF` into the uniform finding schema.

### 2.6b Staging code for SAST (local, OSS, or given by a program)

SAST **needs code**, not a URL. A target that only gives you an HTTPS URL **cannot be SAST-scanned**: that is DAST territory (see §4.J). SAST applies when the code is available to you: your own codebase, open source (GitHub/GitLab), or source a program hands over. BugHound does **not** download/clone automatically (SAST has no network) and has **no code upload in the GUI**: **you** put the code under `-sast-root`.

**Option a: bind-mount a host folder (recommended: set up once, no repeated `cp`).**
Mount a host folder *read-only* into the sast-root when you run the container:
```bash
docker run ... \
  -e BUGHOUND_SAST_ROOT=/data/sast \
  -v C:/path/to/sast-ext:/data/sast/ext:ro \
  ...
```
Then `git clone`/copy a repo into `C:/path/to/sast-ext/<name>` on the host and the container reads it right away. In `/sast`, **Subpath** = `ext/<name>`. Read-only because SAST never writes to the code.

**Option b: `docker cp` (no container recreate).**
```bash
git clone --depth 1 https://github.com/org/app /tmp/app
docker cp /tmp/app bughound:/data/sast/app
MSYS_NO_PATHCONV=1 docker exec -u root bughound chown -R bh:bh /data/sast/app
```
**Subpath** = `app`.

> The path scope still applies: anything outside `-sast-root` is rejected (default-deny; `..`/symlink escapes are blocked). Secrets in the code stay redacted in findings.

### 2.7 Normalization, dedup & triage

- Every engine writes one schema (`BH-SPEC-FINDING`): severity/status/confidence/evidence/`owasp`.
- **Dedup** per `(program, dedup_key)` with `duplicate_of`; the dedup_key includes the HTTP method (GET≠POST) and collapses site-wide (ignores path/port).
- Triage at `/findings`: set the status (confirmed/false-positive/…), fill in `impact` + reproduction steps, which then populates the report & export.

### 2.8 Report & export (no auto-submit)

The report generator assembles a **draft** from confirmed findings; the **HackerOne / Bugcrowd** export is filled in (repro + impact), **not** a placeholder. Submission stays manual.

### 2.9 Burp integration

- A read-only API `GET /api/v1/findings` (reuses HTTP Basic) pulls findings into your tooling.
- A Montoya extension (`burp-ext/`) loads findings + **Send to Repeater** for manual verification. The onboarding page is at `/burp`.

**Faithful vs fallback.** Findings from `nuclei` (DAST mode included) and `dalfox` carry `evidence.request` (the raw request; sensitive headers become `[REDACTED]`); the extension sends it whole (method/path/body, including `OPTIONS`/`POST`) to Repeater. A finding without a raw request (`zap`, `ffuf`, `retire`) falls back to a **plain `GET`** of `location.url` (the ZAP payload is still in the finding URL, so it is still reproducible minus the headers). That is why IDOR/BAC validation stays manual in Burp.

**Handoff test (end to end):**

1. Scan a **parameterized** target with a roster that includes `dalfox` + `nuclei-dast`, e.g. the lab `http://<lab-ip>/greet?name=hunter` (reflected XSS) and `/search?q=hound`. `in_scope` includes the lab IP/CIDR. (ZAP `quick` is passive and does **not** inject; for SQLi rely on `nuclei-dast`, or add `-zap-mode full`.)
2. At `/findings/{id}`: a `nuclei`/`dalfox` finding has a **raw request**, so the **Copy request** button appears = `evidence.request` is filled.
3. Burp extension: fill in the URL/user/pass + program name → **Load findings** → pick a `nuclei`/`dalfox` finding → **Send to Repeater**.
4. Verify in Repeater: the request is **faithful** (not a plain `GET /`), the host/port is right, sensitive headers are `[REDACTED]`. For comparison: pick a `zap`/`ffuf` finding and you get a plain `GET` to `location.url`.

### 2.10 gRPC (optional)

The `/grpc` form: `program`, `targets`, a `fuzz` checkbox. The real engine is `grpcurl` (started with `-grpc real`, `-grpc-plaintext` for no TLS). Service/method enumeration via reflection.

### 2.11 Stop, Rerun & Delete

- **Stop** (Dashboard ▸ Scanning processes, or a run's status at `/scan`) stops one run: the running engine is killed, other runs are untouched. Findings already saved stay.
- **Rerun** runs an already-finished run again with the same parameters. Scope is re-evaluated from the program's **current** definition.
- **Delete** removes one **already-finished** run entry (done/failed/stopped) from the Scanning processes list. This **only** clears the monitor: **findings already saved are NOT removed** (to delete findings: Dashboard ▸ delete findings of a program). A still-running run cannot be deleted; **Stop first**, then Delete. Useful when an old scan entry is still stuck in the list even though the program has been cleaned up.
- All three need the operator/admin role and are recorded in the audit (`run.stop`, `run.rerun`, `run.delete`). Run history is held in memory, so it is lost when the server restarts.

---

## 3. **Scan** form field reference (`/scan`)

| Field | Required? | Contents | Notes |
| --- | --- | --- | --- |
| `program` | ✅ | program name | the key for findings/report & preset. |
| `in_scope` | ✅ | one entry per line | host/wildcard/CIDR. **The target must be here** (default-deny). |
| `out_scope` | no | one per line | wins over in-scope. |
| `targets` | ✅ | one URL/host per line | the first line = the base for OpenAPI. Include **parameterized** URLs so injection/XSS hits. |
| `seeds` | no | one per line | the starting point for recon/crawl. |
| `rps` | no | a number | rate per engine; lower it for real targets. |
| `upstream_proxy` | no | **one hop per line** | `http/https/socks5`, `user:pass@host`. |
| `tags` | no | comma-separated list | nuclei template filter. |
| `severity[]` | no | checkboxes | filter by severity. |
| `stealth` | no | checkbox | low-and-slow. |
| `api_routes` | no | checkbox | the Assetnote `apiroutes` wordlist for ffuf. |
| `openapi` | no | **the spec contents** JSON/YAML | **NOT a URL**: a URL = fail-closed `cannot unmarshal`. |
| `save_preset` | no | checkbox | save the selection (tags/severity/stealth) as the program's preset. |

## 3b. **SAST** form reference (`/sast`)

| Field | Contents |
| --- | --- |
| `program` | program name |
| `subpath` | a relative subdirectory inside `-sast-root` (e.g. `lab`) |
| `engine` | **one**: `semgrep` \| `bandit` \| `gitleaks` \| `findsecbugs` |

## 3c. Startup flags (CLI) that decide capability

| Flag / env | Default | Effect |
| --- | --- | --- |
| `-addr` | `127.0.0.1:8787` | bind loopback. |
| `-engine` | `mock` | `mock` \| a comma-separated real list: `nuclei,ffuf,zap,dalfox,nuclei-dast,retire`. |
| `-zap-mode` | `quick` | `quick`\|`baseline`\|`full` (**full = spider + active scan**). |
| `-sast-root` | empty (off) | the SAST code root; analysis is fenced here. |
| `-grpc` / `-grpc-plaintext` | `mock` / off | the real gRPC engine (`grpcurl`). |
| `-ffuf-wordlist` | built-in | the real ffuf wordlist. |
| `-key` / `BUGHOUND_MASTER_KEY` | `bughound.key` | the secret-encryption key. |
| `BUGHOUND_SAST_ROOT` | none | an env alternative to `-sast-root`. |
| build arg `WITH_FINDSECBUGS` / `WITH_RETIRE` | `false` | include the FindSecBugs / retire.js toolchain in the image. |

---

## 4. What any given scan needs: scenario → minimal input

For each scenario: **the engines that work**, **the input you fill in**, and **prerequisites** (if any).

### A. Full web-app DAST (you have the URL)
- **Engines:** nuclei + ffuf + zap(passive) + nuclei-dast + dalfox.
- **Fill in:** `program`; `in_scope` = the target host; `targets` = URL + parameterized endpoints; a reasonable `rps`; tick `api_routes`.
- **Prerequisite:** roster `-engine nuclei,ffuf,zap,dalfox,nuclei-dast`. For ZAP active add `-zap-mode full`.

### B. XSS focus
- **Engine:** `dalfox` (+ nuclei-dast).
- **Fill in:** `targets` with reflective parameterized URLs (`/greet?name=test`).

### C. Active injection (SQLi etc.)
- **Engine:** `nuclei-dast` (crawl → fuzz). ZAP active (if `-zap-mode full`) complements it.
- **Fill in:** `targets`/`seeds` with parameterized URLs (`/search?q=test`); you can rely on katana crawling from a seed.

### D. Content / secret discovery
- **Engine:** `ffuf` (+ nuclei exposures).
- **Fill in:** the base URL in `targets`; tick `api_routes` for the `/api` surface. Turns up `/admin`, `/backup.zip`, `.env`, `.git/config`.

### E. API via OpenAPI/Swagger
- **Engine:** OpenAPI discovery → body-fuzz (+ nuclei/nuclei-dast).
- **Fill in:** the first line of `targets` = the base URL; paste the **spec contents** into `openapi` (not a URL).

### F. Recon / attack surface from a domain or wildcard
- **Engine:** recon subfinder → httpx → katana, then DAST on the live ones.
- **Fill in:** `in_scope` = `*.example.com` (**only if the RoE/scope allows a wildcard**); `seeds` = the apex domain. Only in-scope subdomains are scanned.

### G. Source-code SAST (OSS/external targets included)
- **Engine:** semgrep / bandit / gitleaks / findsecbugs (one per run).
- **Needs code, not a URL.** For an external target, SAST only applies when the code is available (OSS or given by the program); a URL-only target uses DAST (§4.J).
- **Fill in:** stage the code under `-sast-root` (**bind-mount** or `docker cp`, see §2.6b); in `/sast` fill in `program`, `subpath`, pick an `engine`. Run it several times for several engines.
- **Flow for an OSS target:** SAST the repo → find candidate sinks → prove them live via DAST/Burp (use the same `program` so the findings merge).
- **Prerequisite:** the server runs with `-sast-root`/`BUGHOUND_SAST_ROOT`. FindSecBugs needs a `WITH_FINDSECBUGS=true` image + bytecode.

### H. Scan through Burp / a proxy (watch & record traffic, inject a marker header)
- **Fill in:** put the Burp proxy in `upstream_proxy`. **From a Docker container use `http://host.docker.internal:8080`** (not `127.0.0.1:8080`, which is the container's loopback). Validate it first in the Proxy menu.
- **Note:** the scope guard + pin IP still run **before** forwarding to the proxy. Burp Match/Replace can add the marker header/User-Agent a program asks for.

### I. gRPC
- **Fill in:** `/grpc` → `program`, `targets`, tick `fuzz`.
- **Prerequisite:** `-grpc real` (+ `-grpc-plaintext` for no TLS).

### J. A real bug bounty target (the program only gives an HTTPS URL)
1. **Pre-flight:** read the policy. Confirm the URL is in-scope; note the exact scope shape (host only? wildcard?); confirm **the RoE allows automation** + the rate limit; note any required marker header.
2. **Scope:** `in_scope` = **only** the assets from the policy; fill in `out_scope` for exclusions.
3. **Scan:** `targets` = the HTTPS URL; a **conservative** `rps` (5-10) and/or tick `stealth`; start with one endpoint.
4. **Proxy (optional, recommended):** route through Burp (`http://host.docker.internal:8080`) for auditing + to inject the marker header.
5. **Triage → Report:** verify by hand (Burp Repeater), export the H1/Bugcrowd draft. **Submit by hand.**

> A public in-scope IP **may** be reached; what is rejected is out-of-scope and private IPs (unless explicit). An aggressive roster (`nuclei-dast`, `ffuf`) sends many requests, so for a real target consider a lighter roster + stealth.

---

## 5. Quick troubleshooting

| Symptom | Cause & fix |
| --- | --- |
| "out of scope" / denied | The target is not in `in_scope` (default-deny). Add its host/IP. |
| OpenAPI `cannot unmarshal !!str http://...` | You put a **URL** in the `openapi` field; put the **spec contents** there, or clear it. |
| SQLi/XSS does not show up | No parameterized URL in `targets`/`seeds`, or `nuclei-dast`/`dalfox` is not in the roster. |
| ZAP finds no injection | `quick` mode is passive; you need to start with `-zap-mode full`. |
| SAST "disabled" | The server runs without `-sast-root`; set the root + use the right `subpath`. |
| Proxy to Burp fails from the container | Use `host.docker.internal:8080`, not `127.0.0.1:8080`. |
| retire/findsecbugs missing | The image was built without `WITH_RETIRE`/`WITH_FINDSECBUGS`; rebuild + add it to the roster. |
| Scan too slow / wrong target | Press **Stop** in Dashboard ▸ Scanning processes. No need to restart the container (a restart stops every run). |
