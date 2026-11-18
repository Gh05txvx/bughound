# BH-DESIGN-analyst-spk: Analyst + decision support (SPK) app for triaging BugHound findings

> An internal design document for an app **separate** from the BugHound core that:
> reads findings via the read-only API → deterministic analytics → SAW ranking → "what-if" output
> (a manual validation plan for Burp). AI = advisor; **a human executes in Burp**.
> Last updated: 2026-11-13.

---

## 1. Principles & limits

- **Read-only.** The app only does `GET /api/v1/findings` (Basic, read-only). It never triggers a scan, submits, or touches a target. There is no side path to the scanner (BugHound's Principle #1 stays intact).
- **Outside the core.** BugHound = the source of truth; this app is a consumer. If the app breaks, the core is unaffected.
- **AI = a hypothesis & narrative generator, not an actor.** The numbers (SAW, clusters, FP) come from **deterministic code**. The LLM only narrates `why` + drafts `hypotheses`. Execution in Burp = a **human**.
- **Data handling:** `evidence` is scrubbed before it touches the LLM (see §6).

## 2. Flow

```
BugHound  ──GET /api/v1/findings?program=X──▶  Analyst+SPK
(source)      (Basic auth, JSON read-only)       │
                                                 ├─ ingest  → model.Finding
                                                 ├─ analyst → cluster, fp_likelihood, derived
                                                 ├─ saw     → score + ranking (explainable)
                                                 └─ whatif  → plan scaffold + scrubbed evidence
                                                                  │
                                                        you + Burp Repeater (manual execution)
```

The interface to the AI (Claude): an **MCP server** wraps the app → the tools `list_findings`, `rank_findings`, `whatif`. Claude calls them, reasons, and drafts hypotheses over the scrubbed evidence.

## 3. Data model

### 3.1 Ingested from the API (the `finding.Finding` schema fields)

| Field | Type | Used for |
|---|---|---|
| `id`, `dedup_key`, `program`, `run_id`, `target` | string | identity, clustering |
| `type`, `title`, `description` | string | display, heuristics |
| `severity` | enum `info\|low\|medium\|high\|critical` | C2 |
| `confidence` | enum `low\|medium\|high` | C1 |
| `cwe[]`, `tags[]` | []string | heuristics |
| `owasp` | obj (OWASP 2021 category) | C6 |
| `source_engine`, `source_template` | string | C1 exploitability, FP |
| `location{url,method,parameter,param_location}` | obj | what-if target |
| `evidence{request,response_excerpt,payload,matched,screenshot_ref}` | obj | what-if (base request) |
| `reproduction[]`, `impact` | - | narrative context |
| `status` | enum `new\|confirmed\|duplicate\|false_positive\|ignored` | filter |
| `duplicate_of`, `in_report` | - | filter |
| `created_at`, `updated_at` | time | C8 freshness |

### 3.2 External enrichment (optional)

- **Scope asset** (from a HackerOne/Bugcrowd CSV import): `asset.max_severity`, `eligible_for_bounty` → C3 bounty. Fallback = `severity` when scope is not available.

### 3.3 Computed (the analyst layer, deterministic)

| Derived | Formula |
|---|---|
| `cluster_id`, `cluster_size` | group by `dedup_key` → fallback `host(url)+type+parameter` |
| `siblings_on_endpoint` | the count of other findings with the same `location.url` → chain potential |
| `exploitability_raw` | `confidence_num × engine_factor` (§4, C1) |
| `fp_likelihood` ∈ [0,1] | heuristic (§3.4) |
| `bounty_weight` ∈ [1,5] | `asset.max_severity` × (eligible_for_bounty? 1 : 0.4); fallback `severity_num` |

### 3.4 The `fp_likelihood` heuristic (tunable)

| Condition | fp |
|---|---|
| `status=confirmed` | 0.0 |
| `confidence=high` & engine ∈ {nuclei-dast, dalfox} | 0.1 |
| engine=ffuf & a response like an SPA/soft-404 (body heuristic) | 0.7 |
| a passive engine {retire, zap-passive} & `confidence=low` | 0.5 |
| default | 0.3 |

## 4. SPK: SAW (Simple Additive Weighting)

**Algorithm:** a decision matrix (alternatives = findings, columns = criteria) → normalize → weighted sum → rank descending.

- Benefit: `r_ij = x_ij / max_i(x_ij)`
- Cost:    `r_ij = min_i(x_ij) / x_ij`
- Score:   `V_i = Σ_j w_j · r_ij`,  with `Σ w_j = 1`

### 4.1 Final criteria (default, tunable)

| # | Criterion | Type | Raw value | Weight |
|---|---|---|---|---|
| C1 | Exploitability | benefit | `confidence_num(1/2/3) × engine_factor` | **0.26** |
| C2 | Signal payout | benefit | the vulnerability class (§4.2): high 1.0 · neutral 0.5 · noise 0.1 | **0.22** |
| C3 | Bounty potential | benefit | `bounty_weight` 1-5 (scope `max_severity` if present) | **0.16** |
| C4 | Severity/Impact | benefit | info1·low2·med3·high4·crit5 (the weight is deliberately low: scanner severity often inflates for passive) | **0.12** |
| C5 | FP-likelihood | cost | `fp_likelihood` 0-1 | **0.12** |
| C6 | Verification effort | cost | reflected 1 · SQLi/IDOR 2 · blind/2nd-order 3 | **0.06** |
| C7 | OWASP priority | benefit | the category mapping (§4.4) | **0.04** |
| C8 | Freshness | benefit | relative to the latest `created_at` in the batch: day-gap ≤1→5 · ≤7→4 · ≤30→3 · else 2 | **0.02** |

Σ weights = **1.00**. The weights are kept in the config (`weights.yaml`) → easy to tune without changing code.

### 4.2 Signal payout (C2): the anti "header-noise" lever

A real problem (proven on live RF data): without C2, passive hygiene (CSP/SRI/clickjacking/HSTS/cookie/timestamp) rated "medium" by the scanner rises to the top, even though in bug bounty it **nearly won't pay**. C2 gives a payout signal per **vulnerability class** (not the scanner severity):

- **high 1.0**: exploitable/paid: sqli, xss, rce, ssrf, xxe, idor/bola, broken-access, path/dir-traversal, lfi/rfi, deserial, ssti, exposed-panel/config, secret/key-leak, takeover, file-upload.
- **noise 0.1**: hygiene/header: csp, sub-resource-integrity, clickjacking, hsts, samesite/cookie-flags, referrer/permissions-policy, x-content-type, x-powered-by, timestamp-disclosure, cache-control, mixed-content, cross-domain-javascript, tls/ssl best-practice.
- **neutral 0.5**: anything else (e.g. ffuf `exposed-path`, needs a look, not necessarily a bug).

Matching is at a **token boundary** (lookaround, not a bare substring) so a short token does not stick (e.g. `rce` in `resource`, `file-inclusion` in `cross-domain-javascript-source-file-inclusion`), and **noise is checked first** (e.g. `x-xss-protection` is not raised to high via the `xss` token). The patterns are in `signal_patterns` (`weights.yaml`) → tunable.

**Signal also reads the URL path** (it only **promotes** to high, it never demotes to noise): a generic `exposed-path` to `/.git`, `/.env`, `/admin`, `/backup`, `/actuator`, `wp-admin` → high 1.0. Conversely a **boring** path (a standard file: `robots.txt`, `sitemap`, `/.well-known`, `favicon`, `healthz`, `manifest.json`) demotes a NEUTRAL `exposed-path` to noise, so a real endpoint (`/search`, `/signup`) rises above static files. The list is in `signal_patterns.boring`.

### 4.2a ffuf FP: soft-404/SPA calibration (C5)

An `exposed-path` from ffuf is prone to false positives on an app that returns 200 for nearly every path. Two priors (tunable in `heuristics`) raise `fp_likelihood`: (1) an **SPA shell marker** (React/Vue/Angular/Next/Nuxt/Svelte/webpack) in the body → fp 0.7; (2) a **flood**: when one host has ≥`ffuf_flood_threshold` (default 8) `exposed-path` findings, that indicates a soft-404/wildcard → fp is forced to ≥`ffuf_flood_fp` (0.6). A `confirmed` finding is never raised.

### 4.3 `engine_factor`

`nuclei-dast`=1.0 · `dalfox`=1.0 · `nuclei`=0.8 · `zap`(active)=0.8 · `ffuf`=0.7 · `retire`/`zap-passive`/`sast`=0.5 · default 0.6.

### 4.4 OWASP priority (C7, value 1-5)

A01 Broken Access Control = 5 · A03 Injection = 5 · A10 SSRF = 4 · A07 Auth Failures = 4 · A02 Crypto Failures = 4 · A04 Insecure Design = 3 · A05 Misconfig = 3 · A06 Vulnerable Components = 3 · A08 Integrity = 3 · A09 Logging = 2 · (unclassified) = 2.

### 4.5 Pre-filter (before SAW)

Drop: `status ∈ {duplicate, false_positive, ignored}`; by default optional `info` severity is skipped; only one representative per `cluster_id` (the highest score) so verification is not doubled.

### 4.6 Example

Columns = C1 exploitability · C2 signal · C3 bounty · C4 severity · C5 fp · C6 effort · C7 owasp · C8 freshness.

| Finding | C1 | C2 | C3 | C4 | C5 | C6 | C7 | C8 |
|---|---|---|---|---|---|---|---|---|
| SQLi `/rest/search` (nuclei-dast, high) | 3.0 | 1.0 | 5 | 5 | 0.1 | 2 | 5 | 5 |
| Reflected XSS `/q` (dalfox, med) | 2.0 | 1.0 | 4 | 3 | 0.2 | 1 | 5 | 5 |
| `exposed-path /admin` (ffuf, low) | 2.1 | 0.5 | 2 | 2 | 0.3 | 2 | 3 | 5 |
| Missing-CSP header (zap, med) | 2.4 | 0.1 | 3 | 3 | 0.3 | 2 | 3 | 5 |

→ ranking SQLi > XSS > exposed-path > **Missing-CSP**: the header hygiene drops to the bottom even though its "medium" severity ≥ exposed-path, because the C2 noise (0.1) sinks it. **Proven on real RF data**: the top shifted from header-hygiene (score 0.976) to `exposed-path` (0.858), the header dropped. **The breakdown is always shown** (explainable).

## 5. "What-if" output (per top finding)

A stable schema (JSON) + markdown render. The deterministic part comes from the app; `hypotheses` + `why` are filled by the LLM over scrubbed evidence.

```json
{
  "finding_id": "…", "rank": 1, "score": 0.95,
  "score_breakdown": {"C1":0.26,"C2":0.22,"C3":0.16,"C4":0.12,"C5":0.12,"C6":0.06,"C7":0.04,"C8":0.02},
  "why": "<LLM: a short note on why it is a priority>",
  "base_request_ref": "evidence.request (already in Repeater)",
  "target": {"url":"…/rest/search","method":"GET","parameter":"q"},
  "hypotheses": [
    {"mutation":"q=' OR 1=1--","expected":"more rows / the error disappears","confirms":"boolean SQLi"},
    {"mutation":"q=1;WAITFOR DELAY '0:0:5'--","expected":"response ~5s","confirms":"time-based blind"}
  ],
  "decision": "verify_now | likely_fp | needs_more_info",
  "safety": "non-destructive (SELECT/boolean/time); respect the program's rate limit & RoE"
}
```

## 6. Data handling (required)

Before evidence touches the LLM (for `hypotheses`/`why`):
- **Scrub** `Authorization`, `Cookie`, `Set-Cookie`, token/bearer, and PII in `response_excerpt` → the placeholder `[REDACTED]`.
- Send the **minimum**: `url`, `method`, `parameter`, `payload`, `matched`, a scrubbed request excerpt, not a full dump.
- A sensitive program (financial, e.g. Deriv) → consider a **local model**.
- SAW/clustering/FP do **not** need the LLM → no data leaves for that part.

## 7. App structure (see `../bughound-analyst/`)

```
bughound-analyst/
├─ bughound_analyst/
│  ├─ __init__.py
│  ├─ config.py        # weights, engine_factor, OWASP map, effort map (tunable)
│  ├─ client.py        # BughoundClient: GET /api/v1/findings (Basic, read-only)
│  ├─ model.py         # Finding dataclass from the schema JSON
│  ├─ analyst.py       # cluster, fp_likelihood, derived metrics
│  ├─ saw.py           # SAW: normalize + score + ranking (REAL + tested)
│  ├─ scrub.py         # redact evidence before the LLM
│  └─ whatif.py        # the what-if plan scaffold (deterministic; hypotheses filled by the LLM)
├─ server.py           # MCP server: the tools list_findings / rank_findings / whatif
├─ tests/test_saw.py   # SAW unit test (the §4.5 example ranking)
├─ weights.yaml        # weights & mapping (the tunable source for config.py)
├─ requirements.txt    # httpx, pyyaml, mcp
├─ .env.example        # BUGHOUND_URL, BUGHOUND_USER, BUGHOUND_PASS
└─ README.md
```

## 8. Backlog

- [ ] Scope asset enrichment (max_severity/bounty) from a CSV import.
- [ ] SPA FP heuristic (soft-404/SPA body detection), calibrated with lab data.
- [ ] A local-model option for `whatif` on a sensitive program.
- [ ] (optional) a limited write tool `set_triage_status` via the API, only if BugHound adds an RBAC + audit write endpoint (none yet).
