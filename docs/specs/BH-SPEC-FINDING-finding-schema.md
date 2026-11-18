# Spec: Unified Finding Schema (BugHound)

Oct 21, 2026 · @Gh05t

The unified finding schema is BugHound's foundation: one format that every engine (recon & DAST) normalizes into, and the data source for triage and reporting. This document fixes the fields, types, enums, evidence structure, dedup key, and versioning rules so every component (engine adapter, store, triage, report, UI) agrees on one data shape. ID: `BH-SPEC-FINDING`.

## Summary & role

Each engine (nuclei, httpx, ZAP, etc.) produces output in a different shape. A **finding** is one normalized record: a single security issue at a single location, in the same shape whatever engine it came from.

This schema is where every component meets:

- **Engine adapters** write to the schema (normalizing raw output).
- **The store** keeps findings in the schema shape.
- **Triage** reads the schema for dedup, scoring, and priority.
- **The report generator** assembles a draft from the schema fields.
- **The web UI** displays and filters by the schema fields.

So a change to the schema reaches every component. The schema must be stable, versioned, and rich enough for triage and reporting without going back to an engine's raw output.

## Schema design principles

1. **Engine-neutral.** No field is specific to one engine. Engine-specific detail lives in `raw` (see the fields), it does not pollute the core schema.
2. **Enough for triage and reporting.** Fields are chosen so triage (dedup, severity, priority) and reporting (title, steps, impact, evidence) work without opening the raw output.
3. **Stable and versioned.** The schema has a `schema_version`. New fields are added additively; old fields are not removed carelessly (see Versioning).
4. **Stable identity.** Every finding has a unique `id` and a deterministic `dedup_key`, so duplicates across scans/engines can be merged reliably.
5. **Safe by default.** The schema never stores a raw secret; evidence is scrubbed before it goes in (in line with BugHound's security principles).
6. **Exchange format: JSON.** The canonical representation is JSON (UTF-8). Storage can be anything (relational/document DB) as long as it maps to this JSON shape.
7. **Time in UTC ISO 8601.** Every timestamp uses `YYYY-MM-DDThh:mm:ssZ`.

## Core schema fields

A finding is a JSON object with the fields below. "Required" means it must be present on every stored finding.

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| schema\_version | string | yes | Schema version, e.g. `"1.0"` |
| id | string (UUID) | yes | The finding's unique identity |
| dedup\_key | string | yes | A deterministic key for merging duplicates |
| program | string | yes | The related bounty program |
| run\_id | string | yes | The run that produced the finding |
| target | string | yes | The asset tested (URL/host); must be in-scope |
| type | string | yes | The vulnerability type, a stable slug (e.g. `xss`, `ssrf`, `info-disclosure`) |
| title | string | yes | A short finding title |
| description | string | no | An explanation of the issue |
| severity | enum | yes | `info` / `low` / `medium` / `high` / `critical` |
| confidence | enum | yes | `low` / `medium` / `high` (automatic confidence, before manual verification) |
| cvss | object | no | `{ version, vector, score }` when available |
| cwe | string\[\] | no | A list of CWE ids, e.g. `["CWE-79"]` |
| tags | string\[\] | no | Free-form labels for filtering |
| owasp | string | no | An OWASP Top 10 2021 category (e.g. `A03:2021`); additive, a best-effort classification from cwe/tags/type. The native `type` stays the source of precision & the dedup basis |
| location | object | yes | The specific location of the finding (see Structure) |
| evidence | object | no | Evidence: request/response, payload, a screenshot reference |
| reproduction | string\[\] | no | Ordered reproduction steps |
| impact | string | no | The concrete impact for the report; filled in during triage/draft completion |
| source\_engine | string | yes | The originating engine, e.g. `nuclei`, `zap` |
| source\_template | string | no | The originating template/rule id (e.g. a nuclei template id) |
| references | string\[\] | no | Reference links (CVE, documentation) |
| raw | object | no | The engine's raw payload, not normalized |
| status | enum | yes | `new` / `confirmed` / `duplicate` / `false_positive` / `ignored` |
| duplicate\_of | string | no | The `id` of the primary finding when `status = duplicate` |
| in\_report | boolean | no | Whether it has been added to the report (default `false`) |
| verified\_by | string | no | The team member who confirmed it |
| created\_at | datetime | yes | When the finding was produced (UTC ISO 8601) |
| updated\_at | datetime | no | When it was last changed |

A field that is not set is omitted from the JSON (not set to `null`), except where `null` has an explicit meaning.

## Enums

Enum values are closed: only the values below are valid. Adding a new value requires a `schema_version` bump (see Versioning).

**severity**:

| Value | Meaning |
| --- | --- |
| critical | Very severe impact; the top priority |
| high | Severe impact |
| medium | Moderate impact |
| low | Minor impact |
| info | Informational; not a direct vulnerability |

**status** (triage status):

| Value | Meaning |
| --- | --- |
| new | New, not yet triaged |
| confirmed | Manually verified; fit for the report |
| duplicate | A duplicate of another finding (`duplicate_of` is set) |
| false\_positive | Judged not to be a real finding |
| ignored | Deliberately ignored (e.g. accepted risk, out of interest) |

**confidence** (automatic confidence before manual verification):

| Value | Meaning |
| --- | --- |
| high | The engine is very sure (e.g. a definite match) |
| medium | Needs a check |
| low | A weak indication; prone to false positives |

Severity comes from the engine/template or CVSS scoring; confidence comes from the engine. Both can be overridden by hand during triage, and the change is recorded in the audit trail.

## Evidence & location structure

**location** points at exactly where the finding is. The object shape:

```json
{
  "url": "https://api.acme.io/fetch",
  "method": "POST",
  "parameter": "url",
  "param_location": "body"
}
```

- `url` (required inside location): the specific affected URL.
- `method` (optional): the HTTP method when relevant.
- `parameter` (optional): the name of the parameter that is the entry point.
- `param_location` (optional): `query` / `body` / `header` / `cookie` / `path`.

**evidence** holds evidence that has been scrubbed of secrets. The object shape:

```json
{
  "request": "POST /fetch HTTP/1.1\nHost: api.acme.io\n...",
  "response_excerpt": "HTTP/1.1 200 OK\n...",
  "payload": "http://169.254.169.254/latest/meta-data/",
  "matched": "ami-id",
  "screenshot_ref": "blob://findings/abc123/1.png"
}
```

- All sub-fields are optional, but at least one should be present so the finding can be verified.
- `request` / `response_excerpt`: an HTTP excerpt, trimmed and scrubbed of credentials.
- `payload`: the payload that triggered the finding.
- `matched`: the part of the response that matched the pattern.
- `screenshot_ref`: a reference to binary evidence in the store (not inline data), so the schema stays light.

Security rule: before anything enters `evidence`, authentication header values, tokens, and credentials **must be redacted**. The schema never stores a raw secret.

## Dedup key

`dedup_key` gives two findings that are "essentially the same" an identical key, so triage can merge them. The key is computed deterministically from the fields that define an issue's identity, not from detail that changes every scan.

The default v1 recipe:

```text
dedup_key = sha256( lower(type) + "|" + host(target) + "|" + path(location.url) + "|" + upper(location.method) + "|" + (location.parameter | "") )
```

- `type`: the vulnerability type (not the free-form title).
- `host(target)`: the host of the target, without the scheme and **without the port** (the port is deliberately excluded from the key).
- `path(location.url)`: the URL path, without the query string (query values vary).
- `location.method`: the HTTP method, normalized to uppercase; empty when it is not relevant (e.g. ffuf/retire/SAST). It separates e.g. `GET` vs `POST` on the same path+parameter so they are not merged by mistake.
- `location.parameter`: the parameter name if present, an empty string if not.

For **site-wide** types (origin-level issues: an absent security header, CSP, CORS, etc., see `siteWide()` in `internal/finding/dedup.go`), the `path` **and** `method` are ignored (identity = the origin), so appearances across many URLs collapse into one.

What is **not** in the key: `run_id`, `source_engine`, timestamps, the specific payload, query values, and the target port. That way the same XSS issue on the same parameter stays one finding even when two different engines or two different runs find it.

When dedup happens, the new finding is given `status = duplicate` and `duplicate_of` points at the primary finding; or an implementation may keep one finding with a list of appearances. That storage decision belongs to the store spec, but the key and its meaning stay as in this document.

Note: the recipe is deliberately simple. The `method` refinement (so `GET` vs `POST` are not merged by mistake) and the site-wide collapse are **already applied** in `internal/finding/dedup.go` (see the "Open questions" checklist below).

## Example finding

A complete record:

```json
{
  "schema_version": "1.0",
  "id": "f1a2b3c4-5d6e-7f80-9a1b-2c3d4e5f6071",
  "dedup_key": "9f2c...e41a",
  "program": "acme-public",
  "run_id": "run_20261021_0912",
  "target": "https://api.acme.io",
  "type": "ssrf",
  "title": "SSRF in the url parameter at /fetch",
  "description": "The /fetch endpoint fetches a URL from the parameter without validation, allowing requests to the internal network.",
  "severity": "critical",
  "confidence": "medium",
  "cvss": { "version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:L", "score": 9.3 },
  "cwe": ["CWE-918"],
  "tags": ["ssrf", "cloud-metadata"],
  "location": {
    "url": "https://api.acme.io/fetch",
    "method": "POST",
    "parameter": "url",
    "param_location": "body"
  },
  "evidence": {
    "request": "POST /fetch HTTP/1.1\nHost: api.acme.io\nAuthorization: [REDACTED]\n\nurl=http://169.254.169.254/latest/meta-data/",
    "response_excerpt": "HTTP/1.1 200 OK\n...\nami-id\n...",
    "payload": "http://169.254.169.254/latest/meta-data/",
    "matched": "ami-id",
    "screenshot_ref": "blob://findings/f1a2b3c4/1.png"
  },
  "reproduction": [
    "Send a POST to /fetch with the body url=http://169.254.169.254/latest/meta-data/",
    "Observe the response contains the instance metadata"
  ],
  "source_engine": "nuclei",
  "source_template": "ssrf-via-fetch",
  "references": ["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
  "status": "new",
  "in_report": false,
  "created_at": "2026-10-21T09:14:03Z"
}
```

Note the `Authorization` header is redacted to `[REDACTED]` in `evidence.request`, per the security rule.

## Versioning & extension

The schema is versioned `MAJOR.MINOR` via `schema_version`.

- **MINOR change (additive, compatible):** adding a new optional field, or adding an enum value. Old consumers can still read it. Bump MINOR (e.g. `1.0` -> `1.1`).
- **MAJOR change (breaking):** removing/renaming a field, changing a type, making an optional field required, or removing an enum value. Bump MAJOR (e.g. `1.x` -> `2.0`) and provide a migration.

Rules of thumb:

- Add additively first; avoid a MAJOR change unless it is truly needed.
- Do not reuse an old field name for a different meaning.
- Engine-specific detail never becomes a core field; put it in `raw`.
- Every version bump is recorded (a short changelog), because the store, triage, report, and UI rely on this contract.

The store must keep `schema_version` per finding so old data stays readable after the schema bumps version.

### Version history

- `1.0`: the initial schema (M0).
- `1.1`: add `impact` (concrete impact for the report; additive).
- `1.2`: add `owasp` (OWASP Top 10 2021 category; additive, a best-effort classification).

## Engine-to-schema mapping

Each engine has one adapter that turns its raw output into a schema finding. The adapter is responsible for filling the required fields; the rest are filled when available.

An example mapping (illustrative, not final):

| Schema field | From nuclei | From ZAP |
| --- | --- | --- |
| type | `template-id` / `classification` | `pluginid` / alert name -> slug |
| title | `info.name` | `alert` |
| severity | `info.severity` (mapped to the enum) | `risk` (mapped to the enum) |
| confidence | from the match type | `confidence` |
| cwe | `info.classification.cwe-id` | `cweid` |
| location.url | `matched-at` | `url` |
| location.parameter | from the match if present | `param` |
| evidence | the request/response match | `evidence`, `attack`, `other` |
| source\_template | `template-id` | `pluginid` |
| references | `info.reference` | `reference` |
| raw | the whole nuclei result object | the whole ZAP alert object |

The adapter's responsibilities:

- Map the engine's severity/confidence to the schema enum (not a raw copy).
- Redact secrets from the evidence before writing.
- Compute the `dedup_key` per the recipe in this document.
- Fill in `source_engine` and `schema_version`.

Because every engine meets at one schema, adding a new engine = adding one adapter, without touching triage, the report, or the UI.

## Open questions

> Reconciled with the implementation on 2026-11-04. `[x]` = decided/implemented (with evidence), `[~]` = partial, `[ ]` = still open.

- [x] `dedup_key` refinement: the key is now `sha256(lower(type)|host|path|method|parameter)` (`internal/finding/dedup.go`). **The HTTP method is included** so GET vs POST on the same path+parameter are not merged by mistake; the method is normalized to uppercase, empty (ffuf/retire/SAST) stays empty, and for site-wide types the path+method are ignored (identity = the origin). The port stays deliberately excluded.
- [x] The `type` taxonomy: it **stays a per-engine native slug** (nuclei template-id, ZAP alert slug, etc.) as the source of precision + the dedup basis; a single canonical list is **not** built. Cross-engine correlation is handled by the **additive** `owasp` field (OWASP Top 10 2021) from a best-effort classifier (CWE -> tag/type keyword) in `Finalize`, see `internal/finding/owasp.go`; it shows in the finding detail, report, & H1/Bugcrowd export. A WASC map is deliberately not built (OWASP was chosen as the single standard).
- [x] Severity: **the engine is the primary source**, mapped per adapter to the schema enum (`mapSeverity`/`mapRisk` in each `internal/engine/*/parse.go`). It is not recomputed from CVSS.
- [x] The dedup storage model: **a separate record with `duplicate_of`** pointing at the primary finding; duplicates are hidden from counts/reports but stored whole for audit. Enforced per `(program, dedup_key)` in `internal/store` (Mem & SQLite), plus the site-wide collapse for origin-level issues.
- [x] `evidence` size: **an inline limit is applied**. Each textual sub-field is trimmed in `Finding.Finalize` at a rune boundary (max 32 KiB/field) with a marker of the byte count dropped; `screenshot_ref` (a reference, not content) is not trimmed. The limit is generous so a request can still be replayed (e.g. into Burp). See `internal/finding/finding.go` (`clampFields`/`clampText`).
- [~] `program`/`run_id` vs `workspace`/`tenant`: multi-user is present via **RBAC** (admin/operator/viewer, `internal/auth`) over **one shared workspace**; `program`+`run_id` stay the data boundary. A `workspace`/`tenant` partition is deliberately not added yet (enough for a small team).

Note: the schema foundation has stood since M0; the remaining items above are refinements, not blockers.
