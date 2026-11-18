# Spec: Payload & Template Bank (BugHound)

Oct 21, 2026 · @Gh05t

The payload bank is where every template/payload an engine runs lives, is organized, updated, and added to. The goal: payloads are easy to update and add without touching BugHound's code, while staying safe and traceable. This document picks the model (a thin-leaning hybrid: payloads stay in the engine's native format, with one neutral catalog layer on top), then defines the bank structure, metadata, format, update mechanism, and security rules. ID: `BH-SPEC-PAYLOAD`.

## Summary & role

An engine (nuclei, ZAP, etc.) does not know what to check until it is given a **template/payload**: the rule that defines one test. The payload bank is where all of those templates live, are organized, updated, and added to.

This bank bridges three things:

- **The sources** a template comes from (the nuclei community repo, your own custom directory, an external feed).
- **The engine workers** that run a template during a scan.
- **The finding schema** (`BH-SPEC-FINDING`): when a template produces a finding, its id carries into the `source_template` field, so the finding can be traced back to the payload it came from.

The bank's main value: payloads can be updated and added without touching BugHound's code, stay safe (an outside source is treated as untrusted), and are traceable (each scan records the template version it used).

## Design principles

1. **Store in the engine's native format.** The payload contents are not translated to our own format. A nuclei template stays nuclei YAML. This avoids rebuilding a mature ecosystem.
2. **One neutral catalog layer on top.** BugHound only adds a uniform metadata manifest that catalogs every template, whatever its engine, without touching the contents.
3. **Sources are pluggable.** The bank is a set of sources that can be added/removed through configuration, not one fixed folder.
4. **Payloads are data, not code.** A template is never embedded in BugHound's code; it is read from a source at runtime, so an update = refresh the source, not rebuild.
5. **Safe by default.** A template from outside is treated as untrusted and validated before it runs.
6. **Traceable.** Each scan records the source and version of the templates it used, so results can be reproduced and audited.
7. **Easy to add to.** Adding a payload = dropping one file in a source + minimal metadata, without changing any other component.

## The chosen model

Chosen: **a thin-leaning hybrid.** Payloads stay engine-native; BugHound adds a neutral catalog (metadata), not a new payload format.

A comparison of three options:

| Model | Pros | Cons | Verdict |
| --- | --- | --- | --- |
| Thin layer over the engine | Fastest; follows the nuclei ecosystem | Flexibility tied to the nuclei format; hard to go cross-engine | Too narrow |
| Our own neutral payload format | Portable across engines | Must build a translator + risks rebuilding nuclei | Over-engineering for a small team |
| **Thin-leaning hybrid (chosen)** | Native payloads (cheap) + a uniform catalog (flexible update/add/safe) | Needs the discipline to maintain the metadata | The best fit |

The reason: translating payload contents is a large, error-prone job, while what we actually need for "flexible update and add" sits at the catalog level (metadata, sources, update, security). Our own neutral payload format is only introduced later, only for a check no engine can express, and that is recorded as an open question, not built now.

## Bank structure & sources

The bank is not one folder but a set of **sources** registered in the configuration. Each source is a repo/directory of templates in its native format. On top of every source, BugHound builds one **catalog** (manifest) that makes each template's metadata uniform without touching the contents.

> _Diagram: bank structure · native sources -> neutral catalog -> engine (available in the Claude Docs version; not carried into the Markdown export)._

Each source has: a location (a path or repo URL), the engine type, a trust level, and how it updates. Adding a source = adding one config entry. The catalog keeps, for each template: the id, the originating source, the engine, the version, and metadata (default severity, tags, references). Engine workers select and run templates through the catalog, not by touching the source directly. An untrusted external feed must pass validation before it enters the catalog (see Security).

## Catalog metadata

For each template, the catalog keeps the uniform metadata below, whatever the originating engine. This metadata is what lets the bank be filtered, prioritized, updated, and traced back.

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| template\_id | string | yes | A stable id, unique across the whole bank (e.g. `nuclei:ssrf-via-fetch`) |
| source | string | yes | The originating source id (e.g. `nuclei-community`, `custom`) |
| engine | string | yes | The engine that runs it (e.g. `nuclei`, `zap`) |
| native\_ref | string | yes | The template's location/id in its native format in the source |
| name | string | yes | A short human-readable name |
| type | string | no | The vulnerability type, aligned with the `type` taxonomy in the finding schema |
| severity\_default | enum | no | The default severity (per the finding schema enum) |
| tags | string\[\] | no | Labels for selection (e.g. `ssrf`, `cve`, `fast`) |
| references | string\[\] | no | Reference links |
| trust | enum | yes | `trusted` / `review` / `untrusted` (sets the security treatment) |
| version | string | yes | The template version (a content hash or source version) |
| enabled | boolean | yes | Whether it runs by default |
| added\_at | datetime | no | When it entered the catalog |

`template_id` here is the value that carries into `source_template` on a finding, so each finding can be traced back to its payload and version.

## The format of one template/payload

One template = **the native body** (untouched) + **metadata**. Metadata is supplied in one of two ways:

1. **Derived from the native body.** For an engine whose template already carries metadata (nuclei has an `info:` block with name, severity, tags, reference), the catalog extracts it automatically. No extra file needed.
2. **A sidecar.** For a payload whose native format does not carry metadata, supply one sidecar file `<name>.meta.yaml` next to it that fills in the catalog metadata fields.

An example nuclei template (native body, metadata derived from `info:`):

```yaml
id: ssrf-via-fetch
info:
  name: SSRF via fetch parameter
  severity: high
  tags: [ssrf, cloud-metadata]
  reference:
    - https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
# ... the native nuclei requests/matchers section below ...
```

An example sidecar for a non-nuclei payload (`myscan.meta.yaml`):

```yaml
template_id: custom:open-redirect-logout
engine: custom
name: Open redirect on the logout parameter
type: open-redirect
severity_default: medium
tags: [open-redirect, custom]
trust: trusted
```

Rule: the native body is never edited by BugHound. If metadata is incomplete and cannot be derived, the template still enters the catalog but is marked as needing completion, not quietly used with empty metadata.

## Update & addition mechanism

**Update (refreshing what exists):**

- Each source has its own update method that BugHound calls: `git pull` for a repo, nuclei's built-in update command for nuclei templates, a download for a feed.
- The `bughound templates update` command updates every source (or one source), then refreshes the catalog.
- A content change is detected via `version` (a hash), so the catalog knows what changed.

**Addition (adding a new payload):**

- Add a native template to a source directory (e.g. drop a `.yaml` file in the custom directory), fill in the metadata (from `info:` or a sidecar), then refresh the catalog. No change to BugHound's code.
- Adding a new **source** = adding one config entry (location, engine, trust, update method).

**Reproducibility & pinning:**

- Each run records the version of every template it used (a catalog snapshot), so the scan result can be reproduced.
- A source can be pinned to a specific version/commit, so an update does not change behavior by accident. An update becomes a deliberate act, not a surprise.

**Selection:**

- A scan selects templates through the catalog metadata (by `tags`, `type`, `severity_default`, `enabled`), rather than running everything blindly.

## Untrusted-template security

A template is an instruction the engine executes, so a malicious template could make unwanted requests, including to an out-of-scope target. So a template from outside is treated as untrusted.

Rules:

- **Explicit trust level.** Each source is marked `trusted` / `review` / `untrusted`. Only a `trusted` source may run automatically.
- **Review before active.** A template from a `review`/`untrusted` source enters the catalog as `enabled = false` until it is reviewed and its trust is raised deliberately.
- **The scope guard still binds.** Whatever a template requests, every outbound connection still goes through the scope guard (`BH-SPEC-SCOPE`). A template cannot bypass scope.
- **Shape validation.** A template is validated against the engine's format schema before use; an invalid one is rejected, not run.
- **Limit dangerous capabilities.** Template features that can execute a local command or read a system file (if the engine supports them) are disabled or limited for a non-`trusted` template.
- **Source integrity.** A source update is done through a verified channel (e.g. a known repo); changes are recorded via `version`.

For early personal use, it is enough to use sources you trust (the official nuclei repo + your own custom directory). The full trust rules matter when the bank accepts a template from outside or the tool is used by someone else.

## Integration

**To the engine adapter.** During a scan, the orchestrator selects a template from the catalog (by its metadata), then hands the `native_ref` to the matching engine adapter. The adapter runs the template in its native format; the bank does not translate the payload contents. This keeps the separation: the bank governs *what is available and selected*, the adapter governs *how it runs*.

**To the finding schema.** When a template produces a finding, the adapter fills `source_template` on the finding with the `template_id` from the catalog (`BH-SPEC-FINDING`). That way each finding can be traced back to its payload and version, and triage can, for example, mute every finding from one template that turns out to be noisy.

**To config.** The source list, trust levels, version pins, and selection profiles are kept in BugHound's configuration (the Config module in the PRD), not in code.

The result: adding a new detection capability = adding a template to the bank (or adding a source), not writing code, as long as the engine is already supported.

## Open questions

> Reconciled with the implementation on 2026-11-04. `[x]` = decided/implemented, `[~]` = partial, `[ ]` = still open.

- [ ] Our own neutral payload format: **still deliberately deferred** (only for a check no engine can express). Not introduced yet.
- [x] Global `template_id`: the **`<engine>:<native-id>`** scheme is applied (`internal/payload/payload.go`, `source.go`), unique and stable across sources (the first wins on an id collision).
- [x] The minimum metadata to be `enabled`: applied via `hasMinMeta`/`canEnable`: a template is only `enabled` automatically when it is from a **trusted** source AND its minimum metadata is met.
- [x] Native severity/tag -> uniform mapping: done per engine adapter during normalization to the finding schema (`mapSeverity` in each `internal/engine/*/parse.go`); the payload catalog stores `type`/severity aligned with the schema.
- [x] Selection profiles ("run tag X, severity >= Y" per program): **implemented** as a per-program preset: `store.ScanPreset{Tags,Severity,Stealth}` on `Program` (the `preset` column in the `programs` table, an idempotent additive migration for an old DB), prefilling the scan form when a program is selected. Saved only when the user ticks "save preset" (an ordinary scan does NOT overwrite it). Per-scan selection still goes through tags/severity + `enabled`/the source trust level; empty = every template. The preset does not touch the scope guard/egress/rate/secrets.
- [~] Template security validation: **the trust model is applied** (only a trusted source is auto-`enabled`) with the scope guard as the main runtime safety net; **a deeper template-execution sandbox is deferred** per the v1 plan.
- [x] Catalog storage: **the snapshot is built at runtime from pluggable template-directory sources** (`nuclei-dir`, `custom-dir` via `DefaultSources`/`Build`): not in the finding store, and no separate manifest needed.

Note: the most urgent items (the `template_id` scheme and the minimum metadata) are answered because both bind to `source_template` in the finding schema.
