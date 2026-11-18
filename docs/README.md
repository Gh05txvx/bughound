# BugHound docs

The Markdown files in this folder are BugHound's **foundational technical specs**
and **operational guides**, written to be read right inside the repo. Some are
exported from Claude Docs; `guides/` is written directly in the repo.

> Note: internal planning & process docs (PRD, design spec, work personas,
> pre-launch audit, ADR) are kept private by the repo owner and **are not included
> in the public repo**.

## Structure

```
docs/
  specs/            technical foundation specs (referenced by every component)
  guides/           operational feature guides (written directly in the repo)
  BH-CHANGELOG.md   implementation progress notes (what has been built)
```

> **Implementation progress:** see [`BH-CHANGELOG.md`](BH-CHANGELOG.md) for a summary
> of what has been built (M0-M3, releases, security, engines, and so on).

## File list

### `docs/specs/`: Technical specs (foundation)

| ID | File |
| --- | --- |
| `BH-SPEC-FINDING` | `specs/BH-SPEC-FINDING-finding-schema.md` |
| `BH-SPEC-SCOPE` | `specs/BH-SPEC-SCOPE-scope-guard.md` |
| `BH-SPEC-PAYLOAD` | `specs/BH-SPEC-PAYLOAD-payload-bank.md` |

### `docs/guides/`: Operational guides

| ID | File | Core |
| --- | --- | --- |
| `BH-GUIDE-SCAN` | `guides/BH-GUIDE-SCAN.md` | How each feature works (scope guard, egress/proxy, DAST/SAST/recon, rate limiter, triage/report) + the input each scan scenario needs; a reference for the Scan/SAST form fields & startup flags. |
| `BH-GUIDE-PROXY` | `guides/BH-GUIDE-PROXY.md` | The Proxy menu: upstream chain, the IP echo endpoint (must be in-scope), which proxies can be used, and what an external bug bounty program requires. |

## Export notes

- **Diagrams do not carry over.** Only text, tables, and code blocks make it into
  Markdown. Each missing diagram is marked with a `> _Diagram: … (available in the Claude Docs version)_`
  line at its original spot.
- **Date/mention chips** are kept as plain text (e.g. `Oct 21, 2026 · @Gh05t`).
- These files are static copies. When the source document in Claude Docs changes,
  re-export to sync.
