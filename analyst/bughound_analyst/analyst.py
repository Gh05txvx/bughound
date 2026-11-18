"""Analyst layer, DETERMINISTIC metrics (no LLM): clusters, fp_likelihood,
exploitability, bounty_weight, and a pre-filter before SAW."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Set

from .config import CONF_NUM, SEV_NUM, Config
from .model import Finding

# statuses dropped from triage.
_DROP_STATUS = {"duplicate", "false_positive", "ignored"}


def cluster_key(f: Finding) -> str:
    """Cluster identity: dedup_key when present, else host+type+parameter."""
    if f.dedup_key:
        return f.dedup_key
    return f"{f.host()}|{f.type}|{f.location.parameter}"


def clusters(findings: List[Finding]) -> Dict[str, List[Finding]]:
    out: Dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        out[cluster_key(f)].append(f)
    return out


def siblings_on_endpoint(findings: List[Finding]) -> Dict[str, int]:
    by_url: Dict[str, int] = defaultdict(int)
    for f in findings:
        by_url[f.location.url] += 1
    return {f.id: by_url[f.location.url] - 1 for f in findings}


# Common SPA shell markers (React/Vue/Angular/Next/Nuxt/Svelte/webpack). When these
# show up in the body, a large ffuf response is probably the app shell (soft-200), not a real path.
_SPA_MARKERS = (
    '<div id="root"', '<div id="app"', "<app-root", "ng-version", "data-reactroot",
    "window.__", "__next_data__", "__nuxt__", "__initial_state__",
    "data-v-", "data-svelte", "webpackjsonp", "/_next/static",
)


def _looks_like_spa(f: Finding) -> bool:
    body = (f.evidence.response_excerpt if f.evidence else "").lower()
    return any(s in body for s in _SPA_MARKERS)


def _ffuf_flood_hosts(findings: List[Finding], threshold: int) -> Set[str]:
    """A host with >=threshold exposed-path findings from ffuf is probably a
    soft-404/wildcard (the server answers 200 for nearly every path). A FP prior."""
    c = Counter(f.host() for f in findings
                if f.source_engine == "ffuf" and "exposed" in (f.type or "").lower())
    return {h for h, n in c.items() if n >= threshold}


def fp_likelihood(f: Finding) -> float:
    if f.status == "confirmed":
        return 0.0
    if f.confidence == "high" and f.source_engine in ("nuclei-dast", "dalfox"):
        return 0.1
    if f.source_engine == "ffuf" and _looks_like_spa(f):
        return 0.7
    if f.source_engine in ("retire", "zap-passive") and f.confidence == "low":
        return 0.5
    return 0.3


def exploitability_raw(f: Finding, cfg: Config) -> float:
    return CONF_NUM.get(f.confidence, 1) * cfg.engine_f(f.source_engine)


def bounty_weight(f: Finding, scope: Optional[Dict] = None) -> float:
    """Bounty potential. When `scope` holds asset->{max_severity, eligible_for_bounty},
    use it; otherwise the fallback = the finding severity."""
    base = SEV_NUM.get(f.severity, 1)
    if scope:
        meta = scope.get(f.host()) or scope.get(f.target) or {}
        ms = meta.get("max_severity")
        if ms == "none":
            ms = "info"
        if ms in SEV_NUM:
            base = SEV_NUM[ms]
        if meta.get("eligible_for_bounty") is False:
            base *= 0.4
    return base


def _parse_time(s: str) -> Optional[datetime]:
    """Parse created_at (RFC3339/ISO8601) into an aware datetime, or None on failure."""
    if not s:
        return None
    s = s.strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def _freshness_bucket(gap_days: float) -> int:
    if gap_days <= 1:
        return 5
    if gap_days <= 7:
        return 4
    if gap_days <= 30:
        return 3
    return 2


def freshness_map(findings: List[Finding]) -> Dict[str, int]:
    """Freshness per finding = how recent `created_at` is relative to the NEWEST
    finding in the batch (newest run -> 5; older drops off). An unreadable created_at
    -> 3 (neutral). Relative to the newest, not to the current clock: the ranking of
    an old export stays stable & the last run is always the freshest."""
    times = {f.id: _parse_time(f.created_at) for f in findings}
    valid = [t for t in times.values() if t is not None]
    if not valid:
        return {f.id: 3 for f in findings}
    newest = max(valid)
    out: Dict[str, int] = {}
    for f in findings:
        t = times[f.id]
        if t is None:
            out[f.id] = 3
        else:
            out[f.id] = _freshness_bucket((newest - t).total_seconds() / 86400.0)
    return out


def derive(findings: List[Finding], cfg: Config,
           scope: Optional[Dict] = None) -> Dict[str, Dict]:
    """Compute every derived metric -> map finding.id -> dict."""
    sib = siblings_on_endpoint(findings)
    fresh = freshness_map(findings)
    flood_fp = float(cfg.heuristics.get("ffuf_flood_fp", 0.6))
    flood_hosts = _ffuf_flood_hosts(findings, int(cfg.heuristics.get("ffuf_flood_threshold", 8)))
    out: Dict[str, Dict] = {}
    for f in findings:
        fp = fp_likelihood(f)
        if f.status != "confirmed" and f.source_engine == "ffuf" and f.host() in flood_hosts:
            fp = max(fp, flood_fp)   # prior soft-404/wildcard
        # the path is part of the signal -> an exposed-path to /.git /admin /backup is promoted to high;
        # a boring path (robots/sitemap/.well-known) -> NEUTRAL dropped to noise.
        sig = cfg.signal(" ".join(x for x in [f.type, f.title, *f.tags] if x), f.path())
        if sig == 0.5 and cfg.is_boring_path(f.path()):
            sig = 0.1
        out[f.id] = {
            "cluster_id": cluster_key(f),
            "siblings_on_endpoint": sib.get(f.id, 0),
            "fp_likelihood": fp,
            "exploitability_raw": exploitability_raw(f, cfg),
            "bounty_weight": bounty_weight(f, scope),
            "signal": sig,
            "freshness": fresh.get(f.id, 3),
        }
    return out


def prefilter(findings: List[Finding], drop_info: bool = True,
              collapse_clusters: bool = True) -> List[Finding]:
    """Drop duplicate/FP/ignored statuses (+ optional info), then one representative
    per cluster (highest severity) to avoid double verification."""
    kept = [f for f in findings if f.status not in _DROP_STATUS]
    if drop_info:
        kept = [f for f in kept if f.severity != "info"]
    if not collapse_clusters:
        return kept
    rep: Dict[str, Finding] = {}
    for f in kept:
        k = cluster_key(f)
        cur = rep.get(k)
        if cur is None or SEV_NUM.get(f.severity, 1) > SEV_NUM.get(cur.severity, 1):
            rep[k] = f
    return list(rep.values())
