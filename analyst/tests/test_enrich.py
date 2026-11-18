"""Test enrichment: freshness (from created_at) + scope assets (bounty).
Deterministic, no network. Run: `python tests/test_enrich.py` or `pytest`."""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bughound_analyst import analyst, scope  # noqa: E402
from bughound_analyst.model import Evidence, Finding, Location  # noqa: E402


def _mk(fid, url, sev="low", created=""):
    return Finding(id=fid, dedup_key=fid, program="demo", type="t", title="t",
                   severity=sev, location=Location(url=url), created_at=created)


# ---- freshness ----

def test_freshness_newer_ranks_higher():
    fs = [
        _mk("new", "https://t/a", created="2026-11-13T00:00:00Z"),
        _mk("mid", "https://t/b", created="2026-11-05T00:00:00Z"),  # 8 days -> 3
        _mk("old", "https://t/c", created="2026-09-01T00:00:00Z"),  # 73 days -> 2
    ]
    fr = analyst.freshness_map(fs)
    assert fr["new"] == 5, fr
    assert fr["mid"] == 3, fr
    assert fr["old"] == 2, fr
    assert fr["new"] > fr["mid"] > fr["old"]


def test_freshness_unparseable_is_neutral():
    fs = [
        _mk("a", "https://t/a", created="2026-11-13T00:00:00Z"),
        _mk("b", "https://t/b", created=""),        # empty -> neutral 3
        _mk("c", "https://t/c", created="not-a-date"),
    ]
    fr = analyst.freshness_map(fs)
    assert fr["a"] == 5 and fr["b"] == 3 and fr["c"] == 3, fr


def test_freshness_all_missing_all_neutral():
    fs = [_mk("a", "https://t/a"), _mk("b", "https://t/b")]
    assert analyst.freshness_map(fs) == {"a": 3, "b": 3}


def test_derive_includes_freshness():
    import bughound_analyst.config as config
    fs = [_mk("a", "https://t/a", created="2026-11-13T00:00:00Z")]
    d = analyst.derive(fs, config.load())
    assert d["a"]["freshness"] == 5


# ---- scope lookup ----

def test_scope_exact_then_wildcard_and_port():
    t = scope.ScopeTable()
    t.wildcard["deriv.com"] = {"max_severity": "critical", "eligible_for_bounty": True}
    t.exact["app.deriv.com"] = {"max_severity": "high", "eligible_for_bounty": True}
    assert t.get("app.deriv.com")["max_severity"] == "high"       # exact wins
    assert t.get("sub.deriv.com")["max_severity"] == "critical"   # wildcard
    assert t.get("app.deriv.com:443")["max_severity"] == "high"   # port dropped
    assert t.get("other.com") is None
    assert t.get("") is None


def _write_csv(rows):
    fd, path = tempfile.mkstemp(suffix=".csv")
    os.close(fd)
    header = "identifier,asset_type,eligible_for_submission,eligible_for_bounty,max_severity\n"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(header)
        fh.writelines(r + "\n" for r in rows)
    return path


def test_load_csv_filters_and_classifies():
    path = _write_csv([
        "*.deriv.com,WILDCARD,true,true,critical",
        "app.deriv.com,URL,true,false,high",
        "info.deriv.com,URL,true,true,none",
        "out.deriv.com,URL,false,true,high",      # out-of-scope -> dropped
        "SOME_APP_ID,OTHER,true,true,high",        # not a host -> dropped
    ])
    try:
        t = scope.load_csv(path)
    finally:
        os.remove(path)
    assert len(t.wildcard) == 1 and "deriv.com" in t.wildcard
    assert set(t.exact) == {"app.deriv.com", "info.deriv.com"}, t.exact
    assert t.get("x.deriv.com")["max_severity"] == "critical"     # wildcard
    assert t.get("app.deriv.com")["eligible_for_bounty"] is False
    assert t.get("out.deriv.com") is None                          # not loaded


# ---- bounty_weight uses scope ----

def test_bounty_weight_scope_overrides_severity():
    t = scope.ScopeTable()
    t.wildcard["deriv.com"] = {"max_severity": "critical", "eligible_for_bounty": True}
    f = _mk("x", "https://www.deriv.com/p", sev="low")   # severity low
    # the scope cap critical (5) wins over severity low (2)
    assert analyst.bounty_weight(f, t) == 5


def test_bounty_weight_not_eligible_discounted():
    t = scope.ScopeTable()
    t.exact["app.deriv.com"] = {"max_severity": "high", "eligible_for_bounty": False}
    f = _mk("x", "https://app.deriv.com/p", sev="critical")
    # high(4) × 0.4 (not bounty-eligible) = 1.6
    assert abs(analyst.bounty_weight(f, t) - 1.6) < 1e-9


def test_bounty_weight_none_severity():
    t = scope.ScopeTable()
    t.exact["info.deriv.com"] = {"max_severity": "none", "eligible_for_bounty": True}
    f = _mk("x", "https://info.deriv.com/p", sev="critical")
    assert analyst.bounty_weight(f, t) == 1   # none → info (1)


def test_bounty_weight_no_scope_falls_back_to_severity():
    f = _mk("x", "https://t/a", sev="high")
    assert analyst.bounty_weight(f, None) == 4   # SEV_NUM[high]


# ---- signal (anti header-noise) ----

def _finding(fid, typ, sev, conf, engine, url="https://t/x"):
    return Finding(id=fid, dedup_key=fid, program="demo", type=typ, title=typ,
                   severity=sev, confidence=conf, source_engine=engine,
                   location=Location(url=url))


def test_signal_classification():
    import bughound_analyst.config as config
    cfg = config.load()
    assert cfg.signal("content-security-policy-csp-header-not-set") == 0.1
    assert cfg.signal("strict-transport-security-header-not-set") == 0.1
    assert cfg.signal("sub-resource-integrity-attribute-missing") == 0.1
    assert cfg.signal("timestamp-disclosure-unix") == 0.1
    assert cfg.signal("sql-injection error-based") == 1.0
    assert cfg.signal("reflected xss") == 1.0
    assert cfg.signal("exposed-admin-panel") == 1.0
    assert cfg.signal("exposed-path") == 0.5          # neutral (ambiguous)
    assert cfg.signal("") == 0.5
    # collision guard: a short token must not catch as a substring
    assert cfg.signal("x-xss-protection-header-missing") == 0.1   # not high via 'xss'
    assert cfg.signal("cross-domain-javascript-source-file-inclusion") == 0.1  # not 'file-inclusion'
    assert cfg.signal("remote-file-inclusion") == 1.0             # real RFI stays high


def test_hygiene_ranks_below_real_bug():
    import bughound_analyst.config as config
    from bughound_analyst import saw
    cfg = config.load()
    fs = [
        _finding("hygiene", "content-security-policy-csp-header-not-set",
                 "medium", "high", "zap"),
        _finding("real", "sql-injection", "high", "high", "nuclei-dast",
                 "https://t/rest/s?q=1"),
    ]
    kept = analyst.prefilter(fs)
    d = analyst.derive(kept, cfg)
    assert d["hygiene"]["signal"] == 0.1 and d["real"]["signal"] == 1.0
    ranked = saw.rank_findings(kept, d, cfg)
    assert [r["finding"].id for r in ranked] == ["real", "hygiene"]
    assert ranked[0]["score"] > ranked[1]["score"]


# ---- signal via URL path (promote to high only) + ffuf SPA-FP ----

def test_signal_path_promotes_only_to_high():
    import bughound_analyst.config as config
    cfg = config.load()
    assert cfg.signal("exposed-path") == 0.5                        # generic -> neutral
    assert cfg.signal("exposed-path", "/.git/config") == 1.0        # path juicy → high
    assert cfg.signal("exposed-path", "/db-backup.sql") == 1.0
    assert cfg.signal("exposed-path", "/assets/main.js") == 0.5     # ordinary asset -> neutral
    # the path NEVER drops a real finding to noise (noise comes from the type only)
    assert cfg.signal("sql-injection", "/api/cache-control-test") == 1.0
    # a header stays noise even when its path is juicy
    assert cfg.signal("content-security-policy-header", "/.git/config") == 0.1


def test_ffuf_flood_raises_fp():
    import bughound_analyst.config as config
    cfg = config.load()
    thr = int(cfg.heuristics["ffuf_flood_threshold"])
    floor = cfg.heuristics["ffuf_flood_fp"]
    flood = [_finding(f"p{i}", "exposed-path", "low", "high", "ffuf",
                      f"https://flood.test/p{i}") for i in range(thr)]
    d = analyst.derive(flood, cfg)
    assert all(d[f.id]["fp_likelihood"] >= floor for f in flood)    # flood -> fp rises
    few = [_finding(f"q{i}", "exposed-path", "low", "high", "ffuf",
                    f"https://calm.test/q{i}") for i in range(2)]
    d2 = analyst.derive(few, cfg)
    assert all(d2[f.id]["fp_likelihood"] < floor for f in few)      # few -> not affected


def test_expanded_spa_markers():
    f = _finding("s", "exposed-path", "low", "high", "ffuf", "https://t/app")
    f.evidence = Evidence(response_excerpt='<script id="__NEXT_DATA__">{}</script>')
    assert analyst.fp_likelihood(f) == 0.7   # recognized SPA (Next.js) -> high fp


def test_boring_path_downgrades_neutral():
    import bughound_analyst.config as config
    cfg = config.load()
    assert cfg.is_boring_path("/robots.txt") and cfg.is_boring_path("/.well-known/security.txt")
    assert not cfg.is_boring_path("/signup")
    fs = [
        _finding("boring", "exposed-path", "low", "high", "ffuf", "https://t/robots.txt"),
        _finding("real", "exposed-path", "low", "high", "ffuf", "https://t/signup"),
        _finding("juicy", "exposed-path", "low", "high", "ffuf", "https://t/.git/config"),
    ]
    d = analyst.derive(fs, cfg)
    assert d["boring"]["signal"] == 0.1   # standard file -> noise
    assert d["real"]["signal"] == 0.5     # real endpoint -> neutral
    assert d["juicy"]["signal"] == 1.0    # juicy path -> high (wins over boring)


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} tests PASSED")
