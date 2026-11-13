"""Uji SPK/SAW — fungsi murni + pipeline end-to-end (deterministik, tanpa jaringan).
Jalankan: `python tests/test_saw.py` atau `pytest`."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bughound_analyst import analyst, config, saw  # noqa: E402
from bughound_analyst.model import Evidence, Finding, Location  # noqa: E402


def test_normalize_benefit_and_cost():
    assert saw.normalize_column([5, 10, 0], "benefit") == [0.5, 1.0, 0.0]
    # cost: min positif / x ; 0 cost = ideal (1.0)
    assert saw.normalize_column([2, 4, 0], "cost") == [1.0, 0.5, 1.0]
    assert saw.normalize_column([], "benefit") == []


def test_saw_score_weighted_sum():
    rows = [{"a": 10, "b": 2}, {"a": 5, "b": 1}]
    weights = {"a": 0.5, "b": 0.5}
    types = {"a": "benefit", "b": "cost"}
    res = saw.saw_score(rows, weights, types)
    # baris0: a=10/10=1 (w.5)=.5 ; b cost min=1 →1/2=.5 (w.5)=.25 → .75
    assert abs(res[0]["score"] - 0.75) < 1e-9
    # baris1: a=5/10=.5→.25 ; b=1→1.0→.5 → .75
    assert abs(res[1]["score"] - 0.75) < 1e-9


def _mk(fid, typ, sev, conf, engine, owasp, url, param, status="new", spa=False):
    body = '<div id="root"></div>' if spa else "ok"
    return Finding(
        id=fid, dedup_key=fid, program="demo", type=typ, title=typ,
        severity=sev, confidence=conf, source_engine=engine, owasp_category=owasp,
        status=status, location=Location(url=url, method="GET", parameter=param),
        evidence=Evidence(response_excerpt=body),
    )


def test_pipeline_ranks_sqli_first():
    """§4.5 — SQLi (nuclei-dast/high/crit) > XSS (dalfox/med) > dir (ffuf/low+SPA-FP)."""
    cfg = config.load()
    findings = [
        _mk("f-dir", "exposed-dir", "low", "low", "ffuf", "A05",
            "https://t.test/admin", "", spa=True),
        _mk("f-sqli", "sqli", "critical", "high", "nuclei-dast", "A03",
            "https://t.test/rest/search", "q"),
        _mk("f-xss", "xss reflected", "medium", "medium", "dalfox", "A03",
            "https://t.test/search", "q2"),
    ]
    kept = analyst.prefilter(findings)
    assert len(kept) == 3
    ranked = saw.rank_findings(kept, analyst.derive(kept, cfg), cfg)
    order = [r["finding"].id for r in ranked]
    assert order == ["f-sqli", "f-xss", "f-dir"], order
    assert ranked[0]["score"] > ranked[1]["score"] > ranked[2]["score"]
    # breakdown lengkap & explainable
    assert set(ranked[0]["breakdown"]) == set(cfg.weights)


def test_prefilter_drops_and_collapses():
    cfg = config.load()
    findings = [
        _mk("a", "sqli", "high", "high", "nuclei-dast", "A03", "https://t.test/x", "q"),
        _mk("dup", "sqli", "high", "high", "nuclei-dast", "A03", "https://t.test/x", "q",
            status="false_positive"),
        _mk("info", "banner", "info", "low", "nuclei", "", "https://t.test/y", ""),
    ]
    kept = analyst.prefilter(findings)
    ids = {f.id for f in kept}
    assert ids == {"a"}, ids  # FP dibuang, info dibuang


def test_weights_sum_to_one():
    config.load().validate()  # raise bila Σ != 1


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} test LULUS")
