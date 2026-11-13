"""SPK — Simple Additive Weighting (SAW).

Dua lapis:
  - fungsi MURNI `saw_score` / `normalize_column` (mudah diuji, tanpa domain).
  - `rank_findings` yang memetakan Finding → baris kriteria (pakai config + analyst)
    lalu memanggil SAW dan mengembalikan daftar ter-ranking + breakdown explainable.

Normalisasi: benefit r=x/max ; cost r=min/x (0 cost = ideal → r=1).
Skor: V = Σ w·r,  Σ w = 1.
"""
from __future__ import annotations

from typing import Callable, Dict, List

from .config import CONF_NUM, SEV_NUM, Config
from .model import Finding


def normalize_column(values: List[float], ctype: str) -> List[float]:
    vals = [float(v) for v in values]
    if not vals:
        return []
    if ctype == "cost":
        positive = [v for v in vals if v > 0]
        mn = min(positive) if positive else 0.0
        return [1.0 if v <= 0 else (mn / v if mn > 0 else 1.0) for v in vals]
    # benefit
    mx = max(vals)
    return [(v / mx if mx > 0 else 0.0) for v in vals]


def saw_score(rows: List[Dict[str, float]], weights: Dict[str, float],
              types: Dict[str, str]) -> List[Dict]:
    """rows: daftar dict kriteria→nilai mentah. Kembalikan per-baris:
    {index, score, norm{crit→r}, weighted{crit→w·r}} (urutan input dipertahankan)."""
    crits = list(weights.keys())
    norm = {c: normalize_column([r.get(c, 0.0) for r in rows], types[c]) for c in crits}
    out: List[Dict] = []
    for i in range(len(rows)):
        weighted = {c: weights[c] * norm[c][i] for c in crits}
        out.append({
            "index": i,
            "score": round(sum(weighted.values()), 6),
            "norm": {c: round(norm[c][i], 4) for c in crits},
            "weighted": {c: round(weighted[c], 4) for c in crits},
        })
    return out


# ---- Pemetaan domain: Finding → baris kriteria mentah ----

def build_row(f: Finding, derived: Dict, cfg: Config) -> Dict[str, float]:
    """Satu baris matriks keputusan (nilai MENTAH, belum dinormalisasi).
    Semua metrik turunan (termasuk `freshness`) dihitung di `analyst.derive`."""
    return {
        "exploitability": derived.get("exploitability_raw", 0.0),
        "signal": derived.get("signal", 0.5),
        "severity": SEV_NUM.get(f.severity, 1),
        "bounty": derived.get("bounty_weight", SEV_NUM.get(f.severity, 1)),
        "fp_likelihood": derived.get("fp_likelihood", 0.3),
        "effort": cfg.effort(f.type or f.title),
        "owasp": cfg.owasp_p(f.owasp_category),
        "freshness": derived.get("freshness", 3),
    }


def rank_findings(findings: List[Finding], derived_map: Dict[str, Dict],
                  cfg: Config) -> List[Dict]:
    """Kembalikan daftar ter-ranking (skor desc): {finding, rank, score, breakdown, raw}."""
    rows = [build_row(f, derived_map.get(f.id, {}), cfg) for f in findings]
    scored = saw_score(rows, cfg.weights, cfg.types)
    merged = [{
        "finding": findings[s["index"]],
        "score": s["score"],
        "breakdown": s["weighted"],
        "norm": s["norm"],
        "raw": rows[s["index"]],
    } for s in scored]
    merged.sort(key=lambda m: m["score"], reverse=True)
    for i, m in enumerate(merged, 1):
        m["rank"] = i
    return merged
