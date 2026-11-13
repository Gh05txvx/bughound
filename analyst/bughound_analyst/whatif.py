"""What-if — scaffold rencana validasi manual di Burp.

Bagian DETERMINISTIK dibangun di sini (identitas, skor, target, evidence
terscrub, safety). `why` + `hypotheses` DIKOSONGKAN: diisi LLM (Claude) yang
menalar atas evidence terscrub — lihat BH-DESIGN §5. App tak pernah mengeksekusi.
"""
from __future__ import annotations

from typing import Dict, List

from .model import Finding
from .scrub import minimal_evidence

# Benih hipotesis per kelas bug — HINT untuk LLM, bukan perintah eksekusi.
# LLM wajib menyesuaikan ke konteks (param, DBMS, encoding) & boleh menolak.
_SEED_HINTS: Dict[str, List[str]] = {
    "sqli": ["boolean: `' OR 1=1--`", "time-based: `1;WAITFOR DELAY '0:0:5'--`"],
    "injection": ["boolean/true-vs-false", "time-based delay"],
    "xss": ["context-break reflektif: `\"><svg onload=…>`", "atribut vs HTML vs JS context"],
    "idor": ["naik/turunkan id objek", "tukar ke objek milik akun lain"],
    "ssrf": ["ganti host ke callback terkendali (OAST) — HATI-HATI RoE", "cek 169.254.169.254 bila diizinkan"],
    "access": ["akses endpoint tanpa sesi / sesi peran lebih rendah"],
}


def _seed_for(f: Finding) -> List[str]:
    t = (f.type or f.title).lower()
    for key, hints in _SEED_HINTS.items():
        if key in t:
            return hints
    return []


def build_whatif(ranked_item: Dict) -> Dict:
    """ranked_item = elemen dari saw.rank_findings. Kembalikan scaffold what-if.
    Field `why`/`hypotheses` sengaja kosong → diisi LLM."""
    f: Finding = ranked_item["finding"]
    return {
        "finding_id": f.id,
        "rank": ranked_item.get("rank"),
        "score": ranked_item.get("score"),
        "score_breakdown": ranked_item.get("breakdown"),
        "title": f.title,
        "type": f.type,
        "severity": f.severity,
        "confidence": f.confidence,
        "owasp": f.owasp_category,
        "source_engine": f.source_engine,
        "base_request_ref": "evidence.request (sudah dilempar ke Burp Repeater)",
        "target": {
            "url": f.location.url, "method": f.location.method,
            "parameter": f.location.parameter, "param_location": f.location.param_location,
        },
        "evidence_scrubbed": minimal_evidence(f),
        "seed_hints": _seed_for(f),          # HINT deterministik untuk LLM
        "why": "",                            # ← diisi LLM
        "hypotheses": [],                     # ← diisi LLM: [{mutation, expected, confirms}]
        "decision": "needs_more_info",        # LLM boleh ubah: verify_now|likely_fp|needs_more_info
        "safety": "non-destruktif saja (SELECT/boolean/time); hormati rate-limit & RoE program; eksekusi MANUAL",
    }


def render_markdown(wi: Dict) -> str:
    """Render ringkas untuk dibaca manusia."""
    t = wi["target"]
    lines = [
        f"**#{wi['rank']} · score {wi['score']} · {wi['title']} ({wi['decision']})**",
        f"- target: `{t['method']} {t['url']}` param `{t['parameter']}`",
        f"- engine: {wi['source_engine']} · severity {wi['severity']} · conf {wi['confidence']} · {wi['owasp'] or '-'}",
    ]
    if wi.get("why"):
        lines.append(f"- kenapa: {wi['why']}")
    if wi.get("hypotheses"):
        lines.append("- coba di Repeater:")
        lines += [f"    - `{h.get('mutation','')}` → {h.get('expected','')} ⇒ {h.get('confirms','')}"
                  for h in wi["hypotheses"]]
    elif wi.get("seed_hints"):
        lines.append("- benih (LLM harus sesuaikan): " + "; ".join(wi["seed_hints"]))
    lines.append(f"- ⚠️ {wi['safety']}")
    return "\n".join(lines)
