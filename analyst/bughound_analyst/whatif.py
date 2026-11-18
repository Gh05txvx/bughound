"""What-if: a scaffold of the manual validation plan in Burp.

The DETERMINISTIC part is built here (identity, score, target, scrubbed
evidence, safety). `why` + `hypotheses` are LEFT EMPTY: filled by the LLM (Claude)
reasoning over the scrubbed evidence, see BH-DESIGN §5. The app never executes.
"""
from __future__ import annotations

from typing import Dict, List

from .model import Finding
from .scrub import minimal_evidence

# Hypothesis seeds per bug class, a HINT for the LLM, not an execution command.
# The LLM must adapt to context (param, DBMS, encoding) & may decline.
_SEED_HINTS: Dict[str, List[str]] = {
    "sqli": ["boolean: `' OR 1=1--`", "time-based: `1;WAITFOR DELAY '0:0:5'--`"],
    "injection": ["boolean/true-vs-false", "time-based delay"],
    "xss": ["reflective context-break: `\"><svg onload=…>`", "attribute vs HTML vs JS context"],
    "idor": ["increment/decrement the object id", "swap to an object owned by another account"],
    "ssrf": ["point the host at a controlled callback (OAST), MIND the RoE", "check 169.254.169.254 if allowed"],
    "access": ["access the endpoint with no session / a lower-role session"],
}


def _seed_for(f: Finding) -> List[str]:
    t = (f.type or f.title).lower()
    for key, hints in _SEED_HINTS.items():
        if key in t:
            return hints
    return []


def build_whatif(ranked_item: Dict) -> Dict:
    """ranked_item = an element from saw.rank_findings. Return the what-if scaffold.
    The `why`/`hypotheses` fields are intentionally empty -> filled by the LLM."""
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
        "base_request_ref": "evidence.request (already sent to Burp Repeater)",
        "target": {
            "url": f.location.url, "method": f.location.method,
            "parameter": f.location.parameter, "param_location": f.location.param_location,
        },
        "evidence_scrubbed": minimal_evidence(f),
        "seed_hints": _seed_for(f),          # deterministic HINT for the LLM
        "why": "",                            # <- filled by the LLM
        "hypotheses": [],                     # <- filled by the LLM: [{mutation, expected, confirms}]
        "decision": "needs_more_info",        # the LLM may change: verify_now|likely_fp|needs_more_info
        "safety": "non-destructive only (SELECT/boolean/time); respect the program rate-limit & RoE; execute MANUALLY",
    }


def render_markdown(wi: Dict) -> str:
    """Render a short, human-readable summary."""
    t = wi["target"]
    lines = [
        f"**#{wi['rank']} · score {wi['score']} · {wi['title']} ({wi['decision']})**",
        f"- target: `{t['method']} {t['url']}` param `{t['parameter']}`",
        f"- engine: {wi['source_engine']} · severity {wi['severity']} · conf {wi['confidence']} · {wi['owasp'] or '-'}",
    ]
    if wi.get("why"):
        lines.append(f"- why: {wi['why']}")
    if wi.get("hypotheses"):
        lines.append("- try in Repeater:")
        lines += [f"    - `{h.get('mutation','')}` → {h.get('expected','')} ⇒ {h.get('confirms','')}"
                  for h in wi["hypotheses"]]
    elif wi.get("seed_hints"):
        lines.append("- seeds (the LLM must adapt): " + "; ".join(wi["seed_hints"]))
    lines.append(f"- ⚠️ {wi['safety']}")
    return "\n".join(lines)
