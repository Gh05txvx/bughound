"""MCP server: wraps the Analyst+decision-support pipeline as tools for Claude.

Tools (all READ-ONLY, never trigger a scan/submit):
  - rank(program, top)      -> SAW ranking + breakdown (decision support, deterministic)
  - whatif(program, id)     -> a validation-plan scaffold + scrubbed evidence
                              (Claude fills in `hypotheses`/`why`; you execute in Burp)

Run:  python server.py   (needs `pip install -r requirements.txt`)
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Dict, List

try:
    from dotenv import load_dotenv
    # .env next to server.py -> read even when the MCP client calls from another cwd
    load_dotenv(Path(__file__).with_name(".env"))
except ImportError:
    pass

from bughound_analyst import analyst, config, saw
from bughound_analyst import whatif as whatif_mod  # alias: the `whatif` tool below shadows the module name
from bughound_analyst.client import BughoundClient

# mcp 2.x renamed FastMCP -> MCPServer (the tool/run API is compatible). Support both:
try:
    from mcp.server import MCPServer as _MCPServer       # mcp >= 2
except ImportError:
    try:
        from mcp.server.fastmcp import FastMCP as _MCPServer  # mcp 1.x
    except ImportError:
        _MCPServer = None


def _load_scope():
    """Optional scope assets (bounty enrichment) from a platform CSV. Env
    `BUGHOUND_SCOPE_CSV`. Unset / read failure -> None (severity fallback)."""
    path = (os.getenv("BUGHOUND_SCOPE_CSV") or "").strip()
    if not path:
        return None
    from bughound_analyst import scope as scope_mod
    try:
        table = scope_mod.load_csv(path)
        print(f"[scope] {len(table)} in-scope assets from {path}", file=sys.stderr)
        return table
    except OSError as e:
        print(f"[scope] failed to read {path}: {e}", file=sys.stderr)
        return None


def _pipeline(program: str):
    """Fetch -> prefilter -> derive -> rank. Used by the tool & CLI; no LLM."""
    cfg = config.load()
    findings = BughoundClient().list_findings(program)
    kept = analyst.prefilter(findings)
    derived = analyst.derive(kept, cfg, _load_scope())
    return saw.rank_findings(kept, derived, cfg)


def _rank_payload(program: str, top: int) -> List[Dict]:
    ranked = _pipeline(program)[:top]
    return [{
        "rank": r["rank"], "score": r["score"], "finding_id": r["finding"].id,
        "title": r["finding"].title, "type": r["finding"].type,
        "severity": r["finding"].severity, "confidence": r["finding"].confidence,
        "owasp": r["finding"].owasp_category, "engine": r["finding"].source_engine,
        "breakdown": r["breakdown"],
    } for r in ranked]


def _whatif_payload(program: str, finding_id: str) -> Dict:
    for r in _pipeline(program):
        if r["finding"].id == finding_id:
            return whatif_mod.build_whatif(r)
    return {"error": f"finding {finding_id!r} is not in the ranked results for program {program!r}"}


if _MCPServer is not None:
    mcp = _MCPServer("bughound-analyst")

    @mcp.tool()
    def rank(program: str, top: int = 10) -> List[Dict]:
        """Verify-first ranking (SAW) for a program. Deterministic + explainable."""
        return _rank_payload(program, top)

    @mcp.tool()
    def whatif(program: str, finding_id: str) -> Dict:
        """A validation-plan scaffold for one finding (scrubbed evidence). Fill in
        `hypotheses`/`why` from your reasoning; execution in Burp is MANUAL."""
        return _whatif_payload(program, finding_id)


if __name__ == "__main__":
    if _MCPServer is None:
        raise SystemExit("MCP not installed, `pip install -r requirements.txt`")
    mcp.run()   # transport stdio (default)
