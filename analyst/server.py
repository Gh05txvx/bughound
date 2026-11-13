"""MCP server — membungkus pipeline Analyst+SPK sebagai tool untuk Claude.

Tool (semua BACA-SAJA, tak pernah memicu scan/submit):
  - rank(program, top)      → peringkat SAW + breakdown (SPK, deterministik)
  - whatif(program, id)     → scaffold rencana validasi + evidence terscrub
                              (Claude mengisi `hypotheses`/`why`; kamu eksekusi di Burp)

Jalankan:  python server.py   (butuh `pip install -r requirements.txt`)
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Dict, List

try:
    from dotenv import load_dotenv
    # .env di samping server.py → terbaca walau MCP client memanggil dari cwd lain
    load_dotenv(Path(__file__).with_name(".env"))
except ImportError:
    pass

from bughound_analyst import analyst, config, saw
from bughound_analyst import whatif as whatif_mod  # alias: tool `whatif` di bawah menaungi nama modul
from bughound_analyst.client import BughoundClient

# mcp 2.x me-rename FastMCP → MCPServer (API tool/run kompatibel). Dukung keduanya:
try:
    from mcp.server import MCPServer as _MCPServer       # mcp >= 2
except ImportError:
    try:
        from mcp.server.fastmcp import FastMCP as _MCPServer  # mcp 1.x
    except ImportError:
        _MCPServer = None


def _load_scope():
    """Scope asset opsional (enrichment bounty) dari CSV platform. Env
    `BUGHOUND_SCOPE_CSV`. Tak diset / gagal baca → None (fallback severity)."""
    path = (os.getenv("BUGHOUND_SCOPE_CSV") or "").strip()
    if not path:
        return None
    from bughound_analyst import scope as scope_mod
    try:
        table = scope_mod.load_csv(path)
        print(f"[scope] {len(table)} aset in-scope dari {path}", file=sys.stderr)
        return table
    except OSError as e:
        print(f"[scope] gagal baca {path}: {e}", file=sys.stderr)
        return None


def _pipeline(program: str):
    """Fetch → prefilter → derive → rank. Dipakai tool & CLI; tanpa LLM."""
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
    return {"error": f"temuan {finding_id!r} tak ada di hasil ter-ranking program {program!r}"}


if _MCPServer is not None:
    mcp = _MCPServer("bughound-analyst")

    @mcp.tool()
    def rank(program: str, top: int = 10) -> List[Dict]:
        """Peringkat verify-first (SAW) untuk sebuah program. Deterministik + explainable."""
        return _rank_payload(program, top)

    @mcp.tool()
    def whatif(program: str, finding_id: str) -> Dict:
        """Scaffold rencana validasi untuk satu temuan (evidence terscrub). Isi
        `hypotheses`/`why` dari penalaranmu; eksekusi di Burp dilakukan MANUAL."""
        return _whatif_payload(program, finding_id)


if __name__ == "__main__":
    if _MCPServer is None:
        raise SystemExit("MCP belum terpasang — `pip install -r requirements.txt`")
    mcp.run()   # transport stdio (default)
