"""Uji lapisan MCP server (server.py) — tanpa jaringan.

Regresi khusus: tool `whatif` sempat menaungi modul `whatif` (name collision),
sehingga `whatif.build_whatif` memanggil fungsi tool, bukan modul → AttributeError
saat runtime walau 21 test lain hijau. Test ini memanggil `server.whatif`/`server.rank`
LEWAT jalur dispatch asli (monkeypatch hanya `_pipeline`), jadi shadowing apa pun
di kemudian hari langsung ketahuan.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import server  # noqa: E402
from bughound_analyst.model import Evidence, Finding, Location  # noqa: E402

pytestmark = pytest.mark.skipif(
    server._MCPServer is None, reason="mcp belum terpasang — tool rank/whatif tak terdefinisi"
)


def _ranked_item():
    f = Finding(
        id="fid-1", dedup_key="fid-1", program="demo", type="sql-injection",
        title="SQLi di /search", severity="high", confidence="high",
        source_engine="nuclei-dast", owasp_category="A03", status="new",
        location=Location(url="https://example.test/search", method="GET", parameter="q"),
        evidence=Evidence(response_excerpt="ok"),
    )
    return {"rank": 1, "score": 0.9, "finding": f, "breakdown": {"severity": 0.9}}


@pytest.fixture
def _stub_pipeline(monkeypatch):
    monkeypatch.setattr(server, "_pipeline", lambda program: [_ranked_item()])


def test_rank_returns_payload(_stub_pipeline):
    out = server.rank("demo", top=5)
    assert isinstance(out, list) and len(out) == 1
    assert out[0]["finding_id"] == "fid-1"
    assert out[0]["owasp"] == "A03"
    assert out[0]["breakdown"] == {"severity": 0.9}


def test_whatif_dispatches_to_module_not_shadowed_tool(_stub_pipeline):
    # Jalur ini yang dulu putus: _whatif_payload → whatif_mod.build_whatif.
    out = server.whatif("demo", "fid-1")
    assert isinstance(out, dict)
    assert out["finding_id"] == "fid-1"
    # field scaffold yang HANYA ada bila build_whatif modul benar-benar jalan:
    assert out["why"] == "" and out["hypotheses"] == []
    assert out["decision"] == "needs_more_info"
    assert "non-destruktif" in out["safety"]


def test_whatif_unknown_id_returns_error(_stub_pipeline):
    out = server.whatif("demo", "tidak-ada")
    assert "error" in out
