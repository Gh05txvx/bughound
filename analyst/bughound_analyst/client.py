"""Klien API BugHound — BACA-SAJA. Hanya GET /api/v1/findings (Basic auth).

Tak pernah POST/mutasi. Kredensial dari env (.env): BUGHOUND_URL/USER/PASS.
"""
from __future__ import annotations

import os
from typing import List, Optional

from .model import Finding

try:
    import httpx
except ImportError:  # scaffold tetap importable tanpa httpx
    httpx = None


class BughoundClient:
    def __init__(self, base_url: Optional[str] = None, user: Optional[str] = None,
                 password: Optional[str] = None, timeout: float = 15.0):
        self.base_url = (base_url or os.getenv("BUGHOUND_URL", "http://127.0.0.1:8787")).rstrip("/")
        self.user = user or os.getenv("BUGHOUND_USER", "admin")
        self.password = password or os.getenv("BUGHOUND_PASS", "")
        self.timeout = timeout

    def _client(self):
        if httpx is None:
            raise RuntimeError("butuh httpx: pip install httpx")
        return httpx.Client(base_url=self.base_url, auth=(self.user, self.password),
                            timeout=self.timeout, headers={"Accept": "application/json"})

    def list_findings(self, program: str, *, status: Optional[str] = None,
                      severity: Optional[str] = None, run_id: Optional[str] = None,
                      include_duplicates: bool = False) -> List[Finding]:
        """GET /api/v1/findings?program=… (read-only)."""
        params = {"program": program}
        if status:
            params["status"] = status
        if severity:
            params["severity"] = severity
        if run_id:
            params["run_id"] = run_id
        if include_duplicates:
            params["include_duplicates"] = "1"
        with self._client() as c:
            resp = c.get("/api/v1/findings", params=params)
            resp.raise_for_status()
            data = resp.json()
        return [Finding.from_json(x) for x in data.get("findings", [])]

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        with self._client() as c:
            resp = c.get(f"/api/v1/findings/{finding_id}")
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return Finding.from_json(resp.json())
