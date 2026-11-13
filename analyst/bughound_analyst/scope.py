"""Enrichment scope asset dari CSV platform (HackerOne/Bugcrowd export).

Memberi C3 (bounty) data nyata: `max_severity` + `eligible_for_bounty` per aset.
Hanya aset in-scope (`eligible_for_submission=true`) yang dimuat. Cocokkan host
temuan → entri scope dengan exact lalu wildcard (mis. `app.deriv.com` → `*.deriv.com`).

Read-only, offline (baca file CSV lokal). Tak menyentuh jaringan/target.
"""
from __future__ import annotations

import csv
import re
from typing import Dict, Optional


def _host_of(identifier: str) -> str:
    s = identifier.strip().lower()
    s = re.sub(r"^[a-z][\w+.\-]*://", "", s)   # buang skema
    s = s.split("/", 1)[0].split("?", 1)[0]    # buang path/query
    return s.split(":", 1)[0]                   # buang port


class ScopeTable:
    """Lookup host → {max_severity, eligible_for_bounty}. Exact lalu wildcard.
    Out-of-scope MENANG (sesuai BH-SPEC-SCOPE): host yang cocok exclusion → None,
    walau ada wildcard in-scope yang menutupinya."""

    def __init__(self) -> None:
        self.exact: Dict[str, dict] = {}
        self.wildcard: Dict[str, dict] = {}   # base domain (deriv.com) → meta
        self.excl_exact: set = set()
        self.excl_wildcard: set = set()

    @staticmethod
    def _wildcard_hit(h: str, table) -> Optional[str]:
        parts = h.split(".")
        for i in range(len(parts) - 1):           # deriv.com, com → cocok *.deriv.com
            base = ".".join(parts[i:])
            if base in table:
                return base
        return None

    def excluded(self, host: Optional[str]) -> bool:
        if not host:
            return False
        h = _host_of(host)
        return h in self.excl_exact or self._wildcard_hit(h, self.excl_wildcard) is not None

    def get(self, host: Optional[str], default=None):
        if not host:
            return default
        h = _host_of(host)
        if self.excluded(h):                      # out-of-scope menang
            return default
        if h in self.exact:
            return self.exact[h]
        base = self._wildcard_hit(h, self.wildcard)
        return self.wildcard[base] if base else default

    def __len__(self) -> int:
        return len(self.exact) + len(self.wildcard)


def _meta(row: dict) -> dict:
    return {
        "max_severity": (row.get("max_severity") or "").strip().lower() or None,
        "eligible_for_bounty": (row.get("eligible_for_bounty") or "").strip().lower() == "true",
    }


def load_csv(path: str) -> ScopeTable:
    """Muat scope dari CSV HackerOne (kolom: identifier, eligible_for_submission,
    eligible_for_bounty, max_severity). Baris in-scope (submission=true) → meta
    bounty; baris out-of-scope → exclusion (menang atas wildcard in-scope)."""
    t = ScopeTable()
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            ident = (row.get("identifier") or "").strip()
            if not ident:
                continue
            in_scope = (row.get("eligible_for_submission") or "").strip().lower() == "true"
            if ident.startswith("*."):
                host = _host_of(ident[2:])
                if not host:
                    continue
                if in_scope:
                    t.wildcard[host] = _meta(row)
                else:
                    t.excl_wildcard.add(host)
            else:
                host = _host_of(ident)
                if "*" in host or "." not in host:
                    continue  # bentuk aneh / bukan host → lewati
                if in_scope:
                    t.exact[host] = _meta(row)
                else:
                    t.excl_exact.add(host)
    return t
