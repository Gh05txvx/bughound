"""Data model: Finding from BugHound schema JSON (BH-SPEC-FINDING).

Only the fields used by analytics/decision-support are taken; the rest are safely
ignored. A missing value -> a neutral default (never a KeyError)."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

_OWASP_RE = re.compile(r"A0?([1-9]|10)\b", re.IGNORECASE)


def _owasp_cat(owasp: Any) -> str:
    """Extract the OWASP 2021 category code (A01..A10) from any shape.

    The `owasp` object in the schema can be a dict {category/code/id/...} or a string.
    Best-effort: look for the A0x pattern in its text form. '' when absent.
    """
    if not owasp:
        return ""
    if isinstance(owasp, dict):
        for k in ("category", "code", "id", "name"):
            v = owasp.get(k)
            if isinstance(v, str) and (m := _OWASP_RE.search(v)):
                return f"A{int(m.group(1)):02d}"
        text = " ".join(str(v) for v in owasp.values())
    else:
        text = str(owasp)
    m = _OWASP_RE.search(text)
    return f"A{int(m.group(1)):02d}" if m else ""


@dataclass
class Location:
    url: str = ""
    method: str = ""
    parameter: str = ""
    param_location: str = ""


@dataclass
class Evidence:
    request: str = ""
    response_excerpt: str = ""
    payload: str = ""
    matched: str = ""
    screenshot_ref: str = ""


@dataclass
class Finding:
    id: str = ""
    dedup_key: str = ""
    program: str = ""
    run_id: str = ""
    target: str = ""
    type: str = ""
    title: str = ""
    severity: str = "info"      # info|low|medium|high|critical
    confidence: str = "low"     # low|medium|high
    cwe: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    owasp_category: str = ""     # A01..A10 (extracted)
    source_engine: str = ""
    source_template: str = ""
    location: Location = field(default_factory=Location)
    evidence: Optional[Evidence] = None
    status: str = "new"          # new|confirmed|duplicate|false_positive|ignored
    duplicate_of: str = ""
    in_report: bool = False
    created_at: str = ""
    updated_at: str = ""

    @classmethod
    def from_json(cls, d: Dict[str, Any]) -> "Finding":
        loc = d.get("location") or {}
        ev = d.get("evidence")
        return cls(
            id=d.get("id", ""), dedup_key=d.get("dedup_key", ""), program=d.get("program", ""),
            run_id=d.get("run_id", ""), target=d.get("target", ""), type=d.get("type", ""),
            title=d.get("title", ""), severity=d.get("severity", "info"),
            confidence=d.get("confidence", "low"),
            cwe=list(d.get("cwe") or []), tags=list(d.get("tags") or []),
            owasp_category=_owasp_cat(d.get("owasp")),
            source_engine=d.get("source_engine", ""), source_template=d.get("source_template", ""),
            location=Location(**{k: loc.get(k, "") for k in ("url", "method", "parameter", "param_location")}),
            evidence=Evidence(**{k: (ev.get(k, "") or "") for k in
                                 ("request", "response_excerpt", "payload", "matched", "screenshot_ref")})
            if ev else None,
            status=d.get("status", "new"), duplicate_of=d.get("duplicate_of", ""),
            in_report=bool(d.get("in_report", False)),
            created_at=d.get("created_at", "") or "", updated_at=d.get("updated_at", "") or "",
        )

    def host(self) -> str:
        """Host from location.url (without scheme/path) for clustering."""
        u = self.location.url
        u = re.sub(r"^[a-zA-Z][\w+.\-]*://", "", u)
        return u.split("/", 1)[0].split("?", 1)[0]

    def path(self) -> str:
        """Path+file from location.url (without scheme/host/query), lowercase.
        Used by the signal to tell a juicy exposed-path (/.git, /admin) from an ordinary asset."""
        u = re.sub(r"^[a-zA-Z][\w+.\-]*://", "", self.location.url or "")
        slash = u.find("/")
        if slash < 0:
            return ""
        return u[slash:].split("?", 1)[0].split("#", 1)[0].lower()
