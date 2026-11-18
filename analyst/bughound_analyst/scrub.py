"""Redact evidence BEFORE it reaches the LLM (BH-DESIGN §6).

Strip credentials & PII from the request/response so they do not leak to a third party.
Return a MINIMAL shape (metadata + a scrubbed excerpt), not a full dump.
"""
from __future__ import annotations

import re
from typing import Dict, Optional

from .model import Finding

_REDACTED = "[REDACTED]"

# Sensitive headers (the whole line is replaced).
_HEADER_RE = re.compile(
    r"(?im)^(authorization|cookie|set-cookie|x-api-key|x-auth-token|proxy-authorization)\s*:.*$"
)
# Token bearer / api-key inline.
_BEARER_RE = re.compile(r"(?i)bearer\s+[a-z0-9._\-]+")
# Email (PII).
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
# Sensitive query params (token=..., password=..., access_token=...).
_PARAM_RE = re.compile(r"(?i)\b(token|password|passwd|secret|access_token|api_key|apikey)=[^&\s\"']+")


def scrub_text(s: str, limit: int = 2048) -> str:
    if not s:
        return ""
    s = _HEADER_RE.sub(lambda m: m.group(0).split(":", 1)[0] + ": " + _REDACTED, s)
    s = _BEARER_RE.sub("Bearer " + _REDACTED, s)
    s = _PARAM_RE.sub(lambda m: m.group(1) + "=" + _REDACTED, s)
    s = _EMAIL_RE.sub(_REDACTED, s)
    if len(s) > limit:
        s = s[:limit] + "\n…[trimmed]"
    return s


def minimal_evidence(f: Finding) -> Dict[str, Optional[str]]:
    """A minimal, scrubbed payload for the LLM. The full request is NOT sent,
    only the scrubbed request line (trimmed) + location metadata."""
    ev = f.evidence
    return {
        "url": f.location.url,
        "method": f.location.method,
        "parameter": f.location.parameter,
        "param_location": f.location.param_location,
        "payload": scrub_text(ev.payload, 256) if ev else "",
        "matched": scrub_text(ev.matched, 256) if ev else "",
        "request_excerpt": scrub_text(ev.request, 1024) if ev else "",
        "response_excerpt": scrub_text(ev.response_excerpt, 512) if ev else "",
    }
