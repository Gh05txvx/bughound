"""Decision-support config: weights + mappings. Loaded from weights.yaml (fallback
to the defaults here). Validation: Σ weights == 1.0 and each criterion has a benefit/cost type."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Dict

try:
    import yaml  # pyyaml
except ImportError:  # the scaffold is still importable without pyyaml (use defaults)
    yaml = None

# Map enum -> number (BugHound finding schema).
CONF_NUM: Dict[str, int] = {"low": 1, "medium": 2, "high": 3}
SEV_NUM: Dict[str, int] = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}

_DEFAULTS = {
    "weights": {
        "exploitability": 0.26, "signal": 0.22, "bounty": 0.16, "severity": 0.12,
        "fp_likelihood": 0.12, "effort": 0.06, "owasp": 0.04, "freshness": 0.02,
    },
    "types": {
        "exploitability": "benefit", "signal": "benefit", "bounty": "benefit",
        "severity": "benefit", "fp_likelihood": "cost", "effort": "cost",
        "owasp": "benefit", "freshness": "benefit",
    },
    "engine_factor": {
        "nuclei-dast": 1.0, "dalfox": 1.0, "nuclei": 0.8, "zap": 0.8,
        "ffuf": 0.7, "retire": 0.5, "zap-passive": 0.5, "sast": 0.5, "_default": 0.6,
    },
    "owasp_priority": {
        "A01": 5, "A02": 4, "A03": 5, "A04": 3, "A05": 3, "A06": 3,
        "A07": 4, "A08": 3, "A09": 2, "A10": 4, "_default": 2,
    },
    "effort_by_type": {
        "reflected": 1, "xss": 1, "sqli": 2, "injection": 2, "idor": 2,
        "access": 2, "blind": 3, "second-order": 3, "ssrf": 3, "_default": 2,
    },
    # Payout signal (C2 signal) per vulnerability class, substring match (lowercase).
    # high->1.0 (exploitable/paid), noise->0.1 (hygiene/header, almost won't-pay),
    # otherwise 0.5. This is the anti-"header noise" lever.
    "signal_patterns": {
        "high": [
            "sqli", "sql-injection", "sql injection", "nosql",
            "xss", "cross-site-scripting", "cross site scripting",
            "rce", "remote-code", "command-injection", "command injection", "os-command",
            "ssrf", "server-side-request", "xxe", "xml-external",
            "idor", "bola", "broken-access", "broken access",
            "authorization-bypass", "auth-bypass", "authentication-bypass",
            "auth bypass", "login-bypass",
            "path-traversal", "directory-traversal", "lfi", "local-file",
            "rfi", "remote-file", "deserial", "ssti", "template-injection",
            "template injection", "prototype-pollution",
            "exposed-panel", "exposed-admin", "admin-panel", "exposed-config",
            "config-exposure", "backup-file", ".git", "git-config", ".env", "env-file",
            "secret", "api-key", "apikey", "access-key", "private-key",
            "credential", "token-leak", "hardcoded",
            "takeover", "subdomain-takeover", "unrestricted-upload", "file-upload",
            # juicy paths (also matched against the URL path via the signal extra):
            "backup", ".sql", ".bak", ".svn", "wp-admin", "phpmyadmin", "actuator",
        ],
        "noise": [
            "content-security-policy", "csp", "sub-resource-integrity",
            "subresource-integrity", "clickjacking", "anti-clickjacking",
            "x-frame", "frame-options", "strict-transport", "hsts", "samesite",
            "cookie-with", "cookie-without", "httponly", "secure-flag",
            "referrer-policy", "permissions-policy", "feature-policy",
            "x-content-type", "content-type-options", "nosniff", "x-xss-protection",
            "x-powered-by", "server-version", "banner", "version-disclosure",
            "timestamp-disclosure", "cache-control", "mixed-content", "autocomplete",
            "cross-domain-javascript", "cross-domain-script",
            "tls-version", "deprecated-tls", "weak-cipher", "ssl-certificate",
            "self-signed", "private-ip-disclosure", "internal-ip", "viewstate",
        ],
        # "boring" paths: standard files (not vulnerabilities), which drop a NEUTRAL
        # exposed-path to noise so a real endpoint rises above static files.
        "boring": [
            "robots.txt", "sitemap", "favicon", ".well-known", "security.txt",
            "humans.txt", "healthz", "health", "manifest.json", "service-worker",
            "crossdomain.xml", "ads.txt",
        ],
    },
    # Heuristic priors (tunable).
    "heuristics": {
        "ffuf_flood_threshold": 8,   # >=N ffuf exposed-paths per host -> probably soft-404/wildcard
        "ffuf_flood_fp": 0.6,        # the minimum fp_likelihood forced during a flood
    },
}


@dataclass
class Config:
    weights: Dict[str, float] = field(default_factory=lambda: dict(_DEFAULTS["weights"]))
    types: Dict[str, str] = field(default_factory=lambda: dict(_DEFAULTS["types"]))
    engine_factor: Dict[str, float] = field(default_factory=lambda: dict(_DEFAULTS["engine_factor"]))
    owasp_priority: Dict[str, int] = field(default_factory=lambda: dict(_DEFAULTS["owasp_priority"]))
    effort_by_type: Dict[str, int] = field(default_factory=lambda: dict(_DEFAULTS["effort_by_type"]))
    signal_patterns: Dict[str, list] = field(
        default_factory=lambda: {k: list(v) for k, v in _DEFAULTS["signal_patterns"].items()})
    heuristics: Dict[str, float] = field(default_factory=lambda: dict(_DEFAULTS["heuristics"]))

    def validate(self) -> None:
        s = sum(self.weights.values())
        if abs(s - 1.0) > 1e-6:
            raise ValueError(f"Σ weights = {s:.4f}, must be 1.0, fix weights.yaml")
        for c in self.weights:
            t = self.types.get(c)
            if t not in ("benefit", "cost"):
                raise ValueError(f"criterion {c!r} needs a benefit/cost type, got {t!r}")

    def engine_f(self, engine: str) -> float:
        return self.engine_factor.get(engine, self.engine_factor["_default"])

    def owasp_p(self, category: str) -> int:
        return self.owasp_priority.get(category, self.owasp_priority["_default"])

    def effort(self, ftype: str) -> int:
        t = (ftype or "").lower()
        for key, val in self.effort_by_type.items():
            if key != "_default" and key in t:
                return val
        return self.effort_by_type["_default"]

    def _signal_re(self, kind: str):
        """Cached regex: patterns match at token BOUNDARIES (lookaround) so they do not
        catch as a substring (e.g. 'rce' inside 'resource')."""
        attr = f"_re_{kind}"
        rx = getattr(self, attr, None)
        if rx is None:
            pats = self.signal_patterns.get(kind) or ()
            if pats:
                joined = "|".join(re.escape(p) for p in pats)
                rx = re.compile(rf"(?<![a-z0-9])(?:{joined})(?![a-z0-9])")
            else:
                rx = re.compile(r"(?!)")  # never matches
            object.__setattr__(self, attr, rx)
        return rx

    def is_boring_path(self, path: str) -> bool:
        """True when the path is a boring standard file (robots.txt, /.well-known, …)."""
        return bool(path) and self._signal_re("boring").search(path.lower()) is not None

    def signal(self, text: str, extra: str = "") -> float:
        """Payout signal per class: 0.1 hygiene-noise, 1.0 exploitable, 0.5 neutral.
        Noise is checked FIRST from `text` (the finding type) only: 'x-xss-protection' (a header)
        must not go high via 'xss'. `extra` (e.g. the URL path) may only PROMOTE
        to high (e.g. exposed-path -> /.git), never drop to noise."""
        t = (text or "").lower()
        if self._signal_re("noise").search(t):
            return 0.1
        if self._signal_re("high").search(t + " " + (extra or "").lower()):
            return 1.0
        return 0.5


def load(path: str | None = None) -> Config:
    """Load config from weights.yaml when present; otherwise use the defaults."""
    path = path or os.path.join(os.path.dirname(os.path.dirname(__file__)), "weights.yaml")
    cfg = Config()
    if yaml and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        for k in ("weights", "types", "engine_factor", "owasp_priority",
                  "effort_by_type", "signal_patterns", "heuristics"):
            if k in data and isinstance(data[k], dict):
                getattr(cfg, k).update(data[k])
    cfg.validate()
    return cfg
