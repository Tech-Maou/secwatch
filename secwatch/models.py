"""Finding model, stable keys, severity bands and priority ordering."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any

KINDS = ["vuln", "hardening", "exposure", "secret", "auth", "update", "scan_error"]
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0, "none": 0}
SEVERITY_SCORE = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.0}


def severity_from_cvss(score: float | None) -> str:
    """CVSS v3 bands: Critical >= 9, High >= 7, Medium >= 4, Low > 0, otherwise none."""
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def norm_severity(s: str | None) -> str:
    s = (s or "").strip().lower()
    if s in ("critical", "high", "medium", "low", "none"):
        return s
    if s in ("moderate",):
        return "medium"
    if s in ("negligible", "info", "informational"):
        return "low"
    return "unknown"


def matrix_severity(s: str) -> str:
    """Severity used for the notification matrix (only four columns)."""
    return s if s in ("critical", "high", "medium", "low") else "low"


def stable_key(host: str, source: str, kind: str, id_: str, package: str, component: str) -> str:
    raw = "\x1f".join([host, source, kind, id_, package or "", component or ""])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


@dataclass
class Finding:
    host: str
    source: str
    kind: str
    id: str
    package: str = ""
    installed: str = ""
    fixed: str = ""
    severity: str = "unknown"
    cvss: float | None = None
    title: str = ""
    url: str = ""
    component: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return stable_key(self.host, self.source, self.kind, self.id, self.package, self.component)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["key"] = self.key
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        names = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        kw = {k: v for k, v in d.items() if k in names}
        kw.setdefault("extra", {})
        if kw.get("extra") is None:
            kw["extra"] = {}
        return cls(**kw)


def priority_tuple(kev: bool, epss: float | None, cvss: float | None, severity: str,
                   first_seen: str) -> tuple:
    """Sort key: KEV > EPSS > CVSS (or severity band) > age (older first). Use with reverse=False."""
    score = cvss if cvss is not None else SEVERITY_SCORE.get(severity, 0.0)
    return (0 if kev else 1, -(epss or 0.0), -score, first_seen or "")


def advisory_url(vuln_id: str) -> str:
    if vuln_id.startswith("CVE-"):
        return f"https://nvd.nist.gov/vuln/detail/{vuln_id}"
    if vuln_id.startswith("GHSA-"):
        return f"https://github.com/advisories/{vuln_id}"
    return ""
