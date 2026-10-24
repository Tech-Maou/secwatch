"""CVSS severity bands (offline): fill in severity from the score when the scanner gave none."""

from __future__ import annotations

from ..models import severity_from_cvss


def enrich(cfg, findings) -> str:
    n = 0
    for f in findings:
        if f.kind != "vuln":
            continue
        if f.severity in ("unknown", "", None) and f.cvss is not None:
            f.severity = severity_from_cvss(f.cvss)
            n += 1
        if f.cvss is not None:
            f.extra["cvss_band"] = severity_from_cvss(f.cvss)
    return f"{n} severities derived"
