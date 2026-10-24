"""CISA Known Exploited Vulnerabilities catalog (download only)."""

from __future__ import annotations

import json
from pathlib import Path

from . import EnrichError, fetch_cached


def load_catalog(path: Path) -> dict[str, dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise EnrichError(f"KEV catalog unreadable: {e}") from e
    out = {}
    for v in data.get("vulnerabilities") or []:
        cve = v.get("cveID")
        if cve:
            out[cve] = v
    return out


def apply(catalog: dict[str, dict], findings) -> int:
    n = 0
    for f in findings:
        v = catalog.get(f.id)
        if v is None:
            f.extra.pop("kev", None)
            continue
        f.extra.update({
            "kev": True, "kev_date_added": v.get("dateAdded", ""), "kev_due_date": v.get("dueDate", ""),
            "kev_ransomware": v.get("knownRansomwareCampaignUse", ""),
            "kev_name": v.get("vulnerabilityName", ""),
        })
        n += 1
    return n


def enrich(cfg, findings) -> str:
    path, status = fetch_cached(cfg.get("enrichers.kev.url"), cfg.cache_dir / "kev.json",
                                float(cfg.get("enrichers.kev.max_age_hours", 24)))
    n = apply(load_catalog(path), findings)
    return f"{status}, {n} KEV matches"
