"""Enrichers add exploitation/severity context to findings (KEV, EPSS, CVSS bands).

Each enricher: ``enrich(cfg, findings) -> str`` (short status), may raise on hard failure.
Downloads are cached in <state>/cache and refreshed at most every ``max_age_hours``; when a
download fails a stale cache is used.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path

import httpx

from .. import __version__

log = logging.getLogger(__name__)

USER_AGENT = f"secwatch/{__version__} (+https://github.com/Tech-Maou/secwatch)"


class EnrichError(RuntimeError):
    pass


def cache_age_hours(path: Path) -> float | None:
    try:
        return (time.time() - path.stat().st_mtime) / 3600
    except OSError:
        return None


def fetch_cached(url: str, path: Path, max_age_hours: float, timeout: float = 120) -> tuple[Path, str]:
    """Download ``url`` to ``path`` unless the cached copy is fresh. Returns (path, status)."""
    age = cache_age_hours(path)
    if age is not None and age < max_age_hours:
        return path, "cached"
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".part")
    try:
        with httpx.stream("GET", url, timeout=timeout, follow_redirects=True,
                          headers={"User-Agent": USER_AGENT}) as r:
            r.raise_for_status()
            with open(tmp, "wb") as f:
                for chunk in r.iter_bytes():
                    f.write(chunk)
        os.replace(tmp, path)
        return path, "downloaded"
    except (httpx.HTTPError, OSError) as e:
        try:
            tmp.unlink()
        except OSError:
            pass
        if age is not None:
            log.warning("download of %s failed (%s), using cache from %.0f h ago", url, e, age)
            return path, f"stale cache ({age:.0f} h)"
        raise EnrichError(f"download failed: {e.__class__.__name__}: {e}") from e


def run_enrichers(cfg, findings) -> dict[str, dict]:
    """Run all enabled enrichers. Returns {name: {ok, status|error}}; failures are isolated."""
    from . import cvss, epss, kev

    out: dict[str, dict] = {}
    for name, mod in (("kev", kev), ("epss", epss), ("cvss", cvss)):
        if not cfg.get(f"enrichers.{name}.enabled", True):
            out[name] = {"ok": True, "status": "disabled"}
            continue
        try:
            out[name] = {"ok": True, "status": mod.enrich(cfg, findings)}
        except Exception as e:  # isolate every enricher
            log.error("enricher %s failed: %s", name, e)
            out[name] = {"ok": False, "error": str(e)[:300]}
    return out
