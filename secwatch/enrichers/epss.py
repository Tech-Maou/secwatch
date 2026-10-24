"""FIRST EPSS scores.

mode=csv (default): download the full daily CSV - no CVE list ever leaves the host.
mode=api: query api.first.org with the CVE IDs that were found (opt-in).
"""

from __future__ import annotations

import gzip
import io
import json
from pathlib import Path

import httpx

from . import USER_AGENT, EnrichError, cache_age_hours, fetch_cached


def parse_csv(stream: io.TextIOBase, wanted: set[str] | None = None) -> dict[str, tuple[float, float]]:
    out: dict[str, tuple[float, float]] = {}
    header_seen = False
    for line in stream:
        if line.startswith("#"):
            continue
        if not header_seen:
            header_seen = True
            if line.lower().startswith("cve,"):
                continue
        parts = line.strip().split(",")
        if len(parts) < 3:
            continue
        cve = parts[0]
        if wanted is not None and cve not in wanted:
            continue
        try:
            out[cve] = (float(parts[1]), float(parts[2]))
        except ValueError:
            continue
    return out


def load_csv_gz(path: Path, wanted: set[str]) -> dict[str, tuple[float, float]]:
    try:
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
            return parse_csv(f, wanted)
    except (OSError, EOFError) as e:
        raise EnrichError(f"EPSS CSV unreadable: {e}") from e


def query_api(url: str, cves: list[str], cache: Path, max_age_hours: float) -> dict[str, tuple[float, float]]:
    cached: dict = {}
    age = cache_age_hours(cache)
    if age is not None and age < max_age_hours:
        try:
            cached = json.loads(cache.read_text())
        except (OSError, ValueError):
            cached = {}
    todo = [c for c in cves if c not in cached]
    with httpx.Client(timeout=60, headers={"User-Agent": USER_AGENT}) as client:
        for i in range(0, len(todo), 100):
            chunk = todo[i:i + 100]
            try:
                r = client.get(url, params={"cve": ",".join(chunk)})
                r.raise_for_status()
            except httpx.HTTPError as e:
                raise EnrichError(f"EPSS API failed: {e}") from e
            for row in r.json().get("data") or []:
                try:
                    cached[row["cve"]] = [float(row["epss"]), float(row["percentile"])]
                except (KeyError, ValueError, TypeError):
                    pass
            for c in chunk:
                cached.setdefault(c, None)
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(cached))
    return {k: tuple(v) for k, v in cached.items() if v}


def apply(scores: dict[str, tuple[float, float]], findings) -> int:
    n = 0
    for f in findings:
        s = scores.get(f.id)
        if s:
            f.extra["epss"], f.extra["epss_percentile"] = round(s[0], 5), round(s[1], 5)
            n += 1
    return n


def enrich(cfg, findings) -> str:
    cves = sorted({f.id for f in findings if f.id.startswith("CVE-")})
    if not cves:
        return "no CVEs"
    max_age = float(cfg.get("enrichers.epss.max_age_hours", 24))
    if cfg.get("enrichers.epss.mode", "csv") == "api":
        scores = query_api(cfg.get("enrichers.epss.api_url"), cves, cfg.cache_dir / "epss_api.json", max_age)
        status = "api"
    else:
        path, status = fetch_cached(cfg.get("enrichers.epss.csv_url"), cfg.cache_dir / "epss_scores.csv.gz",
                                    max_age, timeout=300)
        scores = load_csv_gz(path, set(cves))
    return f"{status}, {apply(scores, findings)} scored"
