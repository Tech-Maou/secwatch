"""Shared Trivy helpers (used by the os and containers collectors)."""

from __future__ import annotations

import json
import logging
from functools import lru_cache

from ..models import Finding, advisory_url, norm_severity, severity_from_cvss
from ..runner import ToolError, run

log = logging.getLogger(__name__)

CVSS_PREFERENCE = ("nvd", "ghsa", "redhat")


@lru_cache(maxsize=8)
def supported_flags(subcommand: str) -> frozenset[str]:
    """Flags offered by ``trivy <subcommand> --help`` (checked at runtime, versions differ)."""
    try:
        text = run(["trivy", subcommand, "--help"], timeout=60).stdout
    except ToolError as e:
        log.warning("trivy %s --help failed: %s", subcommand, e)
        return frozenset()
    return frozenset(tok.rstrip(",") for tok in text.split() if tok.startswith("--"))


def base_args(subcommand: str, cfg, cache_dir: str, timeout: int, skip_db_update: bool = False) -> list[str]:
    flags = supported_flags(subcommand)
    args = ["trivy", subcommand, "--format", "json", "--quiet", "--skip-version-check",
            "--cache-dir", cache_dir, "--scanners", cfg.get("trivy.scanners", "vuln") or "vuln",
            "--timeout", f"{max(60, int(timeout))}s"]
    if "--disable-telemetry" in flags:
        args.append("--disable-telemetry")
    for repo in cfg.get("trivy.db_repository") or []:
        args += ["--db-repository", str(repo)]
    for repo in cfg.get("trivy.java_db_repository") or []:
        args += ["--java-db-repository", str(repo)]
    if skip_db_update or cfg.get("trivy.skip_db_update"):
        args.append("--skip-db-update")
    return args


def _best_cvss(v: dict) -> float | None:
    cv = v.get("CVSS") or {}
    for src in CVSS_PREFERENCE:
        s = (cv.get(src) or {}).get("V3Score")
        if isinstance(s, (int, float)):
            return float(s)
    scores = [x.get("V3Score") for x in cv.values() if isinstance(x, dict) and isinstance(x.get("V3Score"), (int, float))]
    return float(max(scores)) if scores else None


def parse_trivy(data: dict, host: str, source: str, component: str = "") -> list[Finding]:
    if not isinstance(data, dict):
        raise ValueError("trivy JSON: expected an object")
    out: list[Finding] = []
    artifact = data.get("ArtifactName", "")
    os_info = (data.get("Metadata") or {}).get("OS") or {}
    for res in data.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            vid = v.get("VulnerabilityID") or ""
            if not vid:
                continue
            cvss = _best_cvss(v)
            sev = norm_severity(v.get("Severity"))
            if sev == "unknown" and cvss is not None:
                sev = severity_from_cvss(cvss)
            descr = (v.get("Description") or "").strip()
            out.append(Finding(
                host=host, source=source, kind="vuln", id=vid, package=v.get("PkgName") or "",
                installed=v.get("InstalledVersion") or "", fixed=v.get("FixedVersion") or "",
                severity=sev, cvss=cvss, title=(v.get("Title") or descr[:160]).strip(),
                url=v.get("PrimaryURL") or advisory_url(vid), component=component,
                extra={
                    "target": res.get("Target", ""), "class": res.get("Class", ""), "type": res.get("Type", ""),
                    "status": v.get("Status", ""), "description": descr[:2000],
                    "published": v.get("PublishedDate", ""), "references": (v.get("References") or [])[:6],
                    "pkg_path": v.get("PkgPath", ""), "artifact": artifact,
                    "os": f"{os_info.get('Family', '')} {os_info.get('Name', '')}".strip(),
                    "eosl": bool(os_info.get("EOSL")),
                },
            ))
    return out


def run_json(cmd: list[str], timeout: int) -> dict:
    r = run(cmd, timeout=timeout + 60)
    try:
        return json.loads(r.stdout or "{}")
    except json.JSONDecodeError as e:
        raise ToolError(f"trivy returned invalid JSON: {e}") from e


def trivy_info(cache_dir: str) -> dict:
    info = {"name": "trivy", "version": "", "db_age": None}
    try:
        r = run(["trivy", "version", "--format", "json", "--cache-dir", cache_dir], timeout=60)
        d = json.loads(r.stdout or "{}")
        info["version"] = d.get("Version", "")
        info["db_age"] = (d.get("VulnerabilityDB") or {}).get("UpdatedAt")
    except (ToolError, json.JSONDecodeError):
        pass
    return info
