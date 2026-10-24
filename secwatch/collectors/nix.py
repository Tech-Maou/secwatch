"""NixOS collector: vulnix against the current (and booted) system closure."""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from ..models import Finding, advisory_url, severity_from_cvss
from ..runner import ToolError, run, which
from . import Collector, register

log = logging.getLogger(__name__)

_STORE_RE = re.compile(r"^/nix/store/[0-9a-z]{32}-(?P<name>.+?)(\.drv)?$")


def split_name(name: str) -> tuple[str, str]:
    """'openssl-3.0.7' -> ('openssl', '3.0.7'); version starts at the first '-<digit>'."""
    m = re.search(r"-(\d[^-]*.*)$", name)
    if not m:
        return name, ""
    return name[: m.start()], m.group(1)


def name_from_store_path(path: str) -> tuple[str, str]:
    m = _STORE_RE.match(path or "")
    if not m:
        return "", ""
    return split_name(m.group("name"))


def parse_vulnix(data: list, host: str, component: str = "") -> list[Finding]:
    out: list[Finding] = []
    if not isinstance(data, list):
        raise ValueError("vulnix JSON: expected a list")
    for pkg in data:
        if not isinstance(pkg, dict):
            continue
        pname, version = pkg.get("pname") or "", pkg.get("version") or ""
        if not pname:
            pname, version = split_name(pkg.get("name") or "")
        if not pname:
            pname, version = name_from_store_path(pkg.get("derivation") or "")
        whitelisted = set(pkg.get("whitelisted") or [])
        scores = pkg.get("cvssv3_basescore") or {}
        descr = pkg.get("description") or {}
        for cve in pkg.get("affected_by") or []:
            if cve in whitelisted:
                continue
            score = scores.get(cve)
            try:
                score = float(score) if score is not None else None
            except (TypeError, ValueError):
                score = None
            text = (descr.get(cve) or "").strip()
            out.append(Finding(
                host=host, source="nix", kind="vuln", id=cve, package=pname, installed=version,
                severity=severity_from_cvss(score), cvss=score,
                title=(text[:160] + "…") if len(text) > 160 else text,
                url=advisory_url(cve), component=component,
                extra={"derivation": pkg.get("derivation", ""), "description": text[:2000],
                       "nix_name": pkg.get("name", "")},
            ))
    return out


@register
class NixCollector(Collector):
    name = "nix"
    default_timeout = 1800

    def auto_enabled(self) -> bool:
        return bool(self.ctx.env.get("is_nixos"))

    def _cmd(self, targets: list[str]) -> list[str]:
        cache = self.ctx.cache / "vulnix"
        cache.mkdir(parents=True, exist_ok=True)
        cmd = ["vulnix", "--json", "--cache-dir", str(cache)]
        for w in self.settings.get("whitelist") or []:
            cmd += ["--whitelist", str(w)]
        if self.settings.get("mirror"):
            cmd += ["--mirror", str(self.settings["mirror"])]
        return cmd + targets

    def _run(self, targets: list[str]) -> list:
        # vulnix: 0 = nothing found, 1 = only whitelisted, 2 = vulnerabilities found
        r = run(self._cmd(targets), timeout=self.timeout, ok_codes=(0, 1, 2),
                env={"NIX_REMOTE": os.environ.get("NIX_REMOTE", "daemon")})
        text = r.stdout.strip()
        if not text:
            return []
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            raise ToolError(f"vulnix returned invalid JSON: {e}") from e

    def collect(self) -> list[Finding]:
        if not which("vulnix"):
            raise ToolError("vulnix not found on PATH")
        host = self.ctx.host
        findings = parse_vulnix(self._run(["--system"]), host)
        if self.settings.get("booted_system", True):
            cur, booted = Path("/run/current-system"), Path("/run/booted-system")
            try:
                differs = booted.exists() and booted.resolve() != cur.resolve()
            except OSError:
                differs = False
            if differs:
                seen = {(f.id, f.package) for f in findings}
                for f in parse_vulnix(self._run([str(booted.resolve())]), host, component="booted-system"):
                    if (f.id, f.package) not in seen:
                        f.extra["booted_only"] = True
                        findings.append(f)
                self.messages.append("booted system differs from current system (reboot pending)")
        return findings

    def info(self) -> dict:
        version = ""
        try:
            version = run(["vulnix", "--version"], timeout=60).stdout.strip().split()[-1]
        except (ToolError, IndexError):
            pass
        return {"name": "vulnix", "version": version, "db_age": newest_mtime(self.ctx.cfg.cache_dir / "vulnix")}


def newest_mtime(path: Path) -> str | None:
    try:
        newest = 0.0
        for root, _dirs, files in os.walk(path):
            for fn in files:
                newest = max(newest, os.stat(os.path.join(root, fn)).st_mtime)
        if not newest:
            return None
        return datetime.fromtimestamp(newest, timezone.utc).replace(microsecond=0).isoformat()
    except OSError:
        return None
