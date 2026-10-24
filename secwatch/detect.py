"""Environment auto-detection (used by the wizard and by the 'auto' collector defaults)."""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from urllib.parse import urlparse

from .collectors.containers import detect_runtime, list_containers
from .runner import ToolError, run, which

log = logging.getLogger(__name__)

AUTH_UNITS = {
    "sshd": re.compile(r"^(sshd|ssh)\.service$"),
    "fail2ban": re.compile(r"^fail2ban\.service$"),
    "vaultwarden": re.compile(r"^vaultwarden\.service$"),
    "nextcloud": re.compile(r"^(phpfpm-nextcloud|nextcloud.*)\.service$"),
    "forgejo": re.compile(r"^(forgejo|gitea)\.service$"),
}
TOOLS = ["vulnix", "trivy", "lynis", "gitleaks", "ss", "podman", "docker", "journalctl"]


def read_os_release(root: str = "/") -> dict:
    out = {}
    for p in (Path(root) / "etc/os-release", Path(root) / "usr/lib/os-release"):
        try:
            for line in p.read_text().splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    out[k.strip()] = v.strip().strip('"')
            break
        except OSError:
            continue
    return out


def parse_ss(text: str) -> list[dict]:
    """Parse `ss -tulnH` (optionally with -p) into unique {proto, address, port, process}."""
    seen, out = set(), []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0]
        local = parts[4]
        if ":" not in local:
            continue
        addr, _, port = local.rpartition(":")
        addr = addr.strip("[]")
        if "%" in addr:
            addr = addr.split("%", 1)[0]
        proc = ""
        m = re.search(r'users:\(\("([^"]+)"', line)
        if m:
            proc = m.group(1)
        if not port.isdigit():
            continue
        k = (proto, addr, port)
        if k in seen:
            continue
        seen.add(k)
        out.append({"proto": proto, "address": addr, "port": int(port), "process": proc,
                    "public": addr not in ("127.0.0.1", "::1", "localhost") and not addr.startswith("127.")})
    return sorted(out, key=lambda x: (x["proto"], x["port"], x["address"]))


def read_registry(path: str) -> list[dict]:
    """Homelab registry JSON: {"services": [{name,label,url,exposure,...}]} or a plain list."""
    if not path:
        return []
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        log.warning("registry file %s unreadable: %s", path, e)
        return []
    services = data.get("services", []) if isinstance(data, dict) else data
    out = []
    for s in services if isinstance(services, list) else []:
        if not isinstance(s, dict):
            continue
        url = s.get("url") or ""
        host = urlparse(url).hostname if url else None
        out.append({"name": s.get("name") or s.get("label") or host or "", "url": url, "hostname": host or "",
                    "exposure": s.get("exposure") or "unknown"})
    return out


def detect(cfg=None, privileged: bool | None = None) -> dict:
    privileged = (os.geteuid() == 0) if privileged is None else privileged
    root = "/"
    if cfg is not None:
        root = str(cfg.get("collectors.os.root") or "/")
    osr = read_os_release(root)
    env: dict = {
        "privileged": privileged,
        "os": osr.get("PRETTY_NAME") or osr.get("NAME") or "unknown",
        "os_id": osr.get("ID", ""),
        "is_nixos": osr.get("ID") == "nixos" or Path(root, "etc/NIXOS").exists(),
        "in_container": Path("/.dockerenv").exists() or Path("/run/.containerenv").exists(),
        "tools": {t: bool(which(t)) for t in TOOLS},
    }
    rt = detect_runtime(cfg.get("collectors.containers.runtime", "auto") if cfg else "auto",
                        cfg.get("collectors.containers.socket", "") if cfg else "")
    env["container_runtime"] = rt.get("runtime", "")
    env["container_socket"] = rt.get("socket", "")
    env["containers"] = []
    if rt:
        try:
            env["containers"] = list_containers(rt, timeout=20)
        except Exception as e:  # unprivileged web process often cannot see rootful containers
            env["containers_error"] = str(e)[:200]
    env["journald"] = Path("/run/systemd/journal").exists() or bool(which("journalctl"))
    env["auth_sources"] = []
    if which("systemctl"):
        try:
            text = run(["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain"],
                       timeout=20).stdout
            units = [ln.split()[0] for ln in text.splitlines() if ln.strip()]
            env["auth_sources"] = sorted({src for src, rx in AUTH_UNITS.items() for u in units if rx.match(u)})
        except ToolError as e:
            env["auth_sources_error"] = str(e)[:200]
    env["ports"] = []
    if which("ss"):
        try:
            args = ["ss", "-tulnH"] + (["-p"] if privileged else [])
            env["ports"] = parse_ss(run(args, timeout=20).stdout)
        except ToolError as e:
            env["ports_error"] = str(e)[:200]
    env["registry"] = read_registry(cfg.get("registry_file", "") if cfg else "")
    env["hostnames"] = sorted({s["hostname"] for s in env["registry"] if s["hostname"]})
    env["public_hostnames"] = sorted({s["hostname"] for s in env["registry"]
                                      if s["hostname"] and s["exposure"] == "public"})
    env["git_repos"] = []
    return env


def save(cfg, env: dict) -> None:
    try:
        p = cfg.state / "detect.json"
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(env, indent=1, default=str))
        os.chmod(tmp, 0o640)
        os.replace(tmp, p)
    except OSError as e:
        log.warning("cannot write detect.json: %s", e)


def load_saved(cfg) -> dict | None:
    try:
        return json.loads((cfg.state / "detect.json").read_text())
    except (OSError, ValueError):
        return None
