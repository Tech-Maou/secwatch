"""Container image collector: list running containers (docker/podman) and scan their images
with Trivy. component = container name."""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path

import httpx

from ..models import Finding
from ..runner import ToolError, run, which
from . import Collector, register
from .trivy import base_args, parse_trivy, run_json, trivy_info

log = logging.getLogger(__name__)

SOCKETS = {
    "docker": ["/var/run/docker.sock", "/run/docker.sock"],
    "podman": ["/run/podman/podman.sock"],
}


def detect_runtime(runtime: str = "auto", socket: str = "") -> dict:
    """Return {runtime, socket, cli} or {} if nothing found."""
    order = ["docker", "podman"] if runtime == "auto" else [runtime]
    if socket and os.path.exists(socket):
        rt = order[0] if runtime != "auto" else ("podman" if "podman" in socket else "docker")
        return {"runtime": rt, "socket": socket, "cli": which(rt)}
    for rt in order:
        for s in SOCKETS[rt]:
            if os.path.exists(s):
                return {"runtime": rt, "socket": s, "cli": which(rt)}
    for rt in order:
        if which(rt):
            return {"runtime": rt, "socket": "", "cli": which(rt)}
    return {}


def _norm(name: str, image: str, image_id: str, state: str = "running") -> dict:
    return {"name": name.lstrip("/"), "image": image, "image_id": image_id, "state": state}


def parse_podman_ps(text: str) -> list[dict]:
    data = json.loads(text or "[]") or []
    out = []
    for c in data:
        names = c.get("Names") or []
        name = names[0] if isinstance(names, list) and names else str(names or c.get("Id", "")[:12])
        out.append(_norm(name, c.get("Image", ""), c.get("ImageID", ""), str(c.get("State", "running"))))
    return out


def parse_docker_ps(text: str) -> list[dict]:
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        c = json.loads(line)
        name = str(c.get("Names", "")).split(",")[0] or c.get("ID", "")[:12]
        out.append(_norm(name, c.get("Image", ""), c.get("ImageID", ""), str(c.get("State", "running"))))
    return out


def parse_engine_api(data: list) -> list[dict]:
    out = []
    for c in data or []:
        names = c.get("Names") or []
        name = names[0] if names else c.get("Id", "")[:12]
        out.append(_norm(name, c.get("Image", ""), c.get("ImageID", ""), str(c.get("State", "running"))))
    return out


def list_containers(rt: dict, timeout: int = 60) -> list[dict]:
    if rt.get("socket"):
        transport = httpx.HTTPTransport(uds=rt["socket"])
        with httpx.Client(transport=transport, base_url="http://engine", timeout=timeout) as c:
            r = c.get("/containers/json")
            r.raise_for_status()
            return parse_engine_api(r.json())
    if rt.get("runtime") == "podman":
        return parse_podman_ps(run(["podman", "ps", "--format", "json"], timeout=timeout).stdout)
    if rt.get("runtime") == "docker":
        return parse_docker_ps(run(["docker", "ps", "--no-trunc", "--format", "{{json .}}"], timeout=timeout).stdout)
    raise ToolError("no container runtime found")


@register
class ContainersCollector(Collector):
    name = "containers"
    default_timeout = 3600

    def __init__(self, ctx):
        super().__init__(ctx)
        self.keep_components: set[str] = set()  # containers whose scan failed -> keep old findings

    def auto_enabled(self) -> bool:
        return bool(self.ctx.env.get("container_runtime") or detect_runtime())

    def collect(self) -> list[Finding]:
        if not which("trivy"):
            raise ToolError("trivy not found on PATH")
        rt = detect_runtime(self.settings.get("runtime", "auto"), self.settings.get("socket", ""))
        if not rt:
            raise ToolError("no docker/podman socket or CLI found")
        # `ps` and GET /containers/json only list running containers by default
        containers = list_containers(rt)
        exclude = set(self.settings.get("exclude") or [])
        containers = [c for c in containers if c["name"] not in exclude]
        by_image: dict[str, list[dict]] = {}
        for c in containers:
            ref = c["image"] or c["image_id"]
            by_image.setdefault(ref, []).append(c)
        cache = self.ctx.cache / "trivy"
        cache.mkdir(parents=True, exist_ok=True)
        per_image = int(self.settings.get("image_timeout") or 900)
        findings: list[Finding] = []
        first = True
        for ref, cs in sorted(by_image.items()):
            try:
                data = self._scan_image(rt, ref, str(cache), per_image, skip_db=not first)
                first = False
            except (ToolError, OSError, ValueError) as e:
                names = ", ".join(c["name"] for c in cs)
                self.messages.append(f"image {ref} ({names}): {e}")
                log.warning("containers: scan of %s failed: %s", ref, e)
                for c in cs:
                    self.keep_components.add(c["name"])
                    findings.append(Finding(host=self.ctx.host, source="containers", kind="scan_error",
                                            id="scan_error", component=c["name"], severity="medium",
                                            title=f"image scan failed: {ref}", extra={"error": str(e)[:500]}))
                continue
            for c in cs:
                for f in parse_trivy(data, self.ctx.host, "containers", component=c["name"]):
                    f.extra["image"] = ref
                    findings.append(f)
        self.messages.append(f"{len(containers)} containers, {len(by_image)} images ({rt['runtime']})")
        return findings

    def _scan_image(self, rt: dict, ref: str, cache: str, timeout: int, skip_db: bool) -> dict:
        cmd = base_args("image", self.ctx.cfg, cache, timeout, skip_db_update=skip_db)
        if rt.get("socket"):
            if rt["runtime"] == "podman":
                cmd += ["--image-src", "podman", "--podman-host", rt["socket"]]
            else:
                cmd += ["--image-src", "docker", "--docker-host", "unix://" + rt["socket"]]
            return run_json(cmd + [ref], timeout)
        # no socket: export the image with the CLI and scan the tarball (never pulls from registries)
        with tempfile.TemporaryDirectory(dir=self.ctx.cache) as tmp:
            tar = str(Path(tmp) / "image.tar")
            run([rt["runtime"], "save", "-o", tar, ref], timeout=timeout)
            return run_json(cmd + ["--input", tar], timeout)

    def info(self) -> dict:
        return trivy_info(str(self.ctx.cfg.cache_dir / "trivy"))
