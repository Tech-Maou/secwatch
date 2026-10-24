"""OS package collector for non-NixOS hosts: trivy rootfs."""

from __future__ import annotations

import os

from ..models import Finding
from ..runner import ToolError, which
from . import Collector, register
from .trivy import base_args, parse_trivy, run_json, trivy_info


@register
class OsCollector(Collector):
    name = "os"
    default_timeout = 1800

    def auto_enabled(self) -> bool:
        return not self.ctx.env.get("is_nixos")

    def collect(self) -> list[Finding]:
        if not which("trivy"):
            raise ToolError("trivy not found on PATH")
        root = str(self.settings.get("root") or "/")
        cache = self.ctx.cache / "trivy"
        cache.mkdir(parents=True, exist_ok=True)
        cmd = base_args("rootfs", self.ctx.cfg, str(cache), self.timeout)
        for d in self.settings.get("skip_dirs") or []:
            d = str(d)
            if root != "/" and d.startswith("/"):
                d = os.path.join(root, d.lstrip("/"))
            cmd += ["--skip-dirs", d]
        cmd.append(root)
        data = run_json(cmd, self.timeout)
        return parse_trivy(data, self.ctx.host, "os", component="")

    def info(self) -> dict:
        return trivy_info(str(self.ctx.cfg.cache_dir / "trivy"))
