"""Collector plugin interface and registry.

A collector is a class with ``name``, ``collect(ctx) -> list[Finding]`` and
``info(ctx) -> {name, version, db_age}``. Register it with ``@register``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import Config
from ..models import Finding

log = logging.getLogger(__name__)

REGISTRY: dict[str, type["Collector"]] = {}


def register(cls: type["Collector"]) -> type["Collector"]:
    REGISTRY[cls.name] = cls
    return cls


@dataclass
class Context:
    cfg: Config
    host: str
    env: dict[str, Any] = field(default_factory=dict)  # detection results (is_nixos, runtime, ...)
    notes: list[str] = field(default_factory=list)

    @property
    def cache(self) -> Path:
        p = self.cfg.cache_dir
        p.mkdir(parents=True, exist_ok=True)
        return p

    def settings(self, name: str) -> dict:
        return self.cfg.collector_cfg(name)


class Collector:
    name: str = ""
    description_key: str = ""  # i18n key
    implemented: bool = True
    default_timeout: int = 900

    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.settings = ctx.settings(self.name)
        self.timeout = int(self.settings.get("timeout") or self.default_timeout)
        self.messages: list[str] = []

    def auto_enabled(self) -> bool:
        """Value used when the setting is 'auto'."""
        return True

    def enabled(self) -> bool:
        v = self.settings.get("enabled", True)
        if v == "auto":
            return self.auto_enabled()
        return bool(v)

    def collect(self) -> list[Finding]:  # pragma: no cover - interface
        raise NotImplementedError

    def info(self) -> dict:
        return {"name": self.name, "version": "", "db_age": None}


class StubCollector(Collector):
    """Registered and toggleable, implemented in phase 2."""
    implemented = False

    def collect(self) -> list[Finding]:
        self.messages.append("not implemented yet (phase 2)")
        log.info("collector %s: not implemented yet", self.name)
        return []


def load_all() -> dict[str, type[Collector]]:
    # import for side effect (registration)
    from . import containers, nix, os_scan, stubs  # noqa: F401
    return REGISTRY
