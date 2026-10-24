"""Phase-2 collectors: registered and toggleable, they currently return no findings."""

from __future__ import annotations

from . import StubCollector, register


@register
class LynisCollector(StubCollector):
    name = "lynis"


@register
class ExposureCollector(StubCollector):
    name = "exposure"


@register
class SecretsCollector(StubCollector):
    name = "secrets"


@register
class AuthCollector(StubCollector):
    name = "auth"


@register
class UpdatesCollector(StubCollector):
    name = "updates"


@register
class SbomCollector(StubCollector):
    name = "sbom"

    def auto_enabled(self) -> bool:
        return False
