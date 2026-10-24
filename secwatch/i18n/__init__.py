"""Translations. Every UI string and notification text lives in <lang>.json in this directory.
Adding a language = dropping in a new JSON file (keys missing there fall back to English)."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

DIR = Path(__file__).parent
DEFAULT = "en"
_LANG_RE = re.compile(r"^[a-z]{2,3}(-[A-Za-z]{2,4})?$")


def languages() -> list[str]:
    return sorted(p.stem for p in DIR.glob("*.json") if _LANG_RE.match(p.stem))


@lru_cache(maxsize=16)
def catalog(lang: str) -> dict[str, str]:
    if not _LANG_RE.match(lang or ""):
        lang = DEFAULT
    base: dict[str, str] = {}
    if lang != DEFAULT:
        base = dict(catalog(DEFAULT))
    p = DIR / f"{lang}.json"
    if p.exists():
        base.update(json.loads(p.read_text(encoding="utf-8")))
    return base


def t(lang: str, key: str, **kw) -> str:
    s = catalog(lang).get(key) or catalog(DEFAULT).get(key) or key
    try:
        return s.format(**kw) if kw else s
    except (KeyError, IndexError, ValueError):
        return s
