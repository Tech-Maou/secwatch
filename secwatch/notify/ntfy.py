"""ntfy push channel (JSON publish, bearer token from file)."""

from __future__ import annotations

import httpx

from ..config import read_secret
from ..enrichers import USER_AGENT


def payload(cfg, m) -> dict:
    prio = (cfg.get("notify.ntfy.priority") or {}).get(m.severity, 3)
    p = {"topic": cfg.get("notify.ntfy.topic"), "title": m.title[:250], "message": m.body[:3800],
         "priority": int(prio) if str(prio).isdigit() else 3}
    if m.tags:
        p["tags"] = m.tags
    if m.click:
        p["click"] = m.click
    return p


def send(cfg, m, client: httpx.Client | None = None) -> None:
    url = (cfg.get("notify.ntfy.url") or "").rstrip("/")
    if not url.startswith(("http://", "https://")):
        raise ValueError("ntfy url must start with http(s)://")
    headers = {"User-Agent": USER_AGENT}
    token = read_secret(cfg.get("notify.ntfy.token_file", ""))
    if cfg.get("notify.ntfy.token_file") and not token:
        raise RuntimeError("ntfy token file set but not readable")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    own = client is None
    client = client or httpx.Client(timeout=20)
    try:
        r = client.post(url, json=payload(cfg, m), headers=headers)
        if r.status_code >= 400:
            raise RuntimeError(f"ntfy answered HTTP {r.status_code}")
    finally:
        if own:
            client.close()
