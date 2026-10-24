"""Notification decisions: event x severity matrix, dedup/rate limiting, short messages.

Channels: "push" (ntfy) and "mail" (SMTP). Every matrix cell is {push: bool, mail: bool}.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Callable

from .. import i18n
from ..config import EVENTS
from ..db import DB, now_iso, utcnow
from ..lifecycle import Diff
from ..models import SEVERITY_ORDER, matrix_severity, priority_tuple

log = logging.getLogger(__name__)

CHANNELS = ("push", "mail")
SEV_LABEL_KEYS = {s: f"severity.{s}" for s in ("critical", "high", "medium", "low", "unknown")}
NTFY_TAGS = {"critical": "rotating_light", "high": "warning", "medium": "large_orange_diamond",
             "low": "information_source", "unknown": "grey_question"}
SUMMARY_EVENTS = ("weekly_summary", "monthly_report")


@dataclass
class Message:
    event: str
    host: str
    channel: str
    title: str
    body: str
    severity: str
    click: str
    keys: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


def cell(cfg, event: str, severity: str) -> dict:
    row = (cfg.get("notify.matrix") or {}).get(event) or {}
    c = row.get(matrix_severity(severity)) or {}
    return {"push": bool(c.get("push")), "mail": bool(c.get("mail"))}


def channel_enabled(cfg, channel: str) -> bool:
    if channel == "push":
        return bool(cfg.get("notify.ntfy.enabled")) and bool(cfg.get("notify.ntfy.topic"))
    return bool(cfg.get("notify.mail.enabled")) and bool(cfg.get("notify.mail.host")) and bool(cfg.get("notify.mail.to"))


def events_from_diff(cfg, diff: Diff) -> dict[str, list[dict]]:
    ev: dict[str, list[dict]] = {e: [] for e in EVENTS}
    sec_only = cfg.get("notify.update_security_only", True)
    for f in diff.new:
        if f.get("state", "open") != "open":
            continue
        kind = f.get("kind")
        if kind in ("vuln", "hardening"):
            (ev["kev_finding"] if f.get("kev") else ev["new_finding"]).append(f)
        elif kind == "exposure":
            ev["exposure_change"].append(f)
        elif kind == "secret":
            ev["secret_found"].append(f)
        elif kind == "auth":
            ev["auth_anomaly"].append(f)
        elif kind == "update":
            if not sec_only or (f.get("extra") or {}).get("security"):
                ev["update_available"].append(f)
        elif kind == "scan_error":
            ev["scan_error"].append(f)
    for f in diff.newly_kev:
        ev["kev_finding"].append(f)
    for f in diff.fixed:
        if f.get("kind") == "exposure":
            ev["exposure_change"].append({**f, "fixed_now": True})
    return {k: v for k, v in ev.items() if v}


def sort_items(items: list[dict]) -> list[dict]:
    return sorted(items, key=lambda f: priority_tuple(bool(f.get("kev")), f.get("epss"), f.get("cvss"),
                                                      f.get("severity", "unknown"), f.get("first_seen", "")))


def _item_line(lang: str, f: dict) -> str:
    marks = [i18n.t(lang, SEV_LABEL_KEYS.get(f.get("severity", "unknown"), "severity.unknown"))]
    if f.get("kev"):
        marks.append("KEV")
    if f.get("epss") is not None and (f.get("epss") or 0) >= 0.01:
        marks.append(f"EPSS {f['epss'] * 100:.0f}%")
    pkg = " ".join(x for x in (f.get("package"), f.get("installed")) if x)
    comp = f.get("component") or ""
    where = f" @{comp}" if comp and comp not in ("booted-system",) else ""
    title = "" if pkg else (f.get("title") or "")[:60]
    if f.get("fixed_now"):
        marks.append(i18n.t(lang, "state.fixed"))
    return f"• {f.get('id')} {pkg or title}{where} [{', '.join(marks)}]".replace("  ", " ")


def counts_line(lang: str, items: list[dict]) -> str:
    counts: dict[str, int] = {}
    for f in items:
        counts[f.get("severity", "unknown")] = counts.get(f.get("severity", "unknown"), 0) + 1
    parts = [f"{i18n.t(lang, SEV_LABEL_KEYS.get(s, 'severity.unknown'))} {n}"
             for s, n in sorted(counts.items(), key=lambda kv: -SEVERITY_ORDER.get(kv[0], 0))]
    kev = sum(1 for f in items if f.get("kev"))
    if kev:
        parts.append(f"KEV {kev}")
    return " · ".join(parts)


def build_message(cfg, event: str, host: str, channel: str, items: list[dict], extra_line: str = "",
                  click_path: str = "#/findings") -> Message:
    lang = cfg.get("language", "en")
    items = sort_items(items)
    top = items[:5]
    lines = [counts_line(lang, items)]
    if extra_line:
        lines.append(extra_line)
    lines += [_item_line(lang, f) for f in top]
    if len(items) > 5:
        lines.append(i18n.t(lang, "notify.more", count=len(items) - 5))
    worst = max((f.get("severity", "unknown") for f in items), key=lambda s: SEVERITY_ORDER.get(s, 0),
                default="unknown")
    base = (cfg.get("web.base_url") or "").rstrip("/")
    click = f"{base}/{click_path}" if base else ""
    if click and host and click_path == "#/findings":
        click += f"?host={host}"
    title = i18n.t(lang, f"notify.title.{event}", count=len(items), host=host)
    tags = ["secwatch", NTFY_TAGS.get(worst, "warning")] if cfg.get("notify.ntfy.tags", True) else []
    if any(f.get("kev") for f in items):
        tags.append("skull")
    body = "\n".join(lines)
    if channel == "mail" and click:
        body += "\n\n" + click
    return Message(event=event, host=host, channel=channel, title=title, body=body, severity=worst,
                   click=click, keys=[f.get("key", "") for f in items], tags=tags)


class Notifier:
    def __init__(self, cfg, db: DB, senders: dict[str, Callable[[object, Message], None]] | None = None):
        self.cfg = cfg
        self.db = db
        if senders is None:
            from . import mail, ntfy
            senders = {"push": ntfy.send, "mail": mail.send}
        self.senders = senders
        self.sent: list[Message] = []
        self.errors: list[str] = []

    def _recent(self, event: str, key: str, channel: str, hours: float) -> bool:
        since = (utcnow() - timedelta(hours=hours)).replace(microsecond=0).isoformat()
        return self.db.one("SELECT 1 FROM notifications WHERE event=? AND key=? AND channel=? AND ok=1 AND ts>=?",
                           (event, key, channel, since)) is not None

    def _rate_exceeded(self, channel: str) -> bool:
        limit = int(self.cfg.get("notify.max_per_hour", 12) or 0)
        if limit <= 0:
            return False
        since = (utcnow() - timedelta(hours=1)).replace(microsecond=0).isoformat()
        n = self.db.one("SELECT COUNT(*) n FROM notifications WHERE channel=? AND key='*message*' AND ts>=?",
                        (channel, since))["n"]
        return n >= limit

    def plan(self, events: dict[str, list[dict]]) -> list[Message]:
        """Decide which messages to send (matrix + dedup). Does not send."""
        dedup = float(self.cfg.get("notify.dedup_hours", 72) or 0)
        out: list[Message] = []
        for event, items in events.items():
            for channel in CHANNELS:
                if not channel_enabled(self.cfg, channel):
                    continue
                selected = [f for f in items if cell(self.cfg, event, f.get("severity", "unknown"))[channel]]
                if dedup > 0 and event not in SUMMARY_EVENTS:
                    selected = [f for f in selected if not self._recent(event, f.get("key", ""), channel, dedup)]
                by_host: dict[str, list[dict]] = {}
                for f in selected:
                    by_host.setdefault(f.get("host", ""), []).append(f)
                for host, its in sorted(by_host.items()):
                    out.append(build_message(self.cfg, event, host, channel, its))
        return out

    def deliver(self, messages: list[Message]) -> None:
        for m in messages:
            if self._rate_exceeded(m.channel):
                self.errors.append(f"{m.channel}: rate limit reached, dropped '{m.title}'")
                log.warning("notification rate limit reached on %s, dropping %s", m.channel, m.title)
                self._record(m, ok=False, info="rate limited")
                continue
            try:
                self.senders[m.channel](self.cfg, m)
                self.sent.append(m)
                self._record(m, ok=True)
            except Exception as e:  # never let a channel failure break the scan
                msg = f"{m.channel}: {e.__class__.__name__}: {str(e)[:200]}"
                self.errors.append(msg)
                log.error("notification failed: %s", msg)
                self._record(m, ok=False, info=msg)

    def _record(self, m: Message, ok: bool, info: str = "") -> None:
        ts = now_iso()
        rows = [(ts, m.event, "*message*", m.channel, 1 if ok else 0, (info or m.title)[:300])]
        if ok:
            rows += [(ts, m.event, k, m.channel, 1, "") for k in m.keys if k]
        with self.db.tx() as conn:
            conn.executemany("INSERT INTO notifications(ts,event,key,channel,ok,info) VALUES(?,?,?,?,?,?)", rows)

    def notify(self, events: dict[str, list[dict]]) -> list[Message]:
        msgs = self.plan(events)
        self.deliver(msgs)
        return msgs


def summary_messages(cfg, event: str, items: list[dict], period: str, report_path: str) -> list[Message]:
    """Weekly/monthly: one message per channel for all hosts together."""
    lang = cfg.get("language", "en")
    out = []
    for channel in CHANNELS:
        if not channel_enabled(cfg, channel):
            continue
        sel = [f for f in items if cell(cfg, event, f.get("severity", "unknown"))[channel]]
        if not sel:
            continue
        hosts = sorted({f.get("host", "") for f in sel})
        host = hosts[0] if len(hosts) == 1 else i18n.t(lang, "notify.hosts", count=len(hosts))
        m = build_message(cfg, event, host, channel, sel, extra_line=i18n.t(lang, "notify.period", period=period),
                          click_path=report_path)
        m.keys = [f"{event}:{period}"]
        out.append(m)
    return out


def test_message(cfg, channel: str) -> Message:
    lang = cfg.get("language", "en")
    base = (cfg.get("web.base_url") or "").rstrip("/")
    return Message(event="test", host=cfg.host, channel=channel,
                   title=i18n.t(lang, "notify.title.test", host=cfg.host),
                   body=i18n.t(lang, "notify.test_body"), severity="low", click=base, tags=["secwatch", "white_check_mark"])
