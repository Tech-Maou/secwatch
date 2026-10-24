"""Schedule decisions (config driven; the systemd timer / container loop only wakes us up)."""

from __future__ import annotations

from datetime import datetime, timedelta

from .config import WEEKDAYS
from .db import DB, parse_ts
from .reports import period_for


def _at(day: datetime, hhmm: str) -> datetime:
    h, m = (int(x) for x in (hhmm or "00:00").split(":"))
    return day.replace(hour=h, minute=m, second=0, microsecond=0)


def _naive_local(dt: datetime) -> datetime:
    return dt.astimezone().replace(tzinfo=None) if dt.tzinfo else dt


def last_occurrence(now: datetime, frequency: str, hhmm: str, weekday: str = "sun", monthday: int = 1) -> datetime:
    """Most recent scheduled time <= now, as aware local time (DST-correct: computed on wall clock)."""
    return _last(_naive_local(now), frequency, hhmm, weekday, monthday).astimezone()


def _last(now: datetime, frequency: str, hhmm: str, weekday: str, monthday: int) -> datetime:
    if frequency == "daily":
        t = _at(now, hhmm)
        return t if t <= now else t - timedelta(days=1)
    if frequency == "weekly":
        wd = WEEKDAYS.index(weekday) if weekday in WEEKDAYS else 6
        t = _at(now - timedelta(days=(now.weekday() - wd) % 7), hhmm)
        return t if t <= now else t - timedelta(days=7)
    # monthly
    md = max(1, min(28, int(monthday or 1)))
    t = _at(now.replace(day=md), hhmm)
    if t <= now:
        return t
    prev = (now.replace(day=1) - timedelta(days=1)).replace(day=md)
    return _at(prev, hhmm)


def next_occurrence(now: datetime, frequency: str, hhmm: str, weekday: str = "sun", monthday: int = 1) -> datetime:
    last = _last(_naive_local(now), frequency, hhmm, weekday, monthday)
    if frequency == "daily":
        nxt = last + timedelta(days=1)
    elif frequency == "weekly":
        nxt = last + timedelta(days=7)
    else:
        y, m = (last.year + (last.month == 12), last.month % 12 + 1)
        nxt = last.replace(year=y, month=m)
    return nxt.astimezone()


def _installed_at(db: DB) -> datetime | None:
    return parse_ts(db.get_meta("installed_at"))


def scan_due(cfg, db: DB, now: datetime | None = None) -> bool:
    now = (now or datetime.now()).astimezone()
    s = cfg.get("schedule.scan") or {}
    occ = last_occurrence(now, s.get("frequency", "daily"), s.get("time", "03:30"), s.get("weekday", "sun"),
                          s.get("monthday", 1))
    last = db.one("SELECT started_at FROM scans WHERE host=? AND trigger<>'hub' ORDER BY id DESC LIMIT 1", (cfg.host,))
    if last is None:
        return True  # never scanned: scan now
    return parse_ts(last["started_at"]) < occ


def reports_due(cfg, db: DB, now: datetime | None = None) -> list[tuple[str, str]]:
    """List of (kind, period) to generate now."""
    now = (now or datetime.now()).astimezone()
    installed = _installed_at(db)
    out = []
    r = cfg.get("schedule.reports") or {}
    specs = [
        ("daily", "daily", r.get("daily", {})),
        ("weekly", "weekly", r.get("weekly", {})),
        ("monthly", "monthly", r.get("monthly", {})),
    ]
    for kind, freq, spec in specs:
        if not spec.get("enabled", True):
            continue
        occ = last_occurrence(now, freq, spec.get("time", "07:00"), spec.get("weekday", "sun"), spec.get("monthday", 1))
        if installed and occ < installed:
            continue  # do not back-fill reports from before installation
        period = period_for(kind, occ)
        if db.one("SELECT 1 FROM reports WHERE kind=? AND period=?", (kind, period)) is None:
            out.append((kind, period))
    return out


def next_runs(cfg, now: datetime | None = None) -> dict:
    now = (now or datetime.now()).astimezone()
    s = cfg.get("schedule.scan") or {}
    r = cfg.get("schedule.reports") or {}
    out = {"scan": next_occurrence(now, s.get("frequency", "daily"), s.get("time", "03:30"), s.get("weekday", "sun"),
                                   s.get("monthday", 1)).isoformat()}
    for kind in ("daily", "weekly", "monthly"):
        spec = r.get(kind, {})
        if spec.get("enabled", True):
            out[f"report_{kind}"] = next_occurrence(now, kind, spec.get("time", "07:00"), spec.get("weekday", "sun"),
                                                    spec.get("monthday", 1)).isoformat()
    return out
