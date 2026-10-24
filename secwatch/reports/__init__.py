"""Daily / weekly / monthly reports (JSON + HTML) and monthly comparisons."""

from __future__ import annotations

import json
import logging
import os
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .. import __version__, i18n
from ..db import DB, now_iso, parse_ts, row_to_finding_dict
from ..models import SEVERITY_ORDER, priority_tuple

log = logging.getLogger(__name__)

TEMPLATES = Path(__file__).parent / "templates"
SEVS = ["critical", "high", "medium", "low", "unknown"]
KINDS = ["vuln", "hardening", "exposure", "secret", "auth", "update", "scan_error"]


def _env() -> Environment:
    return Environment(loader=FileSystemLoader(str(TEMPLATES)), autoescape=select_autoescape(["html", "j2"]))


def _sort(items: list[dict]) -> list[dict]:
    return sorted(items, key=lambda f: priority_tuple(f.get("kev", False), f.get("epss"), f.get("cvss"),
                                                      f.get("severity", "unknown"), f.get("first_seen", "")))


def _slim(f: dict, now: datetime) -> dict:
    first = parse_ts(f.get("first_seen"))
    return {
        "key": f["key"], "host": f["host"], "source": f["source"], "kind": f["kind"], "id": f["id"],
        "package": f.get("package", ""), "installed": f.get("installed", ""), "fixed": f.get("fixed", ""),
        "severity": f.get("severity", "unknown"), "cvss": f.get("cvss"), "kev": bool(f.get("kev")),
        "epss": f.get("epss"), "title": f.get("title", ""), "url": f.get("url", ""),
        "component": f.get("component", ""), "state": f.get("state", ""), "first_seen": f.get("first_seen"),
        "fixed_at": f.get("fixed_at"), "age_days": (now - first).days if first else None,
    }


def _findings_by_events(db: DB, types: tuple[str, ...], since: str, until: str) -> list[dict]:
    rows = db.q(
        "SELECT DISTINCT f.* FROM events e JOIN findings f ON f.key=e.key WHERE e.type IN (%s) "
        "AND e.ts>=? AND e.ts<?" % ",".join("?" * len(types)), [*types, since, until])
    return [row_to_finding_dict(r) for r in rows]


def _open(db: DB) -> list[dict]:
    return [row_to_finding_dict(r) for r in db.q("SELECT * FROM findings WHERE state='open'")]


def _totals(items: list[dict]) -> dict:
    t = {"total": len(items), "kev": sum(1 for f in items if f.get("kev")),
         "by_severity": {s: 0 for s in SEVS}, "by_kind": {}, "by_host": {}}
    for f in items:
        sev = f.get("severity") if f.get("severity") in SEVS else "unknown"
        t["by_severity"][sev] += 1
        t["by_kind"][f["kind"]] = t["by_kind"].get(f["kind"], 0) + 1
        h = t["by_host"].setdefault(f["host"], {s: 0 for s in SEVS} | {"total": 0})
        h[sev] += 1
        h["total"] += 1
    return t


def period_for(kind: str, now_local: datetime) -> str:
    if kind == "daily":
        return now_local.date().isoformat()
    if kind == "weekly":
        y, w, _ = now_local.isocalendar()
        return f"{y}-W{w:02d}"
    first = now_local.date().replace(day=1)
    prev = first - timedelta(days=1)
    return f"{prev.year}-{prev.month:02d}"


def month_bounds(period: str) -> tuple[str, str]:
    y, m = map(int, period.split("-"))
    start = datetime(y, m, 1).astimezone()
    end = datetime(y + (m == 12), m % 12 + 1, 1).astimezone()
    return start.astimezone(timezone.utc).isoformat(), end.astimezone(timezone.utc).isoformat()


def prev_period(period: str) -> str:
    y, m = map(int, period.split("-"))
    d = date(y, m, 1) - timedelta(days=1)
    return f"{d.year}-{d.month:02d}"


def compare(a: dict, b: dict) -> dict:
    """Deltas b - a for two monthly summaries (a = older)."""
    def delta(x: dict, y: dict) -> dict:
        keys = set(x) | set(y)
        return {k: (y.get(k, 0) or 0) - (x.get(k, 0) or 0) for k in keys if isinstance(y.get(k, x.get(k)), (int, float))}
    ta, tb = a.get("totals", {}), b.get("totals", {})
    out = {
        "total": (tb.get("total", 0) - ta.get("total", 0)),
        "kev": (tb.get("kev", 0) - ta.get("kev", 0)),
        "by_severity": delta(ta.get("by_severity", {}), tb.get("by_severity", {})),
        "by_kind": delta(ta.get("by_kind", {}), tb.get("by_kind", {})),
        "by_host": {h: (tb.get("by_host", {}).get(h, {}).get("total", 0) - ta.get("by_host", {}).get(h, {}).get("total", 0))
                    for h in set(ta.get("by_host", {})) | set(tb.get("by_host", {}))},
        "new": b.get("new_count", 0) - a.get("new_count", 0),
        "fixed": b.get("fixed_count", 0) - a.get("fixed_count", 0),
    }
    ma, mb = a.get("mttf_days"), b.get("mttf_days")
    out["mttf_days"] = round(mb - ma, 1) if isinstance(ma, (int, float)) and isinstance(mb, (int, float)) else None
    return out


def _summary(rep: dict) -> dict:
    keys = ("kind", "period", "generated_at", "totals", "new_count", "fixed_count", "mttf_days", "open_count",
            "hardening_index", "auth_total")
    return {k: rep.get(k) for k in keys if k in rep}


def build(cfg, db: DB, kind: str, now: datetime | None = None, period: str | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    now_local = now.astimezone()
    period = period or period_for(kind, now_local)
    rep: dict = {"kind": kind, "period": period, "generated_at": now.replace(microsecond=0).isoformat(),
                 "version": __version__, "hosts": sorted({r["host"] for r in db.q("SELECT DISTINCT host FROM findings")})}
    if kind == "daily":
        last = db.one("SELECT created_at FROM reports WHERE kind='daily' AND period<>? ORDER BY created_at DESC LIMIT 1",
                      (period,))
        since = last["created_at"] if last else (now - timedelta(days=1)).isoformat()
        new = [_slim(f, now) for f in _findings_by_events(db, ("new", "reopened"), since, now.isoformat())]
        new = [f for f in new if f["state"] in ("open", "accepted")]
        fixed = [_slim(f, now) for f in _findings_by_events(db, ("fixed",), since, now.isoformat())]
        fixed = [f for f in fixed if f["state"] == "fixed"]
        rep.update(since=since, new=_sort(new), fixed=_sort(fixed), new_count=len(new), fixed_count=len(fixed),
                   totals=_totals(new))
    elif kind == "weekly":
        items = _sort([_slim(f, now) for f in _open(db)])
        groups: dict[str, dict[str, list]] = {}
        for f in items:
            groups.setdefault(f["severity"], {}).setdefault(f["host"], []).append(f)
        rep.update(open=items, open_count=len(items), totals=_totals(items),
                   groups={s: groups[s] for s in sorted(groups, key=lambda s: -SEVERITY_ORDER.get(s, 0))})
    elif kind == "monthly":
        start, end = month_bounds(period)
        new = [_slim(f, now) for f in _findings_by_events(db, ("new", "reopened"), start, end)]
        fixed_rows = [_slim(f, now) for f in _findings_by_events(db, ("fixed",), start, end)]
        durations = []
        for f in fixed_rows:
            a, b = parse_ts(f.get("first_seen")), parse_ts(f.get("fixed_at"))
            if a and b and b >= a:
                durations.append((b - a).total_seconds() / 86400)
        open_items = _sort([_slim(f, now) for f in _open(db)])
        auth = db.one("SELECT COALESCE(SUM(count),0) n FROM auth_stats WHERE day>=? AND day<?",
                      (start[:10], end[:10]))["n"]
        rep.update(
            totals=_totals(open_items), open_count=len(open_items), new_count=len(new), fixed_count=len(fixed_rows),
            new_by_severity=_totals(new)["by_severity"], fixed_by_severity=_totals(fixed_rows)["by_severity"],
            mttf_days=round(sum(durations) / len(durations), 1) if durations else None,
            hardening_index=db.get_meta("lynis_index"),  # filled by the lynis collector (phase 2)
            auth_total=auth, top_open=open_items[:25],
        )
        history = []
        p = period
        for _ in range(6):
            p = prev_period(p)
            r = db.one("SELECT summary FROM reports WHERE kind='monthly' AND period=?", (p,))
            if r:
                history.append(json.loads(r["summary"]))
        rep["previous"] = history
        rep["comparison"] = compare(history[0], _summary(rep)) if history else None
    else:
        raise ValueError(f"unknown report kind {kind}")
    return rep


def render_html(cfg, rep: dict) -> str:
    lang = cfg.get("language", "en")
    tpl = _env().get_template("report.html.j2")
    return tpl.render(r=rep, t=lambda k, **kw: i18n.t(lang, k, **kw), lang=lang, sevs=SEVS)


def generate(cfg, db: DB, kind: str, now: datetime | None = None, period: str | None = None) -> dict:
    rep = build(cfg, db, kind, now, period)
    d = cfg.reports_dir / kind
    d.mkdir(parents=True, exist_ok=True)
    jp, hp = d / f"{rep['period']}.json", d / f"{rep['period']}.html"
    _write(jp, json.dumps(rep, indent=1, default=str))
    _write(hp, render_html(cfg, rep))
    summary = _summary(rep)
    db.exec("INSERT INTO reports(kind,period,created_at,json_path,html_path,summary) VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(kind,period) DO UPDATE SET created_at=excluded.created_at, json_path=excluded.json_path, "
            "html_path=excluded.html_path, summary=excluded.summary",
            (kind, rep["period"], rep["generated_at"], str(jp), str(hp), json.dumps(summary)))
    apply_retention(cfg, db)
    return rep


def _write(p: Path, text: str) -> None:
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.chmod(tmp, 0o640)
    os.replace(tmp, p)


def apply_retention(cfg, db: DB, now: datetime | None = None) -> int:
    days = int(cfg.get("schedule.reports.retention_days", 0) or 0)
    if days <= 0:
        return 0
    cutoff = ((now or datetime.now(timezone.utc)) - timedelta(days=days)).isoformat()
    n = 0
    for r in db.q("SELECT * FROM reports WHERE created_at<?", (cutoff,)):
        for p in (r["json_path"], r["html_path"]):
            try:
                Path(p).unlink()
            except OSError:
                pass
        db.exec("DELETE FROM reports WHERE id=?", (r["id"],))
        n += 1
    return n
