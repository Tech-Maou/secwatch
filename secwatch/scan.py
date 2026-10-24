"""Scan orchestration: collectors -> enrichers -> lifecycle diff -> hub pull -> notifications,
plus report generation and trigger-file handling."""

from __future__ import annotations

import fcntl
import json
import logging
import os
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from . import detect as detect_mod
from . import reports, schedule
from .collectors import Context, load_all
from .db import DB, now_iso, row_to_finding_dict
from .enrichers import run_enrichers
from .hub import _host_row, pull_agent
from .lifecycle import Diff, Scope, apply_snapshot
from .models import Finding
from .notify import Notifier, events_from_diff, summary_messages, test_message

log = logging.getLogger(__name__)
ENRICH_FIELDS = {"kev": ("kev", "kev_date_added", "kev_due_date", "kev_ransomware", "kev_name"),
                 "epss": ("epss", "epss_percentile")}


@contextmanager
def scan_lock(cfg):
    cfg.state.mkdir(parents=True, exist_ok=True)
    p = cfg.state / "scan.lock"
    fd = os.open(p, os.O_RDWR | os.O_CREAT, 0o660)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("another scan is running")
        yield
    finally:
        os.close(fd)


def _error_finding(host: str, source: str, err: str, component: str = "") -> Finding:
    short = err.strip().splitlines()[0][:200] if err.strip() else "failed"
    return Finding(host=host, source=source, kind="scan_error", id="scan_error", component=component,
                   severity="medium", title=f"{source}: {short}", extra={"error": err[:1000]})


def _preserve_enrichment(db: DB, findings: list[Finding], failed: list[str]) -> None:
    """If an enricher failed, keep the values from the last successful run."""
    fields = [f for name in failed for f in ENRICH_FIELDS.get(name, ())]
    if not fields:
        return
    keys = [f.key for f in findings]
    old: dict[str, dict] = {}
    for i in range(0, len(keys), 500):
        chunk = keys[i:i + 500]
        for r in db.q("SELECT key, extra FROM findings WHERE key IN (%s)" % ",".join("?" * len(chunk)), chunk):
            try:
                old[r["key"]] = json.loads(r["extra"])
            except ValueError:
                pass
    for f in findings:
        prev = old.get(f.key) or {}
        for fld in fields:
            if fld in prev and fld not in f.extra:
                f.extra[fld] = prev[fld]


def _merge(a: Diff, b: Diff) -> Diff:
    for fld in ("new", "still_open", "fixed", "reopened", "newly_kev", "expired"):
        getattr(a, fld).extend(getattr(b, fld))
    return a


def _save_tool(db: DB, host: str, info: dict) -> None:
    if not info or not info.get("name"):
        return
    db.exec("INSERT INTO tools(host,name,version,db_age,info,updated_at) VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(host,name) DO UPDATE SET version=excluded.version, db_age=excluded.db_age, "
            "info=excluded.info, updated_at=excluded.updated_at",
            (host, info["name"], info.get("version") or "", info.get("db_age"), json.dumps(info, default=str), now_iso()))


def run_scan(cfg, db: DB, trigger: str = "timer", only: list[str] | None = None, notifier: Notifier | None = None,
             env: dict | None = None) -> dict:
    if db.get_meta("installed_at") is None:
        db.set_meta("installed_at", now_iso())
    host = cfg.host
    started = now_iso()
    scan_id = db.exec("INSERT INTO scans(host,started_at,trigger,status) VALUES(?,?,?,?)",
                      (host, started, trigger, "running")).lastrowid
    if env is None:
        try:
            env = detect_mod.detect(cfg)
            detect_mod.save(cfg, env)
        except Exception as e:
            log.error("environment detection failed: %s", e)
            env = {}
    ctx = Context(cfg=cfg, host=host, env=env)
    findings: list[Finding] = []
    scopes: list[Scope] = []
    status: dict[str, dict] = {}
    for name, cls in load_all().items():
        if only and name not in only:
            continue
        try:
            c = cls(ctx)
            enabled = c.enabled()
        except Exception as e:
            status[name] = {"enabled": False, "ok": False, "error": str(e)[:300]}
            continue
        if not enabled:
            status[name] = {"enabled": False}
            continue
        t0 = time.monotonic()
        try:
            fs = c.collect()
            findings.extend(fs)
            sc = Scope(name, keep_components=sorted(getattr(c, "keep_components", set())))
            status[name] = {"enabled": True, "ok": True, "count": len(fs), "implemented": c.implemented,
                            "messages": c.messages[-10:]}
        except Exception as e:  # isolate every collector
            log.error("collector %s failed: %s", name, e)
            findings.append(_error_finding(host, name, str(e)))
            sc = Scope(name, kinds=["scan_error"])
            status[name] = {"enabled": True, "ok": False, "error": str(e)[:500], "messages": c.messages[-10:]}
        status[name]["duration_s"] = round(time.monotonic() - t0, 1)
        status[name]["scope"] = {"source": sc.source, "kinds": sc.kinds, "keep_components": sc.keep_components}
        scopes.append(sc)
        if c.implemented:
            try:
                _save_tool(db, host, c.info())
            except Exception as e:
                log.debug("info() of %s failed: %s", name, e)

    enr = run_enrichers(cfg, [f for f in findings if f.kind == "vuln"])
    failed = [n for n, r in enr.items() if not r.get("ok")]
    _preserve_enrichment(db, findings, failed)
    for name, r in enr.items():
        src = f"enricher.{name}"
        if r.get("ok"):
            scopes.append(Scope(src))
        else:
            findings.append(_error_finding(host, src, r.get("error", "")))
            scopes.append(Scope(src))
    status["_enrichers"] = enr

    diff = apply_snapshot(db, host, findings, scopes, scan_id)
    _host_row(db, host, "ok" if not any(not s.get("ok", True) for k, s in status.items() if not k.startswith("_"))
              else "partial", started, {"role": cfg.get("role")}, role=cfg.get("role", "standalone"))

    if cfg.get("role") == "hub":
        for agent in cfg.get("hub.agents") or []:
            try:
                _merge(diff, pull_agent(cfg, db, agent))
            except Exception as e:
                log.error("hub pull of %s failed: %s", agent.get("name"), e)
                status.setdefault("_hub", {})[str(agent.get("name"))] = str(e)[:200]

    notifier = notifier or Notifier(cfg, db)
    try:
        notifier.notify(events_from_diff(cfg, diff))
    except Exception as e:
        log.error("notifications failed: %s", e)
        notifier.errors.append(str(e))
    status["_notify"] = {"sent": len(notifier.sent), "errors": notifier.errors[-10:]}

    errors = sum(1 for k, s in status.items() if not k.startswith("_") and s.get("enabled") and not s.get("ok"))
    summary = {**diff.counts(), "errors": errors, "total_findings": len(findings)}
    final = "ok" if errors == 0 and not failed else ("failed" if errors and errors == sum(
        1 for k, s in status.items() if not k.startswith("_") and s.get("enabled")) else "partial")
    db.exec("UPDATE scans SET finished_at=?, status=?, summary=?, collectors=? WHERE id=?",
            (now_iso(), final, json.dumps(summary), json.dumps(status, default=str), scan_id))
    log.info("scan %d finished: %s %s", scan_id, final, summary)
    return {"scan_id": scan_id, "status": final, "summary": summary, "collectors": status}


def generate_reports(cfg, db: DB, due: list[tuple[str, str]], notifier: Notifier | None = None,
                     now: datetime | None = None) -> list[dict]:
    out = []
    notifier = notifier or Notifier(cfg, db)
    for kind, period in due:
        try:
            rep = reports.generate(cfg, db, kind, now=now, period=period)
            out.append({"kind": kind, "period": period, "ok": True})
        except Exception as e:
            log.error("report %s %s failed: %s", kind, period, e)
            out.append({"kind": kind, "period": period, "ok": False, "error": str(e)[:200]})
            continue
        event = {"weekly": "weekly_summary", "monthly": "monthly_report"}.get(kind)
        if not event:
            continue
        items = rep.get("open") or rep.get("top_open") or []
        if kind == "monthly":
            items = [row_to_finding_dict(r) for r in db.q("SELECT * FROM findings WHERE state='open'")]
        if kind == "weekly" and not items and cfg.get("schedule.reports.weekly.notify_only_if_open", True):
            continue
        try:
            notifier.deliver(summary_messages(cfg, event, items, period, "#/reports"))
        except Exception as e:
            log.error("summary notification failed: %s", e)
    return out


def read_trigger(cfg) -> list[dict]:
    """Atomically take the trigger file. Each line may be JSON {"action": ...}; empty = scan."""
    p: Path = cfg.trigger_path
    if not p.exists():
        return []
    taken = p.with_name(f".trigger.{os.getpid()}")
    try:
        os.replace(p, taken)
    except OSError:
        return []
    actions = []
    try:
        text = taken.read_text(encoding="utf-8", errors="replace")[:65536]
    finally:
        try:
            taken.unlink()
        except OSError:
            pass
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            a = json.loads(line)
            if isinstance(a, dict) and a.get("action") in ("scan", "notify-test", "report"):
                actions.append(a)
        except ValueError:
            continue
    return actions or [{"action": "scan"}]


def write_trigger(cfg, action: dict) -> None:
    """Append an action to the trigger file (used by the web process)."""
    cfg.state.mkdir(parents=True, exist_ok=True)
    line = json.dumps(action, separators=(",", ":")) + "\n"
    fd = os.open(cfg.trigger_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o660)
    try:
        os.write(fd, line.encode())
    finally:
        os.close(fd)


def record_action(cfg, result: dict) -> None:
    p = cfg.state / "actions.json"
    try:
        items = json.loads(p.read_text()) if p.exists() else []
    except (OSError, ValueError):
        items = []
    items = ([{**result, "ts": now_iso()}] + items)[:20]
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(items, indent=1))
    os.chmod(tmp, 0o660)
    os.replace(tmp, p)


def notify_test(cfg, db: DB, channel: str | None = None, notifier: Notifier | None = None) -> dict:
    notifier = notifier or Notifier(cfg, db)
    results = {}
    for ch in ([channel] if channel else ["push", "mail"]):
        if ch not in ("push", "mail"):
            continue
        enabled = cfg.get("notify.ntfy.enabled") if ch == "push" else cfg.get("notify.mail.enabled")
        if not enabled:
            results[ch] = {"ok": False, "error": "disabled"}
            continue
        try:
            notifier.senders[ch](cfg, test_message(cfg, ch))
            results[ch] = {"ok": True}
        except Exception as e:
            results[ch] = {"ok": False, "error": f"{e.__class__.__name__}: {str(e)[:200]}"}
    return results


def cycle(cfg, db: DB, force: bool = False, trigger: str = "timer") -> dict:
    """One wake-up: handle trigger actions, run a scan if due, generate due reports."""
    out: dict = {"scan": None, "reports": [], "actions": []}
    with scan_lock(cfg):
        actions = read_trigger(cfg)
        want_scan = force or any(a["action"] == "scan" for a in actions)
        for a in actions:
            if a["action"] == "notify-test":
                res = notify_test(cfg, db, a.get("channel"))
                record_action(cfg, {"action": "notify-test", "results": res})
                out["actions"].append(res)
        if want_scan:
            trigger = "manual" if actions else trigger
        if want_scan or schedule.scan_due(cfg, db):
            out["scan"] = run_scan(cfg, db, trigger=trigger)
            if actions:
                record_action(cfg, {"action": "scan", "status": out["scan"]["status"]})
        due = schedule.reports_due(cfg, db)
        if due:
            out["reports"] = generate_reports(cfg, db, due)
    return out


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
