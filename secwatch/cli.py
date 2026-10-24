"""secwatch-scan: scan, reports, notification test, config check, container scheduler loop."""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import time
from datetime import datetime

from . import __version__, config as config_mod, i18n
from .db import DB


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO,
                        format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)


def _load() -> tuple[config_mod.Config, DB]:
    cfg = config_mod.load()
    for w in cfg.warnings:
        logging.getLogger("secwatch").warning("config: %s", w)
    cfg.state.mkdir(parents=True, exist_ok=True)
    return cfg, DB(cfg.db_path)


def cmd_scan(args) -> int:
    from .scan import cycle, run_scan, scan_lock
    cfg, db = _load()
    if args.if_due:
        out = cycle(cfg, db, trigger="timer")
    else:
        with scan_lock(cfg):
            out = {"scan": run_scan(cfg, db, trigger="cli", only=args.only or None)}
    res = out.get("scan")
    if args.json:
        print(json.dumps(out, indent=1, default=str))
    elif res:
        s = res["summary"]
        print(f"scan {res['scan_id']}: {res['status']} - new {s['new']}, still open {s['still_open']}, "
              f"fixed {s['fixed']}, errors {s['errors']}")
        for name, st in res["collectors"].items():
            if name.startswith("_") or not st.get("enabled"):
                continue
            state = "ok" if st.get("ok") else f"FAILED: {st.get('error', '')}"
            print(f"  {name:<11} {state} ({st.get('count', 0)} findings, {st.get('duration_s', 0)} s)")
    else:
        print("nothing due")
    for r in out.get("reports") or []:
        print(f"report {r['kind']} {r['period']}: {'ok' if r['ok'] else r.get('error')}")
    return 0 if not res or res["status"] != "failed" else 2


def cmd_report(args) -> int:
    from . import reports
    from .scan import generate_reports
    cfg, db = _load()
    if args.no_notify:
        rep = reports.generate(cfg, db, args.kind, period=args.period)
        print(f"{args.kind} report {rep['period']} written to {cfg.reports_dir / args.kind}")
        return 0
    period = args.period or reports.period_for(args.kind, datetime.now().astimezone())
    res = generate_reports(cfg, db, [(args.kind, period)])
    for r in res:
        print(f"{r['kind']} report {r['period']}: {'ok' if r['ok'] else r.get('error')}")
    return 0 if all(r["ok"] for r in res) else 1


def cmd_notify_test(args) -> int:
    from .scan import notify_test
    cfg, db = _load()
    res = notify_test(cfg, db, args.channel)
    for ch, r in res.items():
        print(f"{ch}: {'ok' if r['ok'] else r['error']}")
    return 0 if res and all(r["ok"] for r in res.values()) else 1


def cmd_config_check(args) -> int:
    cfg = config_mod.load()
    errors = config_mod.validate(cfg.data, i18n.languages())
    for w in cfg.warnings:
        if w not in errors:
            print(f"warning: {w}")
    for e in errors:
        print(f"error: {e}")
    if args.show:
        print(json.dumps(config_mod.redact(cfg.data), indent=1))
    print(f"locked keys: {len(cfg.locked)}; state dir: {cfg.state}")
    for name in ("notify.ntfy.token_file", "notify.mail.password_file", "web.token_file", "agent.token_file"):
        if cfg.get(name):
            print(f"{name}: {config_mod.secret_status(cfg.get(name))}")
    print("config OK" if not errors else f"{len(errors)} error(s)")
    return 0 if not errors else 1


def cmd_loop(args) -> int:
    """Scheduler loop for the container image: wake up every --interval seconds."""
    from .scan import cycle
    stop = {"flag": False}

    def _stop(*_):
        stop["flag"] = True
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    log = logging.getLogger("secwatch.loop")
    log.info("scheduler loop started (interval %s s)", args.interval)
    trigger = config_mod.load().trigger_path
    while not stop["flag"]:
        try:
            cfg, db = _load()
            try:
                cycle(cfg, db)
            finally:
                db.close()
        except Exception as e:
            log.error("cycle failed: %s", e)
        for _ in range(int(args.interval)):
            if stop["flag"]:
                break
            if trigger.exists():
                break
            time.sleep(1)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="secwatch-scan", description="secwatch scanner")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="run a scan now (or with --if-due: only what is scheduled/triggered)")
    s.add_argument("--if-due", action="store_true", help="timer mode: trigger file, schedule, due reports")
    s.add_argument("--only", action="append", help="run only this collector (repeatable)")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_scan)
    r = sub.add_parser("report", help="generate a report now")
    r.add_argument("kind", choices=["daily", "weekly", "monthly"])
    r.add_argument("--period", help="e.g. 2026-10-24, 2026-W43, 2026-09")
    r.add_argument("--no-notify", action="store_true")
    r.set_defaults(func=cmd_report)
    n = sub.add_parser("notify-test", help="send a test notification")
    n.add_argument("--channel", choices=["push", "mail"])
    n.set_defaults(func=cmd_notify_test)
    c = sub.add_parser("config", help="configuration tools")
    csub = c.add_subparsers(dest="ccmd", required=True)
    cc = csub.add_parser("check", help="validate the merged configuration")
    cc.add_argument("--show", action="store_true", help="print the merged config (secrets redacted)")
    cc.set_defaults(func=cmd_config_check)
    lp = sub.add_parser("loop", help="scheduler loop (container image)")
    lp.add_argument("--interval", type=int, default=60)
    lp.set_defaults(func=cmd_loop)
    args = p.parse_args(argv)
    _setup_logging(args.verbose)
    try:
        return args.func(args)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
