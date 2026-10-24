"""secwatch-web: FastAPI JSON API + static UI. Runs unprivileged; never runs scanners."""

from __future__ import annotations

import json
import logging
import os
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from .. import __version__, config as config_mod, i18n
from ..collectors import load_all
from ..config import COLLECTORS, ENRICHERS, EVENTS, MATRIX_PRESETS, PHASE2_COLLECTORS, SEVERITIES
from ..db import DB, row_to_finding_dict, utcnow
from ..lifecycle import ActionError, open_counts, set_state
from ..reports import compare as compare_reports
from ..schedule import next_runs
from . import auth

log = logging.getLogger(__name__)
STATIC = Path(__file__).parent / "static"
_FAILED: dict[str, list[float]] = {}  # failed logins per client IP (throttling)
KEY_RE = re.compile(r"^[0-9a-f]{24}$")
SECRET_FIELDS = {  # UI field -> (config path of *_file, secret file name)
    "notify.ntfy.token": ("notify.ntfy.token_file", "ntfy-token"),
    "notify.mail.password": ("notify.mail.password_file", "mail-password"),
    "agent.token": ("agent.token_file", "agent-token"),
    "web.token": ("web.token_file", "web-token"),
}
SEV_SQL = "CASE severity WHEN 'critical' THEN 9.5 WHEN 'high' THEN 7.5 WHEN 'medium' THEN 5 WHEN 'low' THEN 2 ELSE 0 END"
SORTS = {
    "priority": f"kev DESC, COALESCE(epss,0) DESC, COALESCE(cvss, {SEV_SQL}) DESC, first_seen ASC",
    "severity": f"COALESCE(cvss, {SEV_SQL}) DESC, kev DESC, first_seen ASC",
    "age": "first_seen ASC",
    "newest": "first_seen DESC",
    "host": "host ASC, kev DESC, COALESCE(cvss,0) DESC",
    "package": "package ASC, vuln_id ASC",
}


class Ctx:
    def __init__(self, state: Path | None = None):
        self.state_override = state
        self.cfg = self.reload()
        self.cfg.state.mkdir(parents=True, exist_ok=True)
        self.db = DB(self.cfg.db_path)
        if auth.needs_setup_code(self.cfg):
            auth.setup_code(self.cfg.state)

    def reload(self):
        self.cfg = config_mod.load(self.state_override)
        return self.cfg


def _json_body(data: Any, limit: int = 256 * 1024) -> dict:
    if not isinstance(data, dict):
        raise HTTPException(400, "JSON object expected")
    if len(json.dumps(data)) > limit:
        raise HTTPException(413, "request too large")
    return data


def create_app(state: Path | None = None) -> FastAPI:
    app = FastAPI(title="secwatch", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    ctx = Ctx(state)
    app.state.ctx = ctx

    # ------------------------------------------------------------------ middleware / auth
    @app.middleware("http")
    async def security(request: Request, call_next):
        cfg = ctx.reload()
        path = request.url.path
        request.state.user = None
        if cfg.get("role") == "agent" and not cfg.get("agent.ui", True):
            if not (path.startswith("/api/agent/") or path == "/healthz"):
                return JSONResponse({"error": "not found"}, status_code=404)
        public = path in ("/", "/healthz", "/api/session", "/api/login", "/api/logout", "/favicon.ico") \
            or path.startswith("/static/") or path.startswith("/api/i18n") or path.startswith("/api/agent/")
        authz = request.headers.get("authorization", "")
        bearer = authz[7:].strip() if authz.lower().startswith("bearer ") else None
        user, csrf = None, None
        if cfg.get("web.auth_mode") == "trusted_proxy":
            user, csrf = "proxy", auth.proxy_csrf(cfg.state)
        elif bearer and not path.startswith("/api/agent/") and auth.token_ok(cfg, bearer):
            user, csrf = "token", None  # header auth: not CSRF-prone
        else:
            sess = auth.get_session(ctx.db, request.cookies.get(auth.COOKIE))
            if sess:
                user, csrf = "admin", sess["csrf"]
        request.state.user = user
        request.state.csrf = csrf
        if not public:
            if user is None:
                return JSONResponse({"error": "unauthorized"}, status_code=401)
            if request.method not in ("GET", "HEAD", "OPTIONS") and csrf is not None:
                presented = request.headers.get(auth.CSRF_HEADER, "")
                if not presented or not _ct_eq(presented, csrf):
                    return JSONResponse({"error": "csrf"}, status_code=403)
        elif request.method not in ("GET", "HEAD") and path in ("/api/login", "/api/logout"):
            # login/logout: require the custom header so that cross-site forms cannot post
            if request.headers.get(auth.CSRF_HEADER) is None:
                return JSONResponse({"error": "csrf"}, status_code=403)
        try:
            resp = await call_next(request)
        except Exception:  # never leak a traceback to the client
            log.exception("unhandled error on %s", path)
            resp = JSONResponse({"error": "internal error"}, status_code=500)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Content-Security-Policy",
                                "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
                                "frame-src 'self'; frame-ancestors 'self'; base-uri 'none'; form-action 'self'")
        if path.startswith("/api/"):
            resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    def cfg_():
        return ctx.cfg

    # ------------------------------------------------------------------ static / session
    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-cache"})

    app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")

    @app.get("/healthz")
    def healthz():
        return {"ok": True, "version": __version__}

    @app.get("/api/session")
    def session(request: Request):
        cfg = cfg_()
        return {
            "authenticated": request.state.user is not None, "user": request.state.user,
            "csrf": request.state.csrf, "version": __version__, "setup_complete": bool(cfg.get("setup_complete")),
            "auth_mode": cfg.get("web.auth_mode"), "needs_setup_code": auth.needs_setup_code(cfg),
            "password_set": bool(cfg.get("web.admin_password_hash")), "token_set": bool(auth.api_token(cfg)),
            "language": cfg.get("language", "en"), "languages": i18n.languages(), "role": cfg.get("role"),
            "host": cfg.host,
        }

    @app.post("/api/login")
    async def login(request: Request):
        cfg = cfg_()
        client_ip = request.client.host if request.client else "?"
        now = time.monotonic()
        recent = [t for t in _FAILED.get(client_ip, []) if now - t < 300]
        _FAILED[client_ip] = recent
        if len(recent) >= 8:
            raise HTTPException(429, "too many failed logins, try again later")
        body = _json_body(await _read_json(request))
        pw, tok, code = str(body.get("password") or ""), str(body.get("token") or ""), str(body.get("setup_code") or "")
        ok = False
        if pw and auth.verify_password(cfg.get("web.admin_password_hash", ""), pw):
            ok = True
        elif tok and auth.token_ok(cfg, tok):
            ok = True
        elif code and auth.needs_setup_code(cfg):
            expected = auth.setup_code(cfg.state, create=False)
            ok = bool(expected) and _ct_eq(code.strip(), expected)
        if not ok:
            log.warning("failed login from %s", client_ip)
            _FAILED.setdefault(client_ip, []).append(time.monotonic())
            raise HTTPException(401, "invalid credentials")
        _FAILED.pop(client_ip, None)
        token, csrf = auth.create_session(ctx.db, int(cfg.get("web.session_hours", 12)))
        resp = JSONResponse({"ok": True, "csrf": csrf})
        resp.set_cookie(auth.COOKIE, token, httponly=True, samesite="strict", secure=bool(cfg.get("web.secure_cookie")),
                        max_age=int(cfg.get("web.session_hours", 12)) * 3600, path="/")
        return resp

    @app.post("/api/logout")
    def logout(request: Request):
        auth.delete_session(ctx.db, request.cookies.get(auth.COOKIE))
        resp = JSONResponse({"ok": True})
        resp.delete_cookie(auth.COOKIE, path="/")
        return resp

    @app.get("/api/i18n")
    def i18n_list():
        return {"languages": [{"code": c, "name": i18n.catalog(c).get("lang.name", c)} for c in i18n.languages()],
                "default": i18n.DEFAULT}

    @app.get("/api/i18n/{lang}")
    def i18n_get(lang: str):
        if lang not in i18n.languages():
            raise HTTPException(404, "unknown language")
        return i18n.catalog(lang)

    # ------------------------------------------------------------------ agent
    @app.get("/api/agent/snapshot")
    def agent_snapshot(request: Request):
        cfg = cfg_()
        if cfg.get("role") != "agent":
            raise HTTPException(404, "not an agent")
        authz = request.headers.get("authorization", "")
        if not authz.lower().startswith("bearer ") or not auth.agent_token_ok(cfg, authz[7:].strip()):
            raise HTTPException(401, "unauthorized")
        from ..hub import build_snapshot
        return build_snapshot(cfg, ctx.db)

    # ------------------------------------------------------------------ overview
    @app.get("/api/overview")
    def overview(host: str | None = None):
        cfg = cfg_()
        db = ctx.db
        counts = open_counts(db, host or None)
        hosts = []
        for r in db.q("SELECT * FROM hosts ORDER BY host"):
            c = open_counts(db, r["host"])
            hosts.append({"host": r["host"], "role": r["role"], "status": r["status"], "last_scan": r["last_scan"],
                          "last_contact": r["last_contact"], "counts": c})
        last = db.one("SELECT * FROM scans ORDER BY id DESC LIMIT 1")
        last_scan = None
        if last:
            try:
                coll = json.loads(last["collectors"] or "{}")
            except ValueError:
                coll = {}
            last_scan = {"id": last["id"], "host": last["host"], "started_at": last["started_at"],
                         "finished_at": last["finished_at"], "status": last["status"],
                         "summary": json.loads(last["summary"] or "{}"), "collectors": coll}
        tools = [dict(r) for r in db.q("SELECT host, name, version, db_age, updated_at FROM tools ORDER BY host, name")]
        for t in tools:
            t.pop("info", None)
        accepted = db.one("SELECT COUNT(*) n FROM findings WHERE state='accepted'" + (" AND host=?" if host else ""),
                          (host,) if host else ())["n"]
        return {"counts": counts, "accepted": accepted, "hosts": hosts, "last_scan": last_scan,
                "trend": _trend(db, host, 90), "next": next_runs(cfg), "tools": tools,
                "trigger_pending": cfg.trigger_path.exists(), "role": cfg.get("role"),
                "modules": {n: _enabled_flag(cfg, n) for n in PHASE2_COLLECTORS}}

    # ------------------------------------------------------------------ findings
    @app.get("/api/findings")
    def findings(host: str | None = None, kind: str | None = None, severity: str | None = None,
                 kev: str | None = None, state: str | None = "open", source: str | None = None, q: str | None = None,
                 sort: str = "priority", limit: int = 200, offset: int = 0):
        where, args = [], []
        for col, val, allowed in (("host", host, None), ("kind", kind, None), ("source", source, None),
                                  ("severity", severity, ["critical", "high", "medium", "low", "unknown", "none"])):
            if val:
                vals = [v for v in val.split(",") if v][:20]
                if allowed:
                    vals = [v for v in vals if v in allowed]
                if vals:
                    where.append(f"{col} IN ({','.join('?' * len(vals))})")
                    args += vals
        if state and state != "all":
            vals = [s for s in state.split(",") if s in ("open", "fixed", "accepted", "false_positive")]
            if vals:
                where.append(f"state IN ({','.join('?' * len(vals))})")
                args += vals
        if kev in ("1", "true", "yes"):
            where.append("kev=1")
        if q:
            q = q[:100]
            where.append("(vuln_id LIKE ? OR package LIKE ? OR title LIKE ? OR component LIKE ?)")
            args += [f"%{q}%"] * 4
        sql_where = (" WHERE " + " AND ".join(where)) if where else ""
        order = SORTS.get(sort, SORTS["priority"])
        limit = max(1, min(int(limit), 1000))
        offset = max(0, int(offset))
        total = ctx.db.one(f"SELECT COUNT(*) n FROM findings{sql_where}", args)["n"]
        rows = ctx.db.q(f"SELECT * FROM findings{sql_where} ORDER BY {order} LIMIT ? OFFSET ?", [*args, limit, offset])
        items = []
        for r in rows:
            d = row_to_finding_dict(r)
            ex = d.get("extra") or {}
            d["extra"] = {k: ex[k] for k in ("image", "kev_due_date", "booted_only", "target") if k in ex}
            items.append(d)
        facets = {
            "hosts": [r["host"] for r in ctx.db.q("SELECT DISTINCT host FROM findings ORDER BY host")],
            "kinds": [r["kind"] for r in ctx.db.q("SELECT DISTINCT kind FROM findings ORDER BY kind")],
            "sources": [r["source"] for r in ctx.db.q("SELECT DISTINCT source FROM findings ORDER BY source")],
        }
        return {"total": total, "items": items, "facets": facets}

    @app.get("/api/findings/{key}")
    def finding(key: str):
        if not KEY_RE.match(key):
            raise HTTPException(400, "invalid key")
        r = ctx.db.one("SELECT * FROM findings WHERE key=?", (key,))
        if r is None:
            raise HTTPException(404, "not found")
        d = row_to_finding_dict(r)
        d["events"] = [dict(e) for e in ctx.db.q("SELECT ts,type,detail FROM events WHERE key=? ORDER BY id DESC LIMIT 50",
                                                  (key,))]
        d["links"] = _links(d)
        return d

    @app.post("/api/findings/{key}/action")
    async def finding_action(key: str, request: Request):
        if not KEY_RE.match(key):
            raise HTTPException(400, "invalid key")
        body = _json_body(await _read_json(request))
        try:
            return set_state(ctx.db, key, str(body.get("action", "")), str(body.get("reason") or ""),
                             str(body["until"]) if body.get("until") else None)
        except ActionError as e:
            raise HTTPException(400, str(e))

    # ------------------------------------------------------------------ reports
    @app.get("/api/reports")
    def reports_list(kind: str | None = None):
        sql, args = "SELECT id, kind, period, created_at, summary FROM reports", []
        if kind in ("daily", "weekly", "monthly"):
            sql += " WHERE kind=?"
            args.append(kind)
        out = []
        for r in ctx.db.q(sql + " ORDER BY created_at DESC LIMIT 500", args):
            d = dict(r)
            try:
                d["summary"] = json.loads(d["summary"])
            except ValueError:
                d["summary"] = {}
            out.append(d)
        return {"items": out}

    def _report_row(rid: int):
        r = ctx.db.one("SELECT * FROM reports WHERE id=?", (rid,))
        if r is None:
            raise HTTPException(404, "not found")
        return r

    def _safe_report_path(p: str) -> Path:
        path = Path(p).resolve()
        base = cfg_().reports_dir.resolve()
        if base not in path.parents or not path.is_file():
            raise HTTPException(404, "report file missing")
        return path

    @app.get("/api/reports/{rid}/html")
    def report_html(rid: int):
        p = _safe_report_path(_report_row(rid)["html_path"])
        return HTMLResponse(p.read_text(encoding="utf-8"), headers={
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; sandbox allow-popups allow-popups-to-escape-sandbox; frame-ancestors 'self'",
            "X-Frame-Options": "SAMEORIGIN"})

    @app.get("/api/reports/{rid}/json")
    def report_json(rid: int):
        p = _safe_report_path(_report_row(rid)["json_path"])
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except ValueError:
            raise HTTPException(500, "report unreadable")

    @app.get("/api/reports/compare/{a}/{b}")
    def report_compare(a: int, b: int):
        ra, rb = _report_row(a), _report_row(b)
        if ra["kind"] != "monthly" or rb["kind"] != "monthly":
            raise HTTPException(400, "only monthly reports can be compared")
        sa, sb = json.loads(ra["summary"]), json.loads(rb["summary"])
        if sa.get("period", "") > sb.get("period", ""):
            sa, sb = sb, sa
        return {"a": sa, "b": sb, "delta": compare_reports(sa, sb)}

    # ------------------------------------------------------------------ actions
    @app.post("/api/scan")
    def scan_now():
        from ..scan import write_trigger
        write_trigger(cfg_(), {"action": "scan"})
        return {"ok": True, "queued": True}

    @app.post("/api/notify/test")
    async def notify_test(request: Request):
        from ..scan import write_trigger
        body = _json_body(await _read_json(request))
        ch = body.get("channel")
        if ch not in ("push", "mail", None):
            raise HTTPException(400, "invalid channel")
        write_trigger(cfg_(), {"action": "notify-test", "channel": ch})
        return {"ok": True, "queued": True}

    @app.get("/api/actions")
    def actions():
        p = cfg_().state / "actions.json"
        try:
            return {"items": json.loads(p.read_text()), "trigger_pending": cfg_().trigger_path.exists()}
        except (OSError, ValueError):
            return {"items": [], "trigger_pending": cfg_().trigger_path.exists()}

    @app.get("/api/scans")
    def scans(limit: int = 30):
        rows = ctx.db.q("SELECT id, host, started_at, finished_at, trigger, status, summary FROM scans ORDER BY id DESC LIMIT ?",
                        (max(1, min(limit, 200)),))
        return {"items": [{**dict(r), "summary": json.loads(r["summary"] or "{}")} for r in rows]}

    # ------------------------------------------------------------------ config / wizard
    @app.get("/api/config")
    def get_config():
        cfg = cfg_()
        data = config_mod.redact(cfg.data)
        secrets_ = {}
        for field, (path, _name) in SECRET_FIELDS.items():
            secrets_[field] = config_mod.secret_status(cfg.get(path, ""))
        agents = [{**a, "token_status": config_mod.secret_status(a.get("token_file", ""))}
                  for a in cfg.get("hub.agents") or []]
        collectors = {}
        for name, cls in load_all().items():
            collectors[name] = {"implemented": cls.implemented, "phase2": name in PHASE2_COLLECTORS}
        return {"config": data, "locked": sorted(cfg.locked), "secrets": secrets_, "agents": agents,
                "admin_password": "set" if cfg.get("web.admin_password_hash") else "unset",
                "presets": MATRIX_PRESETS, "events": EVENTS, "severities": SEVERITIES, "collectors": collectors,
                "enrichers": ENRICHERS, "languages": i18n.languages(), "warnings": cfg.warnings,
                "state_dir": str(cfg.state)}

    @app.put("/api/config")
    async def put_config(request: Request):
        cfg = cfg_()
        body = _json_body(await _read_json(request))
        changes = body.get("changes") or {}
        if not isinstance(changes, dict):
            raise HTTPException(400, "changes must be an object")
        changes = json.loads(json.dumps(changes))
        # never accept hashes or *_file paths of UI-managed secrets directly from the browser
        if config_mod.get_path(changes, "web.admin_password_hash") is not None:
            raise HTTPException(400, "use admin_password")
        errors: list[str] = []
        pw = body.get("admin_password")
        if pw:
            if config_mod.is_locked("web.admin_password_hash", cfg.locked):
                errors.append("web.admin_password_hash: locked by system configuration")
            else:
                try:
                    config_mod.set_path(changes, "web.admin_password_hash", auth.hash_password(str(pw)))
                except ValueError as e:
                    errors.append(str(e))
        for field, value in (body.get("secrets") or {}).items():
            if field not in SECRET_FIELDS or not isinstance(value, str) or not value.strip():
                continue
            path, name = SECRET_FIELDS[field]
            if config_mod.is_locked(path, cfg.locked):
                errors.append(f"{path}: locked by system configuration")
                continue
            config_mod.set_path(changes, path, config_mod.write_secret(cfg, name, value))
        agent_tokens = body.get("agent_tokens") or {}
        agents = config_mod.get_path(changes, "hub.agents")
        if isinstance(agents, list):
            for a in agents:
                if not isinstance(a, dict):
                    continue
                a.pop("token_status", None)
                tok = agent_tokens.get(a.get("name", "")) if isinstance(agent_tokens, dict) else None
                if tok and isinstance(tok, str):
                    a["token_file"] = config_mod.write_secret(cfg, f"agent-{a.get('name', '')}", tok)
        if errors:
            return JSONResponse({"ok": False, "errors": errors}, status_code=400)
        errors = config_mod.save_user_config(cfg, changes, i18n.languages())
        if errors:
            return JSONResponse({"ok": False, "errors": errors}, status_code=400)
        if pw:  # password changed: end all other sessions
            auth.drop_other_sessions(ctx.db, request.cookies.get(auth.COOKIE))
        ctx.reload()
        return {"ok": True}

    @app.get("/api/detect")
    def detect_env():
        from .. import detect as detect_mod
        cfg = cfg_()
        saved = detect_mod.load_saved(cfg) or {}
        try:
            live = detect_mod.detect(cfg, privileged=False)
        except Exception as e:
            log.warning("live detection failed: %s", e)
            live = {}
        out = {**live}
        # the root scan service sees more (rootful containers, process names): prefer its results
        for k in ("containers", "ports", "auth_sources"):
            if saved.get(k):
                out[k] = saved[k]
        out["from_scan"] = bool(saved)
        return out

    @app.post("/api/agents/test")
    async def agents_test(request: Request):
        from ..hub import test_agent
        cfg = cfg_()
        body = _json_body(await _read_json(request))
        url = str(body.get("url") or "")
        if not url.startswith(("http://", "https://")) or len(url) > 500:
            raise HTTPException(400, "invalid url")
        token = str(body.get("token") or "")
        tf = str(body.get("token_file") or "")
        if not token and tf:
            # only token files of configured agents - never an arbitrary path chosen by the client
            known = {str(a.get("token_file")) for a in cfg.get("hub.agents") or [] if a.get("token_file")}
            if tf not in known:
                raise HTTPException(400, "unknown token file")
            token = config_mod.read_secret(tf) or ""
        if not token:
            raise HTTPException(400, "token required")
        return test_agent(url, token, verify=bool(cfg.get("hub.verify_tls", True)))

    @app.post("/api/wizard/complete")
    def wizard_complete():
        from ..scan import write_trigger
        cfg = cfg_()
        if not cfg.get("web.admin_password_hash") and cfg.get("web.auth_mode") == "password" and not auth.api_token(cfg):
            raise HTTPException(400, "set an admin password first")
        errors = config_mod.save_user_config(cfg, {"setup_complete": True}) if not config_mod.is_locked(
            "setup_complete", cfg.locked) else []
        if errors:
            return JSONResponse({"ok": False, "errors": errors}, status_code=400)
        try:
            (cfg.state / "setup-code").unlink()
        except OSError:
            pass
        write_trigger(cfg, {"action": "scan"})
        ctx.reload()
        return {"ok": True}

    @app.get("/api/hosts")
    def hosts():
        return {"items": [dict(r) for r in ctx.db.q("SELECT host, role, last_scan, last_contact, status FROM hosts")]}

    @app.get("/api/trend")
    def trend(host: str | None = None, days: int = 90):
        return {"items": _trend(ctx.db, host, max(1, min(days, 730)))}

    return app


def _ct_eq(a: str, b: str) -> bool:
    import hmac
    return hmac.compare_digest(a.encode(), b.encode())


async def _read_json(request: Request) -> Any:
    raw = await request.body()
    if len(raw) > 256 * 1024:
        raise HTTPException(413, "request too large")
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except ValueError:
        raise HTTPException(400, "invalid JSON")


def _enabled_flag(cfg, name: str):
    return cfg.get(f"collectors.{name}.enabled", False)


def _links(d: dict) -> list[dict]:
    vid = d.get("id", "")
    links = []
    if vid.startswith("CVE-"):
        links += [{"label": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{vid}"},
                  {"label": "CVE.org", "url": f"https://www.cve.org/CVERecord?id={vid}"}]
    elif vid.startswith("GHSA-"):
        links.append({"label": "GitHub Advisory", "url": f"https://github.com/advisories/{vid}"})
    if d.get("url") and all(d["url"] != x["url"] for x in links):
        links.append({"label": "Advisory", "url": d["url"]})
    for ref in (d.get("extra") or {}).get("references", [])[:4]:
        if isinstance(ref, str) and ref.startswith("https://") and all(ref != x["url"] for x in links):
            links.append({"label": ref.split("/")[2], "url": ref})
    return links


def _trend(db: DB, host: str | None, days: int) -> list[dict]:
    since = (utcnow() - timedelta(days=days)).isoformat()
    sql, args = "SELECT ts, host, counts FROM history WHERE ts>=?", [since]
    if host:
        sql += " AND host=?"
        args.append(host)
    per_day: dict[str, dict[str, dict]] = {}
    for r in db.q(sql + " ORDER BY ts", args):
        try:
            c = json.loads(r["counts"])
        except ValueError:
            continue
        day = datetime.fromisoformat(r["ts"]).astimezone().date().isoformat()
        per_day.setdefault(day, {})[r["host"]] = c  # last record of the day wins
    out = []
    last_seen: dict[str, dict] = {}
    for day in sorted(per_day):
        last_seen.update(per_day[day])
        tot = {s: 0 for s in ("critical", "high", "medium", "low", "unknown", "kev", "total")}
        for c in last_seen.values():
            for s in tot:
                tot[s] += int(c.get(s, 0) or 0)
        out.append({"day": day, **tot})
    return out


def main() -> None:
    import argparse

    import uvicorn
    p = argparse.ArgumentParser(prog="secwatch-web")
    p.add_argument("--host", help="listen address (default from config web.listen)")
    p.add_argument("--port", type=int, help="listen port (default from config web.port)")
    p.add_argument("--proxy-headers", action="store_true", help="trust X-Forwarded-* from the local proxy")
    args = p.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    if os.geteuid() == 0 and not os.environ.get("SECWATCH_ALLOW_ROOT_WEB"):
        raise SystemExit("secwatch-web must not run as root (set SECWATCH_ALLOW_ROOT_WEB=1 to override)")
    cfg = config_mod.load()
    app = create_app()
    uvicorn.run(app, host=args.host or cfg.get("web.listen", "127.0.0.1"), port=args.port or int(cfg.get("web.port", 8478)),
                proxy_headers=args.proxy_headers, forwarded_allow_ips="127.0.0.1", log_level="info", access_log=False)


if __name__ == "__main__":
    main()
