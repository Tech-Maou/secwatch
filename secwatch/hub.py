"""Multi-host: agent snapshots and hub pulling (pull model, agents never push)."""

from __future__ import annotations

import json
import logging
import re

import httpx

from . import __version__
from .config import read_secret
from .db import DB, now_iso, row_to_finding_dict
from .enrichers import USER_AGENT
from .lifecycle import Diff, Scope, apply_snapshot
from .models import Finding

log = logging.getLogger(__name__)
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")


def build_snapshot(cfg, db: DB) -> dict:
    host = cfg.host
    rows = db.q("SELECT * FROM findings WHERE host=? AND state<>'fixed'", (host,))
    last = db.one("SELECT * FROM scans WHERE host=? AND status<>'running' ORDER BY id DESC LIMIT 1", (host,))
    scopes, last_scan = [], None
    if last:
        last_scan = {"started_at": last["started_at"], "finished_at": last["finished_at"], "status": last["status"]}
        try:
            for name, st in json.loads(last["collectors"]).items():
                if st.get("scope"):
                    scopes.append(st["scope"])
        except (ValueError, AttributeError):
            pass
    tools = [dict(r) for r in db.q("SELECT name, version, db_age, updated_at FROM tools WHERE host=?", (host,))]
    findings = []
    for r in rows:
        d = row_to_finding_dict(r)
        findings.append({k: d.get(k) for k in ("source", "kind", "id", "package", "installed", "fixed", "severity",
                                               "cvss", "title", "url", "component", "extra", "first_seen")})
    return {"host": host, "version": __version__, "generated_at": now_iso(), "last_scan": last_scan,
            "scopes": scopes, "tools": tools, "findings": findings}


def _validate_snapshot(data: dict) -> None:
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise ValueError("invalid snapshot")
    if len(data["findings"]) > 200000:
        raise ValueError("snapshot too large")


def pull_agent(cfg, db: DB, agent: dict, client: httpx.Client | None = None) -> Diff:
    name = str(agent.get("name", ""))
    if not HOST_RE.match(name):
        raise ValueError(f"invalid agent name {name!r}")
    url = str(agent.get("url", "")).rstrip("/") + "/api/agent/snapshot"
    token = read_secret(agent.get("token_file", ""))
    headers = {"User-Agent": USER_AGENT}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    own = client is None
    client = client or httpx.Client(timeout=float(cfg.get("hub.timeout", 30)), verify=bool(cfg.get("hub.verify_tls", True)))
    try:
        error = None
        data: dict = {}
        try:
            r = client.get(url, headers=headers)
            if r.status_code != 200:
                raise RuntimeError(f"HTTP {r.status_code}")
            data = r.json()
            _validate_snapshot(data)
        except (httpx.HTTPError, ValueError, RuntimeError) as e:
            error = f"{e.__class__.__name__}: {str(e)[:200]}"
    finally:
        if own:
            client.close()
    if error:
        log.warning("agent %s unreachable: %s", name, error)
        f = Finding(host=name, source="hub", kind="scan_error", id="scan_error", component=name,
                    severity="medium", title=f"agent {name} unreachable", extra={"error": error})
        diff = apply_snapshot(db, name, [f], [Scope("hub")], None)
        _host_row(db, name, "unreachable", None, {"error": error})
        return diff
    findings = []
    for d in data["findings"]:
        try:
            f = Finding.from_dict({**d, "host": name})
        except TypeError:
            continue
        findings.append(f)
    scopes = [Scope("hub")]
    for sc in data.get("scopes") or []:
        if isinstance(sc, dict) and sc.get("source"):
            scopes.append(Scope(sc["source"], sc.get("kinds"), sc.get("keep_components") or []))
    if len(scopes) == 1:  # old agent without scope info: trust the full snapshot
        scopes += [Scope(s) for s in sorted({f.source for f in findings})]
    diff = apply_snapshot(db, name, findings, scopes, None)
    ls = data.get("last_scan") or {}
    _host_row(db, name, "ok", ls.get("finished_at"), {"version": data.get("version"), "tools": data.get("tools", [])})
    for t in data.get("tools") or []:
        db.exec("INSERT INTO tools(host,name,version,db_age,info,updated_at) VALUES(?,?,?,?,?,?) "
                "ON CONFLICT(host,name) DO UPDATE SET version=excluded.version, db_age=excluded.db_age, "
                "updated_at=excluded.updated_at", (name, t.get("name", ""), t.get("version", ""), t.get("db_age"),
                                                   "{}", t.get("updated_at") or now_iso()))
    return diff


def _host_row(db: DB, host: str, status: str, last_scan: str | None, info: dict, role: str = "agent") -> None:
    db.exec("INSERT INTO hosts(host,role,last_scan,last_contact,status,info) VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(host) DO UPDATE SET role=excluded.role, last_scan=COALESCE(excluded.last_scan, hosts.last_scan), "
            "last_contact=CASE WHEN excluded.status='ok' THEN excluded.last_contact ELSE hosts.last_contact END, "
            "status=excluded.status, info=excluded.info",
            (host, role, last_scan, now_iso(), status, json.dumps(info, default=str)))


def test_agent(url: str, token: str, timeout: float = 15, verify: bool = True) -> dict:
    try:
        r = httpx.get(url.rstrip("/") + "/api/agent/snapshot", timeout=timeout, verify=verify,
                      headers={"Authorization": f"Bearer {token}", "User-Agent": USER_AGENT})
        if r.status_code != 200:
            return {"ok": False, "error": f"HTTP {r.status_code}"}
        d = r.json()
        return {"ok": True, "host": d.get("host"), "findings": len(d.get("findings") or []),
                "version": d.get("version")}
    except (httpx.HTTPError, ValueError) as e:
        return {"ok": False, "error": e.__class__.__name__}
