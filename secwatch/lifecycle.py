"""Finding lifecycle: snapshot diffing (new / still_open / fixed) and user state changes."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime

from .db import DB, now_iso, parse_ts, row_to_finding_dict, utcnow
from .models import Finding

ACTIVE_STATES = ("open", "accepted")
STATES = ("open", "fixed", "accepted", "false_positive")


@dataclass
class Scope:
    """Which part of the finding space a collector run is authoritative for.

    A successful collector run covers all kinds of its source; a failed run only covers its
    scan_error finding, so earlier findings are not wrongly marked as fixed."""
    source: str
    kinds: list[str] | None = None
    keep_components: list[str] = field(default_factory=list)  # partial failure: do not mark fixed


@dataclass
class Diff:
    new: list[dict] = field(default_factory=list)
    still_open: list[dict] = field(default_factory=list)
    fixed: list[dict] = field(default_factory=list)
    reopened: list[dict] = field(default_factory=list)  # subset of new: previously fixed
    newly_kev: list[dict] = field(default_factory=list)  # still open, became KEV listed
    expired: list[dict] = field(default_factory=list)  # acceptances that expired

    def counts(self) -> dict:
        return {"new": len(self.new), "still_open": len(self.still_open), "fixed": len(self.fixed),
                "reopened": len(self.reopened), "newly_kev": len(self.newly_kev)}


def _row_values(f: Finding) -> dict:
    ex = f.extra or {}
    return {
        "host": f.host, "source": f.source, "kind": f.kind, "vuln_id": f.id, "package": f.package or "",
        "installed": f.installed or "", "fixed_version": f.fixed or "", "severity": f.severity,
        "cvss": f.cvss, "title": f.title or "", "url": f.url or "", "component": f.component or "",
        "extra": json.dumps(ex, sort_keys=True, default=str), "kev": 1 if ex.get("kev") else 0,
        "epss": ex.get("epss"), "epss_pct": ex.get("epss_percentile"),
    }


def _event(conn, ts: str, scan_id: int | None, host: str, key: str, typ: str, detail: str = "") -> None:
    conn.execute("INSERT INTO events(ts,scan_id,host,key,type,detail) VALUES(?,?,?,?,?,?)",
                 (ts, scan_id, host, key, typ, detail))


def expire_acceptances(db: DB, now: datetime | None = None) -> list[dict]:
    now = now or utcnow()
    ts = now.replace(microsecond=0).isoformat()
    out = []
    with db.tx() as conn:
        for r in conn.execute("SELECT * FROM findings WHERE state='accepted' AND until IS NOT NULL").fetchall():
            until = parse_ts(r["until"])
            if until and until <= now:
                conn.execute("UPDATE findings SET state='open', state_changed_at=?, reason='' WHERE key=?",
                             (ts, r["key"]))
                _event(conn, ts, None, r["host"], r["key"], "acceptance_expired")
                d = row_to_finding_dict(r)
                d["state"] = "open"
                out.append(d)
    return out


def apply_snapshot(db: DB, host: str, findings: list[Finding], scopes: list[Scope],
                   scan_id: int | None, now: datetime | None = None) -> Diff:
    now = now or utcnow()
    ts = now.replace(microsecond=0).isoformat()
    diff = Diff()
    diff.expired = expire_acceptances(db, now)

    # merge duplicates (same key) - keep highest severity data, join installed versions
    present: dict[str, Finding] = {}
    for f in findings:
        k = f.key
        if k in present:
            old = present[k]
            vers = {v for v in (old.installed.split(", ") + [f.installed]) if v}
            old.installed = ", ".join(sorted(vers))
            if (f.cvss or 0) > (old.cvss or 0):
                old.cvss, old.severity = f.cvss, f.severity
        else:
            present[k] = f

    with db.tx() as conn:
        existing: dict[str, dict] = {}
        for sc in scopes:
            sql = "SELECT * FROM findings WHERE host=? AND source=?"
            args: list = [host, sc.source]
            if sc.kinds:
                sql += " AND kind IN (%s)" % ",".join("?" * len(sc.kinds))
                args += sc.kinds
            for r in conn.execute(sql, args).fetchall():
                existing[r["key"]] = dict(r)
        # findings outside the declared scopes (should not happen) are still looked up
        missing = [k for k in present if k not in existing]
        for i in range(0, len(missing), 500):
            chunk = missing[i:i + 500]
            for r in conn.execute("SELECT * FROM findings WHERE key IN (%s)" % ",".join("?" * len(chunk)),
                                  chunk).fetchall():
                existing[r["key"]] = dict(r)

        for k, f in present.items():
            vals = _row_values(f)
            row = existing.get(k)
            if row is None:
                cols = ["key", *vals.keys(), "state", "first_seen", "last_seen", "state_changed_at"]
                conn.execute(
                    "INSERT INTO findings(%s) VALUES(%s)" % (",".join(cols), ",".join("?" * len(cols))),
                    [k, *vals.values(), "open", ts, ts, ts])
                _event(conn, ts, scan_id, host, k, "new")
                d = {**f.to_dict(), "state": "open", "first_seen": ts, "kev": bool(vals["kev"]),
                     "epss": vals["epss"]}
                diff.new.append(d)
                continue
            sets = ", ".join(f"{c}=?" for c in vals) + ", last_seen=?"
            args = [*vals.values(), ts]
            d = {**f.to_dict(), "first_seen": row["first_seen"], "kev": bool(vals["kev"]), "epss": vals["epss"]}
            if row["state"] == "fixed":
                sets += ", state='open', fixed_at=NULL, reopened=reopened+1, state_changed_at=?"
                args.append(ts)
                _event(conn, ts, scan_id, host, k, "reopened")
                d["state"] = "open"
                diff.new.append(d)
                diff.reopened.append(d)
            else:
                d["state"] = row["state"]
                diff.still_open.append(d)
                if vals["kev"] and not row["kev"] and row["state"] == "open":
                    diff.newly_kev.append(d)
            conn.execute(f"UPDATE findings SET {sets} WHERE key=?", [*args, k])

        keep = {(sc.source, c) for sc in scopes for c in sc.keep_components}
        for k, row in existing.items():
            if k in present or row["state"] not in ACTIVE_STATES or row["host"] != host:
                continue
            if (row["source"], row["component"]) in keep and row["kind"] != "scan_error":
                continue
            conn.execute("UPDATE findings SET state='fixed', fixed_at=?, state_changed_at=? WHERE key=?",
                         (ts, ts, k))
            _event(conn, ts, scan_id, host, k, "fixed")
            d = row_to_finding_dict(row)
            d["state"] = "fixed"
            d["fixed_at"] = ts
            diff.fixed.append(d)

        if scan_id is not None:
            conn.executemany("INSERT OR IGNORE INTO scan_items(scan_id,key) VALUES(?,?)",
                             [(scan_id, k) for k in present])
    record_history(db, host, scan_id, ts)
    return diff


def open_counts(db: DB, host: str | None = None) -> dict:
    sql = "SELECT severity, kind, kev, COUNT(*) n FROM findings WHERE state='open'"
    args: list = []
    if host:
        sql += " AND host=?"
        args.append(host)
    sql += " GROUP BY severity, kind, kev"
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0, "kev": 0, "total": 0,
              "by_kind": {}}
    for r in db.q(sql, args):
        sev = r["severity"] if r["severity"] in counts else "unknown"
        counts[sev] += r["n"]
        counts["total"] += r["n"]
        counts["by_kind"][r["kind"]] = counts["by_kind"].get(r["kind"], 0) + r["n"]
        if r["kev"]:
            counts["kev"] += r["n"]
    return counts


def record_history(db: DB, host: str, scan_id: int | None, ts: str | None = None) -> None:
    db.exec("INSERT INTO history(ts,scan_id,host,counts) VALUES(?,?,?,?)",
            (ts or now_iso(), scan_id, host, json.dumps(open_counts(db, host))))


class ActionError(ValueError):
    pass


def set_state(db: DB, key: str, action: str, reason: str = "", until: str | None = None) -> dict:
    """User actions: accept (reason, optional expiry), false_positive (reason), reopen."""
    r = db.one("SELECT * FROM findings WHERE key=?", (key,))
    if r is None:
        raise ActionError("unknown finding")
    reason = (reason or "").strip()[:500]
    ts = now_iso()
    if action == "accept":
        if r["state"] == "fixed":
            raise ActionError("finding is already fixed")
        if not reason:
            raise ActionError("reason required")
        if until:
            u = parse_ts(until if "T" in until else until + "T23:59:59")
            if u is None:
                raise ActionError("invalid expiry date")
            if u <= utcnow():
                raise ActionError("expiry must be in the future")
            until = u.replace(microsecond=0).isoformat()
        new_state = "accepted"
    elif action == "false_positive":
        if not reason:
            raise ActionError("reason required")
        new_state, until = "false_positive", None
    elif action == "reopen":
        if r["state"] not in ("accepted", "false_positive"):
            raise ActionError("only accepted or false-positive findings can be reopened")
        new_state, reason, until = "open", "", None
    else:
        raise ActionError("unknown action")
    with db.tx() as conn:
        conn.execute("UPDATE findings SET state=?, reason=?, until=?, state_changed_at=? WHERE key=?",
                     (new_state, reason, until, ts, key))
        _event(conn, ts, None, r["host"], key, action, reason)
    record_history(db, r["host"], None, ts)
    out = db.one("SELECT * FROM findings WHERE key=?", (key,))
    return row_to_finding_dict(out)
