import json
from datetime import datetime, timedelta, timezone

from secwatch import reports
from secwatch.db import now_iso
from secwatch.lifecycle import Scope, apply_snapshot, set_state
from secwatch.models import Finding


def F(id_, sev="high", host="h", kev=False):
    return Finding(host=host, source="nix", kind="vuln", id=id_, package="pkg", installed="1", severity=sev,
                   cvss=None, extra={"kev": kev} if kev else {})


def test_daily_weekly(cfg, db):
    apply_snapshot(db, "h", [F("CVE-1", "critical", kev=True), F("CVE-2", "medium")], [Scope("nix")], None)
    rep = reports.generate(cfg, db, "daily")
    assert rep["new_count"] == 2 and rep["fixed_count"] == 0
    assert rep["new"][0]["id"] == "CVE-1"  # KEV first
    html = (cfg.reports_dir / "daily" / f"{rep['period']}.html").read_text()
    assert "CVE-1" in html and "KEV" in html
    j = json.loads((cfg.reports_dir / "daily" / f"{rep['period']}.json").read_text())
    assert j["new_count"] == 2
    apply_snapshot(db, "h", [F("CVE-1", "critical", kev=True)], [Scope("nix")], None)
    w = reports.generate(cfg, db, "weekly")
    assert w["open_count"] == 1 and list(w["groups"]) == ["critical"]
    assert w["open"][0]["age_days"] == 0
    assert db.one("SELECT COUNT(*) n FROM reports")["n"] == 2


def test_html_escapes(cfg, db):
    f = F("CVE-9")
    f.title = "<script>alert(1)</script>"
    apply_snapshot(db, "h", [f], [Scope("nix")], None)
    rep = reports.generate(cfg, db, "daily")
    html = (cfg.reports_dir / "daily" / f"{rep['period']}.html").read_text()
    assert "<script>alert" not in html and "&lt;script&gt;" in html


def test_monthly_with_comparison(cfg, db):
    now = datetime.now(timezone.utc)
    apply_snapshot(db, "h", [F("CVE-1"), F("CVE-2"), F("CVE-3", "critical")], [Scope("nix")], None)
    apply_snapshot(db, "h", [F("CVE-3", "critical")], [Scope("nix")], None)  # two fixed
    period = f"{now.year}-{now.month:02d}"
    prev = reports.prev_period(period)
    # previous month summary stored in the DB
    db.exec("INSERT INTO reports(kind,period,created_at,json_path,html_path,summary) VALUES(?,?,?,?,?,?)",
            ("monthly", prev, now_iso(), "x", "y", json.dumps({
                "kind": "monthly", "period": prev, "open_count": 5, "new_count": 1, "fixed_count": 0, "mttf_days": 3.0,
                "totals": {"total": 5, "kev": 0, "by_severity": {"critical": 2, "high": 3}, "by_kind": {"vuln": 5},
                           "by_host": {"h": {"total": 5}}}})))
    rep = reports.generate(cfg, db, "monthly", period=period)
    assert rep["new_count"] == 3 and rep["fixed_count"] == 2 and rep["open_count"] == 1
    assert rep["mttf_days"] == 0.0
    c = rep["comparison"]
    assert c["total"] == -4 and c["by_severity"]["critical"] == -1 and c["by_severity"]["high"] == -3
    assert c["fixed"] == 2 and c["mttf_days"] == -3.0
    assert rep["previous"][0]["period"] == prev
    html = (cfg.reports_dir / "monthly" / f"{period}.html").read_text()
    assert prev in html


def test_compare_function():
    a = {"totals": {"total": 3, "kev": 1, "by_severity": {"high": 3}, "by_kind": {"vuln": 3}, "by_host": {"a": {"total": 3}}},
         "new_count": 1, "fixed_count": 1, "mttf_days": None}
    b = {"totals": {"total": 5, "kev": 0, "by_severity": {"high": 2, "critical": 3}, "by_kind": {"vuln": 5},
                    "by_host": {"a": {"total": 2}, "b": {"total": 3}}}, "new_count": 4, "fixed_count": 2, "mttf_days": 2}
    d = reports.compare(a, b)
    assert d["total"] == 2 and d["kev"] == -1
    assert d["by_severity"] == {"high": -1, "critical": 3}
    assert d["by_host"] == {"a": -1, "b": 3}
    assert d["mttf_days"] is None


def test_retention(cfg, db):
    reports.generate(cfg, db, "daily")
    old = (datetime.now(timezone.utc) - timedelta(days=40)).isoformat()
    db.exec("UPDATE reports SET created_at=?", (old,))
    cfg.data["schedule"]["reports"]["retention_days"] = 30
    assert reports.apply_retention(cfg, db) == 1
    assert db.one("SELECT COUNT(*) n FROM reports")["n"] == 0
    assert not list((cfg.reports_dir / "daily").glob("*.html"))


def test_accepted_not_in_weekly(cfg, db):
    apply_snapshot(db, "h", [F("CVE-1")], [Scope("nix")], None)
    set_state(db, F("CVE-1").key, "accept", "ok")
    w = reports.generate(cfg, db, "weekly")
    assert w["open_count"] == 0
