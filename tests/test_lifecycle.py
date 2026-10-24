from datetime import timedelta

import pytest

from secwatch.db import utcnow
from secwatch.lifecycle import ActionError, Scope, apply_snapshot, open_counts, set_state
from secwatch.models import Finding, priority_tuple, severity_from_cvss, stable_key


def F(id_, pkg="openssl", sev="high", source="nix", kind="vuln", comp="", host="h", **extra):
    return Finding(host=host, source=source, kind=kind, id=id_, package=pkg, installed="1.0", severity=sev,
                   cvss=7.5, component=comp, extra=dict(extra))


def test_stable_key():
    a = F("CVE-1")
    b = F("CVE-1")
    b.installed = "2.0"
    assert a.key == b.key == stable_key("h", "nix", "vuln", "CVE-1", "openssl", "")
    assert F("CVE-1", comp="web").key != a.key


def test_severity_bands():
    assert [severity_from_cvss(x) for x in (9.0, 8.9, 7.0, 4.0, 3.9, 0.1, 0.0, None)] == \
        ["critical", "high", "high", "medium", "low", "low", "none", "unknown"]


def test_priority_order():
    items = [
        ("old-high", priority_tuple(False, None, 8.0, "high", "2026-01-01")),
        ("kev-low", priority_tuple(True, 0.01, 3.0, "low", "2026-05-01")),
        ("epss", priority_tuple(False, 0.9, 5.0, "medium", "2026-05-01")),
        ("new-high", priority_tuple(False, None, 8.0, "high", "2026-03-01")),
        ("crit", priority_tuple(False, None, 9.8, "critical", "2026-06-01")),
    ]
    assert [n for n, _ in sorted(items, key=lambda x: x[1])] == ["kev-low", "epss", "crit", "old-high", "new-high"]


def test_new_still_open_fixed_reopened(db):
    d1 = apply_snapshot(db, "h", [F("CVE-1"), F("CVE-2")], [Scope("nix")], None)
    assert len(d1.new) == 2 and not d1.fixed
    d2 = apply_snapshot(db, "h", [F("CVE-1")], [Scope("nix")], None)
    assert len(d2.still_open) == 1 and [f["id"] for f in d2.fixed] == ["CVE-2"]
    assert db.one("SELECT state FROM findings WHERE vuln_id='CVE-2'")["state"] == "fixed"
    d3 = apply_snapshot(db, "h", [F("CVE-1"), F("CVE-2")], [Scope("nix")], None)
    assert [f["id"] for f in d3.reopened] == ["CVE-2"] and len(d3.new) == 1
    r = db.one("SELECT * FROM findings WHERE vuln_id='CVE-2'")
    assert r["state"] == "open" and r["reopened"] == 1 and r["fixed_at"] is None


def test_failed_collector_does_not_fix(db):
    apply_snapshot(db, "h", [F("CVE-1")], [Scope("nix")], None)
    err = Finding(host="h", source="nix", kind="scan_error", id="scan_error", title="boom")
    d = apply_snapshot(db, "h", [err], [Scope("nix", kinds=["scan_error"])], None)
    assert not d.fixed and [f["kind"] for f in d.new] == ["scan_error"]
    assert db.one("SELECT state FROM findings WHERE vuln_id='CVE-1'")["state"] == "open"
    d = apply_snapshot(db, "h", [F("CVE-1")], [Scope("nix")], None)
    assert [f["kind"] for f in d.fixed] == ["scan_error"]


def test_scopes_are_per_source_and_host(db):
    apply_snapshot(db, "h", [F("CVE-1"), F("CVE-9", source="containers", comp="web")], [Scope("nix"), Scope("containers")], None)
    apply_snapshot(db, "other", [F("CVE-1", host="other")], [Scope("nix")], None)
    d = apply_snapshot(db, "h", [], [Scope("nix")], None)
    assert [f["id"] for f in d.fixed] == ["CVE-1"]
    assert db.one("SELECT state FROM findings WHERE vuln_id='CVE-9'")["state"] == "open"
    assert db.one("SELECT state FROM findings WHERE host='other'")["state"] == "open"


def test_keep_components(db):
    apply_snapshot(db, "h", [F("CVE-1", source="containers", comp="web"), F("CVE-2", source="containers", comp="db")],
                   [Scope("containers")], None)
    d = apply_snapshot(db, "h", [F("CVE-2", source="containers", comp="db")], [Scope("containers", keep_components=["web"])], None)
    assert not d.fixed


def test_duplicates_are_merged(db):
    a, b = F("CVE-1"), F("CVE-1")
    b.installed = "1.1"
    d = apply_snapshot(db, "h", [a, b], [Scope("nix")], None)
    assert len(d.new) == 1
    assert db.one("SELECT installed FROM findings")["installed"] == "1.0, 1.1"


def test_accept_expiry_and_reopen(db):
    apply_snapshot(db, "h", [F("CVE-1")], [Scope("nix")], None)
    key = F("CVE-1").key
    with pytest.raises(ActionError):
        set_state(db, key, "accept", "")
    until = (utcnow() + timedelta(days=3)).date().isoformat()
    r = set_state(db, key, "accept", "mitigated by firewall", until)
    assert r["state"] == "accepted" and r["until"].startswith(until)
    assert open_counts(db)["total"] == 0
    d = apply_snapshot(db, "h", [F("CVE-1")], [Scope("nix")], None)
    assert d.still_open[0]["state"] == "accepted"
    d = apply_snapshot(db, "h", [F("CVE-1")], [Scope("nix")], None, now=utcnow() + timedelta(days=5))
    assert [f["id"] for f in d.expired] == ["CVE-1"]
    assert db.one("SELECT state FROM findings")["state"] == "open"


def test_false_positive_stays_closed(db):
    apply_snapshot(db, "h", [F("CVE-1")], [Scope("nix")], None)
    key = F("CVE-1").key
    set_state(db, key, "false_positive", "Drupal module, not the Haskell lib")
    d = apply_snapshot(db, "h", [], [Scope("nix")], None)
    assert not d.fixed
    d = apply_snapshot(db, "h", [F("CVE-1")], [Scope("nix")], None)
    assert not d.new and d.still_open[0]["state"] == "false_positive"
    r = set_state(db, key, "reopen")
    assert r["state"] == "open"
    with pytest.raises(ActionError):
        set_state(db, key, "reopen")


def test_newly_kev(db):
    apply_snapshot(db, "h", [F("CVE-1")], [Scope("nix")], None)
    d = apply_snapshot(db, "h", [F("CVE-1", kev=True)], [Scope("nix")], None)
    assert [f["id"] for f in d.newly_kev] == ["CVE-1"]
    assert db.one("SELECT kev FROM findings")["kev"] == 1
    d = apply_snapshot(db, "h", [F("CVE-1", kev=True)], [Scope("nix")], None)
    assert not d.newly_kev


def test_history_recorded(db):
    apply_snapshot(db, "h", [F("CVE-1", sev="critical")], [Scope("nix")], None)
    import json
    c = json.loads(db.one("SELECT counts FROM history ORDER BY id DESC LIMIT 1")["counts"])
    assert c["critical"] == 1 and c["total"] == 1
