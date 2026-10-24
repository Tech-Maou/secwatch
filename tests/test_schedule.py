from datetime import datetime, timedelta

from secwatch import schedule
from secwatch.db import now_iso


def L(*a):
    return datetime(*a).astimezone()


def test_last_occurrence():
    now = L(2026, 10, 24, 12, 0)  # Saturday
    assert schedule.last_occurrence(now, "daily", "03:30") == L(2026, 10, 24, 3, 30)
    assert schedule.last_occurrence(now, "daily", "18:00") == L(2026, 10, 23, 18, 0)
    assert schedule.last_occurrence(now, "weekly", "18:00", "sun") == L(2026, 10, 18, 18, 0)
    assert schedule.last_occurrence(now, "weekly", "10:00", "sat") == L(2026, 10, 24, 10, 0)
    assert schedule.last_occurrence(now, "monthly", "08:00", monthday=1) == L(2026, 10, 1, 8, 0)
    assert schedule.last_occurrence(L(2026, 10, 1, 7, 0), "monthly", "08:00", monthday=1) == L(2026, 9, 1, 8, 0)
    assert schedule.next_occurrence(now, "monthly", "08:00", monthday=1) == L(2026, 11, 1, 8, 0)
    assert schedule.next_occurrence(L(2026, 12, 5), "monthly", "08:00", monthday=1) == L(2027, 1, 1, 8, 0)


def test_scan_due(cfg, db):
    assert schedule.scan_due(cfg, db)  # never scanned
    db.exec("INSERT INTO scans(host,started_at,status) VALUES(?,?,?)", (cfg.host, now_iso(), "ok"))
    assert not schedule.scan_due(cfg, db)
    old = (datetime.now().astimezone() - timedelta(days=2)).isoformat()
    db.exec("UPDATE scans SET started_at=?", (old,))
    assert schedule.scan_due(cfg, db)


def test_reports_due(cfg, db):
    db.set_meta("installed_at", (datetime.now().astimezone() - timedelta(days=60)).isoformat())
    now = L(2026, 11, 1, 9, 0)  # Sunday, 1st of month
    due = schedule.reports_due(cfg, db, now)
    assert ("daily", "2026-11-01") in due
    assert ("monthly", "2026-10") in due
    assert ("weekly", "2026-W43") in due  # Sunday 25.10. 18:00 was the last weekly slot
    db.exec("INSERT INTO reports(kind,period,created_at,json_path,html_path) VALUES('monthly','2026-10',?, '', '')", (now_iso(),))
    assert ("monthly", "2026-10") not in schedule.reports_due(cfg, db, now)


def test_no_backfill_before_install(cfg, db):
    db.set_meta("installed_at", L(2026, 11, 1, 8, 30).isoformat())
    due = schedule.reports_due(cfg, db, L(2026, 11, 1, 9, 0))
    assert due == []
