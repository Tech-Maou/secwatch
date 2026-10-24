import json
from pathlib import Path

import pytest

from secwatch import scan
from secwatch.collectors import nix as nix_mod
from secwatch.collectors import os_scan
from secwatch.notify import Notifier
from secwatch.runner import Result

FIX = Path(__file__).parent / "fixtures"


class Rec:
    def __init__(self):
        self.msgs = []

    def __call__(self, cfg, m):
        self.msgs.append(m)


@pytest.fixture
def fake_vulnix(monkeypatch):
    calls = []

    def fake_run(cmd, timeout=600, env=None, ok_codes=(0,), **kw):
        calls.append(cmd)
        if "--version" in cmd:
            return Result(0, "vulnix 1.12.4\n", "")
        return Result(2, (FIX / "vulnix_system.json").read_text(), "")
    monkeypatch.setattr(nix_mod, "run", fake_run)
    monkeypatch.setattr(nix_mod, "which", lambda n: "/bin/" + n)
    monkeypatch.setattr(os_scan, "which", lambda n: None)  # trivy missing -> collector error
    return calls


def test_run_scan_isolates_failures(cfg, db, fake_vulnix):
    cfg.data["notify"]["ntfy"].update(enabled=True, topic="t")
    rec = Rec()
    n = Notifier(cfg, db, senders={"push": rec, "mail": rec})
    env = {"is_nixos": True}
    res = scan.run_scan(cfg, db, trigger="test", only=["nix", "os", "lynis"], notifier=n, env=env)
    assert res["collectors"]["nix"]["ok"] is True and res["collectors"]["nix"]["count"] > 0
    # os is 'auto' -> disabled on NixOS; force it on to see the isolated failure
    assert res["collectors"]["os"] == {"enabled": False}
    assert res["collectors"]["lynis"]["ok"] and res["collectors"]["lynis"]["implemented"] is False
    cmd = fake_vulnix[0]
    # default scope "runtime": only the installed closure, never the build-time closure (--system)
    assert cmd[:2] == ["vulnix", "--json"] and cmd[-2:] == ["-C", "/run/current-system"] and "--cache-dir" in cmd
    assert "--system" not in cmd
    cfg.data["collectors"]["os"]["enabled"] = True
    res2 = scan.run_scan(cfg, db, trigger="test", only=["nix", "os"], notifier=Notifier(cfg, db, senders={"push": rec, "mail": rec}), env=env)
    assert res2["collectors"]["os"]["ok"] is False and "trivy not found" in res2["collectors"]["os"]["error"]
    assert res2["status"] == "partial"
    assert res2["summary"]["new"] == 1  # only the scan_error is new
    assert db.one("SELECT COUNT(*) n FROM findings WHERE kind='scan_error' AND state='open'")["n"] == 1
    titles = [m.title for m in rec.msgs]
    assert any(t.startswith("Scan problem on testhost") for t in titles)
    assert any("new findings on testhost" in t for t in titles)
    last = db.one("SELECT * FROM scans ORDER BY id DESC LIMIT 1")
    assert last["status"] == "partial" and json.loads(last["collectors"])["nix"]["scope"]["source"] == "nix"


def test_trigger_file_roundtrip(cfg):
    assert scan.read_trigger(cfg) == []
    scan.write_trigger(cfg, {"action": "scan"})
    scan.write_trigger(cfg, {"action": "notify-test", "channel": "push"})
    acts = scan.read_trigger(cfg)
    assert [a["action"] for a in acts] == ["scan", "notify-test"]
    assert not cfg.trigger_path.exists()
    cfg.trigger_path.write_text("")  # `touch trigger` = scan
    assert scan.read_trigger(cfg) == [{"action": "scan"}]
    cfg.trigger_path.write_text('{"action": "rm -rf"}\n')
    assert scan.read_trigger(cfg) == [{"action": "scan"}]


def test_cycle_scan_and_reports(cfg, db, fake_vulnix, monkeypatch):
    monkeypatch.setattr(scan.detect_mod, "detect", lambda cfg: {"is_nixos": True})
    monkeypatch.setattr(scan.detect_mod, "save", lambda cfg, env: None)
    for c in ("containers", "exposure", "secrets", "auth", "updates", "lynis"):
        cfg.data["collectors"][c]["enabled"] = False
    out = scan.cycle(cfg, db)
    assert out["scan"]["status"] == "ok"
    out2 = scan.cycle(cfg, db)
    assert out2["scan"] is None  # not due again


def test_notify_test_disabled(cfg, db):
    res = scan.notify_test(cfg, db)
    assert res == {"push": {"ok": False, "error": "disabled"}, "mail": {"ok": False, "error": "disabled"}}


def test_scan_lock(cfg):
    with scan.scan_lock(cfg):
        with pytest.raises(RuntimeError):
            with scan.scan_lock(cfg):
                pass
