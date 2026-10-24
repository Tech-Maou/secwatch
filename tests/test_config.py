import json

import pytest
import yaml

from secwatch import config as config_mod


def test_defaults(state):
    c = config_mod.load(state=state, env={})
    assert c.get("role") == "standalone"
    assert c.get("notify.matrix.new_finding.critical") == {"push": True, "mail": True}
    assert c.get("notify.matrix.new_finding.high") == {"push": True, "mail": False}
    assert c.get("notify.matrix.new_finding.medium") == {"push": False, "mail": False}
    assert c.get("notify.matrix.kev_finding.low") == {"push": True, "mail": True}
    assert c.get("enrichers.epss.mode") == "csv"
    assert c.warnings == []


def test_merge_layers(state):
    (state / "config.yaml").write_text(yaml.safe_dump({
        "role": "hub", "notify": {"ntfy": {"topic": "mine"}, "matrix": {"new_finding": {"medium": {"push": True}}}},
        "schedule": {"scan": {"time": "04:00"}}}))
    ov = state / "ov.json"
    ov.write_text(json.dumps({"settings": {"schedule": {"scan": {"time": "05:00"}}, "web": {"port": 9000}},
                              "locked": ["collectors.nix"]}))
    env = {"SECWATCH_OVERRIDES": str(ov), "SECWATCH__notify__ntfy__url": "https://ntfy.example"}
    c = config_mod.load(state=state, env=env)
    assert c.get("role") == "hub"  # yaml
    assert c.get("notify.ntfy.topic") == "mine"
    assert c.get("notify.matrix.new_finding.medium") == {"push": True, "mail": False}  # cell merge
    assert c.get("notify.matrix.new_finding.critical") == {"push": True, "mail": True}  # untouched default
    assert c.get("schedule.scan.time") == "05:00"  # override beats yaml
    assert c.get("web.port") == 9000
    assert c.get("notify.ntfy.url") == "https://ntfy.example"  # env
    assert {"schedule.scan.time", "web.port", "notify.ntfy.url", "collectors.nix"} <= c.locked
    assert config_mod.is_locked("collectors.nix.enabled", c.locked)
    assert config_mod.is_locked("schedule.scan", c.locked)  # parent of a locked key
    assert not config_mod.is_locked("schedule.reports.daily.time", c.locked)


def test_save_rejects_locked_and_invalid(state):
    ov = state / "ov.json"
    ov.write_text(json.dumps({"settings": {"role": "agent"}}))
    c = config_mod.load(state=state, env={"SECWATCH_OVERRIDES": str(ov)})
    errs = config_mod.save_user_config(c, {"role": "hub"})
    assert errs and "locked" in errs[0]
    errs = config_mod.save_user_config(c, {"schedule": {"scan": {"time": "25:00"}}})
    assert errs and "HH:MM" in errs[0]
    errs = config_mod.save_user_config(c, {"web": {"port": "x"}})
    assert errs
    errs = config_mod.save_user_config(c, {"nope": 1})
    assert errs and "unknown key" in errs[0]
    errs = config_mod.save_user_config(c, {"collectors": {"nix": {"enabled": "maybe"}}})
    assert errs
    assert config_mod.save_user_config(c, {"collectors": {"nix": {"enabled": False}}, "language": "de"}, ["en", "de"]) == []
    c2 = config_mod.load(state=state, env={"SECWATCH_OVERRIDES": str(ov)})
    assert c2.get("collectors.nix.enabled") is False and c2.get("language") == "de"
    assert c2.get("role") == "agent"


def test_broken_yaml_is_reported(state):
    (state / "config.yaml").write_text("role: [unclosed")
    c = config_mod.load(state=state, env={})
    assert c.get("role") == "standalone"
    assert any("unreadable" in w for w in c.warnings)


def test_validate_matrix_and_enum(state):
    c = config_mod.load(state=state, env={})
    assert config_mod.validate_value("notify.matrix.new_finding.high.push", True) is None
    assert config_mod.validate_value("notify.matrix.bogus.high.push", True)
    assert config_mod.validate_value("role", "boss")
    assert config_mod.validate_value("enrichers.epss.mode", "api") is None


def test_secrets(state):
    c = config_mod.load(state=state, env={})
    p = config_mod.write_secret(c, "ntfy-token", "tk_abc\n")
    assert config_mod.read_secret(p) == "tk_abc"
    assert config_mod.secret_status(p) == "set"
    assert config_mod.secret_status("") == "unset"
    assert config_mod.secret_status(str(state / "missing")) == "missing"
    red = config_mod.redact({"web": {"admin_password_hash": "$argon2id$..."}})
    assert red["web"]["admin_password_hash"] == "set"
