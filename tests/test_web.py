import json

import httpx
import pytest
from fastapi.testclient import TestClient

from secwatch import config as config_mod
from secwatch.db import DB
from secwatch.hub import pull_agent
from secwatch.lifecycle import Scope, apply_snapshot
from secwatch.models import Finding
from secwatch.web import auth
from secwatch.web.app import create_app

H = {"X-Secwatch-CSRF": "-"}


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SECWATCH_STATE_DIR", str(tmp_path))
    monkeypatch.delenv("SECWATCH_TOKEN", raising=False)
    monkeypatch.delenv("SECWATCH_OVERRIDES", raising=False)
    from secwatch.web import app as app_mod
    app_mod._FAILED.clear()
    return tmp_path


def seed(state, host="web-host"):
    d = DB(state / "secwatch.db")
    apply_snapshot(d, host, [
        Finding(host=host, source="nix", kind="vuln", id="CVE-2024-1", package="openssl", installed="3.0", severity="critical",
                cvss=9.8, title="bad", extra={"kev": True, "description": "very bad"}),
        Finding(host=host, source="nix", kind="vuln", id="CVE-2024-2", package="zlib", installed="1.3", severity="low", cvss=3.0),
    ], [Scope("nix")], None)
    d.close()


def login_setup(client, state):
    code = (state / "setup-code").read_text().strip()
    r = client.post("/api/login", json={"setup_code": code}, headers=H)
    assert r.status_code == 200
    return {"X-Secwatch-CSRF": r.json()["csrf"]}


def test_first_run_flow(env):
    c = TestClient(create_app())
    s = c.get("/api/session").json()
    assert s["authenticated"] is False and s["needs_setup_code"] is True
    assert c.get("/api/overview").status_code == 401
    assert c.post("/api/login", json={"setup_code": "wrong"}, headers=H).status_code == 401
    assert c.post("/api/login", json={"setup_code": "x"}).status_code == 403  # no CSRF header
    csrf = login_setup(c, env)
    assert c.get("/api/overview").status_code == 200
    # POST without CSRF token is rejected
    assert c.put("/api/config", json={"changes": {"language": "de"}}).status_code == 403
    r = c.put("/api/config", json={"changes": {"language": "de"}, "admin_password": "correct horse battery"}, headers=csrf)
    assert r.status_code == 200, r.text
    cfg = config_mod.load(env, env={"SECWATCH_STATE_DIR": str(env)})
    assert cfg.get("language") == "de" and cfg.get("web.admin_password_hash").startswith("$argon2")
    # secrets are never echoed back
    conf = c.get("/api/config").json()
    assert conf["config"]["web"]["admin_password_hash"] == "set" and conf["admin_password"] == "set"
    r = c.post("/api/wizard/complete", headers=csrf)
    assert r.status_code == 200
    assert (env / "trigger").exists() and not (env / "setup-code").exists()
    c2 = TestClient(create_app())
    assert c2.get("/api/session").json()["needs_setup_code"] is False
    assert c2.post("/api/login", json={"password": "wrong-password"}, headers=H).status_code == 401
    assert c2.post("/api/login", json={"password": "correct horse battery"}, headers=H).status_code == 200


def test_cookie_flags(env):
    c = TestClient(create_app())
    code = (env / "setup-code").read_text().strip()
    r = c.post("/api/login", json={"setup_code": code}, headers=H)
    sc = r.headers["set-cookie"].lower()
    assert "httponly" in sc and "samesite=strict" in sc


def test_findings_and_actions(env):
    seed(env)
    c = TestClient(create_app())
    csrf = login_setup(c, env)
    data = c.get("/api/findings").json()
    assert data["total"] == 2 and data["items"][0]["id"] == "CVE-2024-1"  # KEV first
    key = data["items"][0]["key"]
    d = c.get(f"/api/findings/{key}").json()
    assert d["extra"]["description"] == "very bad" and any(l["label"] == "NVD" for l in d["links"])
    assert c.get("/api/findings/../../etc").status_code in (400, 404)
    assert c.get("/api/findings?severity=low").json()["total"] == 1
    assert c.get("/api/findings?kev=1").json()["total"] == 1
    assert c.get("/api/findings?sort=evil;drop").status_code == 200
    r = c.post(f"/api/findings/{key}/action", json={"action": "accept", "reason": ""}, headers=csrf)
    assert r.status_code == 400
    r = c.post(f"/api/findings/{key}/action", json={"action": "accept", "reason": "mitigated", "until": "2999-01-01"}, headers=csrf)
    assert r.status_code == 200 and r.json()["state"] == "accepted"
    assert c.get("/api/findings").json()["total"] == 1
    ov = c.get("/api/overview").json()
    assert ov["accepted"] == 1 and ov["counts"]["low"] == 1 and ov["trend"]
    assert c.post("/api/scan", headers=csrf).json()["queued"] is True
    assert c.get("/api/overview").json()["trigger_pending"] is True


def test_empty_state_never_500(env):
    c = TestClient(create_app())
    login_setup(c, env)
    for path in ("/api/overview", "/api/findings", "/api/reports", "/api/config", "/api/actions", "/api/scans",
                 "/api/hosts", "/api/trend", "/api/detect", "/api/i18n", "/api/i18n/de", "/"):
        r = c.get(path)
        assert r.status_code == 200, (path, r.text)
    assert c.get("/api/reports/99/html").status_code == 404
    assert c.get("/api/i18n/xx").status_code == 404


def test_locked_keys_read_only(env, monkeypatch):
    ov = env / "ov.json"
    ov.write_text(json.dumps({"settings": {"notify": {"ntfy": {"url": "https://ntfy.lan"}}, "web": {"auth_mode": "trusted_proxy"}}}))
    monkeypatch.setenv("SECWATCH_OVERRIDES", str(ov))
    c = TestClient(create_app())
    s = c.get("/api/session").json()
    assert s["authenticated"] and s["user"] == "proxy"
    csrf = {"X-Secwatch-CSRF": s["csrf"]}
    conf = c.get("/api/config").json()
    assert "notify.ntfy.url" in conf["locked"]
    r = c.put("/api/config", json={"changes": {"notify": {"ntfy": {"url": "https://evil"}}}}, headers=csrf)
    assert r.status_code == 400 and "locked" in r.text
    assert c.put("/api/config", json={"changes": {"notify": {"ntfy": {"topic": "x"}}}}, headers={"X-Secwatch-CSRF": "bad"}).status_code == 403
    r = c.put("/api/config", json={"changes": {"notify": {"ntfy": {"topic": "x"}}}, "secrets": {"notify.ntfy.token": "tk_123"}}, headers=csrf)
    assert r.status_code == 200
    conf = c.get("/api/config").json()
    assert conf["secrets"]["notify.ntfy.token"] == "set"
    assert "tk_123" not in json.dumps(conf)


def test_token_auth(env, monkeypatch):
    monkeypatch.setenv("SECWATCH_TOKEN", "s3cr3t-token-value")
    c = TestClient(create_app())
    assert c.get("/api/overview", headers={"Authorization": "Bearer nope"}).status_code == 401
    r = c.get("/api/overview", headers={"Authorization": "Bearer s3cr3t-token-value"})
    assert r.status_code == 200
    assert c.post("/api/scan", headers={"Authorization": "Bearer s3cr3t-token-value"}).status_code == 200


def test_agent_snapshot_and_hub_pull(env, tmp_path_factory, monkeypatch):
    tok = env / "agent-token"
    tok.write_text("agent-secret\n")
    (env / "config.yaml").write_text(f"role: agent\nhost_name: agent1\nagent:\n  token_file: {tok}\n  ui: false\n")
    seed(env, host="agent1")
    agent = TestClient(create_app(), base_url="http://agent1")
    assert agent.get("/api/overview").status_code == 404  # UI disabled on agent
    assert agent.get("/api/agent/snapshot").status_code == 401
    assert agent.get("/api/agent/snapshot", headers={"Authorization": "Bearer wrong"}).status_code == 401
    snap = agent.get("/api/agent/snapshot", headers={"Authorization": "Bearer agent-secret"}).json()
    assert snap["host"] == "agent1" and len(snap["findings"]) == 2

    hub_state = tmp_path_factory.mktemp("hub")
    hub_tok = hub_state / "tok"
    hub_tok.write_text("agent-secret")
    hub_cfg = config_mod.load(hub_state, env={})
    hub_cfg.data["role"] = "hub"
    hub_db = DB(hub_state / "secwatch.db")
    diff = pull_agent(hub_cfg, hub_db, {"name": "agent1", "url": "http://agent1", "token_file": str(hub_tok)}, client=agent)
    assert len(diff.new) == 2
    assert hub_db.one("SELECT COUNT(*) n FROM findings WHERE host='agent1' AND state='open'")["n"] == 2
    assert hub_db.one("SELECT status FROM hosts WHERE host='agent1'")["status"] == "ok"
    # unreachable agent -> scan_error, old findings stay open
    bad = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(502)))
    diff = pull_agent(hub_cfg, hub_db, {"name": "agent1", "url": "http://agent1", "token_file": str(hub_tok)}, client=bad)
    assert [f["kind"] for f in diff.new] == ["scan_error"] and not diff.fixed
    assert hub_db.one("SELECT COUNT(*) n FROM findings WHERE host='agent1' AND state='open' AND kind='vuln'")["n"] == 2
    diff = pull_agent(hub_cfg, hub_db, {"name": "agent1", "url": "http://agent1", "token_file": str(hub_tok)}, client=agent)
    assert [f["kind"] for f in diff.fixed] == ["scan_error"]


def test_report_endpoints(env):
    seed(env)
    from secwatch import reports
    cfg = config_mod.load(env, env={})
    d = DB(cfg.db_path)
    reports.generate(cfg, d, "monthly", period="2026-08")
    reports.generate(cfg, d, "monthly", period="2026-09")
    d.close()
    c = TestClient(create_app())
    login_setup(c, env)
    items = c.get("/api/reports").json()["items"]
    assert len(items) == 2
    r = c.get(f"/api/reports/{items[0]['id']}/html")
    assert r.status_code == 200 and "sandbox" in r.headers["content-security-policy"]
    cmp = c.get(f"/api/reports/compare/{items[0]['id']}/{items[1]['id']}").json()
    assert cmp["a"]["period"] == "2026-08" and cmp["delta"]["total"] == 0


def test_security_headers(env):
    c = TestClient(create_app())
    r = c.get("/")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"


def test_password_hashing():
    h = auth.hash_password("long enough pw")
    assert auth.verify_password(h, "long enough pw") and not auth.verify_password(h, "nope")
    with pytest.raises(ValueError):
        auth.hash_password("short")


def test_login_throttling(env):
    from secwatch.web import app as app_mod
    app_mod._FAILED.clear()
    c = TestClient(create_app())
    for _ in range(8):
        assert c.post("/api/login", json={"password": "wrong"}, headers=H).status_code == 401
    assert c.post("/api/login", json={"password": "wrong"}, headers=H).status_code == 429
    app_mod._FAILED.clear()


def test_agent_test_rejects_arbitrary_token_file(env):
    c = TestClient(create_app())
    csrf = login_setup(c, env)
    r = c.post("/api/agents/test", json={"url": "http://127.0.0.1:9", "token_file": "/etc/shadow"}, headers=csrf)
    assert r.status_code == 400 and "unknown token file" in r.text
