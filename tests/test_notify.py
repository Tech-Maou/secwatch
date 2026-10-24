import json

import httpx

from secwatch.lifecycle import Diff
from secwatch.notify import Notifier, build_message, cell, events_from_diff, summary_messages
from secwatch.notify import mail as mail_mod
from secwatch.notify import ntfy as ntfy_mod


def item(id_, sev, kev=False, kind="vuln", host="h", epss=None, **kw):
    return {"key": f"k-{id_}-{host}", "host": host, "id": id_, "kind": kind, "severity": sev, "kev": kev,
            "package": "openssl", "installed": "3.0.7", "epss": epss, "cvss": None, "state": "open",
            "first_seen": "2026-10-01T00:00:00+00:00", "extra": kw.get("extra", {}), "component": kw.get("component", "")}


def enable(cfg, push=True, mail=True):
    cfg.data["notify"]["ntfy"].update(enabled=push, topic="sec", url="https://ntfy.example")
    cfg.data["notify"]["mail"].update(enabled=mail, host="smtp.example", to=["me@example.org"])


class Rec:
    def __init__(self):
        self.msgs = []

    def __call__(self, cfg, m):
        self.msgs.append(m)


def notifier(cfg, db, fail=None):
    r = Rec()

    def boom(cfg, m):
        raise RuntimeError("smtp down")
    senders = {"push": r, "mail": r if fail != "mail" else boom}
    return Notifier(cfg, db, senders=senders), r


def test_default_matrix_cells(cfg):
    assert cell(cfg, "new_finding", "critical") == {"push": True, "mail": True}
    assert cell(cfg, "new_finding", "high") == {"push": True, "mail": False}
    assert cell(cfg, "new_finding", "medium") == {"push": False, "mail": False}
    assert cell(cfg, "new_finding", "unknown") == {"push": False, "mail": False}  # unknown -> low column
    assert cell(cfg, "kev_finding", "low") == {"push": True, "mail": True}
    assert cell(cfg, "weekly_summary", "critical") == {"push": True, "mail": False}
    assert cell(cfg, "monthly_report", "critical") == {"push": False, "mail": False}
    assert cell(cfg, "scan_error", "medium") == {"push": True, "mail": False}
    assert cell(cfg, "auth_anomaly", "high") == {"push": True, "mail": False}


def test_events_from_diff_routing(cfg):
    d = Diff(new=[item("CVE-1", "critical"), item("CVE-2", "low", kev=True), item("x", "medium", kind="scan_error"),
                  item("u1", "high", kind="update", extra={"security": False}), item("u2", "high", kind="update", extra={"security": True}),
                  item("s", "high", kind="secret"), {**item("acc", "high"), "state": "accepted"}],
             newly_kev=[item("CVE-3", "medium", kev=True)])
    ev = events_from_diff(cfg, d)
    assert [f["id"] for f in ev["new_finding"]] == ["CVE-1"]
    assert sorted(f["id"] for f in ev["kev_finding"]) == ["CVE-2", "CVE-3"]
    assert [f["id"] for f in ev["scan_error"]] == ["x"]
    assert [f["id"] for f in ev["update_available"]] == ["u2"]
    assert [f["id"] for f in ev["secret_found"]] == ["s"]


def test_plan_matrix_push_and_mail(cfg, db):
    enable(cfg)
    n, rec = notifier(cfg, db)
    ev = {"new_finding": [item("CVE-1", "critical"), item("CVE-2", "high"), item("CVE-3", "medium")]}
    msgs = n.plan(ev)
    push = [m for m in msgs if m.channel == "push"]
    mail = [m for m in msgs if m.channel == "mail"]
    assert len(push) == 1 and len(mail) == 1
    assert sorted(push[0].keys) == ["k-CVE-1-h", "k-CVE-2-h"]
    assert mail[0].keys == ["k-CVE-1-h"]
    assert push[0].title == "2 new findings on h"
    assert push[0].severity == "critical"


def test_disabled_channel_and_empty(cfg, db):
    enable(cfg, push=True, mail=False)
    n, rec = notifier(cfg, db)
    assert {m.channel for m in n.plan({"new_finding": [item("CVE-1", "critical")]})} == {"push"}
    assert n.plan({"new_finding": [item("CVE-3", "medium")]}) == []


def test_grouped_per_host(cfg, db):
    enable(cfg, mail=False)
    n, rec = notifier(cfg, db)
    msgs = n.plan({"new_finding": [item("CVE-1", "critical", host="a"), item("CVE-1", "critical", host="b")]})
    assert sorted(m.host for m in msgs) == ["a", "b"]


def test_dedup(cfg, db):
    enable(cfg, mail=False)
    n, rec = notifier(cfg, db)
    ev = {"kev_finding": [item("CVE-1", "high", kev=True)]}
    n.notify(ev)
    assert len(rec.msgs) == 1
    n2, rec2 = notifier(cfg, db)
    n2.notify(ev)
    assert rec2.msgs == []
    cfg.data["notify"]["dedup_hours"] = 0
    n3, rec3 = notifier(cfg, db)
    n3.notify(ev)
    assert len(rec3.msgs) == 1


def test_rate_limit(cfg, db):
    enable(cfg, mail=False)
    cfg.data["notify"]["max_per_hour"] = 2
    n, rec = notifier(cfg, db)
    for i in range(4):
        n.notify({"scan_error": [item(f"e{i}", "medium", kind="scan_error", host=f"h{i}")]})
    assert len(rec.msgs) == 2
    assert any("rate limit" in e for e in n.errors)


def test_channel_failure_is_isolated(cfg, db):
    enable(cfg)
    n, rec = notifier(cfg, db, fail="mail")
    n.notify({"new_finding": [item("CVE-1", "critical")]})
    assert [m.channel for m in rec.msgs] == ["push"]
    assert n.errors and "smtp down" in n.errors[0]
    # failed mail is not recorded as sent -> retried next time
    n2, rec2 = notifier(cfg, db)
    n2.notify({"new_finding": [item("CVE-1", "critical")]})
    assert [m.channel for m in rec2.msgs] == ["mail"]


def test_message_body_top5(cfg):
    cfg.data["web"]["base_url"] = "https://sec.example/"
    items = [item(f"CVE-{i}", "high") for i in range(7)] + [item("CVE-K", "medium", kev=True, epss=0.42)]
    m = build_message(cfg, "new_finding", "srv", "push", items)
    lines = m.body.splitlines()
    assert lines[0] == "High 7 · Medium 1 · KEV 1"
    assert lines[1].startswith("• CVE-K openssl 3.0.7 [Medium, KEV, EPSS 42%]")
    assert len([ln for ln in lines if ln.startswith("•")]) == 5
    assert lines[-1] == "… and 3 more"
    assert m.click == "https://sec.example/#/findings?host=srv"
    assert "skull" in m.tags


def test_message_german(cfg):
    cfg.data["language"] = "de"
    m = build_message(cfg, "new_finding", "srv", "push", [item("CVE-1", "critical")])
    assert m.title == "1 neue Befunde auf srv"
    assert m.body.startswith("Kritisch 1")


def test_summary_messages(cfg):
    enable(cfg)
    items = [item("CVE-1", "critical"), item("CVE-2", "high", host="b"), item("CVE-3", "low")]
    msgs = summary_messages(cfg, "weekly_summary", items, "2026-W43", "#/reports")
    assert [m.channel for m in msgs] == ["push"]  # weekly default: push only
    assert msgs[0].title == "Weekly: 2 open findings (2 hosts)"
    assert "Period 2026-W43" in msgs[0].body
    assert summary_messages(cfg, "monthly_report", items, "2026-09", "#/reports") == []


def test_ntfy_payload_and_token(cfg, tmp_path):
    enable(cfg)
    tok = tmp_path / "tok"
    tok.write_text("tk_secret\n")
    cfg.data["notify"]["ntfy"]["token_file"] = str(tok)
    m = build_message(cfg, "new_finding", "srv", "push", [item("CVE-1", "critical")])
    seen = {}

    def handler(request):
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = json.loads(request.content)
        seen["url"] = str(request.url)
        return httpx.Response(200, json={"id": "x"})
    ntfy_mod.send(cfg, m, client=httpx.Client(transport=httpx.MockTransport(handler)))
    assert seen["auth"] == "Bearer tk_secret"
    assert seen["url"] == "https://ntfy.example"
    assert seen["body"]["topic"] == "sec" and seen["body"]["priority"] == 5
    assert seen["body"]["title"] == "1 new findings on srv"


def test_ntfy_http_error(cfg):
    enable(cfg)
    m = build_message(cfg, "new_finding", "srv", "push", [item("CVE-1", "critical")])
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(403)))
    try:
        ntfy_mod.send(cfg, m, client=client)
        assert False, "should raise"
    except RuntimeError as e:
        assert "403" in str(e)


class FakeSMTP:
    instances = []

    def __init__(self, host, port):
        self.host, self.port, self.calls = host, port, []
        FakeSMTP.instances.append(self)

    def starttls(self, context=None):
        self.calls.append("starttls")

    def login(self, u, p):
        self.calls.append(("login", u, p))

    def send_message(self, msg):
        self.calls.append(("send", msg["To"], msg["Subject"], msg.get_content()))

    def quit(self):
        self.calls.append("quit")


def test_mail_starttls_and_password_file(cfg, tmp_path):
    enable(cfg)
    pw = tmp_path / "pw"
    pw.write_text("hunter2hunter2")
    cfg.data["notify"]["mail"].update(user="bot@example.org", password_file=str(pw), **{"from": "bot@example.org"})
    m = build_message(cfg, "new_finding", "srv", "mail", [item("CVE-1", "critical")])
    mail_mod.send(cfg, m, smtp_factory=FakeSMTP)
    s = FakeSMTP.instances[-1]
    assert s.calls[0] == "starttls"
    assert s.calls[1] == ("login", "bot@example.org", "hunter2hunter2")
    assert s.calls[2][1] == "me@example.org" and s.calls[2][2] == "[secwatch] 1 new findings on srv"
    assert s.calls[-1] == "quit"
