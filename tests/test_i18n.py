import json
import re
from pathlib import Path

from secwatch import i18n

ROOT = Path(__file__).parent.parent / "secwatch"


def literal_keys():
    js = (ROOT / "web/static/app.js").read_text()
    keys = set(re.findall(r'\bt\("([a-z0-9_.]+)"[,)]', js))
    pairs = re.findall(r'\? "([a-z0-9_]+\.[a-z0-9_.]+)" : "([a-z0-9_]+\.[a-z0-9_.]+)"', js)
    keys |= {k for pair in pairs for k in pair}
    keys |= set(re.findall(r'\["[a-z]+", "(nav\.[a-z]+)"', js))
    tpl = (ROOT / "reports/templates/report.html.j2").read_text()
    keys |= set(re.findall(r"t\('([a-z0-9_.]+)'\)", tpl))
    for py in ROOT.rglob("*.py"):
        keys |= set(re.findall(r'i18n\.t\(lang, "([a-z0-9_.]+)"', py.read_text()))
    return {k for k in keys if not k.endswith(".")}


def dynamic_keys():
    from secwatch.config import COLLECTORS, DEFAULTS, ENRICHERS, EVENTS, leaf_paths
    keys = set()
    for s in ("critical", "high", "medium", "low", "unknown", "none"):
        keys.add(f"severity.{s}")
    for s in ("open", "fixed", "accepted", "false_positive", "all"):
        keys.add(f"state.{s}")
    for k in ("vuln", "hardening", "exposure", "secret", "auth", "update", "scan_error"):
        keys.add(f"kind.{k}")
    for c in COLLECTORS:
        keys |= {f"collector.{c}.title", f"collector.{c}.desc", f"collector.{c}.privacy"}
    for e in ENRICHERS:
        keys |= {f"enricher.{e}.title", f"enricher.{e}.privacy"}
    for e in EVENTS:
        keys |= {f"event.{e}", f"matrix.help.{e}", f"notify.title.{e}"}
    for e in ("new", "fixed", "reopened", "accept", "false_positive", "reopen", "acceptance_expired"):
        keys.add(f"event.{e}")
    for w in ("welcome", "environment", "checks", "schedule", "matrix", "channels", "exposure", "secrets", "auth", "agents", "summary"):
        keys |= {f"wiz.{w}.title", f"wiz.{w}.intro"}
    for p in ("hardening", "exposure", "secrets", "auth", "updates"):
        keys.add(f"phase2.body.{p}")
    for r in ("standalone", "agent", "hub"):
        keys.add(f"role.{r}")
    for k in ("daily", "weekly", "monthly"):
        keys |= {f"report.kind.{k}", f"freq.{k}", f"ov.next.report_{k}"}
    keys.add("ov.next.scan")
    for st in ("ok", "partial", "unreachable", "unknown"):
        keys.add(f"hoststatus.{st}")
    for st in ("ok", "partial", "failed", "running"):
        keys.add(f"scan.status.{st}")
    for st in ("set", "unset", "unreadable", "missing"):
        keys.add(f"secret.status.{st}")
    for d in ("mon", "tue", "wed", "thu", "fri", "sat", "sun"):
        keys.add(f"day.{d}")
    for s in ("priority", "severity", "age", "newest", "host", "package"):
        keys.add(f"sort.{s}")
    for f in ("host", "kind", "severity", "state", "sort"):
        keys.add(f"filter.{f}")
    keys |= {"tristate.auto", "tristate.true", "tristate.false", "epss.mode.csv", "epss.mode.api", "matrix.push", "matrix.mail",
             "authmode.password", "authmode.token", "authmode.trusted_proxy", "matrix.preset.quiet", "matrix.preset.normal",
             "matrix.preset.strict", "lang.name", "login.setup_code", "login.password_or_token", "login.setup_title", "login.title"}
    return keys


def form_field_keys():
    js = (ROOT / "web/static/app.js").read_text()
    paths = set(re.findall(r'\{ path: "([a-z0-9_.]+)", type: "(?!tristate)', js))
    paths = {p for p in paths if not re.match(r"(collectors\.[a-z]+\.enabled$|enrichers\.[a-z]+\.enabled$)", p)
             or p in ("collectors.exposure.enabled", "collectors.secrets.enabled", "collectors.auth.enabled")}
    secrets = set(re.findall(r'\{ secret: "([a-z0-9_.]+)"', js))
    return {f"f.{p}" for p in paths | secrets} | {"f.admin_password"}


def test_all_keys_present_in_all_languages():
    needed = literal_keys() | dynamic_keys() | form_field_keys()
    assert "en" in i18n.languages() and "de" in i18n.languages()
    for lang in i18n.languages():
        data = json.loads((ROOT / "i18n" / f"{lang}.json").read_text())
        missing = sorted(k for k in needed if k not in data)
        assert not missing, f"{lang}: missing {missing}"


def test_languages_have_same_keys():
    en = json.loads((ROOT / "i18n/en.json").read_text())
    for lang in i18n.languages():
        data = json.loads((ROOT / "i18n" / f"{lang}.json").read_text())
        assert set(data) == set(en), lang


def test_placeholders_match():
    en = json.loads((ROOT / "i18n/en.json").read_text())
    de = json.loads((ROOT / "i18n/de.json").read_text())
    for k, v in en.items():
        assert set(re.findall(r"\{(\w+)\}", v)) == set(re.findall(r"\{(\w+)\}", de[k])), k


def test_fallback():
    assert i18n.t("xx", "nav.overview") == "Overview"
    assert i18n.t("de", "nav.overview") == "Übersicht"
    assert i18n.t("de", "does.not.exist") == "does.not.exist"
    assert i18n.t("en", "findings.count", n=3) == "3 findings"
