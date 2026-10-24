from pathlib import Path

from secwatch.collectors.containers import parse_docker_ps, parse_engine_api, parse_podman_ps
from secwatch.collectors.nix import name_from_store_path, parse_vulnix, split_name
from secwatch.collectors.trivy import parse_trivy
from secwatch.detect import parse_ss, read_registry

FIX = Path(__file__).parent / "fixtures"


def test_split_name():
    assert split_name("openssl-3.0.7") == ("openssl", "3.0.7")
    assert split_name("glibc-2.42-100-source-unsecvars") == ("glibc", "2.42-100-source-unsecvars")
    assert split_name("python3.13-requests-2.32.3") == ("python3.13-requests", "2.32.3")
    assert split_name("hello") == ("hello", "")
    assert name_from_store_path("/nix/store/q4xrmyhf5hhlzf0mzbpj2n8fmrb72xxd-glibc-2.42.drv") == ("glibc", "2.42")


def test_vulnix_real_output(fixture_json):
    data = fixture_json("vulnix_system.json")
    fs = parse_vulnix(data, "srv")
    expected = sum(len(p["affected_by"]) - len(set(p["whitelisted"]) & set(p["affected_by"])) for p in data)
    assert len(fs) == expected
    diff = [f for f in fs if f.package == "Diff"]
    assert {f.id for f in diff} == {"CVE-2024-13278", "CVE-2026-73478"}
    crit = next(f for f in diff if f.id == "CVE-2024-13278")
    assert crit.cvss == 9.1 and crit.severity == "critical" and crit.installed == "1.0.2"
    assert crit.url == "https://nvd.nist.gov/vuln/detail/CVE-2024-13278"
    assert crit.extra["derivation"].endswith("Diff-1.0.2.drv")
    assert all(f.source == "nix" and f.kind == "vuln" and f.host == "srv" for f in fs)
    # keys do not depend on the installed version or the derivation hash
    zlib = [f for f in fs if f.package == "zlib"]
    assert len({f.key for f in zlib}) == len({f.id for f in zlib})


def test_vulnix_whitelist_missing_cvss_and_fallback_name():
    data = [{"name": "foo-1.2", "derivation": "/nix/store/0000000000000000000000000000000a-foo-1.2.drv",
             "affected_by": ["CVE-1", "CVE-2"], "whitelisted": ["CVE-2"], "cvssv3_basescore": {}, "description": {}}]
    fs = parse_vulnix(data, "h")
    assert len(fs) == 1
    assert fs[0].package == "foo" and fs[0].installed == "1.2"
    assert fs[0].cvss is None and fs[0].severity == "unknown"


def test_trivy_real_output(fixture_json):
    data = fixture_json("trivy_image_alpine.json")
    fs = parse_trivy(data, "h", "containers", component="web")
    assert len(fs) == sum(len(r.get("Vulnerabilities") or []) for r in data["Results"])
    f = next(x for x in fs if x.id == "CVE-2023-42363")
    assert f.package == "busybox" and f.installed == "1.35.0-r29" and f.fixed == "1.35.0-r31"
    assert f.severity == "medium" and f.cvss == 5.5  # nvd score preferred over redhat 7.8
    assert f.component == "web" and f.extra["os"] == "alpine 3.17.0" and f.extra["eosl"] is True
    assert {x.severity for x in fs} <= {"critical", "high", "medium", "low", "unknown"}


def test_trivy_empty_results():
    assert parse_trivy({"Results": [{"Target": "x", "Class": "os-pkgs"}]}, "h", "os") == []
    assert parse_trivy({}, "h", "os") == []


def test_podman_ps():
    cs = parse_podman_ps((FIX / "podman_ps.json").read_text())
    assert [c["name"] for c in cs] == ["web", "app", "web2"]
    assert cs[0]["image"] == "docker.io/library/nginx:1.27-alpine"


def test_docker_ps():
    cs = parse_docker_ps((FIX / "docker_ps.ndjson").read_text())
    assert [(c["name"], c["image"]) for c in cs] == [("proxy", "nginx:1.27"), ("cache", "redis:7")]


def test_engine_api():
    cs = parse_engine_api([{"Id": "abc", "Names": ["/db"], "Image": "postgres:16", "ImageID": "sha256:1", "State": "running"}])
    assert cs == [{"name": "db", "image": "postgres:16", "image_id": "sha256:1", "state": "running"}]


def test_ss():
    ports = parse_ss((FIX / "ss_tulnH.txt").read_text())
    tcp22 = [p for p in ports if p["proto"] == "tcp" and p["port"] == 22]
    assert {p["address"] for p in tcp22} == {"0.0.0.0", "::"}
    assert next(p for p in tcp22 if p["address"] == "0.0.0.0")["process"] == "sshd"
    assert not next(p for p in ports if p["port"] == 5432 and p["address"] == "127.0.0.1")["public"]
    assert next(p for p in ports if p["port"] == 53)["address"] == "*"


def test_registry():
    reg = read_registry(str(FIX / "registry.json"))
    assert [r["hostname"] for r in reg] == ["adguard.example.org", "", "git.example.org"]
    assert reg[2]["exposure"] == "public"
    assert read_registry("/nonexistent") == []


def test_vulnix_skips_generated_files():
    data = [{"name": "polkit-1.pam", "pname": "polkit", "version": "1.pam", "affected_by": ["CVE-2021-4034"],
             "whitelisted": [], "cvssv3_basescore": {"CVE-2021-4034": 7.8}, "description": {}},
            {"name": "openssh-10.5p1", "affected_by": ["CVE-1"], "whitelisted": [], "cvssv3_basescore": {}, "description": {}}]
    assert [(f.package, f.installed) for f in parse_vulnix(data, "h")] == [("openssh", "10.5p1")]
