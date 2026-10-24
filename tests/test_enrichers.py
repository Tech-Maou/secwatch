import gzip
import json

from secwatch.enrichers import cvss, epss, kev
from secwatch.models import Finding


def fs():
    return [Finding(host="h", source="nix", kind="vuln", id="CVE-2021-44228", cvss=10.0),
            Finding(host="h", source="nix", kind="vuln", id="CVE-2000-0001", cvss=None, severity="unknown"),
            Finding(host="h", source="nix", kind="vuln", id="CVE-2024-1", cvss=6.1)]


def test_kev(tmp_path):
    p = tmp_path / "kev.json"
    p.write_text(json.dumps({"vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10", "dueDate": "2021-12-24",
                                                  "knownRansomwareCampaignUse": "Known", "vulnerabilityName": "Log4Shell"}]}))
    items = fs()
    assert kev.apply(kev.load_catalog(p), items) == 1
    assert items[0].extra["kev"] is True and items[0].extra["kev_due_date"] == "2021-12-24"
    assert "kev" not in items[1].extra


def test_epss_csv(tmp_path):
    p = tmp_path / "e.csv.gz"
    with gzip.open(p, "wt") as f:
        f.write("#model_version:v2026.06.15,score_date:2026-10-23T12:00:28Z\ncve,epss,percentile\n"
                "CVE-1999-0001,0.04753,0.91851\nCVE-2021-44228,0.99999,1.00000\nCVE-2024-1,0.0005,0.1\n")
    items = fs()
    scores = epss.load_csv_gz(p, {f.id for f in items})
    assert "CVE-1999-0001" not in scores
    assert epss.apply(scores, items) == 2
    assert items[0].extra["epss"] == 0.99999 and items[0].extra["epss_percentile"] == 1.0


def test_epss_csv_mode_never_calls_api(cfg, tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(epss, "query_api", lambda *a, **k: calls.append(a) or {})
    p = cfg.cache_dir / "epss_scores.csv.gz"
    p.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(p, "wt") as f:
        f.write("cve,epss,percentile\nCVE-2021-44228,0.9,0.99\n")
    cfg.data["enrichers"]["epss"]["enabled"] = True
    items = fs()
    status = epss.enrich(cfg, items)  # cache is fresh -> no download
    assert status.startswith("cached") and not calls
    assert items[0].extra["epss"] == 0.9


def test_cvss_bands():
    items = fs()
    cvss.enrich(None, items)
    assert items[1].severity == "unknown"
    items[1].cvss = 7.2
    cvss.enrich(None, items)
    assert items[1].severity == "high" and items[0].extra["cvss_band"] == "critical"
