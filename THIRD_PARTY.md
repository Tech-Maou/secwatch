# Third-party components and data

secwatch itself is licensed under the PolyForm Noncommercial License 1.0.0 (see `LICENSE`).
That licence covers **secwatch's own code only**. The tools, libraries and data sources below keep
their own licences; all of them also allow commercial use, so a commercial secwatch licence
only needs to cover secwatch itself.

## External tools (run as separate programs, not linked into secwatch)

secwatch calls these programs as subprocesses and parses their output. Calling a program does
not combine it with secwatch's code, so their licences do not affect secwatch's licence.

| Tool | Licence | Used for |
|---|---|---|
| [vulnix](https://github.com/nix-community/vulnix) | BSD-3-Clause | NixOS package vulnerabilities |
| [Trivy](https://github.com/aquasecurity/trivy) | Apache-2.0 | OS packages, container images |
| [Lynis](https://github.com/CISOfy/lynis) | GPL-3.0-only | host hardening audit |
| [gitleaks](https://github.com/gitleaks/gitleaks) | MIT | secrets in repositories |
| [iproute2](https://wiki.linuxfoundation.org/networking/iproute2) (`ss`) | GPL-2.0-only | listening sockets |

**Redistribution (Docker image, packages):** an image that *contains* these tools redistributes
them. Their licence texts must be included, Trivy's `NOTICE` must be kept (Apache-2.0 §4), and for
the GPL tools the corresponding source must be available. The image installs the tools from the
distribution's package repository, which already ships licence files and provides source
packages; keep it that way and do not strip `/usr/share/doc` or licence directories.

## Python libraries (bundled in the package)

| Library | Licence |
|---|---|
| FastAPI | MIT |
| Uvicorn | BSD-3-Clause |
| HTTPX | BSD-3-Clause |
| PyYAML | MIT |
| Jinja2 | BSD-3-Clause |
| argon2-cffi | MIT |

These licences require that their copyright notice and licence text accompany redistributed copies.
They are included in the installed packages (`*.dist-info/LICENSE*`).

## Data sources (downloaded at runtime by the user's installation)

| Source | Terms | Attribution |
|---|---|---|
| NIST National Vulnerability Database (via vulnix) | public domain (U.S. government work) | "This product uses data from the NVD API but is not endorsed or certified by the NVD." |
| CISA Known Exploited Vulnerabilities catalog | public domain (U.S. government work) | source: CISA KEV catalog |
| FIRST EPSS scores | free to use, no registration; attribution requested for products | "EPSS scores: FIRST.org (https://www.first.org/epss)" |
| Trivy vulnerability DB | DB tooling Apache-2.0; advisories keep the terms of their upstream sources (GitHub Advisory Database CC-BY-4.0, distribution security trackers, NVD) | provided by Aqua Security's Trivy |

secwatch does not redistribute these datasets; each installation downloads them directly from
their publishers. The web UI and reports link to the original advisory pages.
