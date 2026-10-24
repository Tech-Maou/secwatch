# secwatch — specification (v1)

Self-hosted security monitoring for small fleets (homelabs, small offices).
**Principle: secwatch only fetches information. It never sends inventory, findings or system
data to third parties.** Outbound traffic is limited to (a) downloading vulnerability data
(NVD via vulnix, Trivy DB, CISA KEV, FIRST EPSS, upstream release metadata) and (b) the
operator's own notification endpoints (ntfy server, SMTP server).

## 1. Goals
- Detect known vulnerabilities on hosts and in container images, prioritise them (KEV, EPSS,
  CVSS), track them over time, and notify according to a per-event × per-severity matrix.
- Keep reports (daily / weekly / monthly) persistently and comparably.
- Run on NixOS (first-class, NixOS module) and on any Linux (container image, pip + systemd).
- Be easy to set up: auto-detect as much as possible; a multi-page setup wizard for the rest.
- Every feature can be enabled/disabled individually.

## 2. Architecture
```
secwatch/
  secwatch/            Python package (>=3.12): core, collectors, enrichers, notify, reports, web
    collectors/        one module per check (plugin interface below)
    web/               FastAPI app + static frontend (vanilla JS, no build step)
    i18n/              en.json (default), de.json; more languages = drop-in files
  nix/                 flake outputs: package + nixosModules.default
  docker/              Dockerfile + docker-compose.yml (generic Linux)
  systemd/             unit files for the pip install path
  README.md            setup for all three install paths, wizard walkthrough, privacy statement
  LICENSE              PolyForm Noncommercial 1.0.0 (licensor: Tech-Maou)
```

Processes:
- **secwatch-web** (unprivileged user `secwatch`): UI + JSON API, reads/writes the state DB and
  config. Never runs scanners itself. "Scan now" writes a trigger file.
- **secwatch-scan** (oneshot, root, hardened): runs enabled collectors, enrichers, diffing,
  report generation, notifications. Triggered by a timer and by a path unit on the trigger file
  (NixOS module / systemd files provide both). In the container image a small scheduler loop does
  the same.
- State dir (default `/var/lib/secwatch`): `secwatch.db` (SQLite), `config.yaml`, `reports/`,
  `cache/` (vuln DBs), `trigger`.

Roles (multi-host):
- `standalone` (default): scans itself, shows itself.
- `agent`: scans itself, exposes `GET /api/agent/snapshot` (bearer token) for a hub; UI optional.
- `hub`: scans itself and pulls snapshots from configured agents (pull model; agents never push).
  The hub's dashboard shows all hosts.

## 3. Collectors (each: `enabled`, own settings, own timeout; failures are recorded as a finding
of type `scan_error` and can notify)

Interface: `collect(ctx) -> list[Finding]` plus `info() -> {name, version, db_age}`.
`Finding = {host, source, kind, id, package, installed, fixed, severity, cvss, title, url,
           component (service/container/path), extra{...}}`; `kind` ∈ vuln | hardening |
exposure | secret | auth | update | scan_error. Stable key = hash(host, source, kind, id, package, component).

| Collector | Default | What | Notes |
|---|---|---|---|
| `nix` | on (if NixOS) | `vulnix -C /run/current-system --json` = installed (runtime) closure only (+ `/run/booted-system` if different); `scope: build` = `vulnix --system` incl. build-time deps | respect vulnix whitelist file; map store paths → package names |
| `os` | on (if not NixOS) | `trivy rootfs --scanners vuln /` | Debian/Ubuntu/Alpine/RHEL… |
| `containers` | on (if docker/podman present) | list images in use (`podman/docker ps --format json`), `trivy image --input` or by ref | component = container name |
| `lynis` | on, monthly | `lynis audit system --quick --no-colors` → hardening index + warnings + suggestions | findings kind=hardening, severity from warning(=medium)/suggestion(=low) |
| `exposure` | on | (1) listening sockets via `ss -tulpnH` vs expected list; (2) for configured public names: resolve via public DNS, TCP connect to expected/unexpected ports on own public IP, TLS (expiry, protocol ≥1.2, chain), HTTP security headers (HSTS, X-Content-Type-Options, frame protection, CSP present?) | only own targets; unexpected open port = high |
| `secrets` | on | `gitleaks detect --no-git` / `gitleaks git` on configured repo paths (and optionally git URLs cloned read-only into cache) | report file+line+rule, never the secret value (redact) |
| `auth` | on | parse journald (sshd, fail2ban, configurable units/regexes for vaultwarden, nextcloud, forgejo) → counts per source/IP/day; anomaly = threshold or ×N baseline | kind=auth; stats stored for charts |
| `updates` | on | (1) NixOS flake: compare locked nixpkgs rev with channel head (GitHub API, info only) and list security-relevant packages that changed; (2) container images: newer tag available in registry; (3) tool/DB freshness: vulnix/trivy/lynis/gitleaks version + DB age | kind=update |

Enrichers (on by default, each toggleable):
- **KEV**: CISA Known Exploited Vulnerabilities JSON (daily) → `extra.kev=true` (+ dateAdded,
  dueDate). KEV findings are always shown first and, by default, always notify.
- **EPSS**: FIRST EPSS scores (daily CSV/API for the CVEs we have) → `extra.epss`, percentile.
- **CVSS**: from scanner output; severity bands Critical ≥9, High ≥7, Medium ≥4, Low >0, None.

## 4. Lifecycle and reports
- Each scan produces a snapshot; diff vs previous: `new`, `still_open`, `fixed`.
- Finding states: `open`, `fixed` (gone from scan), `accepted` (user, with reason + optional
  expiry; reopens automatically after expiry), `false_positive` (user, permanent with reason).
- Reports (stored as JSON + rendered HTML in `reports/`, never deleted automatically unless
  `retention` set):
  - **daily**: only new findings since last daily report (+ fixed ones as info).
  - **weekly** (default Sunday 18:00): all still-open findings, grouped by severity/host,
    with age; only sent if there are open items (configurable).
  - **monthly** (1st of month): totals per severity/kind/host, new/fixed during the month,
    mean time to fix, hardening index trend, auth stats; **comparison with previous months**.
- Scan schedule: `daily` (default) / `weekly` / `monthly` (+ custom time). Report schedule is
  independent from notification toggles: reports are always generated.

## 5. Notifications
Channels: `ntfy` (url, topic, token file, priority mapping, click URL to dashboard) and `mail`
(SMTP host/port/STARTTLS/user/password file/from/to). Both optional.

Matrix (each cell = {push: bool, mail: bool}), events × severities:

| Event | Critical | High | Medium | Low |
|---|---|---|---|---|
| new_finding (daily) | push+mail | push | – | – |
| weekly_summary | push | push | – | – |
| monthly_report | – | – | – | – |
| kev_finding (any severity) | push+mail | | | |
| exposure_change | push+mail (unexpected open port = high) | | | |
| secret_found | push+mail | | | |
| auth_anomaly | push | | | |
| update_available | push (security-relevant only) | | | |
| scan_error | push | | | |
(defaults; all editable in wizard/settings). Messages are short: title = what + host; body =
counts + top 5 items (id, package, severity, KEV/EPSS marker); click opens the dashboard.
Rate limiting/dedup per finding key.

## 6. Web UI (sec dashboard)
- Header: language switcher (en default, de), host filter, last scan time, "Scan now".
- **Overview**: cards per severity (open counts, KEV count), per host status, trend chart
  (open findings over time), next scheduled scan/report, tool & DB freshness.
- **Findings**: table (filter by host, kind, severity, KEV, state; sort by priority =
  KEV > EPSS > CVSS > age), detail drawer (description, fixed version, affected component,
  links: CVE/NVD/advisory), actions: accept (reason, expiry), mark false positive, reopen.
- **Reports**: list of daily/weekly/monthly reports; open HTML; **compare** two monthly
  reports side by side (deltas).
- **Hardening** (Lynis index trend + warnings), **Exposure** (expected vs actual ports per
  host, TLS/header checks), **Secrets**, **Auth** (charts per source/day, top IPs), **Updates**.
- **Settings**: everything from the wizard, editable later; values locked by the NixOS module
  are shown read-only with a hint.
- Auth: single admin password (argon2/bcrypt hash in config) or `SECWATCH_TOKEN`; sessions via
  HttpOnly cookie. Optional "trusted reverse proxy" mode (no login, proxy restricts access).
- Same visual style as the homelab dashboard (dark, cards, rail) but standalone.

## 7. Setup wizard (first run, re-runnable)
Pages, each with a short explanation of what happens and where:
1. Welcome & language, role (standalone/hub/agent), admin password.
2. Detected environment (auto): OS/NixOS, container runtime + containers, journald units,
   listening ports, hostnames (from nginx/registry file if present), git repos → confirm.
3. Checks: enable/disable each collector/enricher with explanation and privacy note
   (what is downloaded from where).
4. Schedule: scan frequency/time, report days/times.
5. Severity & notification matrix (push/mail per event × severity), presets "quiet / normal / strict".
6. Channels: ntfy and/or mail; "send test" buttons.
7. Exposure: public names/IP, expected ports (pre-filled from detection/registry).
8. Secrets: repos to scan.
9. Auth monitoring: sources (pre-filled), thresholds.
10. (hub) agents: URL + token, "test connection".
11. Summary → save → first scan starts.
Anything the NixOS module sets declaratively is pre-filled and locked.

## 8. Configuration
`config.yaml` in the state dir (written by wizard/settings); environment variables and the
NixOS module can provide defaults and lock keys (`locked: [...]`). Secrets only via file paths
(`*_file`). Integration helpers: optional `registry_file` (JSON list of services with url/exposure,
like the homelab `/etc/homelab/registry.json`) to pre-fill exposure targets.

## 9. NixOS module (`services.secwatch`)
Options: `enable`, `role`, `listen` (address/port), `settings` (attrset merged into config,
listed keys locked), `collectors.<name>.enable`, `ntfy.tokenFile`, `mail.passwordFile`,
`agents` (hub), `agentTokenFile`, `openFirewall` (agent port to given sources only),
`nginx.virtualHost` (optional). Provides: users/groups, tmpfiles, `secwatch-web.service`,
`secwatch-scan.service` (+ `.timer`, `.path`), tools on PATH (vulnix, trivy, lynis, gitleaks,
iproute2), journald read access (group `systemd-journal`) for the auth collector,
podman/docker socket access for the containers collector (root scan unit). Hardening on both units.

## 10. Privacy / outbound summary (README must contain this table)
| Destination | Purpose | Data sent |
|---|---|---|
| nvd.nist.gov (via vulnix) | NVD CVE feeds | none (download only) |
| ghcr.io / mirror.gcr.io (Trivy DB) | vuln DB | none; `--skip-version-check`, telemetry off |
| cisa.gov | KEV catalog | none |
| api.first.org | EPSS scores | list of CVE IDs found (configurable: or download full daily CSV instead — default **full CSV**, so no CVE list leaves the host) |
| api.github.com / registries | update checks (channel head, image tags, tool releases) | none beyond the public repo/image names |
| own ntfy / SMTP | notifications | message content |

## 11. Licence
PolyForm Noncommercial 1.0.0, licensor "Tech-Maou". Commercial use requires a separate licence
(contact via the Forgejo profile). README states this clearly.
