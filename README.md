# secwatch

Self-hosted security monitoring for small fleets – homelabs and small offices.

secwatch finds known vulnerabilities on your hosts and in your container images, prioritises
them (CISA KEV › FIRST EPSS › CVSS › age), tracks them over time, writes daily / weekly /
monthly reports and notifies you through your own ntfy server and/or mail – according to a
per-event × per-severity matrix you control.

**Principle: secwatch only fetches information. It never sends inventory, findings or system
data to third parties.**

- NixOS first (flake + NixOS module), but also runs on any Linux (container image, pip + systemd)
- Every check can be switched on or off individually; most things are auto-detected
- Multi-page setup wizard, web dashboard (en / de, more languages = one JSON file)
- Multi-host: `standalone`, `agent`, `hub` (pull model – agents never push)

> Status: **phase 1**. Implemented: NixOS packages (vulnix), OS packages (trivy rootfs),
> container images (trivy), KEV/EPSS/CVSS enrichment, lifecycle, reports, notifications,
> hub/agent, web UI, wizard. Lynis hardening, exposure, secrets (gitleaks), auth monitoring,
> update checks and SBOM are registered and configurable but arrive in phase 2.

## Contents
- [Privacy / outbound connections](#privacy--outbound-connections)
- [Install on NixOS](#install-on-nixos)
- [Install with Docker](#install-with-docker)
- [Install with pip + systemd](#install-with-pip--systemd)
- [Setup wizard](#setup-wizard)
- [How it works](#how-it-works)
- [Configuration reference](#configuration-reference)
- [Command line](#command-line)
- [Development](#development)
- [Licence](#licence)
- [Kurz auf Deutsch](#kurz-auf-deutsch)

## Privacy / outbound connections

| Destination | Purpose | Data sent | Switch |
|---|---|---|---|
| nvd.nist.gov (via vulnix) | NVD CVE feeds | none (download only) | `collectors.nix.enabled`, `collectors.nix.mirror` |
| ghcr.io / mirror.gcr.io (Trivy DB) | vulnerability DB | none; `--skip-version-check`, telemetry off (`--disable-telemetry` when the installed trivy supports it) | `collectors.os/containers.enabled`, `trivy.db_repository`, `trivy.skip_db_update` |
| cisa.gov | KEV catalog (once a day) | none | `enrichers.kev.enabled`, `enrichers.kev.url` |
| epss.empiricalsecurity.com (FIRST's official EPSS file host, `epss.cyentia.com` redirects there) | full daily EPSS CSV (default) | none | `enrichers.epss.enabled`, `enrichers.epss.csv_url` |
| api.first.org | EPSS API – **only if `enrichers.epss.mode: api`** | list of CVE IDs found | `enrichers.epss.mode` (default **csv**, so no CVE list leaves the host) |
| api.github.com / registries | update checks (phase 2: channel head, image tags, tool releases) | none beyond the public repo/image names | `collectors.updates.enabled` |
| your own ntfy / SMTP server | notifications | message content (titles, counts, top 5 IDs) | `notify.ntfy.enabled`, `notify.mail.enabled` |
| your own agents (hub role) | pull snapshots | bearer token | `hub.agents` |

Nothing else: no telemetry, no update pings, no CDN assets (the UI is served locally, no
external fonts or scripts). Container images are read from the local engine and are never
pulled from a registry.

## Install on NixOS

`flake.nix` of your system:

```nix
{
  inputs.secwatch.url = "github:Tech-Maou/secwatch";
  inputs.secwatch.inputs.nixpkgs.follows = "nixpkgs";   # optional: share your nixpkgs

  outputs = { nixpkgs, secwatch, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        secwatch.nixosModules.default
        ./configuration.nix
      ];
    };
  };
}
```

`configuration.nix`:

```nix
{
  services.secwatch = {
    enable = true;
    # Everything below is optional – the wizard can do the rest. Values set here are locked
    # (read-only in the UI).
    nginx.virtualHost = "sec.example.org";
    nginx.virtualHostConfig = { forceSSL = true; useACMEHost = "example.org"; };
    ntfy.tokenFile = "/run/secrets/ntfy-token";          # agenix / sops-nix path, never the Nix store
    settings.notify.ntfy = { enabled = true; url = "https://ntfy.example.org"; topic = "secwatch"; };
    settings.registry_file = "/etc/homelab/registry.json";
  };
}
```

After `nixos-rebuild switch`, open the UI (via the nginx vhost or `ssh -L 8478:127.0.0.1:8478`)
and enter the one-time setup code: `sudo cat /var/lib/secwatch/setup-code`.

The package comes from this flake (`secwatch.packages.<system>.default`); it is not taken from
`pkgs`. The licence is not "free" in the nixpkgs sense – the flake allows exactly this package
for its own nixpkgs instance, so nothing has to be configured on your side.

### Multi-host (hub + agents)

```nix
# agent (e.g. agent1)
services.secwatch = {
  enable = true;
  role = "agent";
  listen.address = "10.100.0.2";                 # e.g. the WireGuard address
  agentTokenFile = "/run/secrets/secwatch-agent";
  openFirewall = { enable = true; sources = [ "10.100.0.1" ]; };   # only the hub
};

# hub (e.g. hub1)
services.secwatch = {
  enable = true;
  role = "hub";
  agents = [ { name = "agent1"; url = "http://10.100.0.2:8478"; tokenFile = "/run/secrets/secwatch-agent"; } ];
};
```

The hub pulls `GET /api/agent/snapshot` (bearer token) on every scan, stores the agent's
findings under the agent's name and notifies for all hosts. Set `settings.agent.ui = false`
on an agent to serve only the snapshot endpoint.

### NixOS module options

| Option | Default | Description |
|---|---|---|
| `enable` | `false` | enable secwatch |
| `package` | this flake's package | |
| `role` | `"standalone"` | `standalone` / `agent` / `hub` |
| `stateDir` | `"/var/lib/secwatch"` | DB, config.yaml, reports, caches, trigger file |
| `listen.address` / `listen.port` | `"127.0.0.1"` / `8478` | web UI / API |
| `settings` | `{}` | merged into the config (same structure as config.yaml); every key is locked |
| `lockedKeys` | `[]` | extra dotted paths to lock without setting them |
| `collectors.<name>.enable` | `null` | `nix os containers lynis exposure secrets auth updates sbom`; `null` = leave to UI/auto |
| `ntfy.tokenFile` | `null` | ntfy token file |
| `mail.passwordFile` | `null` | SMTP password file |
| `tokenFile` | `null` | API/login token file for the web UI |
| `agentTokenFile` | `null` | agent role: token the hub must present |
| `agents` | `[]` | hub role: `[{ name, url, tokenFile }]` |
| `openFirewall.enable` / `.sources` | `false` / `[]` | open the port, optionally only for given sources (iptables or nftables) |
| `nginx.virtualHost` / `.virtualHostConfig` | `null` / `{}` | reverse proxy vhost (sets `web.base_url`, secure cookie) |
| `timerOnCalendar` | `"*:0/15"` | wake-up interval of the scanner (schedule itself is in the config) |
| `extraScanPackages` | `[]` | extra tools on the scanner PATH (phase 2: lynis, gitleaks) |

The module creates user/group `secwatch`, the setgid state dir (tmpfiles), `secwatch-web.service`
(unprivileged, no capabilities), `secwatch-scan.service` (root oneshot, read-only system,
writes only the state dir, member of `systemd-journal`), `secwatch-scan.timer`,
`secwatch-scan.path` (watches the trigger file written by "Scan now") and enables the podman
socket when podman is used.

## Install with Docker

For non-NixOS hosts. The image contains web UI, scanner and trivy; a scheduler loop replaces
the systemd timer.

```sh
git clone https://github.com/Tech-Maou/secwatch && cd secwatch
docker compose -f docker/docker-compose.yml up -d --build
docker compose -f docker/docker-compose.yml exec secwatch cat /var/lib/secwatch/setup-code
# open http://127.0.0.1:8478
```

Mounts: the state volume, the host root file system read-only at `/host` (for the `os`
collector) and the docker socket (for the `containers` collector – remove it if you do not
want that; socket access is root-equivalent even when mounted `:ro`). Inside the container
the web server runs as an unprivileged user, the scanner as root. Any setting can be fixed
via environment variables, e.g. `SECWATCH__notify__ntfy__url=https://ntfy.example.org`.
Use `network_mode: host` if the port detection should see the host's sockets.

## Install with pip + systemd

```sh
sudo python3 -m venv /opt/secwatch
sudo /opt/secwatch/bin/pip install /path/to/secwatch      # Python >= 3.12
sudo cp systemd/secwatch.sysusers.conf /etc/sysusers.d/secwatch.conf && sudo systemd-sysusers
sudo cp systemd/secwatch.tmpfiles.conf /etc/tmpfiles.d/secwatch.conf && sudo systemd-tmpfiles --create
sudo cp systemd/secwatch-*.service systemd/secwatch-scan.timer systemd/secwatch-scan.path /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now secwatch-web.service secwatch-scan.timer secwatch-scan.path
sudo cat /var/lib/secwatch/setup-code
```

Install `trivy` (and `vulnix` on NixOS) and `iproute2` so that they are on the PATH of
`secwatch-scan.service`.

## Setup wizard

The wizard opens on first login (protected by the setup code until an admin password exists)
and can be re-run any time from the sidebar. Every page says what happens and where.

1. **Welcome** – language, role (standalone/hub/agent), admin password (argon2), login mode
   (password, token or trusted reverse proxy), dashboard URL for notification links.
2. **Environment** – auto-detected: OS/NixOS, container runtime and containers, journald
   units (sshd, fail2ban, vaultwarden, nextcloud, forgejo), listening ports (`ss`), host names
   from the registry file. "Use detected values" pre-fills later pages.
3. **Checks** – each collector and enricher with explanation and privacy note.
4. **Schedule** – scan frequency/time, report days/times, retention.
5. **Notifications** – the event × severity matrix (push/mail per cell), presets quiet/normal/strict.
6. **Channels** – ntfy and SMTP; secrets typed here are written to files under
   `<state>/secrets/`, never into config.yaml; "send test" buttons.
7. **Exposure** – public names/IP and expected ports (phase 2).
8. **Secrets** – repositories to scan (phase 2).
9. **Auth monitoring** – sources and thresholds (phase 2).
10. **Agents** – hub: agent URL + token with "test connection"; agent: its token.
11. **Summary** – save, mark setup complete, queue the first scan.

Values locked by the NixOS module (or environment) are shown read-only.

## How it works

- **secwatch-web** (user `secwatch`): UI + JSON API on the state DB. It never runs scanners;
  "Scan now" writes `<state>/trigger`, which starts `secwatch-scan.service` via the path unit.
- **secwatch-scan** (root, hardened oneshot): wakes up every 15 minutes and runs only what is
  due according to the configured schedule: collectors → enrichers → snapshot diff → hub pull
  → notifications → reports. Every collector/enricher/notifier failure is isolated and
  recorded as a `scan_error` finding (which can notify); a failed collector never marks its
  previous findings as fixed.
- **Findings** have a stable key `hash(host, source, kind, id, package, component)` and the
  states `open`, `fixed`, `accepted` (reason + optional expiry, reopens automatically) and
  `false_positive` (reason, permanent). Each scan diffs `new` / `still_open` / `fixed`.
- **Priority** = KEV › EPSS › CVSS (or severity band) › age. Severity bands: critical ≥ 9,
  high ≥ 7, medium ≥ 4, low > 0.
- **Reports** (JSON + HTML in `<state>/reports/<kind>/`): daily (new + fixed since the last
  daily report), weekly (all open, grouped by severity/host, with age), monthly (totals per
  severity/kind/host, new/fixed, mean time to fix, comparison with previous months). Reports
  are always generated; notifications are separate. Two monthly reports can be compared side
  by side in the UI.
- **Notifications**: one short message per event, host and channel – title = what + host,
  body = counts + top 5 (ID, package, severity, KEV/EPSS marker), click opens the dashboard.
  Dedup per finding key (`notify.dedup_hours`) and a per-channel rate limit (`notify.max_per_hour`).

Default matrix:

| Event | Critical | High | Medium | Low |
|---|---|---|---|---|
| new_finding (after each scan) | push+mail | push | – | – |
| weekly_summary | push | push | – | – |
| monthly_report | – | – | – | – |
| kev_finding | push+mail | push+mail | push+mail | push+mail |
| exposure_change | push+mail | push+mail | push+mail | push+mail |
| secret_found | push+mail | push+mail | push+mail | push+mail |
| auth_anomaly | push | push | push | push |
| update_available (security only) | push | push | push | push |
| scan_error | push | push | push | push |

## Configuration reference

Configuration is merged from (later wins): built-in defaults < `<state>/config.yaml` (written
by wizard/settings) < `SECWATCH_OVERRIDES` file (`{settings: {...}, locked: [...]}`, written by
the NixOS module) < `SECWATCH__a__b=value` environment variables. Keys from the last two are
locked. Secrets are only referenced by file path (`*_file`). Check with
`secwatch-scan config check --show`.

| Key | Default | |
|---|---|---|
| `language` | `en` | UI and notification language (`en`, `de`, any `i18n/<lang>.json`) |
| `role` | `standalone` | `standalone` / `agent` / `hub` |
| `host_name` | system host name | |
| `registry_file` | `""` | JSON `{services:[{name,url,exposure}]}` to pre-fill exposure targets |
| `web.listen` / `web.port` | `127.0.0.1` / `8478` | |
| `web.base_url` | `""` | dashboard URL for click links |
| `web.auth_mode` | `password` | `password` / `token` / `trusted_proxy` |
| `web.token_file` | `""` | token file (or env `SECWATCH_TOKEN`) |
| `web.session_hours` / `web.secure_cookie` | `12` / `false` | |
| `schedule.scan.frequency` / `.time` / `.weekday` / `.monthday` | `daily` / `03:30` / `sun` / `1` | |
| `schedule.reports.daily` | `{enabled: true, time: "07:00"}` | |
| `schedule.reports.weekly` | `{enabled: true, weekday: sun, time: "18:00", notify_only_if_open: true}` | |
| `schedule.reports.monthly` | `{enabled: true, monthday: 1, time: "08:00"}` | |
| `schedule.reports.retention_days` | `0` | 0 = keep forever |
| `collectors.nix` | `{enabled: auto, timeout: 1800, whitelist: [], booted_system: true, scope: runtime, mirror: ""}` | auto = on NixOS; `scope: build` also reports build-time dependencies |
| `collectors.os` | `{enabled: auto, root: "/", skip_dirs: [...]}` | auto = not NixOS |
| `collectors.containers` | `{enabled: auto, runtime: auto, socket: "", image_timeout: 900, exclude: []}` | auto = engine found |
| `collectors.lynis/exposure/secrets/auth/updates/sbom` | see `secwatch/config.py` | phase 2 |
| `trivy.db_repository` / `java_db_repository` / `skip_db_update` | `[]` / `[]` / `false` | mirrors |
| `enrichers.kev` | `{enabled: true, url: <CISA>, max_age_hours: 24}` | |
| `enrichers.epss` | `{enabled: true, mode: csv, csv_url, api_url, max_age_hours: 24}` | |
| `enrichers.cvss.enabled` | `true` | |
| `notify.matrix.<event>.<severity>` | see table above | `{push: bool, mail: bool}` |
| `notify.dedup_hours` / `max_per_hour` | `72` / `12` | |
| `notify.ntfy` | `{enabled: false, url, topic, token_file, priority: {critical: 5, ...}, tags: true}` | |
| `notify.mail` | `{enabled: false, host, port: 587, tls: starttls, user, password_file, from, to: []}` | |
| `agent.token_file` / `agent.ui` | `""` / `true` | agent role |
| `hub.agents` / `hub.timeout` / `hub.verify_tls` | `[]` / `30` / `true` | hub role |

## Command line

```
secwatch-scan scan [--only nix] [--json]   # scan now
secwatch-scan scan --if-due                # timer mode: trigger file, schedule, due reports
secwatch-scan report daily|weekly|monthly [--period 2026-09] [--no-notify]
secwatch-scan notify-test [--channel push|mail]
secwatch-scan config check [--show]
secwatch-scan loop [--interval 60]         # container scheduler
secwatch-web [--host H --port P]
```

## Development

```sh
nix develop          # python + vulnix + trivy
pytest               # or: nix build .#default (runs the test-suite)
nix flake check      # package + NixOS module evaluation in three roles
```

Adding a language: copy `secwatch/i18n/en.json` to `<code>.json` and translate; missing keys
fall back to English. A collector is a class with `collect()` and `info()` registered with
`@register` in `secwatch/collectors/`.

## Licence

[PolyForm Noncommercial License 1.0.0](LICENSE) – Copyright Tech-Maou
(https://github.com/Tech-Maou).

You may use, modify and share secwatch for any **noncommercial** purpose (personal use,
homelabs, hobby projects, research, education, charities, public bodies). **Commercial use
requires a separate licence** – please get in touch via the Forgejo profile
https://github.com/Tech-Maou.

## Kurz auf Deutsch

secwatch überwacht Hosts und Container-Images auf bekannte Schwachstellen, priorisiert sie
(KEV › EPSS › CVSS › Alter), verfolgt sie über die Zeit, schreibt Tages-, Wochen- und
Monatsberichte und benachrichtigt per eigenem ntfy-Server und/oder Mail nach einer frei
einstellbaren Matrix aus Ereignis × Schwere. secwatch **lädt nur Daten herunter** und sendet
keine Inventar- oder Befunddaten an Dritte (Tabelle oben). Installation unter NixOS über das
Flake-Input `github:Tech-Maou/secwatch` und `services.secwatch.enable = true;`,
danach im Browser den Einrichtungsassistenten mit dem Code aus
`/var/lib/secwatch/setup-code` öffnen. Die Oberfläche ist auf Deutsch umschaltbar.
Nutzung nur nicht-kommerziell (PolyForm Noncommercial 1.0.0); für kommerzielle Nutzung bitte
über das Forgejo-Profil Kontakt aufnehmen.

## Third-party components and data

secwatch runs vulnix, Trivy, Lynis, gitleaks and `ss` as separate programs and downloads
vulnerability data from NVD, CISA KEV, FIRST EPSS and the Trivy DB. Their licences and the
requested attributions are listed in [THIRD_PARTY.md](THIRD_PARTY.md).
This product uses data from the NVD API but is not endorsed or certified by the NVD.
EPSS scores: FIRST.org (https://www.first.org/epss).

## Development workflow

- Work happens on the `dev` branch (Forgejo, private).
- `nix flake check` (runs the test suite and module checks) must pass before merging.
- `dev` is merged into `main`; only `main` is mirrored to the public GitHub repository.
