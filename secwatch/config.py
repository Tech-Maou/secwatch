"""Configuration: defaults < config.yaml < overrides (NixOS module / env), with locked keys.

Layers (later wins):
  1. DEFAULTS (this file)
  2. <state>/config.yaml        written by the wizard / settings page
  3. SECWATCH_OVERRIDES file    JSON or YAML {"settings": {...}, "locked": [...]}; written by
                                the NixOS module. Every leaf key in "settings" is locked; extra
                                paths can be listed in "locked".
  4. SECWATCH__a__b=value env   e.g. SECWATCH__notify__ntfy__url=https://ntfy.example; locked.

Secrets are never stored in the config, only paths to files (keys ending in ``_file``).
"""

from __future__ import annotations

import copy
import json
import logging
import os
import socket
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger(__name__)

SEVERITIES = ["critical", "high", "medium", "low"]
EVENTS = [
    "new_finding",
    "weekly_summary",
    "monthly_report",
    "kev_finding",
    "exposure_change",
    "secret_found",
    "auth_anomaly",
    "update_available",
    "scan_error",
]
COLLECTORS = ["nix", "os", "containers", "lynis", "exposure", "secrets", "auth", "updates", "sbom"]
PHASE2_COLLECTORS = ["lynis", "exposure", "secrets", "auth", "updates", "sbom"]
ENRICHERS = ["kev", "epss", "cvss"]
WEEKDAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


def _cell(push: bool, mail: bool) -> dict:
    return {"push": push, "mail": mail}


def _row(*cells: tuple[bool, bool]) -> dict:
    return {sev: _cell(*c) for sev, c in zip(SEVERITIES, cells)}


_ALL = lambda p, m: _row((p, m), (p, m), (p, m), (p, m))  # noqa: E731
_OFF = (False, False)

MATRIX_PRESETS: dict[str, dict] = {
    # defaults from SPEC section 5
    "normal": {
        "new_finding": _row((True, True), (True, False), _OFF, _OFF),
        "weekly_summary": _row((True, False), (True, False), _OFF, _OFF),
        "monthly_report": _row(_OFF, _OFF, _OFF, _OFF),
        "kev_finding": _ALL(True, True),
        "exposure_change": _ALL(True, True),
        "secret_found": _ALL(True, True),
        "auth_anomaly": _ALL(True, False),
        "update_available": _ALL(True, False),
        "scan_error": _ALL(True, False),
    },
    "quiet": {
        "new_finding": _row((True, False), _OFF, _OFF, _OFF),
        "weekly_summary": _row((True, False), _OFF, _OFF, _OFF),
        "monthly_report": _row(_OFF, _OFF, _OFF, _OFF),
        "kev_finding": _ALL(True, False),
        "exposure_change": _row((True, False), (True, False), _OFF, _OFF),
        "secret_found": _ALL(True, False),
        "auth_anomaly": _row(_OFF, _OFF, _OFF, _OFF),
        "update_available": _row(_OFF, _OFF, _OFF, _OFF),
        "scan_error": _row(_OFF, _OFF, _OFF, _OFF),
    },
    "strict": {
        "new_finding": _row((True, True), (True, True), (True, False), _OFF),
        "weekly_summary": _row((True, True), (True, True), (True, False), _OFF),
        "monthly_report": _ALL(False, True),
        "kev_finding": _ALL(True, True),
        "exposure_change": _ALL(True, True),
        "secret_found": _ALL(True, True),
        "auth_anomaly": _ALL(True, True),
        "update_available": _ALL(True, False),
        "scan_error": _ALL(True, True),
    },
}

DEFAULTS: dict[str, Any] = {
    "version": 1,
    "setup_complete": False,
    "language": "en",
    "role": "standalone",  # standalone | agent | hub
    "host_name": "",  # empty = system hostname
    "registry_file": "",  # optional JSON list of services (url/exposure) for pre-filling
    "web": {
        "listen": "127.0.0.1",
        "port": 8478,
        "base_url": "",  # public URL of the dashboard, used for click links
        "auth_mode": "password",  # password | token | trusted_proxy
        "admin_password_hash": "",  # argon2 hash (not a secret per se, still never shown)
        "token_file": "",  # file containing an API/login token (alternative: SECWATCH_TOKEN)
        "session_hours": 12,
        "secure_cookie": False,  # set when served via HTTPS
    },
    "schedule": {
        "scan": {"frequency": "daily", "time": "03:30", "weekday": "sun", "monthday": 1},
        "reports": {
            "daily": {"enabled": True, "time": "07:00"},
            "weekly": {"enabled": True, "weekday": "sun", "time": "18:00", "notify_only_if_open": True},
            "monthly": {"enabled": True, "monthday": 1, "time": "08:00"},
            "retention_days": 0,  # 0 = keep forever
        },
    },
    "collectors": {
        "nix": {
            "enabled": "auto",  # true | false | auto (= if NixOS)
            "timeout": 1800,
            "whitelist": [],  # vulnix whitelist files/URLs (TOML)
            "booted_system": True,
            "scope": "runtime",  # runtime = installed closure only | build = incl. build-time deps
            "mirror": "",  # alternative NVD mirror for vulnix
        },
        "os": {
            "enabled": "auto",  # auto = if not NixOS
            "timeout": 1800,
            "root": "/",
            "skip_dirs": ["/proc", "/sys", "/dev", "/run", "/tmp", "/nix", "/var/lib/docker",
                          "/var/lib/containers", "/var/lib/secwatch"],
        },
        "containers": {
            "enabled": "auto",  # auto = if docker/podman present
            "timeout": 3600,
            "runtime": "auto",  # auto | docker | podman
            "socket": "",  # override container engine socket path
            "image_timeout": 900,
            "exclude": [],  # container names to skip
        },
        "lynis": {"enabled": True, "timeout": 1800, "frequency": "monthly"},
        "exposure": {
            "enabled": True,
            "timeout": 300,
            "expected_ports": [],  # e.g. ["tcp/22", "tcp/443", "udp/51820"]
            "public_names": [],
            "public_ip": "",
            "check_tls": True,
            "check_headers": True,
        },
        "secrets": {"enabled": True, "timeout": 900, "repos": [], "git_urls": []},
        "auth": {
            "enabled": True,
            "timeout": 300,
            "sources": ["sshd", "fail2ban"],
            "custom_units": [],  # [{name, unit, regex}]
            "threshold_per_day": 50,
            "baseline_factor": 3,
        },
        "updates": {
            "enabled": True,
            "timeout": 300,
            "flake_lock": "",
            "check_channel": True,
            "check_images": True,
            "security_only": True,
        },
        "sbom": {"enabled": False, "timeout": 900},
    },
    "trivy": {
        "db_repository": [],  # empty = trivy default (mirror.gcr.io, ghcr.io)
        "java_db_repository": [],
        "skip_db_update": False,
        "scanners": "vuln",
    },
    "enrichers": {
        "kev": {
            "enabled": True,
            "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "max_age_hours": 24,
        },
        "epss": {
            "enabled": True,
            "mode": "csv",  # csv (full daily file, nothing leaves the host) | api (sends CVE IDs)
            "csv_url": "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
            "api_url": "https://api.first.org/data/v1/epss",
            "max_age_hours": 24,
        },
        "cvss": {"enabled": True},
    },
    "notify": {
        "matrix": copy.deepcopy(MATRIX_PRESETS["normal"]),
        "preset": "normal",
        "dedup_hours": 72,
        "max_per_hour": 12,  # per channel; protects against notification storms
        "update_security_only": True,
        "ntfy": {
            "enabled": False,
            "url": "",  # intentionally empty: nothing is sent until you set your own server (never public ntfy.sh)
            "topic": "",
            "token_file": "",
            "priority": {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 2},
            "tags": True,
        },
        "mail": {
            "enabled": False,
            "host": "",
            "port": 587,
            "tls": "starttls",  # starttls | ssl | none
            "user": "",
            "password_file": "",
            "from": "",
            "to": [],
        },
    },
    "agent": {
        "token_file": "",  # bearer token the hub must present for /api/agent/snapshot
        "ui": True,  # serve the UI on agents too
    },
    "hub": {
        "agents": [],  # [{name, url, token_file}]
        "timeout": 30,
        "verify_tls": True,
    },
}

ENUMS: dict[str, list] = {
    "language": [],  # validated against available i18n files
    "role": ["standalone", "agent", "hub"],
    "web.auth_mode": ["password", "token", "trusted_proxy"],
    "schedule.scan.frequency": ["daily", "weekly", "monthly"],
    "schedule.scan.weekday": WEEKDAYS,
    "schedule.reports.weekly.weekday": WEEKDAYS,
    "collectors.containers.runtime": ["auto", "docker", "podman"],
    "collectors.nix.scope": ["runtime", "build"],
    "collectors.lynis.frequency": ["daily", "weekly", "monthly"],
    "enrichers.epss.mode": ["csv", "api"],
    "notify.mail.tls": ["starttls", "ssl", "none"],
    "notify.preset": ["quiet", "normal", "strict", "custom"],
}
TRISTATE = {f"collectors.{c}.enabled" for c in ("nix", "os", "containers")}
TIME_KEYS = {"schedule.scan.time", "schedule.reports.daily.time", "schedule.reports.weekly.time",
             "schedule.reports.monthly.time"}
SECRET_SUFFIXES = ("_file",)
SENSITIVE_KEYS = {"web.admin_password_hash"}


def state_dir() -> Path:
    return Path(os.environ.get("SECWATCH_STATE_DIR", "/var/lib/secwatch"))


def deep_merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict) and k != "matrix":
            out[k] = deep_merge(out[k], v)
        elif isinstance(v, dict) and isinstance(out.get(k), dict) and k == "matrix":
            # matrix: merge per event / severity cell
            m = copy.deepcopy(out[k])
            for ev, row in v.items():
                if isinstance(row, dict):
                    m.setdefault(ev, {})
                    for sev, cell in row.items():
                        if isinstance(cell, dict):
                            m[ev].setdefault(sev, {}).update(cell)
            out[k] = m
        else:
            out[k] = copy.deepcopy(v)
    return out


def leaf_paths(d: dict, prefix: str = "") -> list[str]:
    out: list[str] = []
    for k, v in d.items():
        p = f"{prefix}.{k}" if prefix else str(k)
        if isinstance(v, dict) and v:
            out.extend(leaf_paths(v, p))
        else:
            out.append(p)
    return out


def get_path(d: dict, path: str, default: Any = None) -> Any:
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def set_path(d: dict, path: str, value: Any) -> None:
    parts = path.split(".")
    cur = d
    for part in parts[:-1]:
        cur = cur.setdefault(part, {})
    cur[parts[-1]] = value


def is_locked(path: str, locked: set[str]) -> bool:
    """A path is locked if it or any parent or any child is locked."""
    for lk in locked:
        if path == lk or path.startswith(lk + ".") or lk.startswith(path + "."):
            return True
    return False


def _parse_env_value(raw: str) -> Any:
    try:
        return yaml.safe_load(raw)
    except yaml.YAMLError:
        return raw


def _read_structured(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        data = json.loads(text or "{}")
    else:
        data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top level must be a mapping")
    return data


@dataclass
class Config:
    data: dict
    locked: set[str] = field(default_factory=set)
    state: Path = field(default_factory=state_dir)
    user_data: dict = field(default_factory=dict)  # what is in config.yaml
    warnings: list[str] = field(default_factory=list)

    def get(self, path: str, default: Any = None) -> Any:
        return get_path(self.data, path, default)

    @property
    def host(self) -> str:
        return self.data.get("host_name") or socket.gethostname()

    @property
    def db_path(self) -> Path:
        return self.state / "secwatch.db"

    @property
    def reports_dir(self) -> Path:
        return self.state / "reports"

    @property
    def cache_dir(self) -> Path:
        return self.state / "cache"

    @property
    def trigger_path(self) -> Path:
        return self.state / "trigger"

    @property
    def config_path(self) -> Path:
        return Path(os.environ.get("SECWATCH_CONFIG", str(self.state / "config.yaml")))

    def collector_cfg(self, name: str) -> dict:
        return self.data.get("collectors", {}).get(name, {})


def load(state: Path | None = None, env: dict | None = None) -> Config:
    env = dict(os.environ if env is None else env)
    if state is None:
        state = Path(env.get("SECWATCH_STATE_DIR", "/var/lib/secwatch"))
    cfg_path = Path(env.get("SECWATCH_CONFIG", str(state / "config.yaml")))
    warnings: list[str] = []
    user: dict = {}
    if cfg_path.exists():
        try:
            user = _read_structured(cfg_path)
        except Exception as e:  # keep running on a broken file, but say so
            warnings.append(f"config.yaml unreadable: {e}")
            log.error("cannot read %s: %s", cfg_path, e)
    data = deep_merge(DEFAULTS, user)
    locked: set[str] = set()

    ov_file = env.get("SECWATCH_OVERRIDES")
    if ov_file:
        p = Path(ov_file)
        if p.exists():
            try:
                ov = _read_structured(p)
                settings = ov.get("settings", {}) or {}
                data = deep_merge(data, settings)
                locked.update(leaf_paths(settings))
                locked.update(ov.get("locked", []) or [])
            except Exception as e:
                warnings.append(f"overrides file unreadable: {e}")
                log.error("cannot read overrides %s: %s", p, e)
        else:
            warnings.append(f"overrides file {p} not found")

    for key, raw in env.items():
        if key.startswith("SECWATCH__"):
            path = ".".join(part.lower() for part in key[len("SECWATCH__"):].split("__") if part)
            if path:
                set_path(data, path, _parse_env_value(raw))
                locked.add(path)

    cfg = Config(data=data, locked=locked, state=state, user_data=user, warnings=warnings)
    cfg.warnings.extend(validate(data))
    return cfg


def _type_ok(default: Any, value: Any) -> bool:
    if isinstance(default, bool):
        return isinstance(value, bool)
    if isinstance(default, int):
        return isinstance(value, int) and not isinstance(value, bool)
    if isinstance(default, float):
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if isinstance(default, str):
        return isinstance(value, str)
    if isinstance(default, list):
        return isinstance(value, list)
    if isinstance(default, dict):
        return isinstance(value, dict)
    return True


def _valid_time(v: Any) -> bool:
    if not isinstance(v, str) or len(v) != 5 or v[2] != ":":
        return False
    try:
        h, m = int(v[:2]), int(v[3:])
    except ValueError:
        return False
    return 0 <= h < 24 and 0 <= m < 60


def validate_value(path: str, value: Any, languages: list[str] | None = None) -> str | None:
    """Return an error message or None."""
    if path in TRISTATE:
        if value not in (True, False, "auto"):
            return f"{path}: must be true, false or 'auto'"
        return None
    default = get_path(DEFAULTS, path, _MISSING)
    if default is _MISSING:
        if path.startswith("notify.matrix."):
            parts = path.split(".")
            if len(parts) >= 3 and parts[2] not in EVENTS:
                return f"{path}: unknown event"
            if len(parts) >= 4 and parts[3] not in SEVERITIES:
                return f"{path}: unknown severity"
            if len(parts) == 5:
                if parts[4] not in ("push", "mail") or not isinstance(value, bool):
                    return f"{path}: must be push/mail boolean"
            return None
        return f"{path}: unknown key"
    if not _type_ok(default, value):
        return f"{path}: expected {type(default).__name__}"
    if path in ENUMS:
        allowed = ENUMS[path] or (languages or [])
        if allowed and value not in allowed:
            return f"{path}: must be one of {', '.join(map(str, allowed))}"
    if path in TIME_KEYS and not _valid_time(value):
        return f"{path}: must be HH:MM"
    if path == "web.port" and not (1 <= value <= 65535):
        return f"{path}: invalid port"
    if path.endswith("monthday") and not (1 <= value <= 28):
        return f"{path}: must be 1..28"
    if path == "hub.agents":
        for a in value:
            if not isinstance(a, dict) or not a.get("name") or not str(a.get("url", "")).startswith(("http://", "https://")):
                return f"{path}: each agent needs name and http(s) url"
    if path == "notify.mail.to" and not all(isinstance(x, str) and "@" in x for x in value):
        return f"{path}: list of e-mail addresses"
    return None


_MISSING = object()


def validate(data: dict, languages: list[str] | None = None) -> list[str]:
    errors: list[str] = []
    for path in leaf_paths(data):
        if path.startswith("notify.matrix"):
            continue
        err = validate_value(path, get_path(data, path), languages)
        if err:
            errors.append(err)
    return errors


def redact(data: dict) -> dict:
    """Copy of the config safe to show in UI/logs: secret file paths stay (paths are not
    secrets) but get a set/unset flag; hashes are replaced."""
    out = copy.deepcopy(data)
    for path in SENSITIVE_KEYS:
        if get_path(out, path) is not None:
            set_path(out, path, "set" if get_path(out, path) else "")
    return out


def secret_status(path: str) -> str:
    """'set' if a secret file exists and is non-empty, 'unreadable', or 'unset'."""
    if not path:
        return "unset"
    try:
        return "set" if Path(path).read_text().strip() else "unset"
    except PermissionError:
        return "unreadable"  # exists, but not readable for this process (e.g. root-only)
    except OSError:
        return "missing"


def read_secret(path: str) -> str | None:
    if not path:
        return None
    try:
        return Path(path).read_text(encoding="utf-8").strip() or None
    except OSError as e:
        log.warning("cannot read secret file %s: %s", path, e.__class__.__name__)
        return None


def save_user_config(cfg: Config, changes: dict, languages: list[str] | None = None) -> list[str]:
    """Apply ``changes`` (nested dict) on top of config.yaml. Locked keys are rejected.
    Returns a list of errors (empty = saved)."""
    errors = []
    for path in leaf_paths(changes) if changes else []:
        if is_locked(path, cfg.locked):
            errors.append(f"{path}: locked by system configuration")
            continue
        err = validate_value(path, get_path(changes, path), languages)
        if err:
            errors.append(err)
    if errors:
        return errors
    new_user = deep_merge(cfg.user_data, changes)
    write_yaml_atomic(cfg.config_path, new_user)
    cfg.user_data = new_user
    cfg.data = deep_merge(cfg.data, changes)
    return []


def write_yaml_atomic(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".config-", suffix=".yaml")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True)
        os.chmod(tmp, 0o660)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_secret(cfg: Config, name: str, value: str) -> str:
    """Store a secret entered in the UI as a file under <state>/secrets and return the path."""
    d = cfg.state / "secrets"
    d.mkdir(mode=0o770, parents=True, exist_ok=True)
    safe = "".join(c for c in name if c.isalnum() or c in "-_") or "secret"
    p = d / safe
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(value.strip() + "\n")
    os.chmod(p, 0o640)
    return str(p)
