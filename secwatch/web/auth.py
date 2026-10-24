"""Web authentication: admin password (argon2), token (SECWATCH_TOKEN / token file), trusted
reverse proxy mode, DB-backed sessions, CSRF tokens and the first-run setup code."""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
from datetime import timedelta
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from ..config import read_secret
from ..db import DB, now_iso, parse_ts, utcnow

log = logging.getLogger(__name__)
COOKIE = "secwatch_session"
CSRF_HEADER = "x-secwatch-csrf"
_ph = PasswordHasher()


def hash_password(pw: str) -> str:
    if len(pw) < 10:
        raise ValueError("password must have at least 10 characters")
    return _ph.hash(pw)


def verify_password(hash_: str, pw: str) -> bool:
    if not hash_ or not pw:
        return False
    try:
        return _ph.verify(hash_, pw)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def api_token(cfg) -> str | None:
    tok = os.environ.get("SECWATCH_TOKEN") or read_secret(cfg.get("web.token_file", ""))
    return tok or None


def token_ok(cfg, presented: str | None) -> bool:
    tok = api_token(cfg)
    return bool(tok and presented and hmac.compare_digest(tok.encode(), presented.encode()))


def agent_token_ok(cfg, presented: str | None) -> bool:
    tok = read_secret(cfg.get("agent.token_file", ""))
    return bool(tok and presented and hmac.compare_digest(tok.encode(), presented.encode()))


def _h(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(db: DB, hours: int) -> tuple[str, str]:
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
    exp = (utcnow() + timedelta(hours=max(1, hours))).replace(microsecond=0).isoformat()
    db.exec("INSERT INTO sessions(token_hash,csrf,created_at,expires_at) VALUES(?,?,?,?)", (_h(token), csrf, now_iso(), exp))
    db.exec("DELETE FROM sessions WHERE expires_at<?", (now_iso(),))
    return token, csrf


def get_session(db: DB, token: str | None) -> dict | None:
    if not token or len(token) > 200:
        return None
    r = db.one("SELECT * FROM sessions WHERE token_hash=?", (_h(token),))
    if r is None:
        return None
    exp = parse_ts(r["expires_at"])
    if exp is None or exp < utcnow():
        db.exec("DELETE FROM sessions WHERE token_hash=?", (_h(token),))
        return None
    return dict(r)


def delete_session(db: DB, token: str | None) -> None:
    if token:
        db.exec("DELETE FROM sessions WHERE token_hash=?", (_h(token),))


def drop_other_sessions(db: DB, keep_token: str | None) -> None:
    db.exec("DELETE FROM sessions WHERE token_hash<>?", (_h(keep_token) if keep_token else "",))


def server_secret(state: Path) -> bytes:
    p = state / "web-secret"
    try:
        data = p.read_bytes()
        if len(data) >= 32:
            return data
    except OSError:
        pass
    data = secrets.token_bytes(32)
    state.mkdir(parents=True, exist_ok=True)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return data


def proxy_csrf(state: Path) -> str:
    return hmac.new(server_secret(state), b"trusted-proxy-csrf", hashlib.sha256).hexdigest()


def setup_code(state: Path, create: bool = True) -> str | None:
    """One-time code that protects the wizard before an admin password exists."""
    p = state / "setup-code"
    try:
        code = p.read_text().strip()
        if code:
            return code
    except OSError:
        pass
    if not create:
        return None
    code = "-".join(secrets.token_hex(2) for _ in range(3))
    try:
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
        with os.fdopen(fd, "w") as f:
            f.write(code + "\n")
    except OSError as e:
        log.error("cannot write setup code: %s", e)
    log.warning("first run: the setup code is in %s (needed to open the wizard)", p)
    return code


def needs_setup_code(cfg) -> bool:
    return (not cfg.get("setup_complete") and not cfg.get("web.admin_password_hash")
            and cfg.get("web.auth_mode") != "trusted_proxy")
