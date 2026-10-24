"""SMTP mail channel (STARTTLS by default, password from file)."""

from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from ..config import read_secret


def build(cfg, m) -> EmailMessage:
    msg = EmailMessage()
    sender = cfg.get("notify.mail.from") or cfg.get("notify.mail.user") or f"secwatch@{cfg.host}"
    msg["From"] = sender
    msg["To"] = ", ".join(cfg.get("notify.mail.to") or [])
    msg["Subject"] = f"[secwatch] {m.title}"
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=sender.split("@")[-1] if "@" in sender else None)
    msg.set_content(m.body)
    return msg


def send(cfg, m, smtp_factory=None) -> None:
    host = cfg.get("notify.mail.host")
    port = int(cfg.get("notify.mail.port") or 587)
    tls = cfg.get("notify.mail.tls", "starttls")
    to = cfg.get("notify.mail.to") or []
    if not host or not to:
        raise ValueError("mail host and recipients required")
    ctx = ssl.create_default_context()
    if smtp_factory is not None:
        s = smtp_factory(host, port)
    elif tls == "ssl":
        s = smtplib.SMTP_SSL(host, port, timeout=30, context=ctx)
    else:
        s = smtplib.SMTP(host, port, timeout=30)
    try:
        if tls == "starttls":
            s.starttls(context=ctx)
        user = cfg.get("notify.mail.user")
        if user:
            pw = read_secret(cfg.get("notify.mail.password_file", ""))
            if pw is None:
                raise RuntimeError("mail password file not readable")
            s.login(user, pw)
        s.send_message(build(cfg, m))
    finally:
        try:
            s.quit()
        except Exception:
            pass
