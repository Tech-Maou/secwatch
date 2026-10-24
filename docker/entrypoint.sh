#!/bin/bash
# Runs secwatch-web unprivileged and the scanner loop as root (needs the host rootfs and the
# container engine socket). If either process exits, the container stops.
set -euo pipefail
umask 0007
STATE="${SECWATCH_STATE_DIR:-/var/lib/secwatch}"
mkdir -p "$STATE"
chown secwatch:secwatch "$STATE"
chmod 2770 "$STATE"   # setgid: files written by the scanner stay readable for the web user

setpriv --reuid=secwatch --regid=secwatch --init-groups -- secwatch-web &
web=$!
secwatch-scan loop --interval "${SECWATCH_LOOP_INTERVAL:-60}" &
scan=$!

trap 'kill -TERM "$web" "$scan" 2>/dev/null || true' TERM INT
wait -n "$web" "$scan"
status=$?
kill -TERM "$web" "$scan" 2>/dev/null || true
wait || true
exit "$status"
