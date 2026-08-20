#!/bin/sh
# Remove aptai. Configuration, logs and reports are kept unless --purge.
set -eu

PREFIX="${PREFIX:-/usr/local}"
CONFDIR="${CONFDIR:-/etc/aptai}"
LOGDIR="${LOGDIR:-/var/log/aptai}"
STATEDIR="${STATEDIR:-/var/lib/aptai}"
UNITDIR="${UNITDIR:-/etc/systemd/system}"

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

[ "$(id -u)" = "0" ] || { echo "uninstall.sh: must be run as root" >&2; exit 1; }

if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now aptai.timer 2>/dev/null || true
    systemctl stop aptai.service 2>/dev/null || true
fi
rm -f "$UNITDIR/aptai.service" "$UNITDIR/aptai.timer"
command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload || true

rm -f "$PREFIX/bin/aptai"
rm -rf "$PREFIX/lib/aptai"

if [ "$PURGE" = "1" ]; then
    rm -rf "$CONFDIR" "$LOGDIR" "$STATEDIR"
    echo "aptai removed, including $CONFDIR, $LOGDIR and $STATEDIR"
else
    echo "aptai removed. Kept $CONFDIR, $LOGDIR and $STATEDIR (use --purge to delete them)."
fi
