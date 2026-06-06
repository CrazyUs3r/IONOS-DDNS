#!/bin/sh
set -e

CONFIG_DIR="${CONFIG_DIR:-/config}"

mkdir -p "$CONFIG_DIR"

if [ "$(id -u)" = "0" ]; then
    CURRENT_OWNER="$(stat -c '%u' "$CONFIG_DIR" 2>/dev/null || echo 0)"
    if [ "$CURRENT_OWNER" != "1000" ]; then
        chown 1000:1000 "$CONFIG_DIR"
    fi
    exec /sbin/su-exec dyndns /app/dyndns "$@"
fi

exec /app/dyndns "$@"