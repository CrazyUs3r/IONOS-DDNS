#!/bin/sh
set -e

CONFIG_DIR="${CONFIG_DIR:-/config}"

mkdir -p "$CONFIG_DIR"

if [ "$(id -u)" = "0" ]; then
    OWNER="$(stat -c '%u' "$CONFIG_DIR" 2>/dev/null || echo 0)"

    if [ "$OWNER" != "1000" ]; then
        echo "Adjusting ownership of $CONFIG_DIR"
        chown -R 1000:1000 "$CONFIG_DIR"
    fi

    exec su dyndns -c "/app/dyndns"
fi

exec /app/dyndns