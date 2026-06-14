#!/bin/sh
set -e

CONFIG_DIR="${CONFIG_DIR:-/config}"

case "$CONFIG_DIR" in
    ""|"/"|"/app"|"/bin"|"/sbin"|"/usr"|"/etc")
        echo "Refusing unsafe CONFIG_DIR: $CONFIG_DIR" >&2
        exit 1
        ;;
esac

if [ "$(id -u)" = "0" ]; then
    mkdir -p "$CONFIG_DIR"
    CURRENT_OWNER="$(stat -c '%u:%g' "$CONFIG_DIR" 2>/dev/null || echo '')"
    if [ "$CURRENT_OWNER" != "1000:1000" ]; then
        echo "Adjusting ownership of $CONFIG_DIR"
        chown -R 1000:1000 "$CONFIG_DIR"
    fi
        exec su -s /bin/sh -c "/app/dyndns $@" dyndns
    fi
fi

exec /app/dyndns "$@"
