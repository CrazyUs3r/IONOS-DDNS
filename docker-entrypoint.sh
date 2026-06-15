#!/bin/sh
set -eu

APP_UID=1000
APP_GID=1000

CONFIG_DIR="${CONFIG_DIR:-/config}"

case "$CONFIG_DIR" in
    /*)
        ;;
    *)
        echo "CONFIG_DIR must be an absolute path: $CONFIG_DIR" >&2
        exit 1
        ;;
esac

case "$CONFIG_DIR" in
    "/"|\
    "/app"|"/app/"*|\
    "/bin"|"/bin/"*|\
    "/dev"|"/dev/"*|\
    "/etc"|"/etc/"*|\
    "/lib"|"/lib/"*|\
    "/proc"|"/proc/"*|\
    "/root"|"/root/"*|\
    "/run"|"/run/"*|\
    "/sbin"|"/sbin/"*|\
    "/sys"|"/sys/"*|\
    "/usr"|"/usr/"*)
        echo "Refusing unsafe CONFIG_DIR: $CONFIG_DIR" >&2
        exit 1
        ;;
esac

if [ "$(id -u)" -eq 0 ]; then
    mkdir -p "$CONFIG_DIR"

    echo "Ensuring ownership of $CONFIG_DIR"
    chown -R "${APP_UID}:${APP_GID}" "$CONFIG_DIR"

    exec /sbin/su-exec \
        "${APP_UID}:${APP_GID}" \
        /app/dyndns \
        "$@"
fi

if [ ! -d "$CONFIG_DIR" ]; then
    echo "CONFIG_DIR does not exist: $CONFIG_DIR" >&2
    exit 1
fi

if [ ! -w "$CONFIG_DIR" ]; then
    echo "CONFIG_DIR is not writable by UID $(id -u): $CONFIG_DIR" >&2
    exit 1
fi

exec /app/dyndns "$@"
