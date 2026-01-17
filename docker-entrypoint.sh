#!/bin/sh
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "${GREEN}=== Go-DynDNS Initialisierung ===${NC}"

CONFIG_DIR="${CONFIG_DIR:-/config}"

echo "${GREEN}→ Config-Verzeichnis: ${CONFIG_DIR}${NC}"

mkdir -p "${CONFIG_DIR}/lang" "${CONFIG_DIR}/logs"

for lang in de en fr; do
    if [ ! -f "${CONFIG_DIR}/lang/${lang}.json" ]; then
        echo "${YELLOW}→ Kopiere ${lang}.json nach ${CONFIG_DIR}/lang/${NC}"
        cp "/app/lang/${lang}.json" "${CONFIG_DIR}/lang/${lang}.json"
    else
        echo "${GREEN}✓ ${lang}.json bereits vorhanden${NC}"
    fi
done

chmod -R 644 "${CONFIG_DIR}/lang"/*.json 2>/dev/null || true

echo "${GREEN}=== Initialisierung abgeschlossen ===${NC}"
echo ""

exec "$@"