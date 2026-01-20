#!/bin/sh
set -e

# Detect if output is a terminal
if [ -t 1 ]; then
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    RED='\033[0;31m'
    NC='\033[0m'
else
    GREEN=''
    YELLOW=''
    RED=''
    NC=''
fi

printf "${GREEN}=== Go-DynDNS Initialisierung ===${NC}\n"

# Configuration
CONFIG_DIR="${CONFIG_DIR:-/config}"
LANG_DIR="${CONFIG_DIR}/lang"
LOGS_DIR="${CONFIG_DIR}/logs"
PROVIDER="${PROVIDER:-IONOS}" # Standardmäßig IONOS

# Validate environment
printf "${GREEN}→ Validiere Umgebung für Provider: ${PROVIDER}...${NC}\n"

if [ ! -d "${CONFIG_DIR}" ]; then
    printf "${RED}✗ CONFIG_DIR existiert nicht: ${CONFIG_DIR}${NC}\n"
    exit 1
fi

# Provider-spezifische Validierung
case "$(echo "$PROVIDER" | tr '[:lower:]' '[:upper:]')" in
    IONOS)
        if [ -z "${API_PREFIX}" ] || [ -z "${API_SECRET}" ]; then
            printf "${RED}✗ Fehler: Für IONOS müssen API_PREFIX und API_SECRET gesetzt sein!${NC}\n"
            exit 1
        fi
        ;;
    CLOUDFLARE)
        if [ -z "${CLOUDFLARE_TOKEN}" ]; then
            printf "${RED}✗ Fehler: Für CLOUDFLARE muss CLOUDFLARE_TOKEN gesetzt sein!${NC}\n"
            exit 1
        fi
        ;;
    IPV64)
        if [ -z "${IPV64_TOKEN}" ]; then
            printf "${RED}✗ Fehler: Für IPV64 muss IPV64_TOKEN gesetzt sein!${NC}\n"
            exit 1
        fi
        ;;
    *)
        printf "${RED}✗ Fehler: Unbekannter Provider '${PROVIDER}'. Erlaubt sind: IONOS, CLOUDFLARE, IPV64${NC}\n"
        exit 1
        ;;
esac

if [ -z "${DOMAINS}" ] || [ "${DOMAINS}" = "example.com" ]; then
    printf "${YELLOW}⚠ Warnung: Keine Domains konfiguriert oder Beispiel-Domain aktiv${NC}\n"
fi

# Create directories
printf "${GREEN}→ Erstelle Verzeichnisstruktur...${NC}\n"
mkdir -p "${LANG_DIR}" "${LOGS_DIR}"

# Copy language files
printf "${GREEN}→ Prüfe Sprachdateien...${NC}\n"
if [ ! -d "/app/lang" ]; then
    printf "${RED}✗ Quellverzeichnis /app/lang nicht gefunden${NC}\n"
    exit 1
fi

lang_count=0
for src in /app/lang/*.json; do
    [ -e "$src" ] || continue
    filename=$(basename "$src")
    dst="${LANG_DIR}/${filename}"
    
    if [ ! -f "${dst}" ] || ! cmp -s "${src}" "${dst}"; then
        printf "${YELLOW}→ Verarbeite ${filename}...${NC}\n"
        cp -f "${src}" "${dst}" 2>/dev/null || cat "${src}" > "${dst}"
        chmod 644 "${dst}" 2>/dev/null || true
    fi
    lang_count=$((lang_count + 1))
done

# Validate numeric values
if ! echo "${INTERVAL}" | grep -qE '^[0-9]+$'; then
    printf "${RED}✗ INTERVAL muss eine Zahl sein: ${INTERVAL}${NC}\n"
    exit 1
fi

if ! echo "${HEALTH_PORT}" | grep -qE '^[0-9]+$'; then
    printf "${RED}✗ HEALTH_PORT muss eine Zahl sein: ${HEALTH_PORT}${NC}\n"
    exit 1
fi

# Validate IP_MODE
case "${IP_MODE}" in
    IPV4|IPV6|BOTH)
        ;;
    *)
        printf "${RED}✗ Ungültiger IP_MODE: ${IP_MODE} (erlaubt: IPV4, IPV6, BOTH)${NC}\n"
        exit 1
        ;;
esac

printf "\n"
printf "${GREEN}=== Konfiguration ===${NC}\n"
printf "Provider:      ${PROVIDER}\n"
printf "Config Dir:    ${CONFIG_DIR}\n"
printf "Domains:       ${DOMAINS}\n"
printf "IP Mode:       ${IP_MODE}\n"
printf "Interval:      ${INTERVAL}s\n"
printf "Health Port:   ${HEALTH_PORT}\n"
printf "Language:      ${LANG}\n"
printf "Dry-Run:       ${DRY_RUN}\n"
printf "Debug:         ${DEBUG}\n"

printf "\n${GREEN}=== Initialisierung abgeschlossen. Starte Service... ===${NC}\n\n"

exec "$@"
