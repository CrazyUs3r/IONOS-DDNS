#!/bin/sh
set -e

# Detect if output is a terminal
if [ -t 1 ]; then
    # Colors for TTY
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    RED='\033[0;31m'
    NC='\033[0m'
else
    # No colors for non-TTY (docker logs)
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

# Validate environment
printf "${GREEN}→ Validiere Umgebung...${NC}\n"

if [ ! -d "${CONFIG_DIR}" ]; then
    printf "${RED}✗ CONFIG_DIR existiert nicht: ${CONFIG_DIR}${NC}\n"
    exit 1
fi

if [ -z "${API_PREFIX}" ] || [ -z "${API_SECRET}" ]; then
    printf "${YELLOW}⚠ Warnung: API_PREFIX oder API_SECRET nicht gesetzt${NC}\n"
    printf "${YELLOW}  Der Service wird ohne Credentials starten!${NC}\n"
fi

if [ -z "${DOMAINS}" ] || [ "${DOMAINS}" = "example.com" ]; then
    printf "${YELLOW}⚠ Warnung: Keine Domains konfiguriert oder Beispiel-Domain${NC}\n"
fi

# Create directories
printf "${GREEN}→ Erstelle Verzeichnisstruktur...${NC}\n"
mkdir -p "${LANG_DIR}" "${LOGS_DIR}"

# Copy language files if needed
printf "${GREEN}→ Prüfe Sprachdateien...${NC}\n"

# Check if source lang directory exists
if [ ! -d "/app/lang" ]; then
    printf "${RED}✗ Quellverzeichnis /app/lang nicht gefunden${NC}\n"
    exit 1
fi

# Get all .json files from source directory
lang_count=0
for src in /app/lang/*.json; do
    # Check if glob matched any files
    [ -e "$src" ] || continue
    
    # Extract filename
    filename=$(basename "$src")
    lang="${filename%.json}"
    dst="${LANG_DIR}/${filename}"
    
    if [ ! -f "${dst}" ]; then
        printf "${YELLOW}→ Kopiere ${filename} nach ${LANG_DIR}/${NC}\n"
        cp -f "${src}" "${dst}" 2>/dev/null || cat "${src}" > "${dst}"
        chmod 644 "${dst}" 2>/dev/null || true
        lang_count=$((lang_count + 1))
    else
        # Check if update needed
        if ! cmp -s "${src}" "${dst}"; then
            printf "${YELLOW}→ Aktualisiere ${filename} (Version geändert)${NC}\n"
            # Remove first, then copy (works better with permissions)
            rm -f "${dst}" 2>/dev/null || true
            cp -f "${src}" "${dst}" 2>/dev/null || cat "${src}" > "${dst}"
            chmod 644 "${dst}" 2>/dev/null || true
            lang_count=$((lang_count + 1))
        else
            printf "${GREEN}✓ ${filename} aktuell${NC}\n"
            lang_count=$((lang_count + 1))
        fi
    fi
done

if [ $lang_count -eq 0 ]; then
    printf "${RED}✗ Keine Sprachdateien gefunden in /app/lang/${NC}\n"
    exit 1
fi

printf "${GREEN}→ ${lang_count} Sprachdatei(en) verarbeitet${NC}\n"

# Set permissions
chmod -R 644 "${LANG_DIR}"/*.json 2>/dev/null || true
chmod -R 755 "${LOGS_DIR}" 2>/dev/null || true

# Display configuration
printf "\n"
printf "${GREEN}=== Konfiguration ===${NC}\n"
printf "Config Dir:    ${CONFIG_DIR}\n"
printf "Domains:       ${DOMAINS}\n"
printf "IP Mode:       ${IP_MODE}\n"
printf "Interval:      ${INTERVAL}s\n"
printf "Health Port:   ${HEALTH_PORT}\n"
printf "Language:      ${LANG}\n"
printf "Dry-Run:       ${DRY_RUN}\n"
printf "Debug:         ${DEBUG}\n"

# Validate numeric values
if ! echo "${INTERVAL}" | grep -qE '^[0-9][0-9]*$'

# Execute main command
exec "$@"; then
    printf "${RED}✗ INTERVAL muss eine Zahl sein: ${INTERVAL}${NC}\n"
    exit 1
fi

if ! echo "${HEALTH_PORT}" | grep -qE '^[0-9][0-9]*$'

# Execute main command
exec "$@"; then
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
printf "${GREEN}=== Initialisierung abgeschlossen ===${NC}\n"
printf "${GREEN}→ Starte DynDNS Service...${NC}\n"
printf "\n"

# Execute main command
exec "$@"
