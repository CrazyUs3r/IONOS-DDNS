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

# Detect if multi-provider mode
MULTI_PROVIDER_MODE="false"
if [ -n "${DOMAINS_CONFIG}" ]; then
    MULTI_PROVIDER_MODE="true"
    printf "${GREEN}→ Multi-Provider Modus erkannt${NC}\n"
fi

# Validate environment
if [ "${MULTI_PROVIDER_MODE}" = "true" ]; then
    printf "${GREEN}→ Validiere Multi-Provider Konfiguration...${NC}\n"
    
    # Check if DOMAINS_CONFIG is valid JSON
    if ! echo "${DOMAINS_CONFIG}" | grep -q '^\s*\['; then
        printf "${RED}✗ DOMAINS_CONFIG muss ein JSON-Array sein: [...]\n"
        exit 1
    fi
    
    # Count domains
    DOMAIN_COUNT=$(echo "${DOMAINS_CONFIG}" | grep -o '"fqdn"' | wc -l)
    printf "${GREEN}  ✓ ${DOMAIN_COUNT} Domain(s) konfiguriert${NC}\n"
    
    # Detect providers in config
    if echo "${DOMAINS_CONFIG}" | grep -qi '"provider".*:.*"IONOS"'; then
        printf "${GREEN}  ✓ IONOS Provider gefunden${NC}\n"
    fi
    if echo "${DOMAINS_CONFIG}" | grep -qi '"provider".*:.*"CLOUDFLARE"'; then
        printf "${GREEN}  ✓ Cloudflare Provider gefunden${NC}\n"
    fi
    if echo "${DOMAINS_CONFIG}" | grep -qi '"provider".*:.*"IPV64"'; then
        printf "${GREEN}  ✓ IPv64 Provider gefunden${NC}\n"
    fi
    
else
    printf "${GREEN}→ Validiere Umgebung für Provider: ${PROVIDER}...${NC}\n"
    
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
if [ "${MULTI_PROVIDER_MODE}" = "true" ]; then
    printf "Mode:          ${YELLOW}Multi-Provider${NC}\n"
    printf "Domains:       ${DOMAIN_COUNT} (siehe DOMAINS_CONFIG)\n"
else
    printf "Mode:          Single-Provider\n"
    printf "Provider:      ${PROVIDER}\n"
    printf "Domains:       ${DOMAINS}\n"
fi
printf "Config Dir:    ${CONFIG_DIR}\n"
printf "IP Mode:       ${IP_MODE}\n"
printf "Interval:      ${INTERVAL}s\n"
printf "Health Port:   ${HEALTH_PORT}\n"
printf "Language:      ${LANG}\n"
printf "Dry-Run:       ${DRY_RUN}\n"
printf "Debug:         ${DEBUG}\n"

printf "\n${GREEN}=== Initialisierung abgeschlossen. Starte Service... ===${NC}\n\n"

exec "$@"
