# 🏗️ Build & Deployment Guide

## Quick Start

```bash
# 1. Repository klonen
git clone https://github.com/CrazyUs3r/IONOS-DDNS.git
cd IONOS-DDNS

# 2. Environment-Datei erstellen
cp .env.example .env
nano .env  # API Credentials eintragen

# 3. Build & Start
docker compose up -d

# 4. Logs verfolgen
docker compose logs -f
```

## Multi-Architecture Build

### Mit Docker Buildx

```bash
# Buildx einrichten (einmalig)
docker buildx create --name multiarch --use
docker buildx inspect --bootstrap

# Multi-Arch Build
docker buildx build \
  --platform linux/amd64,linux/arm64,linux/arm/v7 \
  --build-arg VERSION=2.1.0 \
  --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') \
  --build-arg VCS_REF=$(git rev-parse --short HEAD) \
  -t yourusername/ionos-ddns:latest \
  -t yourusername/ionos-ddns:2.1.0 \
  --push \
  .
```

### Lokaler Build (Single Architecture)

```bash
# Nur für aktuelle Architektur
docker build \
  --build-arg VERSION=2.1.0 \
  --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') \
  -t ionos-ddns:latest \
  .
```

## Development Build

```bash
# Mit Live-Reload (für Entwicklung)
docker build \
  --build-arg DEBUG=true \
  --target builder \
  -t ionos-ddns:dev \
  .

# Container mit Volume-Mount starten
docker run -it --rm \
  -v $(pwd):/app \
  -e DEBUG=true \
  -e DRY_RUN=true \
  ionos-ddns:dev \
  go run main.go
```

## .env.example

```env
# IONOS API Credentials
API_PREFIX=your-prefix-here
API_SECRET=your-secret-here

# Domains (kommagetrennt)
DOMAINS=example.com,sub.example.com

# Optional: Trigger Token für /api/trigger
TRIGGER_TOKEN=your-secure-random-token

# IP Mode
IP_MODE=BOTH

# Update Interval (Sekunden)
INTERVAL=300

# Timezone
TZ=Europe/Berlin

# Sprache (de, en, fr)
LANG=de
```

## Verzeichnisstruktur

```
IONOS-DDNS/
├── main.go
├── Dockerfile
├── docker-compose.yml
├── docker-entrypoint.sh
├── .env.example
├── lang/
│   ├── de.json
│   ├── en.json
│   └── fr.json
└── config/           # Wird beim Start erstellt
    ├── logs/
    │   ├── dyndns.json
    │   └── update.json
    └── lang/         # Kopien der Sprachdateien
```

## Health Checks

```bash
# Einfacher Health Check
curl http://localhost:8080/health

# Detaillierter Health Check
curl http://localhost:8080/health?detailed=true

# Metriken
curl http://localhost:8080/metrics

# Domain Status
curl http://localhost:8080/api/domains
```

## Manueller Update-Trigger

```bash
# Ohne Token
curl -X POST http://localhost:8080/api/trigger

# Mit Token (wenn TRIGGER_TOKEN gesetzt)
curl -X POST \
  -H "X-Trigger-Token: your-token" \
  http://localhost:8080/api/trigger

# Status prüfen
curl http://localhost:8080/api/trigger/status
```

## Troubleshooting

### Container startet nicht

```bash
# Logs prüfen
docker compose logs ionos-dyndns

# Interaktiv starten
docker compose run --rm ionos-dyndns sh

# Config überprüfen
docker exec ionos-dyndns ls -la /config
```

### API Credentials ungültig

```bash
# Testen mit DRY_RUN
docker compose down
# In docker-compose.yml: DRY_RUN: "true"
docker compose up -d
docker compose logs -f
```

### IPv6 funktioniert nicht

```bash
# Host IPv6 prüfen
docker exec ionos-dyndns ip -6 addr show

# Interface Namen ermitteln
docker exec ionos-dyndns ip link show

# In docker-compose.yml anpassen:
# INTERFACE: "eth0"  # oder dein Interface
```

## Performance Tuning

### Für viele Domains (>20)

```yaml
environment:
  INTERVAL: 600          # Längeres Intervall
  MAX_CONCURRENT: 10     # Mehr parallele Updates
  HOURLY_RATE_LIMIT: 2400  # Höheres API Limit
```

### Für seltene Updates

```yaml
environment:
  INTERVAL: 900          # 15 Minuten
  LOG_MAX_LINES: 1000    # Weniger Log-Retention
```

## Production Deployment

### Mit Watchtower (Auto-Updates)

```yaml
services:
  ionos-dyndns:
    # ... existing config ...
    labels:
      - "com.centurylinklabs.watchtower.enable=true"

  watchtower:
    image: containrrr/watchtower
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      WATCHTOWER_CLEANUP: "true"
      WATCHTOWER_POLL_INTERVAL: 86400  # 24h
```

### Mit Health Check Monitoring

```yaml
services:
  ionos-dyndns:
    # ... existing config ...
    labels:
      - "autoheal=true"

  autoheal:
    image: willfarrell/autoheal
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      AUTOHEAL_CONTAINER_LABEL: autoheal
```

## Backup & Recovery

```bash
# Config sichern
tar -czf ionos-ddns-backup.tar.gz config/

# Wiederherstellen
tar -xzf ionos-ddns-backup.tar.gz
docker compose up -d
```
