# 🌐 IONOS DynDNS Dual-Stack (Go)

[![GitHub Release](https://img.shields.io/github/v/release/crazyUs3r/ionos-ddns?style=flat-square&color=blue)](https://github.com/crazyUs3r/ionos-ddns/releases/latest)
[![GitHub Pre-Release](https://img.shields.io/github/v/release/crazyUs3r/ionos-ddns?include_prereleases&label=pre-release&color=orange&style=flat-square)](https://github.com/crazyUs3r/ionos-ddns/releases)
[![License](https://img.shields.io/github/license/crazyUs3r/ionos-ddns?style=flat-square)](https://github.com/CrazyUs3r/IONOS-DDNS/blob/main/LICENSE)
[![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/crazyUs3r/ionos-ddns/total)](https://github.com/crazyUs3r/ionos-ddns/releases)
[![GitHub Activity](https://img.shields.io/github/commit-activity/y/crazyUs3r/ionos-ddns?style=flat-square)](https://github.com/crazyUs3r/ionos-ddns/commits/main)

<br />

[![Docker Image Version](https://img.shields.io/docker/v/crazyus3r/ionos-ddns?label=docker%20image&logo=docker&style=flat-square)](https://hub.docker.com/r/crazyus3r/ionos-ddns/tags)
[![Docker Pulls](https://img.shields.io/docker/pulls/crazyus3r/ionos-ddns?style=flat-square)](https://hub.docker.com/r/crazyus3r/ionos-ddns)
[![Docker Stars](https://img.shields.io/docker/stars/crazyus3r/ionos-ddns?style=flat-square&logo=docker)](https://hub.docker.com/r/crazyus3r/ionos-ddns)
[![Docker Last Updated](https://img.shields.io/docker/last-updated/crazyus3r/ionos-ddns?style=flat-square)](https://hub.docker.com/r/crazyus3r/ionos-ddns/tags)

<br />

[![Go Report Card](https://goreportcard.com/badge/github.com/CrazyUs3r/IONOS-DDNS/v2)](https://goreportcard.com/report/github.com/CrazyUs3r/IONOS-DDNS/v2)

Ein hochperformanter, in Go geschriebener Dynamic DNS Client für IONOS. Optimiert für moderne Dual-Stack Anschlüsse (IPv4 & IPv6) mit integriertem Web-Dashboard.

## ✨ Highlights
* **Web-Dashboard:** Behalte deine IP-Historie, API-Performance und System-Logs in Echtzeit via WebSockets im Blick.
* **Dual-Stack Ready:** Gleichzeitige Aktualisierung von A (IPv4) und AAAA (IPv6) Records.
* **Intelligente Erkennung:** Erkennt IPv6-Adressen direkt am Interface oder über externe DNS-Validierung.
* **Parallele Verarbeitung:** Schnelle Updates durch Go-Routines mit einstellbarem Worker-Limit (ideal für viele Subdomains).
* **Multi-Architektur:** Native Unterstützung für `amd64` und `arm64` (perfekt für Raspberry Pi, NAS & Server).
* **Robust:** Automatisches Retrying bei API-Fehlern und ordnungsgemäßes Beenden (Graceful Shutdown).

## 🚀 Quick Start (Docker Compose)

```yaml
services:
  ionos-ddns:
    image: crazyus3r/ionos-ddns:latest
    container_name: ionos-ddns
    environment:
      - API_PREFIX=dein_ionos_prefix
      - API_SECRET=dein_ionos_secret
      - DOMAINS=meine-domain.de,sub.andere-domain.com
      - IP_MODE=BOTH # IPV4, IPV6 oder BOTH
    ports:
      - "8080:8080" # Dashboard & Healthcheck
    volumes:
      - ./config:/config # Speichert Logs, Historie und Übersetzungen
    restart: unless-stopped

```

## 🛠 Konfiguration (Umgebungsvariablen)

| Variable | Beschreibung | Standard |
| :--- | :--- | :--- |
| `API_PREFIX` | Dein IONOS API Public Key | (erforderlich) |
| `API_SECRET` | Dein IONOS API Secret | (erforderlich) |
| `DOMAINS` | Kommagetrennte Liste der Domains | (erforderlich) |
| `IP_MODE` | Modus: `IPV4`, `IPV6` oder `BOTH` | `BOTH` |
| `INTERVAL` | Intervall zwischen den Prüfungen (Sekunden) | `300` |
| `INTERFACE` | Netzwerk-Interface für IPv6 (z.B. `eth0`) | `eth0` |
| `DNS_SERVERS` | Externe DNS-Server zur Validierung | `1.1.1.1:53,8.8.8.8:53` |
| `HEALTH_PORT` | Port für Dashboard und Health-Check | `8080` |
| `LANG` | Sprache der Logs & UI (`DE` oder `EN`) | `DE` |
| `LOG_MAX_LINES` | Maximale Zeilenanzahl pro Logdatei | `5000` |
| `MAX_CONCURRENT` | Maximale parallele API-Updates | `5` |
| `HOURLY_RATE_LIMIT` | Max. API-Anfragen pro Stunde | `1200` |
| `DRY_RUN` | Wenn `true`, wird nichts bei IONOS geändert | `false` |
| `DEBUG` | Aktiviert erweitertes Logging | `false` |
| `PROVIDER` | ionos, cloudflare, ipv64 | `ionos` |
| `CLOUDFLARE_TOKEN` | Dein Cloudflare Token | (erforderlich für CF) |
| `CLOUDFLARE_ZONE_ID` |Dein Cloudflare Zone Id für CF) | (erforderlich für CF) |
| `IPV64_TOKEN` |Dein IPV64 Token für IPV64) | (erforderlich für IPV64) |
| `IPV64_DOMAIN_TOKEN` |Dein IPV64 Domain Token | (erforderlich für IPV64) | (erforderlich) |

## 📊 Dashboard & Monitoring
​Das Dashboard ist unter http://server-ip:8080 erreichbar. Es zeigt den aktuellen Status der API-Verbindung, die Performance-Metriken und ein Echtzeit-Log der Systemereignisse.

## ​Logs & Historie
​Das Tool nutzt das Verzeichnis /config (im Docker-Container) zur Speicherung:
​/config/logs/dyndns.json: Detailliertes Ereignis-Log im JSON-Format.
​/config/logs/update.json: Kompakte Historie deiner IP-Wechsel pro Domain.

​Beispiel update.json:
```json
{
  "meine-domain.de": {
    "ips": [
      {
        "time": "18.01.2026 13:22:00",
        "ipv4": "x.x.x.x",
        "ipv6": "x:x:x:x:248:1893:25c8:1946"
      }
    ]
  }
}

```

## 🏗 Manuelle Installation (Binaries)
​Du kannst die vorkompilierten Binaries für Linux (AMD64/ARM64) und Windows direkt aus den GitHub Releases herunterladen.
1. ​Lade die passende Datei für dein System herunter.
2. ​Setze die Umgebungsvariablen (z. B. via .env Datei oder export).
3. ​Starte das Programm: ./ionos-ddns

## ​🔐 API-Keys erstellen
​Logge dich in die IONOS Developer Konsole ein.
​Erstelle einen neuen Key (Typ: Public).
​Kopiere das Prefix und das Secret in deine Konfiguration.

## ​⚖️ Lizenz
​Dieses Projekt ist unter der MIT-Lizenz lizenziert.
