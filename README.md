# 🌐 Go-DynDNS

[![GitHub Release](https://img.shields.io/github/v/release/crazyUs3r/ionos-ddns?style=flat-square&color=blue)](https://github.com/crazyUs3r/ionos-ddns/releases/latest)
[![GitHub Pre-Release](https://img.shields.io/github/v/release/crazyUs3r/ionos-ddns?include_prereleases&label=pre-release&color=orange&style=flat-square)](https://github.com/crazyUs3r/ionos-ddns/releases)
[![License](https://img.shields.io/github/license/crazyUs3r/ionos-ddns?style=flat-square)](https://github.com/CrazyUs3r/IONOS-DDNS/blob/main/LICENSE)
[![GitHub Downloads](https://img.shields.io/github/downloads/crazyus3r/ionos-ddns/total)](https://github.com/crazyUs3r/ionos-ddns/releases)
[![GitHub Activity](https://img.shields.io/github/commit-activity/y/crazyUs3r/ionos-ddns?style=flat-square)](https://github.com/crazyUs3r/ionos-ddns/commits/main)

[![Docker Image Version](https://img.shields.io/docker/v/crazyus3r/ionos-ddns?label=docker%20image&logo=docker&style=flat-square)](https://hub.docker.com/r/crazyus3r/ionos-ddns/tags)
[![Docker Pulls](https://img.shields.io/docker/pulls/crazyus3r/ionos-ddns?style=flat-square)](https://hub.docker.com/r/crazyus3r/ionos-ddns)
[![Docker Stars](https://img.shields.io/docker/stars/crazyus3r/ionos-ddns?style=flat-square&logo=docker)](https://hub.docker.com/r/crazyus3r/ionos-ddns)
[![Docker Last Updated](https://img.shields.io/docker/last-updated/crazyus3r/ionos-ddns?style=flat-square)](https://hub.docker.com/r/crazyus3r/ionos-ddns/tags)

Ein hochperformanter, in Go geschriebener **Multi-Provider Dynamic DNS Client** mit vollwertigem Web-Dashboard. Unterstützt IONOS, Cloudflare, IPv64, Hetzner DNS, Hetzner Cloud Febas und DNScale — gleichzeitig, pro Domain konfigurierbar.

---

## ✨ Highlights

- **Multi-Provider:** IONOS, Cloudflare, IPv64, Hetzner DNS, Hetzner Cloud, Febas und DNScale — auch gemischt in einer Instanz
- **Web-Dashboard:** Echtzeit-Monitoring via WebSockets — IP-Historie, API-Metriken, Logs, Diagnose und Einstellungen
- **Dashboard-Auth:** Rollenbasierte Benutzerverwaltung (Admin / Editor / Viewer) mit sicherem PBKDF2-Passwort-Hashing
- **2FA / TOTP:** Optionale Zwei-Faktor-Authentifizierung per RFC-6238-konformem TOTP (Google Authenticator, Authy)
- **Dual-Stack:** Gleichzeitige Aktualisierung von A (IPv4) und AAAA (IPv6) Records
- **Pro Domain konfigurierbar:** IP-Modus (IPV4/IPV6/BOTH/CNAME) und TTL lassen sich je Domain überschreiben
- **Intelligente IPv6-Erkennung:** Direkt vom Interface (via netlink) oder über öffentliche Endpunkte als Fallback
- **Cache-First:** Zonen- und Record-Caches werden auf Disk persistiert — kein unnötiger API-Call nach Neustart
- **Cleanup:** Automatisches Entfernen verwaister DNS-Records, die nicht mehr in der Konfiguration stehen
- **Benachrichtigungen:** Telegram (inkl. Bot-Commands), Gotify, Ntfy, Webhook, MQTT (inkl. Home Assistant Discovery) und E-Mail (SMTP)
- **Backup & Restore:** Export/Import von Config, Status und Benutzern direkt aus dem Dashboard
- **Diagnose / Health Center:** Übersicht über System-, Provider- und Notifier-Status mit konfigurierbaren Warnungen
- **Prometheus-Metriken:** Endpunkt `/metrics/prometheus` für Grafana & Co.
- **Parallele Verarbeitung:** Einstellbares Worker-Limit für schnelle Updates bei vielen Domains
- **Multi-Architektur:** Native Images für `linux/amd64` und `linux/arm64` (Raspberry Pi, NAS, Server)
- **Keine externen Go-Abhängigkeiten für TOTP:** Stdlib-only-Implementierung

---

## 🚀 Quick Start (Docker Compose)

Das einfachste Setup — Dashboard unter `http://server-ip:8080`, Konfiguration über die UI:

```yaml
services:
  go-dyndns:
    image: crazyus3r/ionos-ddns:latest
    container_name: go-dyndns
    ports:
      - "8080:8080"
    volumes:
      - ./config:/config
    restart: unless-stopped
```

Beim ersten Start öffnet sich die Setup-Seite zum Erstellen des Admin-Accounts. Domains und Provider werden danach vollständig über das Dashboard konfiguriert und in `/config/config.json` gespeichert.

---

## ⚙️ Konfiguration

### Option A — Dashboard (empfohlen)

Alle Einstellungen lassen sich nach dem ersten Login unter **Einstellungen** im Dashboard verwalten:

- System (Intervall, IP-Modus, DNS-Server, Debug, Dry-Run, Sprache …)
- Domains mit Provider-Zugangsdaten
- Benachrichtigungen (Telegram, Gotify, Webhook, MQTT, E-Mail)
- Benutzerverwaltung

Änderungen werden sofort in `/config/config.json` übernommen.

### Option B — Umgebungsvariablen (Legacy / CI)

Für den ersten Start oder automatisierte Deployments können Domains auch per ENV konfiguriert werden. Beim ersten Schreiben wird automatisch eine `config.json` erzeugt.

#### Allgemeine Variablen

| Variable | Beschreibung | Standard |
| :--- | :--- | :--- |
| `CONFIG_DIR` | Verzeichnis für Config, Logs und Cache | `/config` |
| `IP_MODE` | `IPV4`, `IPV6` oder `BOTH` | `BOTH` |
| `INTERVAL` | Sekunden zwischen Prüfungen | `300` |
| `INTERFACE` | Netzwerk-Interface für IPv6 (z. B. `eth0`) | — |
| `DNS_SERVERS` | Kommagetrennte DNS-Server | `1.1.1.1:53,8.8.8.8:53` |
| `HEALTH_PORT` | Port für Dashboard und Healthcheck | `8080` |
| `DASHBOARD_HTTPS_PORT` | Port für https Dashboard | `8443` |
| `LANG` | Sprache der UI (`de` oder `en`) | `de` |
| `LOG_MAX_LINES` | Maximale Log-Zeilen | `500` |
| `MAX_CONCURRENT` | Parallele API-Updates | `5` |
| `MAX_API_RETRIES` | Wiederholungsversuche bei API-Fehlern | `3` |
| `HOURLY_RATE_LIMIT` | Max. API-Anfragen pro Stunde | `1200` |
| `DRY_RUN` | `true` → keine Änderungen bei Providern | `false` |
| `DEBUG` | Erweitertes Logging | `false` |
| `DEBUG_HTTP_RAW` | HTTP-Traffic loggen (Achtung: Secrets!) | `false` |
| `DASHBOARD_AUTH` | `false` → Dashboard ohne Login | `true` |
| `TRIGGER_TOKEN` | Token für den `/api/trigger`-Endpunkt | — |

#### Single-Provider (Legacy)

```bash
# IONOS
PROVIDER=IONOS
API_PREFIX=dein_prefix
API_SECRET=dein_secret
DOMAINS=home.example.com,sub.example.com

# Cloudflare
PROVIDER=CLOUDFLARE
CLOUDFLARE_TOKEN=dein_api_token
DOMAINS=home.example.com

# IPv64
PROVIDER=IPV64
IPV64_TOKEN=dein_token
DOMAINS=home.example.ipv64.net

# Hetzner DNS
PROVIDER=HETZNER
HETZNER_TOKEN=dein_token
DOMAINS=home.example.com

# Hetzner Cloud DNS
PROVIDER=HETZNERCLOUD
HCLOUD_TOKEN=dein_token
DOMAINS=home.example.com

# Febas
PROVIDER=FEBAS
FEBAS_UPDATE_URL=https://www.febas.de/api/dyndns.php?kundenid=DEINE_ID&token=DEIN_TOKEN
DOMAINS=home.example.com

# DNScale
PROVIDER=DNSCALE
DNSCALE_TOKEN=dein_api_key
DOMAINS=home.example.com

```

#### Multi-Provider via `DOMAINS_CONFIG`

Mehrere Provider gleichzeitig — auch gemischt:

```bash
DOMAINS_CONFIG='[
  {
    "fqdn": "home.example.com,sub.example.com",
    "provider": "IONOS",
    "api_prefix": "dein_prefix",
    "api_secret": "dein_secret"
  },
  {
    "fqdn": "home.example.ipv64.net",
    "provider": "IPV64",
    "ipv64_token": "dein_token"
  },
  {
    "fqdn": "cf.example.com",
    "provider": "CLOUDFLARE",
    "cf_token": "dein_cf_token",
    "cf_proxied": false
  },
  {
    "fqdn": "hz.example.com",
    "provider": "HETZNER",
    "api_secret": "dein_hetzner_token"
  },
  {
    "fqdn": "hc.example.com",
    "provider": "HETZNERCLOUD",
    "api_secret": "dein_hcloud_token"
  },
  {
    "fqdn": "febas.example.com",
    "provider": "FEBAS",
    "febas_update_url": "https://www.febas.de/api/dyndns.php?kundenid=DEINE_ID&token=DEIN_TOKEN"
  },
  {
    "fqdn": "dnscale.example.com",
    "provider": "DNSCALE",
    "dnscale_token": "dein_api_key"
  }
]'
```

Unterstützte Felder je Eintrag: `fqdn`, `provider`, `api_prefix`, `api_secret`, `cf_token`, `cf_email`, `cf_secret`, `cf_proxied`, `ipv64_token`, `hetzner_token`, `hcloud_token`, `febas_update_url`, `dnscale_token`, `ttl`, `ip_mode`

---

## 📦 Unterstützte Provider

| Provider | Typ | Records |
| :--- | :--- | :--- |
| **IONOS** | REST API | A, AAAA |
| **Cloudflare** | REST API | A, AAAA |
| **IPv64** | NIC-Update + REST API | A, AAAA |
| **Hetzner DNS** | REST API | A, AAAA |
| **Hetzner Cloud DNS** | REST API | A, AAAA |
| **Febas** | NIC-Update (GET) | A, AAAA |
| **DNScale** | REST API | A, AAAA |

---

## 📊 Dashboard

Das Dashboard ist unter `http://server-ip:8080` erreichbar und bietet:

- **Übersicht:** Letzter Check, Uptime, IP-Endpunkt-Status
- **Domains:** IP-Historie pro Domain mit Zeitstrahl, Provider-Status, Orphan-Erkennung
- **Metriken:** Total Requests, Success Rate, Latenz-Perzentile (P50/P85/P99), HTTP-Methoden-Verteilung, stündliche Charts
- **Diagnose / Health Center:** System-, Config-, Provider- und Notifier-Status auf einen Blick
- **Logs:** Filterbar nach Level und Aktion, Export als TXT oder JSON
- **Debug-Log:** Live-Stream interner Ereignisse (nur bei aktiviertem Debug-Modus)
- **Backup & Restore:** Config, Domain-Status und Benutzer exportieren und wiederherstellen
- **Einstellungen:** Vollständige Konfiguration über die UI — kein manuelles Editieren von JSON nötig
- **Benutzerverwaltung:** Admin, Editor und Viewer-Rollen

### Rollenmodell

| Rolle | Beschreibung |
| :--- | :--- |
| `admin` | Vollzugriff inkl. Benutzerverwaltung, Backup und Config-Speichern |
| `editor` | Lesen, Updates auslösen, Domains verwalten |
| `viewer` | Nur lesen (GET-Requests, WebSocket) |

---

## 🔔 Benachrichtigungen

Konfigurierbar über das Dashboard oder `config.json`:

| Notifier | Beschreibung |
| :--- | :--- |
| **Telegram** | Bot mit interaktiven Commands (`/status`, `/metrics`, `/domains`, `/update`, `/health`) |
| **Gotify** | Push-Nachrichten mit Prioritäten |
| **Webhook** | HTTP POST mit JSON-Payload |
| **MQTT** | Publish auf Topic, inkl. Home Assistant Auto Discovery |
| **E-Mail** | SMTP mit STARTTLS, direktem TLS oder Plain |

Für jeden Notifier lassen sich die gewünschten Events einzeln auswählen (Update, Create, Error, Start, Stop, Cleanup, …).

---

## 🩺 Health Check

```
GET http://server-ip:8080/health
GET http://server-ip:8080/health?detailed=true
GET http://server-ip:8080/metrics/prometheus
```

Die `/health`-Route liefert `200 OK`, `degraded` oder `503 Unhealthy`. Docker-HEALTHCHECK ist im Image bereits konfiguriert.

---

## 📁 Datenverzeichnis (`/config`)

```
/config/
├── config.json             # Hauptkonfiguration
├── users.json              # Benutzerkonten (bcrypt/PBKDF2 gehashed)
├── lang/
│   ├── de.json
│   └── en.json
└── logs/
│   ├── dyndns.json         # Ereignis-Log (JSON Lines)
│   ├── update.json         # IP-Historie pro Domain
│   ├── metrics.json        # Persistierte Metriken
│   ├── ionos_cache.json    # Zonen-/Record-Cache IONOS
│   ├── cloudflare_cache.json
│   ├── ipv64_cache.json
│   ├── hetzner_dns_cache.json
│   └── hetzner_cloud_cache.json
└── tls/
    ├── dashboard.crt
    └── dashboard.key
```

Beispiel `update.json`:

```json
{
  "home.example.com": {
    "provider": "IONOS",
    "last_changed": "18.01.2026 13:22:00",
    "ips": [
      {
        "time": "18.01.2026 13:22:00",
        "ipv4": "203.0.113.1",
        "ipv6": "2001:db8::1"
      }
    ]
  }
}
```

---

## 🏗 Manuelle Installation (Binaries)

Vorkompilierte Binaries für Linux (amd64/arm64) und Windows sind unter [Releases](https://github.com/crazyUs3r/ionos-ddns/releases) verfügbar.

```bash
# Umgebungsvariablen setzen, dann:
./go-dyndns

# Oder mit CONFIG_DIR
CONFIG_DIR=/pfad/zur/config ./go-dyndns
```

---

## 🔑 API-Keys erstellen

**IONOS:** [developer.hosting.ionos.com](https://developer.hosting.ionos.com) → neuen Key anlegen → Public Prefix + Secret kopieren

**Cloudflare:** Mein Profil → API-Token → Token erstellen → `Zone:DNS:Edit`-Berechtigung

**IPv64:** [ipv64.net](https://ipv64.net) → API-Key aus dem Dashboard

**Hetzner DNS:** [dns.hetzner.com](https://dns.hetzner.com) → API-Tokens

**Hetzner Cloud:** [console.hetzner.cloud](https://console.hetzner.cloud) → Projekt → API-Tokens

**Febas:** Kundenbereich auf [febas.de](https://www.febas.de) → Update-URL mit `kundenid` und `token` aus dem DynDNS-Bereich kopieren

**DNScale:** [dnscale.io](https://dnscale.io) → API-Bereich → Bearer-Token erstellen

---

## ⚖️ Lizenz

Dieses Projekt steht unter der [MIT-Lizenz](https://github.com/CrazyUs3r/IONOS-DDNS/blob/main/LICENSE).
