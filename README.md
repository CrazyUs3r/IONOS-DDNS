# 🌐 IONOS DynDNS Dual-Stack (Go)

Ein hochperformanter, in Go geschriebener Dynamic DNS Client für IONOS. Optimiert für moderne Dual-Stack Anschlüsse (IPv4 & IPv6).

## ✨ Highlights
* **Web-Dashboard:** Behalte deine IP-Historie und den Systemstatus direkt im Browser im Blick.
* **Dual-Stack Ready:** Gleichzeitige Aktualisierung von A (IPv4) und AAAA (IPv6) Records.
* **Parallele Verarbeitung:** Schnelle Updates durch Go-Routines (ideal für viele Subdomains).
* **Multi-Architektur:** Native Unterstützung für `amd64` und `arm64` (perfekt für Raspberry Pi & Server).
* **Smart Logging:** Verhindert doppelte Einträge in der Historie bei Neustarts.

## 🚀 Quick Start (Docker Compose)
```yaml
services:
  ionos-ddns:
    image: deinusername/ionos-ddns:latest
    container_name: ionos-ddns
    environment:
      - API_PREFIX=dein_ionos_prefix
      - API_SECRET=dein_ionos_secret
      - DOMAINS=domain.de,sub.domain.de
      - IP_MODE=BOTH # IPV4, IPV6 oder BOTH
    ports:
      - "8080:8080" # Dashboard & Healthcheck
    volumes:
      - ./logs:/logs
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
| `LANG` | Sprache der Logs (`DE` oder `EN`) | `DE` |
| `DRY_RUN` | Wenn `true`, wird nichts bei IONOS geändert | `false` |


## 📊 Dashboard
​Erreichbar unter http://server-ip:8080. Zeigt den aktuellen API-Status und die letzten IP-Änderungen übersichtlich an.

## 📊 Monitoring & Logs
​Das Tool erstellt im gemounteten /logs Verzeichnis zwei Dateien:
​dyndns.json: Ein fortlaufendes Log aller Aktionen (Startup, Updates, Fehler).
​update.json: Eine kompakte Historie der IP-Adressen pro Domain.
​Beispiel der update.json:

```json
{
  "domain.de": {
    "ips": [
      {
        "time": "03.01.2026 18:08:25",
        "ipv4": "*.x.x.x",
        "ipv6": "2001:*:..."
      }
    ]
  }
}
```

## 🏗 Manuelle Installation (Binaries)
​Du kannst die vorkompilierten Binaries für Linux (AMD64/ARM64) und Windows direkt aus den GitHub Releases herunterladen.
​Lade die passende Datei für dein System herunter.
​Setze die Umgebungsvariablen (z. B. via .env Datei oder Export).
​Starte das Programm: ./ionos-ddns-linux-amd64

## ​🔐 API-Keys erstellen
​Um die API-Zugangsdaten zu erhalten, besuche die IONOS Developer Konsole. Erstelle dort einen neuen Key und kopiere das Prefix und das Secret.
## ​⚖️ Lizenz
​Dieses Projekt ist unter der MIT-Lizenz lizenziert.
