​🚀 IONOS DynDNS Dual-Stack (Go)

​Ein leistungsstarker, in Go geschriebener DynDNS-Client für IONOS. Er wurde speziell für moderne Internetanschlüsse entwickelt, die sowohl IPv4 als auch IPv6 (Dual-Stack) nutzen.

​✨ Features
​Dual-Stack Support: Aktualisiert A (IPv4) und AAAA (IPv6) Records gleichzeitig.
​Parallele Verarbeitung: Nutzt Go-Routines, um alle Domains gleichzeitig zu prüfen (ideal bei vielen Subdomains).
​Infrastruktur-Analyse: Zeigt beim Start eine Übersicht aller konfigurierten IONOS DNS-Einträge an.
​Mehrsprachig: Unterstützt deutsche und englische Konsolenausgaben (LANG=DE/LANG=EN).
​Status-Historie: Speichert eine JSON-Datei mit der Historie deiner IP-Wechsel.
​Multi-Architektur: Native Docker-Images für PC (amd64) und Raspberry Pi (arm64).

​🚀 Installation mit Docker Compose
​Dies ist der einfachste Weg, das Tool dauerhaft auf einem Server oder NAS zu betreiben.
```yaml
services:
  ionos-ddns:
    image: crazyus3r/ionos-ddns:latest
    container_name: ionos-ddns
    restart: unless-stopped
    environment:
      - API_PREFIX=${IONOS_PREFIX}
      - API_SECRET=${IONOS_SECRET}
      - DOMAINS=Domain.de,sub.domain.de
      - IP_MODE=BOTH # IPV4, IPV6 oder BOTH
      - INTERVAL=300 # Prüfintervall in Sekunden
      - LANG=DE      # DE oder EN
      - TZ=Europe/Berlin
    volumes:
      - ./logs:/logs
```
🛠 Konfiguration (Umgebungsvariablen)

| Variable | Beschreibung | Standard |
| :--- | :--- | :--- |
| `API_PREFIX` | Dein IONOS API Public Key | (erforderlich) |
| `API_SECRET` | Dein IONOS API Secret | (erforderlich) |
| `DOMAINS` | Kommagetrennte Liste der Domains | (erforderlich) |
| `IP_MODE` | Modus: `IPV4`, `IPV6` oder `BOTH` | `BOTH` |
| `INTERVAL` | Intervall zwischen den Prüfungen (Sekunden) | `300` |
| `LANG` | Sprache der Logs (`DE` oder `EN`) | `DE` |
| `DRY_RUN` | Wenn `true`, wird nichts bei IONOS geändert | `false` |


📊 Monitoring & Logs
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
        "ipv4": "*.*.*.*",
        "ipv6": "*:*:..."
      }
    ]
  }
}

```

🏗 Manuelle Installation (Binaries)
​Du kannst die vorkompilierten Binaries für Linux (AMD64/ARM64) und Windows direkt aus den GitHub Releases herunterladen.
​Lade die passende Datei für dein System herunter.
​Setze die Umgebungsvariablen (z. B. via .env Datei oder Export).
​Starte das Programm: ./ionos-ddns-linux-amd64

​🔐 API-Keys erstellen
​Um die API-Zugangsdaten zu erhalten, besuche die IONOS Developer Konsole. Erstelle dort einen neuen Key und kopiere das Prefix und das Secret.

Lizenz

​Dieses Projekt ist unter der MIT-Lizenz lizenziert.
