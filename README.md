# IONOS Go-DynDNS 🚀

Ein leichtgewichtiger DynDNS-Client für IONOS, geschrieben in Go. Das Tool aktualisiert automatisch A (IPv4) und AAAA (IPv6) Records, führt eine strukturierte Historie der IP-Wechsel und bietet einen Healthcheck-Endpunkt für Docker/Portainer.

## Features ✨

* **Dual-Stack Support:** Aktualisiert IPv4 und IPv6 (identifiziert IPs über externe Dienste oder lokale Interfaces).
* **Kombinierte Historie:** Speichert die letzten 30 IP-Wechsel in einer übersichtlichen `update.json`.
* **JSON Logging:** Maschinenlesbare Logs für einfache Analyse.
* **Healthcheck:** Integrierter HTTP-Endpunkt (`/health`) zur Überwachung des Container-Status.
* **Minimaler Footprint:** Dank Go-Binary und Alpine Linux extrem klein (~15MB).
* **Zeitzonen-Support:** Korrekte Zeitstempel durch `TZ`-Umgebungsvariable.

## Voraussetzungen 📋

Um dieses Tool zu nutzen, benötigst du IONOS API-Credentials (Prefix und Secret). Diese kannst du unter [developer.hosting.ionos.de](https://developer.hosting.ionos.de/) erstellen.

## Schnellanleitung (Docker) 🐳

### 1. Docker Image bauen
```bash
docker build -t ionos-dyndns-go .
