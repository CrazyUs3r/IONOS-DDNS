# IONOS Go-DynDNS 🚀

Ein leichtgewichtiger DynDNS-Client für IONOS, geschrieben in Go. Das Tool aktualisiert automatisch A (IPv4) und AAAA (IPv6) Records, führt eine strukturierte Historie der IP-Wechsel und bietet einen Healthcheck-Endpunkt für Docker/Portainer.

## Features ✨

* **Dual-Stack Support:** Aktualisiert IPv4 und IPv6.
* **Kombinierte Historie:** Speichert die letzten 30 IP-Wechsel in der `update.json`.
* **JSON Logging:** Maschinenlesbare Logs in `dyndns.json`.
* **Healthcheck:** HTTP-Endpunkt (`/health`) für Container-Monitoring.
* **Minimaler Footprint:** Basierend auf Alpine Linux (~15MB).
* **Zeitzonen-Support:** Korrekte Zeitstempel via `TZ` Variable.
* 
### 🌐 Internationalization
By default, the tool uses German logs. You can switch to English by setting the environment variable:
`LANG=EN`

---

## Voraussetzungen 📋

Du benötigst IONOS API-Credentials (Prefix und Secret) vom [IONOS Developer Panel](https://developer.hosting.ionos.de/).

---

## Schnellanleitung (Docker) 🐳

### 1. Docker Image bauen
```bash
docker build -t ionos-dyndns-go .
