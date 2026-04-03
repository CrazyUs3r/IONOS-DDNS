// Package main
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ============================================================================
// PROVIDER INITIALIZATION
// ============================================================================
func saveConfigToFile() error {
	dir := filepath.Dir(configPath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		_ = os.MkdirAll(dir, 0755)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, data, 0644)
}

func initProviderConfig() error {
	// Flag, um zu tracken, ob wir überhaupt irgendwoher Daten bekommen haben
	fileFound := false

	// 1. SCHRITT: config.json laden
	if _, err := os.Stat(configPath); err == nil {
		debugLog("CONFIG", "", "📂 config.json gefunden. Lade Configuration...")
		data, err := os.ReadFile(configPath)
		if err == nil {
			if err := json.Unmarshal(data, &cfg); err == nil {
				debugLog("CONFIG", "", fmt.Sprintf("✅ config.json geladen (%d Domains gefunden).", len(cfg.DomainConfigs)))
				fileFound = true
			} else {
				debugLog("CONFIG", "", "⚠️ Fehler beim Parsen der config.json (Format ungültig).")
			}
		}
	} else {
		debugLog("CONFIG", "", "ℹ️ Keine config.json vorhanden, überspringe Dateimodus.")
	}

	// 2. SCHRITT: DOMAINS_CONFIG (Umgebungsvariable) prüfen
	configJSON := os.Getenv("DOMAINS_CONFIG")
	if configJSON != "" {
		debugLog("CONFIG", "", "📦 Suche in DOMAINS_CONFIG Umgebungsvariable...")
		var raw []rawEntry
		if err := json.Unmarshal([]byte(configJSON), &raw); err == nil {
			envConfigs := expandDomainConfigs(raw)
			// Wir hängen diese an, falls in der config.json schon was stand
			cfg.DomainConfigs = append(cfg.DomainConfigs, envConfigs...)
			debugLog("CONFIG", "", fmt.Sprintf("✅ %d Domains aus DOMAINS_CONFIG hinzugefügt.", len(envConfigs)))
		} else {
			debugLog("CONFIG", "", "⚠️ Ungültiges JSON in DOMAINS_CONFIG.")
		}
	}

	// 3. SCHRITT: Legacy-Mode (nur wenn bisher KEINE Domains gefunden wurden)
	// Das verhindert, dass wir die Legacy-Variablen laden, wenn die config.json absichtlich leer ist
	// oder bereits Domains aus der config.json/DOMAINS_CONFIG vorhanden sind.
	if len(cfg.DomainConfigs) == 0 {
		debugLog("CONFIG", "", "🔍 Bisher keine Domains konfiguriert. Prüfe Legacy-Umgebungsvariablen (DOMAINS, PROVIDER...)...")
		// Wir rufen initLegacyConfig auf, aber ignorieren den Fehler hier kurzzeitig, 
		// da wir am Ende sowieso global validieren.
		_ = initLegacyConfig() 
	}

	// 4. SCHRITT: Globale Validierung
	// Erst jetzt prüfen wir, ob die Summe aller Quellen gültig ist.
	if err := validateDomainConfigs(); err != nil {
		debugLog("CONFIG", "", "❌ Validierung fehlgeschlagen: "+err.Error())
		return err
	}

	// 5. SCHRITT: Speichern (Optional)
	// Falls wir Daten aus ENVs geladen haben, schreiben wir sie in die config.json für das nächste Mal
	if !fileFound && len(cfg.DomainConfigs) > 0 {
		debugLog("CONFIG", "", "💾 Speichere gefundene Configuration in config.json...")
		if err := saveConfigToFile(); err != nil {
			debugLog("CONFIG", "", "⚠️ Konnte config.json nicht automatisch erstellen: "+err.Error())
		}
	}

	debugLog("CONFIG", "", "🚀 Provider-Initialisierung erfolgreich abgeschlossen.")
	return nil
}



func (r rawEntry) toDomainConfig() DomainConfig {
	pick := func(a, b string) string {
		if a != "" {
			return a
		}
		return b
	}
	return DomainConfig{
		Provider:   ProviderType(strings.ToUpper(r.Provider)),
		APIPrefix:  pick(r.APIPrefix, r.APIPrefix2),
		APISecret:  pick(r.APISecret, r.APISecret2),
		CFToken:    pick(r.CFToken, r.CFToken2),
		CFEmail:    pick(r.CFEmail, r.CFEmail2),
		CFSecret:   pick(r.CFSecret, r.CFSecret2),
		CFZoneID:   r.CFZoneID,
		IPv64Token: pick(r.IPv64Token, r.IPv64Token2),
	}
}

func expandDomainConfigs(raw []rawEntry) []DomainConfig {
	out := make([]DomainConfig, 0, len(raw))
	for _, r := range raw {
		base := r.toDomainConfig()
		for _, fqdn := range splitDomains(r.FQDN) {
			fqdn = normalizeDomain(fqdn)
			if fqdn == "" {
				continue
			}
			dc := base
			dc.FQDN = fqdn
			out = append(out, dc)
		}
	}
	return out
}

func splitDomains(s string) []string {
	raw := strings.Split(s, ",")
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func normalizeDomain(d string) string {
	return strings.TrimSpace(strings.ToLower(d))
}

func initLegacyConfig() error {
	providerEnv := strings.ToUpper(os.Getenv("PROVIDER"))
	if providerEnv == "" {
		providerEnv = "IONOS"
	}

	domainsEnv := os.Getenv("DOMAINS")
	if domainsEnv == "" {
		return fmt.Errorf("no domains configured (DOMAINS env var empty)")
	}

	domains := strings.Split(domainsEnv, ",")
	var configs []DomainConfig

	switch providerEnv {
	case "IONOS":
		apiPrefix := os.Getenv("API_PREFIX")
		apiSecret := os.Getenv("API_SECRET")

		if apiPrefix == "" || apiSecret == "" {
			return fmt.Errorf("ionos requires API_PREFIX and API_SECRET")
		}

		for _, d := range domains {
			d = strings.TrimSpace(strings.ToLower(d))
			if d == "" {
				continue
			}
			configs = append(configs, DomainConfig{
				FQDN:      d,
				Provider:  ProviderIONOS,
				APIPrefix: apiPrefix,
				APISecret: apiSecret,
			})
		}

	case "CLOUDFLARE":
		cfToken := os.Getenv("CLOUDFLARE_TOKEN")
		cfEmail := os.Getenv("CLOUDFLARE_EMAIL")
		cfSecret := os.Getenv("CLOUDFLARE_API_SECRET")

		if cfToken == "" && (cfEmail == "" || cfSecret == "") {
			return fmt.Errorf("cloudflare requires CLOUDFLARE_TOKEN or CLOUDFLARE_EMAIL + CLOUDFLARE_API_SECRET")
		}

		for _, d := range domains {
			d = strings.TrimSpace(strings.ToLower(d))
			if d == "" {
				continue
			}
			configs = append(configs, DomainConfig{
				FQDN:     d,
				Provider: ProviderCloudflare,
				CFToken:  cfToken,
				CFEmail:  cfEmail,
				CFSecret: cfSecret,
			})
		}

	case "IPV64":
		token := os.Getenv("IPV64_TOKEN")

		if token == "" {
			return fmt.Errorf("ipv64 requires IPV64_TOKEN")
		}

		for _, d := range domains {
			d = strings.TrimSpace(strings.ToLower(d))
			if d == "" {
				continue
			}
			configs = append(configs, DomainConfig{
				FQDN:       d,
				Provider:   ProviderIPv64,
				IPv64Token: token,
			})
		}

	default:
		return fmt.Errorf("unknown provider: %s (supported: IONOS, CLOUDFLARE, IPV64)", providerEnv)
	}

	cfg.DomainConfigs = configs
	return validateDomainConfigs()
}
