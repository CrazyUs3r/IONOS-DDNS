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
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, data, 0644)
}

func initProviderConfig() error {
	if len(cfg.DomainConfigs) > 0 {
		return validateConfig()
	}

	configJSON := os.Getenv("DOMAINS_CONFIG")
	if configJSON != "" {
		debugLog("CONFIG", "", "📦 config.json fehlt. Migriere Daten aus DOMAINS_CONFIG...")

		var raw []rawEntry
		if err := json.Unmarshal([]byte(configJSON), &raw); err != nil {
			return fmt.Errorf("invalid DOMAINS_CONFIG JSON: %w", err)
		}

		cfg.DomainConfigs = expandDomainConfigs(raw)

		if err := validateDomainConfigs(); err != nil {
			return err
		}

		if err := saveConfigToFile(); err != nil {
			debugLog("CONFIG", "", "⚠️ Konnte config.json nicht erstellen: "+err.Error())
		} else {
			debugLog("CONFIG", "", "✅ config.json erfolgreich aus ENV erstellt.")
		}
		return nil
	}

	debugLog("CONFIG", "", "📦 Keine config.json und keine DOMAINS_CONFIG gefunden. Nutze Legacy-Mode.")
	err := initLegacyConfig()
	if err == nil {
		_ = saveConfigToFile()
	}
	return err
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
