// Package main
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// ============================================================================
// PROVIDER INITIALIZATION
// ============================================================================
func initProviderConfig() error {
	configJSON := os.Getenv("DOMAINS_CONFIG")
	if configJSON != "" {
		debugLog("CONFIG", "", "📦 Loading multi-provider config from DOMAINS_CONFIG")

		var raw []DomainConfig
		if err := json.Unmarshal([]byte(configJSON), &raw); err != nil {
			return fmt.Errorf("invalid DOMAINS_CONFIG JSON: %w", err)
		}

		cfg.DomainConfigs = expandDomainConfigs(raw)

		return validateDomainConfigs()
	}

	debugLog("CONFIG", "", "📦 Using legacy single-provider mode")
	return initLegacyConfig()
}

func expandDomainConfigs(in []DomainConfig) []DomainConfig {
	out := make([]DomainConfig, 0, len(in))
	for _, c := range in {
		fqdn := strings.TrimSpace(c.FQDN)
		if fqdn == "" {
			continue
		}

		parts := splitDomains(fqdn)
		if len(parts) <= 1 {
			c.FQDN = normalizeDomain(fqdn)
			out = append(out, c)
			continue
		}

		for _, d := range parts {
			d = normalizeDomain(d)
			if d == "" {
				continue
			}
			nc := c
			nc.FQDN = d
			out = append(out, nc)
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

// ============================================================================
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
