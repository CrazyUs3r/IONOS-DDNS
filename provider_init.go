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

		var configs []DomainConfig
		if err := json.Unmarshal([]byte(configJSON), &configs); err != nil {
			return fmt.Errorf("invalid DOMAINS_CONFIG JSON: %w", err)
		}

		cfg.DomainConfigs = configs
		return validateDomainConfigs()
	}

	debugLog("CONFIG", "", "📦 Using legacy single-provider mode")
	return initLegacyConfig()
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
			return fmt.Errorf("IONOS requires API_PREFIX and API_SECRET")
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
			return fmt.Errorf("Cloudflare requires CLOUDFLARE_TOKEN or CLOUDFLARE_EMAIL + CLOUDFLARE_API_SECRET")
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
			return fmt.Errorf("IPv64 requires IPV64_TOKEN")
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
