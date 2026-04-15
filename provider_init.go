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
	if err := os.MkdirAll(dir, 0755); err != nil {
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: fmt.Sprintf(T.FailedToCreateConfigDirectoryFormat, err),
		})
		return fmt.Errorf(T.CreateConfigDirectoryFormat, err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: fmt.Sprintf(T.FailedToMarshalConfigFormat, err),
		})
		return fmt.Errorf(T.MarshalConfigFormat, err)
	}

	tmp := configPath + ".tmp"

	if err := os.WriteFile(tmp, data, 0644); err != nil {
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: fmt.Sprintf(T.FailedToWriteTempConfigFileFormat, err),
		})
		return fmt.Errorf(T.WriteTempConfigFileFormat, err)
	}

	if err := os.Rename(tmp, configPath); err != nil {
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: fmt.Sprintf(T.FailedToReplaceConfigFileFormat, err),
		})
		return fmt.Errorf(T.ReplaceConfigFileFormat, err)
	}

	return nil
}

func initProviderConfig() error {
	if len(cfg.DomainConfigs) > 0 {
		return validateConfig()
	}

	configJSON := os.Getenv("DOMAINS_CONFIG")
	if configJSON != "" {
		debugLog("CONFIG", "", T.ConfigJSONMissingMigratingFromDomainsConfig)

		var raw []rawEntry
		if err := json.Unmarshal([]byte(configJSON), &raw); err != nil {
			return fmt.Errorf(T.InvalidDomainsConfigJSONFormat, err)
		}

		cfg.DomainConfigs = expandDomainConfigs(raw)

		if err := validateDomainConfigs(); err != nil {
			return err
		}

		if err := saveConfigToFile(); err != nil {
			debugLog("CONFIG", "", fmt.Sprintf(T.CouldNotCreateConfigJSONFormat, err))
		} else {
			debugLog("CONFIG", "", T.ConfigJSONSuccessfullyCreatedFromEnv)
		}
		return nil
	}

	debugLog("CONFIG", "", T.NoConfigJSONAndNoDomainsConfigFoundUsingLegacyMode)
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
		return fmt.Errorf("%s", T.NoDomainsConfigured)
	}

	domains := strings.Split(domainsEnv, ",")
	var configs []DomainConfig

	switch providerEnv {
	case "IONOS":
		apiPrefix := os.Getenv("API_PREFIX")
		apiSecret := os.Getenv("API_SECRET")

		if apiPrefix == "" || apiSecret == "" {
			return fmt.Errorf("%s", T.IonosRequiresAPIPrefixAndAPISecret)
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
			return fmt.Errorf("%s", T.CloudflareRequiresTokenOrEmailAndAPISecret)
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
			return fmt.Errorf("%s", T.Ipv64RequiresToken)
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
		return fmt.Errorf(T.UnknownProviderFormat, providerEnv)
	}

	cfg.DomainConfigs = configs
	return validateDomainConfigs()
}
