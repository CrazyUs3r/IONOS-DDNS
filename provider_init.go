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
	if err := os.MkdirAll(dir, 0o755); err != nil {
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

	if err := os.WriteFile(tmp, data, 0o600); err != nil {
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
	providerEnv := legacyProviderEnv()
	domains, err := legacyDomainsFromEnv()
	if err != nil {
		return err
	}

	configs, err := buildLegacyDomainConfigs(providerEnv, domains)
	if err != nil {
		return err
	}

	cfg.DomainConfigs = configs
	return validateDomainConfigs()
}

func legacyProviderEnv() string {
	providerEnv := strings.ToUpper(os.Getenv("PROVIDER"))
	if providerEnv == "" {
		return "IONOS"
	}
	return providerEnv
}

func legacyDomainsFromEnv() ([]string, error) {
	domainsEnv := os.Getenv("DOMAINS")
	if domainsEnv == "" {
		return nil, fmt.Errorf("%s", T.NoDomainsConfigured)
	}

	rawDomains := strings.Split(domainsEnv, ",")
	domains := make([]string, 0, len(rawDomains))

	for _, d := range rawDomains {
		d = normalizeLegacyDomain(d)
		if d != "" {
			domains = append(domains, d)
		}
	}

	return domains, nil
}

func normalizeLegacyDomain(domain string) string {
	return strings.TrimSpace(strings.ToLower(domain))
}

func buildLegacyDomainConfigs(providerEnv string, domains []string) ([]DomainConfig, error) {
	switch providerEnv {
	case "IONOS":
		return buildLegacyIONOSConfigs(domains)
	case "CLOUDFLARE":
		return buildLegacyCloudflareConfigs(domains)
	case "IPV64":
		return buildLegacyIPv64Configs(domains)
	default:
		return nil, fmt.Errorf(T.UnknownProviderFormat, providerEnv)
	}
}

func buildLegacyIONOSConfigs(domains []string) ([]DomainConfig, error) {
	apiPrefix := os.Getenv("API_PREFIX")
	apiSecret := os.Getenv("API_SECRET")

	if apiPrefix == "" || apiSecret == "" {
		return nil, fmt.Errorf("%s", T.IonosRequiresAPIPrefixAndAPISecret)
	}

	configs := make([]DomainConfig, 0, len(domains))
	for _, d := range domains {
		configs = append(configs, DomainConfig{
			FQDN:      d,
			Provider:  ProviderIONOS,
			APIPrefix: apiPrefix,
			APISecret: apiSecret,
		})
	}

	return configs, nil
}

func buildLegacyCloudflareConfigs(domains []string) ([]DomainConfig, error) {
	cfToken := os.Getenv("CLOUDFLARE_TOKEN")
	cfEmail := os.Getenv("CLOUDFLARE_EMAIL")
	cfSecret := os.Getenv("CLOUDFLARE_API_SECRET")

	if cfToken == "" && (cfEmail == "" || cfSecret == "") {
		return nil, fmt.Errorf("%s", T.CloudflareRequiresTokenOrEmailAndAPISecret)
	}

	configs := make([]DomainConfig, 0, len(domains))
	for _, d := range domains {
		configs = append(configs, DomainConfig{
			FQDN:     d,
			Provider: ProviderCloudflare,
			CFToken:  cfToken,
			CFEmail:  cfEmail,
			CFSecret: cfSecret,
		})
	}

	return configs, nil
}

func buildLegacyIPv64Configs(domains []string) ([]DomainConfig, error) {
	token := os.Getenv("IPV64_TOKEN")

	if token == "" {
		return nil, fmt.Errorf("%s", T.Ipv64RequiresToken)
	}

	configs := make([]DomainConfig, 0, len(domains))
	for _, d := range domains {
		configs = append(configs, DomainConfig{
			FQDN:       d,
			Provider:   ProviderIPv64,
			IPv64Token: token,
		})
	}

	return configs, nil
}
