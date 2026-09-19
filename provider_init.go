// Pachage main
package main

import (
	"encoding/json"
	"errors"
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
			Message: fmt.Sprintf(phrases().FailedToCreateConfigDirectoryFormat, err),
		})

		return fmt.Errorf(phrases().CreateConfigDirectoryFormat, err)
	}

	cfgMu.RLock()
	configSnapshot := cfg
	configSnapshot.DomainConfigs = append([]DomainConfig(nil), cfg.DomainConfigs...)
	configSnapshot.DNSServers = append([]string(nil), cfg.DNSServers...)
	configSnapshot.IPv4Endpoints = append([]string(nil), cfg.IPv4Endpoints...)
	configSnapshot.IPv6Endpoints = append([]string(nil), cfg.IPv6Endpoints...)
	configSnapshot.Notifications.Events = append([]string(nil), cfg.Notifications.Events...)
	cfgMu.RUnlock()

	data, err := json.MarshalIndent(configSnapshot, "", "  ")
	if err != nil {
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: fmt.Sprintf(phrases().FailedToMarshalConfigFormat, err),
		})

		return fmt.Errorf(phrases().MarshalConfigFormat, err)
	}

	if err := writeFileAtomic(configPath, data); err != nil {
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: fmt.Sprintf(phrases().FailedToReplaceConfigFileFormat, err),
		})

		return fmt.Errorf(phrases().ReplaceConfigFileFormat, err)
	}

	return nil
}

func initProviderConfig() error {
	if len(cfg.DomainConfigs) > 0 {
		if err := validateConfig(); err != nil {
			return err
		}

		return validateDomainConfigs()
	}

	configJSON := os.Getenv("DOMAINS_CONFIG")
	if configJSON != "" {
		debugLog("CONFIG", "", phrases().ConfigJSONMissingMigratingFromDomainsConfig)

		var raw []rawEntry
		if err := json.Unmarshal([]byte(configJSON), &raw); err != nil {
			return fmt.Errorf(phrases().InvalidDomainsConfigJSONFormat, err)
		}

		cfg.DomainConfigs = expandDomainConfigs(raw)

		if err := validateDomainConfigs(); err != nil {
			return err
		}

		if err := saveConfigToFile(); err != nil {
			debugLog("CONFIG", "", fmt.Sprintf(phrases().CouldNotCreateConfigJSONFormat, err))
		} else {
			debugLog("CONFIG", "", phrases().ConfigJSONSuccessfullyCreatedFromEnv)
		}

		return nil
	}

	if strings.TrimSpace(os.Getenv("DOMAINS")) != "" {
		debugLog("CONFIG", "", phrases().NoConfigJSONAndNoDomainsConfigFoundUsingLegacyMode)
		err := initLegacyConfig()
		if err == nil {
			_ = saveConfigToFile()
		}

		return err
	}

	debugLog("CONFIG", "", "No domain/provider configuration found yet; dashboard setup mode active.")

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
		Provider:  normalizeProviderName(r.Provider),
		APIPrefix: pick(r.APIPrefix, r.APIPrefix2),
		APISecret: firstNonEmpty(
			pick(r.APISecret, r.APISecret2),
			r.HetznerToken, r.HetznerToken2,
			r.HetznerDNSToken, r.HetznerDNSToken2,
			r.HetznerCloudToken, r.HetznerCloudToken2,
			r.HCloudToken, r.HCloudToken2,
		),
		CFToken:        pick(r.CFToken, r.CFToken2),
		CFEmail:        pick(r.CFEmail, r.CFEmail2),
		CFSecret:       pick(r.CFSecret, r.CFSecret2),
		CFZoneID:       r.CFZoneID,
		IPv64Token:     pick(r.IPv64Token, r.IPv64Token2),
		FebasUpdateURL: pick(r.FebasUpdateURL, r.FebasUpdateURL2),
		APIKey:         pick(r.APIKey, r.APIKey2),
		TTL:            r.TTL,
		CFProxied:      r.CFProxied,
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
	d = strings.TrimSpace(strings.ToLower(d))

	return strings.TrimSuffix(d, ".")
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
		return nil, fmt.Errorf("%s", phrases().NoDomainsConfigured)
	}

	rawDomains := strings.Split(domainsEnv, ",")
	domains := make([]string, 0, len(rawDomains))

	for _, d := range rawDomains {
		d = normalizeDomain(d)
		if d != "" {
			domains = append(domains, d)
		}
	}

	return domains, nil
}

func buildLegacyDomainConfigs(providerEnv string, domains []string) ([]DomainConfig, error) {
	switch string(normalizeProviderName(providerEnv)) {
	case "IONOS":
		return buildLegacyIONOSConfigs(domains)
	case "CLOUDFLARE":
		return buildLegacyCloudflareConfigs(domains)
	case "IPV64":
		return buildLegacyIPv64Configs(domains)
	case "HETZNER":
		return buildLegacyHetznerDNSConfigs(domains)
	case "HETZNERCLOUD":
		return buildLegacyHetznerCloudConfigs(domains)
	case "FEBAS":
		return buildLegacyFebasConfigs(domains)
	case "DNSCALE":
		return buildLegacyDNScaleConfigs(domains)
	default:
		return nil, fmt.Errorf(phrases().UnknownProviderFormat, providerEnv)
	}
}

func buildLegacyConfigs(domains []string, base DomainConfig) []DomainConfig {
	configs := make([]DomainConfig, 0, len(domains))

	for _, d := range domains {
		dc := base
		dc.FQDN = d
		configs = append(configs, dc)
	}

	return configs
}

func buildLegacyIONOSConfigs(domains []string) ([]DomainConfig, error) {
	apiPrefix := os.Getenv("API_PREFIX")
	apiSecret := os.Getenv("API_SECRET")

	if apiPrefix == "" || apiSecret == "" {
		return nil, fmt.Errorf("%s", phrases().IonosRequiresAPIPrefixAndAPISecret)
	}

	return buildLegacyConfigs(domains, DomainConfig{
		Provider:  ProviderIONOS,
		APIPrefix: apiPrefix,
		APISecret: apiSecret,
	}), nil
}

func buildLegacyCloudflareConfigs(domains []string) ([]DomainConfig, error) {
	cfToken := os.Getenv("CLOUDFLARE_TOKEN")
	cfEmail := os.Getenv("CLOUDFLARE_EMAIL")
	cfSecret := os.Getenv("CLOUDFLARE_API_SECRET")

	if cfToken == "" && (cfEmail == "" || cfSecret == "") {
		return nil, fmt.Errorf("%s", phrases().CloudflareRequiresTokenOrEmailAndAPISecret)
	}

	return buildLegacyConfigs(domains, DomainConfig{
		Provider: ProviderCloudflare,
		CFToken:  cfToken,
		CFEmail:  cfEmail,
		CFSecret: cfSecret,
	}), nil
}

func buildLegacyIPv64Configs(domains []string) ([]DomainConfig, error) {
	token := os.Getenv("IPV64_TOKEN")

	if token == "" {
		return nil, fmt.Errorf("%s", phrases().Ipv64RequiresToken)
	}

	return buildLegacyConfigs(domains, DomainConfig{
		Provider:   ProviderIPv64,
		IPv64Token: token,
	}), nil
}

func buildLegacyFebasConfigs(domains []string) ([]DomainConfig, error) {
	updateURL := strings.TrimSpace(os.Getenv("FEBAS_UPDATE_URL"))
	if updateURL == "" {
		return nil, fmt.Errorf("%s", phrases().FebasUpdateURLRequired)
	}

	return buildLegacyConfigs(domains, DomainConfig{
		Provider:       ProviderFebas,
		FebasUpdateURL: updateURL,
	}), nil
}

func buildLegacyDNScaleConfigs(domains []string) ([]DomainConfig, error) {
	apiKey := strings.TrimSpace(
		firstNonEmptyEnv("DNSCALE_API_KEY", "DNSCALE_TOKEN"),
	)
	if apiKey == "" {
		return nil, fmt.Errorf("%s", phrases().DNScaleAPIKeyRequired)
	}

	return buildLegacyConfigs(domains, DomainConfig{
		Provider: ProviderDNScale,
		APIKey:   apiKey,
	}), nil
}

func buildLegacyHetznerDNSConfigs(domains []string) ([]DomainConfig, error) {
	token := firstNonEmptyEnv("HETZNER_TOKEN", "HETZNER_DNS_TOKEN", "HETZNER_API_TOKEN")
	if token == "" {
		return nil, errors.New("HETZNER requires HETZNER_TOKEN or HETZNER_DNS_TOKEN")
	}

	return buildLegacyConfigs(domains, DomainConfig{
		Provider:  ProviderHetzner,
		APISecret: token,
	}), nil
}

func buildLegacyHetznerCloudConfigs(domains []string) ([]DomainConfig, error) {
	token := firstNonEmptyEnv("HCLOUD_TOKEN", "HETZNER_CLOUD_TOKEN", "HETZNER_CONSOLE_TOKEN")
	if token == "" {
		return nil, errors.New("HETZNERCLOUD requires HCLOUD_TOKEN or HETZNER_CLOUD_TOKEN")
	}

	return buildLegacyConfigs(domains, DomainConfig{
		Provider:  ProviderHetznerCloud,
		APISecret: token,
	}), nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}

	return ""
}

func firstNonEmptyEnv(keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}

	return ""
}
