// Package main
package main

import (
	"fmt"
	"strconv"
	"strings"
)

// ============================================================================
// VALIDATION
// ============================================================================
func validateDomainConfigs() error {
	return validateDomainConfigList(snapshotDomainConfigs())
}

func validateDomainConfigList(
	domainConfigs []DomainConfig,
) error {
	if len(domainConfigs) == 0 {
		return fmt.Errorf(
			"%s",
			phrases().NoDomainsConfigured,
		)
	}

	seenDomains := make(
		map[string]int,
		len(domainConfigs),
	)
	providerAuth := make(map[ProviderType]string)

	for i := range domainConfigs {
		if err := validateDomainConfigEntry(
			i,
			domainConfigs[i],
			seenDomains,
			providerAuth,
		); err != nil {
			return err
		}
	}

	return nil
}

func snapshotDomainConfigs() []DomainConfig {
	cfgMu.RLock()
	defer cfgMu.RUnlock()

	domainConfigs := make([]DomainConfig, len(cfg.DomainConfigs))
	copy(domainConfigs, cfg.DomainConfigs)

	return domainConfigs
}

func validateDomainConfigEntry(
	index int,
	dc DomainConfig,
	seenDomains map[string]int,
	providerAuth map[ProviderType]string,
) error {
	fqdn := normalizeDomain(dc.FQDN)

	if err := validateDomain(fqdn); err != nil {
		return fmt.Errorf(
			phrases().DomainContext,
			index,
			dc.FQDN,
			err.Error(),
		)
	}

	if err := validateUniqueDomain(
		fqdn,
		index,
		seenDomains,
	); err != nil {
		return err
	}

	if err := validateDomainIPMode(fqdn, dc.IPMode); err != nil {
		return err
	}

	if dc.TTL < 0 {
		return fmt.Errorf(
			phrases().InvalidNegativeTTLFormat,
			fqdn,
			dc.TTL,
		)
	}

	if err := validateProviderCredentials(dc, fqdn); err != nil {
		return err
	}

	return validateProviderAccount(dc, providerAuth)
}

func validateUniqueDomain(
	fqdn string,
	index int,
	seenDomains map[string]int,
) error {
	previousIndex, exists := seenDomains[fqdn]
	if exists {
		return fmt.Errorf(
			phrases().DomainConfiguredMoreThanOnceFormat,
			fqdn,
			previousIndex,
			index,
		)
	}

	seenDomains[fqdn] = index
	return nil
}

func validateDomainIPMode(fqdn, configuredMode string) error {
	mode := strings.ToUpper(strings.TrimSpace(configuredMode))

	switch mode {
	case "", IPModeV4, IPModeV6, IPModeBoth:
		return nil
	default:
		return fmt.Errorf(
			phrases().InvalidDomainIPModeFormat,
			fqdn,
			configuredMode,
		)
	}
}

func validateProviderCredentials(
	dc DomainConfig,
	fqdn string,
) error {
	switch dc.Provider {
	case ProviderIONOS:
		if dc.APIPrefix == "" || dc.APISecret == "" {
			return fmt.Errorf(
				phrases().IonosAPIRequired,
				fqdn,
			)
		}

	case ProviderIPv64:
		if dc.IPv64Token == "" {
			return fmt.Errorf(
				phrases().Ipv64TokenRequired,
				fqdn,
			)
		}

	case ProviderCloudflare:
		if dc.CFToken == "" &&
			(dc.CFEmail == "" || dc.CFSecret == "") {
			return fmt.Errorf(
				phrases().CloudflareAuthRequired,
				fqdn,
			)
		}

	case ProviderHetzner, ProviderHetznerCloud:
		if hetznerToken(&dc) == "" {
			return fmt.Errorf(
				phrases().HetznerAuthRequired,
				fqdn,
			)
		}

	case ProviderFebas:
		if err := validateFebasUpdateURL(dc.FebasUpdateURL); err != nil {
			return fmt.Errorf("%s: %w", fqdn, err)
		}

	default:
		return fmt.Errorf(
			phrases().UnknownProvider,
			fqdn,
			dc.Provider,
		)
	}

	return nil
}

func validateProviderAccount(
	dc DomainConfig,
	providerAuth map[ProviderType]string,
) error {
	if dc.Provider == ProviderFebas {
		return nil
	}

	auth := providerAuthFingerprint(dc)

	previousAuth, exists := providerAuth[dc.Provider]
	if !exists {
		providerAuth[dc.Provider] = auth
		return nil
	}

	if previousAuth == auth {
		return nil
	}

	return fmt.Errorf(
		phrases().MultipleProviderAccountsNotSupportedFormat,
		dc.Provider,
	)
}

func providerAuthFingerprint(dc DomainConfig) string {
	switch dc.Provider {
	case ProviderIONOS:
		return dc.APIPrefix + "\x00" + dc.APISecret

	case ProviderCloudflare:
		if dc.CFToken != "" {
			return "token\x00" + dc.CFToken
		}
		return "global\x00" + dc.CFEmail + "\x00" + dc.CFSecret

	case ProviderIPv64:
		return dc.IPv64Token

	case ProviderHetzner, ProviderHetznerCloud:
		return hetznerToken(&dc)

	case ProviderFebas:
		return dc.FebasUpdateURL

	default:
		return ""
	}
}

func validateConfig() error {
	var errs []string

	if len(cfg.DomainConfigs) == 0 {
		errs = append(errs, phrases().NoDomainsConfigured)
	}

	port, err := strconv.Atoi(cfg.HealthPort)
	if err != nil || port < 1 || port > 65535 {
		log(LogContext{
			Level:   LogWarn,
			Action:  ActionConfig,
			Message: fmt.Sprintf(phrases().InvalidPort, cfg.HealthPort),
		})
		cfg.HealthPort = "8080"
	}

	if cfg.Interval < 60 {
		if cfg.Interval < 30 {
			log(LogContext{
				Level:   LogWarn,
				Action:  ActionConfig,
				Message: phrases().IntervalTooSmall,
			})
			cfg.Interval = 60
		} else if len(cfg.DomainConfigs) > 10 {
			log(LogContext{
				Level:   LogWarn,
				Action:  ActionConfig,
				Message: "⚠️ " + phrases().ShortIntervalWarning,
			})
		}
	}

	cfg.IPMode = strings.ToUpper(strings.TrimSpace(cfg.IPMode))

	validModes := map[string]bool{
		IPModeV4:   true,
		IPModeV6:   true,
		IPModeBoth: true,
	}

	if !validModes[cfg.IPMode] {
		log(LogContext{
			Level:   LogWarn,
			Action:  ActionConfig,
			Message: fmt.Sprintf(phrases().InvalidIPMode, cfg.IPMode),
		})
		cfg.IPMode = IPModeBoth
	}

	if len(errs) > 0 {
		return fmt.Errorf(phrases().ConfigErrorPrefix, strings.Join(errs, ", "))
	}

	return nil
}

func validateDomain(domain string) error {
	domain = normalizeDomain(domain)

	if domain == "" {
		return fmt.Errorf("%s", phrases().DomainIsEmpty)
	}

	if len(domain) > 253 {
		return fmt.Errorf(phrases().DomainTooLong, len(domain))
	}

	if !domainRegex.MatchString(domain) {
		return fmt.Errorf(phrases().InvalidDomainFormat, domain)
	}

	for label := range strings.SplitSeq(domain, ".") {
		if len(label) > 63 {
			return fmt.Errorf(phrases().LabelTooLong, label, len(label))
		}
		if !labelRegex.MatchString(label) {
			return fmt.Errorf(phrases().InvalidLabel, label)
		}
	}

	return nil
}
