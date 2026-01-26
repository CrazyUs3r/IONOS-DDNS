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
	if len(cfg.DomainConfigs) == 0 {
		return fmt.Errorf("no domains configured")
	}

	for i, dc := range cfg.DomainConfigs {
		if err := validateDomain(dc.FQDN); err != nil {
			return fmt.Errorf("domain %d (%s): %w", i, dc.FQDN, err)
		}

		switch dc.Provider {
		case ProviderIONOS:
			if dc.APIPrefix == "" || dc.APISecret == "" {
				return fmt.Errorf("domain %s (IONOS): API_PREFIX and API_SECRET required", dc.FQDN)
			}
		case ProviderIPv64:
			if dc.IPv64Token == "" {
				return fmt.Errorf("domain %s (IPv64): IPv64Token required", dc.FQDN)
			}
		case ProviderCloudflare:
			if dc.CFToken == "" && (dc.CFEmail == "" || dc.CFSecret == "") {
				return fmt.Errorf("domain %s (Cloudflare): CFToken or CFEmail+CFSecret required", dc.FQDN)
			}
		default:
			return fmt.Errorf("domain %s: unknown provider %s", dc.FQDN, dc.Provider)
		}
	}

	return nil
}

func validateConfig() error {
	var errs []string

	if len(cfg.DomainConfigs) == 0 {
		errs = append(errs, T.NoDomains)
	}

	port, err := strconv.Atoi(cfg.HealthPort)
	if err != nil || port < 1 || port > 65535 {
		log(LogContext{
			Level:   LogWarn,
			Action:  ActionConfig,
			Message: fmt.Sprintf(T.InvalidPort, cfg.HealthPort),
		})
		cfg.HealthPort = "8080"
	}

	if cfg.Interval < 60 {
		if cfg.Interval < 30 {
			log(LogContext{
				Level:   LogWarn,
				Action:  ActionConfig,
				Message: T.IntervalTooSmall,
			})
			cfg.Interval = 60
		} else if len(cfg.DomainConfigs) > 10 {
			log(LogContext{
				Level:   LogWarn,
				Action:  ActionConfig,
				Message: "⚠️ " + T.ShortIntervalWarning,
			})
		}
	}

	validModes := map[string]bool{"IPV4": true, "IPV6": true, "BOTH": true}
	if !validModes[cfg.IPMode] {
		log(LogContext{
			Level:   LogWarn,
			Action:  ActionConfig,
			Message: fmt.Sprintf(T.InvalidIPMode, cfg.IPMode),
		})
		cfg.IPMode = "BOTH"
	}

	if len(errs) > 0 {
		return fmt.Errorf("Config-Fehler: %s", strings.Join(errs, ", "))
	}

	return nil
}

func validateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("domain is empty")
	}

	if len(domain) > 253 {
		return fmt.Errorf("domain too long: %d chars (max 253)", len(domain))
	}

	if !domainRegex.MatchString(domain) {
		return fmt.Errorf("invalid domain format: %s", domain)
	}

	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if len(label) > 63 {
			return fmt.Errorf("label '%s' too long: %d chars (max 63)", label, len(label))
		}
		if !labelRegex.MatchString(label) {
			return fmt.Errorf("invalid label: %s", label)
		}
	}

	return nil
}
