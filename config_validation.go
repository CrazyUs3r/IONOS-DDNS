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
	if len(cfg.DomainConfigs) == 0 {
		return fmt.Errorf("%s", T.NoDomainsConfigured)
	}

	for i, dc := range cfg.DomainConfigs {
		if err := validateDomain(dc.FQDN); err != nil {
			return fmt.Errorf(T.DomainContext, i, dc.FQDN, err.Error())
		}

		switch dc.Provider {
		case ProviderIONOS:
			if dc.APIPrefix == "" || dc.APISecret == "" {
				return fmt.Errorf(T.IonosAPIRequired, dc.FQDN)
			}
		case ProviderIPv64:
			if dc.IPv64Token == "" {
				return fmt.Errorf(T.Ipv64TokenRequired, dc.FQDN)
			}
		case ProviderCloudflare:
			if dc.CFToken == "" && (dc.CFEmail == "" || dc.CFSecret == "") {
				return fmt.Errorf(T.CloudflareAuthRequired, dc.FQDN)
			}
		case ProviderHetzner, ProviderHetznerCloud:
			if hetznerToken(&dc) == "" {
				return fmt.Errorf(T.HetznerAuthRequired, dc.FQDN)
			}
		default:
			return fmt.Errorf(T.UnknownProvider, dc.FQDN, dc.Provider)
		}
	}

	return nil
}

func validateConfig() error {
	var errs []string

	if len(cfg.DomainConfigs) == 0 {
		errs = append(errs, T.NoDomainsConfigured)
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
		return fmt.Errorf(T.ConfigErrorPrefix, strings.Join(errs, ", "))
	}

	return nil
}

func validateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("%s", T.DomainIsEmpty)
	}

	if len(domain) > 253 {
		return fmt.Errorf(T.DomainTooLong, len(domain))
	}

	if !domainRegex.MatchString(domain) {
		return fmt.Errorf(T.InvalidDomainFormat, domain)
	}

	for label := range strings.SplitSeq(domain, ".") {
		if len(label) > 63 {
			return fmt.Errorf(T.LabelTooLong, label, len(label))
		}
		if !labelRegex.MatchString(label) {
			return fmt.Errorf(T.InvalidLabel, label)
		}
	}

	return nil
}
