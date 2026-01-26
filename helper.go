package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
)

// ============================================================================
// HELPERS
// ============================================================================

func (s *SafeErrorMsg) Set(msg string) {
	s.Lock()
	defer s.Unlock()
	s.msg = msg
}

func (s *SafeErrorMsg) Get() string {
	s.RLock()
	defer s.RUnlock()
	return s.msg
}

func actionCSS(a string) string {
	if c, ok := actionClass[a]; ok {
		return c
	}
	return "act-default"
}

func getClientIP(r *http.Request) string {
	// Default: true
	trustProxy := true

	if v := strings.TrimSpace(os.Getenv("TRUST_PROXY")); v != "" {
		trustProxy = strings.ToLower(v) != "false"
	}

	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			ips := strings.Split(xff, ",")
			if len(ips) > 0 {
				return strings.TrimSpace(ips[0])
			}
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return xri
		}
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func validateTriggerToken(r *http.Request) bool {
	token := r.Header.Get(TriggerTokenHeader)

	expectedToken := os.Getenv("TRIGGER_TOKEN")
	if expectedToken == "" {
		return true
	}

	return token == expectedToken
}

// ============================================================================
// DNS HELPERS
// ============================================================================

func recordNameFromFQDN(fqdn, zone string) string {
	if fqdn == zone {
		return "@"
	}

	suffix := "." + zone
	if strings.HasSuffix(fqdn, suffix) {
		return strings.TrimSuffix(fqdn, suffix)
	}

	return fqdn
}

func isNonRecoverableError(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		switch apiErr.StatusCode {
		case 401, 403, 404:
			return true
		}
	}
	return false
}

func loadZonesForDomainConfig(ctx context.Context, dc *DomainConfig) ([]Zone, error) {
	switch dc.Provider {
	case ProviderCloudflare:
		return loadCloudflareZones(ctx, dc)
	case ProviderIPv64:
		return loadIPv64Domains(ctx, dc)
	case ProviderIONOS:
		return loadIONOSZones(ctx, dc)
	default:
		return nil, fmt.Errorf("unknown provider: %s", dc.Provider)
	}
}

func loadIONOSZones(ctx context.Context, dc *DomainConfig) ([]Zone, error) {
	data, err := ionosAPI(ctx, dc, "GET", ionosBaseURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load ionos zones: %w", err)
	}

	var zones []Zone
	if err := json.Unmarshal(data, &zones); err != nil {
		return nil, fmt.Errorf("failed to parse ionos zones: %w", err)
	}

	return zones, nil
}

func loadAllProviderZones(ctx context.Context) (map[string][]Zone, error) {
	zonesByProvider := make(map[string][]Zone)

	providerConfigs := make(map[ProviderType]*DomainConfig)
	for i := range cfg.DomainConfigs {
		dc := &cfg.DomainConfigs[i]
		if _, exists := providerConfigs[dc.Provider]; !exists {
			providerConfigs[dc.Provider] = dc
		}
	}

	for provider, dc := range providerConfigs {
		zones, err := loadZonesForDomainConfig(ctx, dc)
		if err != nil {
			return nil, fmt.Errorf("failed to load zones for %s: %w", provider, err)
		}
		zonesByProvider[string(provider)] = zones

		debugLog("ZONE", "", fmt.Sprintf("✅ Loaded %d zones for %s", len(zones), provider))
	}

	return zonesByProvider, nil
}
