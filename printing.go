package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ============================================================================
// PRINTING
// ============================================================================

func printGroupedDomains() {
	fmt.Printf("\n🚀  %s [%s] (%s: %s) [Multi-Provider]:\n",
		T.ServiceStarted, cfg.Lang, T.Mode, cfg.IPMode)

	if len(cfg.DomainConfigs) == 0 {
		fmt.Println("\n⚠️  " + T.NoDomains)
		return
	}

	// Gruppiere nach Provider
	byProvider := make(map[ProviderType][]string)
	for _, dc := range cfg.DomainConfigs {
		byProvider[dc.Provider] = append(byProvider[dc.Provider], dc.FQDN)
	}

	// Sortiere Provider-Namen
	providers := make([]ProviderType, 0, len(byProvider))
	for p := range byProvider {
		providers = append(providers, p)
	}
	sort.Slice(providers, func(i, j int) bool {
		return string(providers[i]) < string(providers[j])
	})

	// Ausgabe
	for _, provider := range providers {
		domains := byProvider[provider]
		sort.Strings(domains)

		fmt.Printf("\n📦 %s (%d %s)\n", provider, len(domains),
			func() string {
				if len(domains) == 1 {
					return "domain"
				}
				return "domains"
			}())

		for i, domain := range domains {
			char := "├"
			if i == len(domains)-1 {
				char = "└"
			}
			fmt.Printf("   %s─ 🌐 %s\n", char, domain)
		}
	}

	fmt.Println("\n" + strings.Repeat("-", 40))
}

func printInfrastructure(ctx context.Context, zonesByProvider map[string][]Zone) {
	fmt.Println("\n" + T.InfraHeading)

	for providerStr, zones := range zonesByProvider {
		provider := ProviderType(providerStr)

		fmt.Printf("\n📦 Provider: %s (%d zones)\n", provider, len(zones))

		for _, z := range zones {
			fmt.Printf("\n🌐 %s: %s\n", T.ZoneLabel, z.Name)

			if provider == ProviderIPv64 {
				fmt.Println("   ├─ IPv64 Domain (dynamische IP-Updates)")
				continue
			}

			// Finde passende DomainConfig
			var dc *DomainConfig
			for i := range cfg.DomainConfigs {
				if cfg.DomainConfigs[i].Provider == provider {
					dc = &cfg.DomainConfigs[i]
					break
				}
			}

			if dc == nil {
				continue
			}

			var records []Record
			if provider == ProviderCloudflare {
				records, _ = loadCloudflareRecords(ctx, dc, z.ID)
			} else {
				data, _ := ionosAPI(ctx, dc, "GET", ionosBaseURL+"/"+z.ID, nil)
				var detail struct{ Records []Record }
				_ = json.Unmarshal(data, &detail)
				records = detail.Records
			}

			var relevant []Record
			for _, r := range records {
				if r.Type == "A" || r.Type == "AAAA" || r.Type == "CNAME" {
					relevant = append(relevant, r)
				}
			}
			sort.Slice(relevant, func(i, j int) bool { return relevant[i].Name < relevant[j].Name })
			for _, r := range relevant {
				fmt.Printf("   ├─ %-35s [%-5s] -> %s\n", r.Name, r.Type, r.Content)
			}
		}
	}
	fmt.Println("\n" + strings.Repeat("-", 40))
}

func logHTTPClientStats() {
	if !cfg.DebugEnabled {
		return
	}

	debugLog("CONFIG", "", "========== "+T.ConfigHeading+" ==========")

	// Provider-Übersicht
	providerCounts := make(map[ProviderType]int)
	for _, dc := range cfg.DomainConfigs {
		providerCounts[dc.Provider]++
	}

	for provider, count := range providerCounts {
		debugLog("CONFIG", "", fmt.Sprintf("Provider: %s (%d domains)", provider, count))
	}

	debugLog("CONFIG", "", fmt.Sprintf("%s: %ds", T.ConfigInterval, cfg.Interval))
	debugLog("CONFIG", "", fmt.Sprintf("%s: %s", T.ConfigIpMode, cfg.IPMode))
	debugLog("CONFIG", "", fmt.Sprintf("%s: %s", T.ConfigInterface, cfg.IfaceName))
	debugLog("CONFIG", "", fmt.Sprintf("%s: %s", T.ConfigHealthPort, cfg.HealthPort))
	debugLog("CONFIG", "", fmt.Sprintf("%s: %v", T.ConfigDryRun, cfg.DryRun))
	debugLog("CONFIG", "", fmt.Sprintf("%s: %s", T.ConfigLogDir, cfg.LogDir))
	debugLog("CONFIG", "", fmt.Sprintf("%s: %s", T.ConfigLanguage, cfg.Lang))
	debugLog("CONFIG", "", "===================================")
}
