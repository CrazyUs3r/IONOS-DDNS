// Package main
package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// ============================================================================
// PRINTING
// ============================================================================
func printGroupedDomains() {
	cfgMu.RLock()
	lang := cfg.Lang
	ipMode := cfg.IPMode
	domainConfigs := make([]DomainConfig, len(cfg.DomainConfigs))
	copy(domainConfigs, cfg.DomainConfigs)
	cfgMu.RUnlock()

	fmt.Printf("\n🚀  %s [%s] (%s: %s) [Multi-Provider]:\n",
		T.ServiceStarted, lang, T.Mode, ipMode)

	if len(domainConfigs) == 0 {
		fmt.Println("\n⚠️  " + T.NoDomains)
		return
	}

	byProvider := make(map[ProviderType][]string)
	for _, dc := range domainConfigs {
		byProvider[dc.Provider] = append(byProvider[dc.Provider], dc.FQDN)
	}

	providers := make([]ProviderType, 0, len(byProvider))
	for p := range byProvider {
		providers = append(providers, p)
	}
	sort.Slice(providers, func(i, j int) bool {
		return string(providers[i]) < string(providers[j])
	})

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
	domainConfigs := snapshotDomainConfigsForPrinting()

	fmt.Println("\n" + T.InfraHeading)

	providerTypes := sortedProviderTypes(zonesByProvider)
	for _, pt := range providerTypes {
		printProviderInfrastructure(ctx, ProviderType(pt), zonesByProvider[pt], domainConfigs)
	}

	fmt.Println("\n" + strings.Repeat("-", 40))
}

func snapshotDomainConfigsForPrinting() []DomainConfig {
	cfgMu.RLock()
	defer cfgMu.RUnlock()

	domainConfigs := make([]DomainConfig, len(cfg.DomainConfigs))
	copy(domainConfigs, cfg.DomainConfigs)

	return domainConfigs
}

func sortedProviderTypes(zonesByProvider map[string][]Zone) []string {
	pTypes := make([]string, 0, len(zonesByProvider))
	for p := range zonesByProvider {
		pTypes = append(pTypes, p)
	}
	sort.Strings(pTypes)
	return pTypes
}

func printProviderInfrastructure(
	ctx context.Context,
	provider ProviderType,
	zones []Zone,
	domainConfigs []DomainConfig,
) {
	fmt.Printf("\n📦 Provider: %s (%d zones)\n", provider, len(zones))

	dc := findProviderConfigForPrinting(provider, domainConfigs)

	for _, z := range zones {
		printZoneInfrastructure(ctx, provider, z, dc)
	}
}

func findProviderConfigForPrinting(provider ProviderType, domainConfigs []DomainConfig) *DomainConfig {
	for i := range domainConfigs {
		if domainConfigs[i].Provider == provider {
			return &domainConfigs[i]
		}
	}
	return nil
}

func printZoneInfrastructure(
	ctx context.Context,
	provider ProviderType,
	z Zone,
	dc *DomainConfig,
) {
	fmt.Printf("\n🌐 Zone: %s\n", z.Name)

	records := loadInfrastructureRecords(ctx, provider, z, dc)
	relevant := filterRelevantInfrastructureRecords(records)

	sort.Slice(relevant, func(i, j int) bool {
		return relevant[i].Name < relevant[j].Name
	})

	if len(relevant) == 0 {
		fmt.Printf("   └─ ⚠️ Keine relevanten Records gefunden\n")
		return
	}

	printRelevantInfrastructureRecords(relevant)
}

func loadInfrastructureRecords(ctx context.Context, provider ProviderType, z Zone, dc *DomainConfig) []Record {
	switch provider {
	case ProviderIPv64:
		return loadIPv64InfrastructureRecords(z)
	case ProviderCloudflare:
		if dc == nil {
			return nil
		}
		records, _ := loadCloudflareRecords(ctx, dc, z.ID)
		return records
	case ProviderHetzner:
		if dc == nil {
			return nil
		}
		records, _ := loadHetznerDNSZoneRecords(ctx, dc, z.ID)
		return records
	case ProviderHetznerCloud:
		if dc == nil {
			return nil
		}
		records, _ := loadHetznerCloudZoneRecords(ctx, dc, z.ID)
		return records
	default: // IONOS
		if dc == nil {
			return nil
		}
		return loadIonosInfrastructureRecords(ctx, dc, z.ID)
	}
}

func filterRelevantInfrastructureRecords(records []Record) []Record {
	relevant := make([]Record, 0, len(records))
	for _, r := range records {
		if r.Type == RecordTypeA || r.Type == RecordTypeAAAA || r.Type == RecordTypeCNAME {
			relevant = append(relevant, r)
		}
	}
	return relevant
}

func printRelevantInfrastructureRecords(records []Record) {
	for i, r := range records {
		char := "├"
		if i == len(records)-1 {
			char = "└"
		}
		fmt.Printf("   %s─ %-35s [%-5s] -> %s\n", char, r.Name, r.Type, r.Content)
	}
}

func logHTTPClientStats() {
	cfgMu.RLock()
	debugEnabled := cfg.DebugEnabled
	domainConfigs := make([]DomainConfig, len(cfg.DomainConfigs))
	copy(domainConfigs, cfg.DomainConfigs)
	interval := cfg.Interval
	ipMode := cfg.IPMode
	ifaceName := cfg.IfaceName
	healthPort := cfg.HealthPort
	dryRun := cfg.DryRun
	logDir := cfg.LogDir
	lang := cfg.Lang
	cfgMu.RUnlock()

	if !debugEnabled {
		return
	}

	debugLog("CONFIG", "", "========== "+T.ConfigHeading+" ==========")

	providerCounts := make(map[ProviderType]int)
	for _, dc := range domainConfigs {
		providerCounts[dc.Provider]++
	}

	for provider, count := range providerCounts {
		debugLog("CONFIG", "", fmt.Sprintf("Provider: %s (%d domains)", provider, count))
	}

	debugLog("CONFIG", "", fmt.Sprintf("%s: %ds", T.ConfigInterval, interval))
	debugLog("CONFIG", "", fmt.Sprintf("%s: %s", T.ConfigIPMode, ipMode))
	debugLog("CONFIG", "", fmt.Sprintf("%s: %s", T.ConfigInterface, ifaceName))
	debugLog("CONFIG", "", fmt.Sprintf("%s: %s", T.ConfigHealthPort, healthPort))
	debugLog("CONFIG", "", fmt.Sprintf("%s: %v", T.ConfigDryRun, dryRun))
	debugLog("CONFIG", "", fmt.Sprintf("%s: %s", T.ConfigLogDir, logDir))
	debugLog("CONFIG", "", fmt.Sprintf("%s: %s", T.ConfigLanguage, lang))
	debugLog("CONFIG", "", "===================================")
}
