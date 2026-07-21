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

	fmt.Printf("\n🚀  %s [%s] (%s: %s) [%s]:\n",
		phrases().ServiceStarted, lang, phrases().Mode, ipMode, phrases().MultiProvider)

	if len(domainConfigs) == 0 {
		fmt.Println("\n⚠️  " + phrases().NoDomains)

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

		domainLabel := localizedCountLabel(len(domains), phrases().DomainSingular, phrases().DomainPlural)
		fmt.Printf("\n📦 %s (%d %s)\n", provider, len(domains), domainLabel)

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

func printInfrastructure(ctx context.Context, zonesByProvider map[string][]Zone, cache *ZoneRecordCache) {
	domainConfigs := snapshotDomainConfigsForPrinting()

	fmt.Println("\n" + phrases().InfraHeading)

	providerTypes := sortedProviderTypes(zonesByProvider)
	for _, pt := range providerTypes {
		printProviderInfrastructure(ctx, ProviderType(pt), zonesByProvider[pt], domainConfigs, cache)
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

func localizedCountLabel(count int, singular, plural string) string {
	if count == 1 {
		return singular
	}

	return plural
}

func printProviderInfrastructure(ctx context.Context, provider ProviderType, zones []Zone, domainConfigs []DomainConfig, cache *ZoneRecordCache) {
	fmt.Printf("\n📦 "+phrases().ProviderZonesFormat+"\n", provider, len(zones))

	dc := findProviderConfigForPrinting(provider, domainConfigs)

	for _, z := range zones {
		printZoneInfrastructure(ctx, provider, z, dc, cache)
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

func printZoneInfrastructure(ctx context.Context, provider ProviderType, z Zone, dc *DomainConfig, cache *ZoneRecordCache) {
	fmt.Printf("\n🌐 "+phrases().ZoneFormat+"\n", z.Name)

	records, err := loadInfrastructureRecords(ctx, provider, z, dc, cache)
	if err != nil {
		debugLog("DEBUG", z.Name, err.Error())
		fmt.Printf("   └─ ⚠️ %s\n", err)

		return
	}

	relevant := filterRelevantInfrastructureRecords(records)

	sort.Slice(relevant, func(i, j int) bool {
		return relevant[i].Name < relevant[j].Name
	})

	if len(relevant) == 0 {
		fmt.Printf("   └─ ⚠️ %s\n", phrases().NoRelevantRecordsFound)

		return
	}

	printRelevantInfrastructureRecords(relevant)
}

func loadInfrastructureRecords(ctx context.Context, provider ProviderType, z Zone, dc *DomainConfig, cache *ZoneRecordCache) ([]Record, error) {
	if records, exists := cachedInfrastructureRecords(
		cache,
		z.ID,
	); exists {
		return records, nil
	}

	if provider == ProviderIPv64 {
		return loadIPv64InfrastructureRecords(z)
	}

	if dc == nil {
		return nil, fmt.Errorf(
			phrases().MissingDomainConfigurationFormat,
			provider,
		)
	}

	return loadInfrastructureRecordsFromProvider(
		ctx,
		provider,
		z.ID,
		dc,
	)
}

func cachedInfrastructureRecords(
	cache *ZoneRecordCache,
	zoneID string,
) ([]Record, bool) {
	if cache == nil {
		return nil, false
	}

	return cache.Get(zoneID)
}

func loadInfrastructureRecordsFromProvider(
	ctx context.Context,
	provider ProviderType,
	zoneID string,
	dc *DomainConfig,
) ([]Record, error) {
	switch provider {
	case ProviderIONOS:
		return loadIonosInfrastructureRecords(ctx, dc, zoneID)

	case ProviderCloudflare:
		return loadCloudflareRecords(ctx, dc, zoneID)

	case ProviderHetzner:
		return loadHetznerDNSZoneRecords(ctx, dc, zoneID)

	case ProviderHetznerCloud:
		return loadHetznerCloudZoneRecords(ctx, dc, zoneID)

	case ProviderFebas:
		return loadFebasZoneRecords(ctx, Zone{ID: zoneID, Name: dc.FQDN})

	case ProviderDNScale:
		return loadDNScaleInfrastructureRecords(ctx, dc, zoneID)

	default:
		return nil, fmt.Errorf(phrases().UnsupportedInfrastructureProviderFormat, provider)
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
	cfgMu.RUnlock()

	if !debugEnabled {
		return
	}

	cfgMu.RLock()
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

	debugLog("CONFIG", "", "========== "+phrases().ConfigHeading+" ==========")

	providerCounts := make(map[ProviderType]int)
	for _, dc := range domainConfigs {
		providerCounts[dc.Provider]++
	}

	for provider, count := range providerCounts {
		domainLabel := localizedCountLabel(count, phrases().DomainSingular, phrases().DomainPlural)
		debugLog("CONFIG", "", fmt.Sprintf(
			phrases().ConfigProviderCount,
			phrases().ProviderLabel, provider, count, domainLabel,
		))
	}

	debugLog("CONFIG", "", fmt.Sprintf("%s: %ds", phrases().ConfigInterval, interval))
	debugLog("CONFIG", "", fmt.Sprintf("%s: %s", phrases().ConfigIPMode, ipMode))
	debugLog("CONFIG", "", fmt.Sprintf("%s: %s", phrases().ConfigInterface, ifaceName))
	debugLog("CONFIG", "", fmt.Sprintf("%s: %s", phrases().ConfigHealthPort, healthPort))
	debugLog("CONFIG", "", fmt.Sprintf("%s: %v", phrases().ConfigDryRun, dryRun))
	debugLog("CONFIG", "", fmt.Sprintf("%s: %s", phrases().ConfigLogDir, logDir))
	debugLog("CONFIG", "", fmt.Sprintf("%s: %s", phrases().ConfigLanguage, lang))
	debugLog("CONFIG", "", "===================================")
}
