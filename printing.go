// Package main
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

	byProvider := make(map[ProviderType][]string)
	for _, dc := range cfg.DomainConfigs {
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
	fmt.Println("\n" + T.InfraHeading)

	pTypes := make([]string, 0, len(zonesByProvider))
	for p := range zonesByProvider {
		pTypes = append(pTypes, p)
	}
	sort.Strings(pTypes)

	for _, pt := range pTypes {
		zones := zonesByProvider[pt]
		fmt.Printf("\n📦 Provider: %s (%d zones)\n", pt, len(zones))

		var dc *DomainConfig
		for i := range cfg.DomainConfigs {
			if string(cfg.DomainConfigs[i].Provider) == pt {
				dc = &cfg.DomainConfigs[i]
				break
			}
		}

		for _, z := range zones {
			fmt.Printf("\n🌐 Zone: %s\n", z.Name)
			var records []Record

			switch ProviderType(pt) {
			case ProviderIPv64:
				providerCache.RLock()
				if data, ok := providerCache.ipv64Records[z.Name]; ok {
					for _, ir := range data.Records {
						name := z.Name
						if ir.Praefix != "" {
							name = ir.Praefix + "." + z.Name
						}
						records = append(records, Record{
							Name:    name,
							Type:    ir.Type,
							Content: ir.Content,
						})
					}
				}
				providerCache.RUnlock()

			case ProviderCloudflare:
				if dc != nil {
					records, _ = loadCloudflareRecords(ctx, dc, z.ID)
				}

			default:
				if dc != nil {
					data, _ := ionosAPI(ctx, dc, MethodGET, ionosBaseURL+"/"+z.ID, nil)
					var detail struct{ Records []Record }
					_ = json.Unmarshal(data, &detail)
					records = detail.Records
				}
			}

			var relevant []Record
			for _, r := range records {
				if r.Type == "A" || r.Type == "AAAA" || r.Type == "CNAME" {
					relevant = append(relevant, r)
				}
			}

			sort.Slice(relevant, func(i, j int) bool { return relevant[i].Name < relevant[j].Name })

			if len(relevant) == 0 {
				fmt.Printf("   └─ ⚠️ Keine relevanten Records gefunden\n")
				continue
			}

			for i, r := range relevant {
				char := "├"
				if i == len(relevant)-1 {
					char = "└"
				}
				fmt.Printf("   %s─ %-35s [%-5s] -> %s\n", char, r.Name, r.Type, r.Content)
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

	providerCounts := make(map[ProviderType]int)
	for _, dc := range cfg.DomainConfigs {
		providerCounts[dc.Provider]++
	}

	for provider, count := range providerCounts {
		debugLog("CONFIG", "", fmt.Sprintf("Provider: %s (%d domains)", provider, count))
	}

	debugLog("CONFIG", "", fmt.Sprintf("%s: %ds", T.ConfigInterval, cfg.Interval))
	debugLog("CONFIG", "", fmt.Sprintf("%s: %s", T.ConfigIPMode, cfg.IPMode))
	debugLog("CONFIG", "", fmt.Sprintf("%s: %s", T.ConfigInterface, cfg.IfaceName))
	debugLog("CONFIG", "", fmt.Sprintf("%s: %s", T.ConfigHealthPort, cfg.HealthPort))
	debugLog("CONFIG", "", fmt.Sprintf("%s: %v", T.ConfigDryRun, cfg.DryRun))
	debugLog("CONFIG", "", fmt.Sprintf("%s: %s", T.ConfigLogDir, cfg.LogDir))
	debugLog("CONFIG", "", fmt.Sprintf("%s: %s", T.ConfigLanguage, cfg.Lang))
	debugLog("CONFIG", "", "===================================")
}
