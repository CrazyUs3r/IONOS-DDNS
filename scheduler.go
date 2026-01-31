package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// ============================================================================
// UPDATE ORCHESTRATION
// ============================================================================

func runUpdate(firstRun bool) {
	activeUpdates.Add(1)
	defer activeUpdates.Add(-1)
	debugLog("SCHEDULER", "", fmt.Sprintf(T.SchedulerStarted, firstRun))

	baseTimeout := BaseUpdateTimeout
	perDomainTimeout := time.Duration(len(cfg.DomainConfigs)) * PerDomainTimeout
	buffer := UpdateBufferTimeout
	totalTimeout := baseTimeout + perDomainTimeout + buffer

	if totalTimeout < MinUpdateTimeout {
		totalTimeout = MinUpdateTimeout
	}
	if totalTimeout > MaxUpdateTimeout {
		totalTimeout = MaxUpdateTimeout
	}

	debugLog("SCHEDULER", "", fmt.Sprintf("Context Timeout: %v (für %d Domains)", totalTimeout, len(cfg.DomainConfigs)))

	ctx, cancel := context.WithTimeout(shutdownCtx, totalTimeout)
	defer cancel()

	currentIPv4, currentIPv6, err := fetchCurrentIPs(ctx)
	if err != nil {
		lastOk.Store(false)
		return
	}

	zonesByProvider, err := loadAllProviderZones(ctx)
	if err != nil {
		lastOk.Store(false)
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: T.NoZones,
			Error:   err,
		})
		return
	}

	if firstRun {
		printGroupedDomains()
		printInfrastructure(ctx, zonesByProvider)
	}

	cache, err := loadZoneCache(ctx, zonesByProvider)
	if err != nil {
		lastOk.Store(false)
		return
	}

	for i := range cfg.DomainConfigs {
		if cfg.DomainConfigs[i].Provider == ProviderIPv64 {
			if err := loadAllIPv64Domains(ctx, &cfg.DomainConfigs[i]); err != nil {
				debugLog("CACHE", "", fmt.Sprintf("IPv64 Cache-Fehler: %v", err))
			}
			break
		}
	}

	// Records bereinigen (IONOS & IPv64)
	for providerStr, zones := range zonesByProvider {
		pType := ProviderType(providerStr)

		if pType == ProviderIONOS {
			cleanupOldRecords(ctx, zones, cache)
		} else if pType == ProviderIPv64 {
			// Für IPv64 sammeln wir die aktuell konfigurierten FQDNs
			ipv64Configured := make(map[string]bool)
			var ipv64Config *DomainConfig

			for i := range cfg.DomainConfigs {
				if cfg.DomainConfigs[i].Provider == ProviderIPv64 {
					name := strings.ToLower(strings.TrimSuffix(cfg.DomainConfigs[i].FQDN, "."))
					ipv64Configured[name] = true
					ipv64Config = &cfg.DomainConfigs[i]
				}
			}

			// Cleanup nur starten, wenn wir eine gültige Config (API-Key) gefunden haben
			if ipv64Config != nil {
				debugLog("MAINTENANCE", "", "Prüfe IPv64 auf verwaiste Records...")
				cleanupIPv64Records(ctx)
			}
		}
	}

	successCount := processDomains(ctx, zonesByProvider, cache, currentIPv4, currentIPv6)

	debugLog("SCHEDULER", "", fmt.Sprintf(T.SchedulerCompleted, successCount))
}