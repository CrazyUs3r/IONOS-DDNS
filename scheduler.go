package main

import (
	"context"
	"fmt"
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

	for providerStr, zones := range zonesByProvider {
		if ProviderType(providerStr) == ProviderIONOS {
			cleanupOldRecords(ctx, zones, cache)
			break
		}
	}

	successCount := processDomains(ctx, zonesByProvider, cache, currentIPv4, currentIPv6)

	debugLog("SCHEDULER", "", fmt.Sprintf(T.SchedulerCompleted, successCount))
}
