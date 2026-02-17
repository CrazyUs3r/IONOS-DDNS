// Package main
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

	zonesByProvider, err := loadZonesWithCache(ctx, firstRun)
	if err != nil {
		lastOk.Store(false)
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: T.NoZones,
			Error:   fmt.Errorf("Zone loading fehlgeschlagen: %w", err),
		})
		return
	}

	cache, err := loadRecordsWithCache(ctx, zonesByProvider, firstRun)
	if err != nil {
		lastOk.Store(false)
		debugLog("CACHE", "", fmt.Sprintf("❌ Konnte Record-Cache nicht laden: %v", err))
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

	saveCachesToDisk(zonesByProvider, cache)
	runCleanupIfNeeded(ctx, zonesByProvider, cache)

	if firstRun {
		printGroupedDomains()
		printInfrastructure(ctx, zonesByProvider)
	}

	successCount := processDomains(ctx, zonesByProvider, cache, currentIPv4, currentIPv6)

	debugLog("SCHEDULER", "", fmt.Sprintf(T.SchedulerCompleted, successCount))
}

// ============================================================================
// CACHE-FIRST ZONE LOADING
// ============================================================================
func loadZonesWithCache(ctx context.Context, forceRefresh bool) (map[string][]Zone, error) {
	zoneCacheMutex.RLock()
	cacheAge := time.Since(lastZoneLoad)
	hasCachedZones := len(cachedZones) > 0
	zoneCacheMutex.RUnlock()

	if !forceRefresh && hasCachedZones && cacheAge < ZoneCacheTTL {
		debugLog("SCHEDULER", "", fmt.Sprintf("✅ Nutze Zone-Cache (Alter: %v)", cacheAge.Round(time.Second)))

		zoneCacheMutex.RLock()
		zones := cachedZones
		zoneCacheMutex.RUnlock()

		return zones, nil
	}

	switch {
	case forceRefresh:
		debugLog("SCHEDULER", "", "🔄 Forced Refresh - lade Zones von API...")
	case !hasCachedZones:
		debugLog("SCHEDULER", "", "🔄 Kein Zone-Cache vorhanden - Initial Load...")
	default:
		debugLog("SCHEDULER", "", fmt.Sprintf("🔄 Zone-Cache ist alt (%v) - lade von API...", cacheAge.Round(time.Second)))
	}

	zonesByProvider, err := loadAllProviderZones(ctx)
	if err != nil {
		debugLog("SCHEDULER", "", fmt.Sprintf("⚠️ API-Fehler beim Laden der Zones: %v", err))
		debugLog("SCHEDULER", "", "📄 Versuche Fallback auf Disk-Cache...")

		zonesByProvider, err = loadZonesFromDiskCache()
		if err != nil {
			return nil, fmt.Errorf("API und Disk-Cache fehlgeschlagen: %w", err)
		}
		debugLog("SCHEDULER", "", "✅ Zones erfolgreich von Disk-Cache geladen")
	} else {
		debugLog("SCHEDULER", "", "✅ Zones erfolgreich von API geladen")
	}

	zoneCacheMutex.Lock()
	cachedZones = zonesByProvider
	lastZoneLoad = time.Now()
	zoneCacheMutex.Unlock()

	return zonesByProvider, nil
}

// ============================================================================
// CACHE-FIRST RECORD LOADING
// ============================================================================
func loadRecordsWithCache(ctx context.Context, zonesByProvider map[string][]Zone, forceRefresh bool) (*ZoneRecordCache, error) {
	zoneCacheMutex.RLock()
	cacheAge := time.Since(lastRecordLoad)
	hasCachedRecords := cachedRecords != nil
	zoneCacheMutex.RUnlock()

	if !forceRefresh && hasCachedRecords && cacheAge < RecordCacheTTL {
		debugLog("SCHEDULER", "", fmt.Sprintf("✅ Nutze Record-Cache (Alter: %v)", cacheAge.Round(time.Second)))

		zoneCacheMutex.RLock()
		cache := cachedRecords
		zoneCacheMutex.RUnlock()

		return cache, nil
	}

	switch {
	case forceRefresh:
		debugLog("SCHEDULER", "", "🔄 Forced Refresh - lade Records...")
	case !hasCachedRecords:
		debugLog("SCHEDULER", "", "🔄 Kein Record-Cache vorhanden - Initial Load...")
	default:
		debugLog("SCHEDULER", "", fmt.Sprintf("🔄 Record-Cache ist alt (%v) - lade Records...", cacheAge.Round(time.Second)))
	}

	cache, err := loadZoneCache(ctx, zonesByProvider)
	if err != nil {
		debugLog("CACHE", "", fmt.Sprintf("⚠️ Cache-Fehler: %v", err))
		debugLog("CACHE", "", "📄 Versuche Record-Cache von Disk zu laden...")

		cache, err = loadRecordCacheFromDisk(zonesByProvider)
		if err != nil {
			return nil, fmt.Errorf("Record-Cache konnte nicht geladen werden: %w", err)
		}
		debugLog("CACHE", "", "✅ Record-Cache erfolgreich von Disk geladen")
	} else {
		debugLog("CACHE", "", "✅ Records erfolgreich geladen")
	}

	zoneCacheMutex.Lock()
	cachedRecords = cache
	lastRecordLoad = time.Now()
	zoneCacheMutex.Unlock()

	return cache, nil
}

// ============================================================================
// CACHE ZU DISK SPEICHERN
// ============================================================================
func saveCachesToDisk(zonesByProvider map[string][]Zone, cache *ZoneRecordCache) {
	for providerStr, zones := range zonesByProvider {
		if len(zones) == 0 || cache == nil {
			continue
		}

		pType := ProviderType(providerStr)

		switch pType {
		case ProviderCloudflare:
			if err := saveCloudflareCacheToFile(zones, cache); err != nil {
				debugLog("CACHE", "", fmt.Sprintf("⚠️ Konnte Cloudflare Cache nicht speichern: %v", err))
			}

		case ProviderIONOS:
			if err := saveIONOSCacheToFile(zones, cache); err != nil {
				debugLog("CACHE", "", fmt.Sprintf("⚠️ Konnte IONOS Cache nicht speichern: %v", err))
			}
		}
	}
}

// ============================================================================
// CLEANUP NUR WENN NÖTIG
// ============================================================================
func runCleanupIfNeeded(ctx context.Context, zonesByProvider map[string][]Zone, cache *ZoneRecordCache) {
	timeSinceLastCleanup := time.Since(lastCleanup)

	if timeSinceLastCleanup < CleanupInterval {
		debugLog("MAINTENANCE", "", fmt.Sprintf("⏭️ Cleanup übersprungen (letzter Lauf vor %v)", timeSinceLastCleanup.Round(time.Minute)))
		return
	}

	debugLog("MAINTENANCE", "", fmt.Sprintf("🧹 Starte Cleanup (letzter Lauf vor %v)", timeSinceLastCleanup.Round(time.Minute)))
	lastCleanup = time.Now()

	for providerStr, zones := range zonesByProvider {
		pType := ProviderType(providerStr)

		switch pType {
		case ProviderIONOS:
			cleanupIONOSRecords(ctx, zones, cache)

		case ProviderCloudflare:
			cleanupCloudflareRecords(ctx, zones, cache)

		case ProviderIPv64:
			ipv64Configured := make(map[string]bool)
			var ipv64Config *DomainConfig

			for i := range cfg.DomainConfigs {
				if cfg.DomainConfigs[i].Provider == ProviderIPv64 {
					name := strings.ToLower(strings.TrimSuffix(cfg.DomainConfigs[i].FQDN, "."))
					ipv64Configured[name] = true
					ipv64Config = &cfg.DomainConfigs[i]
				}
			}
			if ipv64Config != nil {
				debugLog("MAINTENANCE", "", "Prüfe IPv64 auf verwaiste Records...")
				cleanupIPv64Records(ctx)
			}
		}
	}
}

// ============================================================================
// DISK CACHE FALLBACK
// ============================================================================
func loadZonesFromDiskCache() (map[string][]Zone, error) {
	zonesByProvider := make(map[string][]Zone)
	loadedAny := false

	for i := range cfg.DomainConfigs {
		if cfg.DomainConfigs[i].Provider == ProviderIPv64 {
			if err := loadIPv64CacheFromDisk(); err == nil {
				providerCache.RLock()
				zones := make([]Zone, 0, len(providerCache.ipv64Records))
				for domainName := range providerCache.ipv64Records {
					zones = append(zones, Zone{
						ID:   domainName,
						Name: domainName,
					})
				}
				providerCache.RUnlock()

				if len(zones) > 0 {
					zonesByProvider[string(ProviderIPv64)] = zones
					loadedAny = true
					debugLog("CACHE", "", fmt.Sprintf("📂 IPv64: %d zones von Disk geladen", len(zones)))
				}
			}
			break
		}
	}

	for i := range cfg.DomainConfigs {
		if cfg.DomainConfigs[i].Provider == ProviderCloudflare {
			zones, _, err := loadCloudflareCacheFromFile()
			if err == nil && len(zones) > 0 {
				zonesByProvider[string(ProviderCloudflare)] = zones
				loadedAny = true
				debugLog("CACHE", "", fmt.Sprintf("📂 Cloudflare: %d zones von Disk geladen", len(zones)))
			}
			break
		}
	}

	for i := range cfg.DomainConfigs {
		if cfg.DomainConfigs[i].Provider == ProviderIONOS {
			zones, _, err := loadIONOSCacheFromFile()
			if err == nil && len(zones) > 0 {
				zonesByProvider[string(ProviderIONOS)] = zones
				loadedAny = true
				debugLog("CACHE", "", fmt.Sprintf("📂 IONOS: %d zones von Disk geladen", len(zones)))
			}
			break
		}
	}

	if !loadedAny {
		return nil, fmt.Errorf("kein Provider-Cache auf Disk gefunden")
	}

	return zonesByProvider, nil
}

func loadRecordCacheFromDisk(zonesByProvider map[string][]Zone) (*ZoneRecordCache, error) {
	cache := NewZoneRecordCache()
	loadedAny := false

	for providerStr, zones := range zonesByProvider {
		pType := ProviderType(providerStr)

		switch pType {
		case ProviderIPv64:
			providerCache.RLock()
			for _, z := range zones {
				domain, ok := providerCache.ipv64Records[z.Name]
				if !ok {
					continue
				}

				records := make([]Record, 0, len(domain.Records))
				for _, rec := range domain.Records {
					records = append(records, Record{
						ID:      fmt.Sprintf("%d", rec.RecordID),
						Type:    rec.Type,
						Content: rec.Content,
					})
				}

				cache.Set(z.ID, records)
				loadedAny = true
			}
			providerCache.RUnlock()

		case ProviderCloudflare:
			_, recordCache, err := loadCloudflareCacheFromFile()
			if err == nil && recordCache != nil {
				for _, zone := range zones {
					if records, exists := recordCache.Get(zone.ID); exists {
						cache.Set(zone.ID, records)
						loadedAny = true
					}
				}
			}

		case ProviderIONOS:
			_, recordCache, err := loadIONOSCacheFromFile()
			if err == nil && recordCache != nil {
				for _, zone := range zones {
					if records, exists := recordCache.Get(zone.ID); exists {
						cache.Set(zone.ID, records)
						loadedAny = true
					}
				}
			}
		}
	}

	if !loadedAny {
		return nil, fmt.Errorf("keine Record-Caches gefunden")
	}

	return cache, nil
}
