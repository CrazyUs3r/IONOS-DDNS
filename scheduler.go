// Package main
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

	forced := firstRun || forceNextUpdate.Swap(false)

	debugLog("SCHEDULER", "", fmt.Sprintf(T.SchedulerStarted, firstRun))

	baseTimeout := BaseUpdateTimeout
	perDomainTimeout := time.Duration(len(cfg.DomainConfigs)) * PerDomainTimeout
	buffer := UpdateBufferTimeout
	totalTimeout := min(max(baseTimeout+perDomainTimeout+buffer, MinUpdateTimeout), MaxUpdateTimeout)

	debugLog("SCHEDULER", "", fmt.Sprintf(T.ContextTimeoutForDomains, totalTimeout, len(cfg.DomainConfigs)))

	ctx, cancel := context.WithTimeout(shutdownCtx, totalTimeout)
	defer cancel()

	type ipPair struct{ v4, v6 string }
	ips, err := doSingleflight(ctx, &ipLoadGroup, "current_ips", func() (ipPair, error) {
		v4, v6, err := fetchCurrentIPs(ctx)
		return ipPair{v4: v4, v6: v6}, err
	})

	if err != nil {
		lastOk.Store(false)
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: fmt.Sprintf(T.IPFetchFailed, err),
		})
		return
	}
	currentIPv4, currentIPv6 := ips.v4, ips.v6

	zonesByProvider, err := loadZonesWithCache(ctx, forced)
	if err != nil {
		lastOk.Store(false)
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: T.NoZones,
			Error:   fmt.Errorf("%s: %w", T.ZoneLoadingFailed, err),
		})
		return
	}

	for i := range cfg.DomainConfigs {
		providerKey := string(cfg.DomainConfigs[i].Provider)
		zones, exists := zonesByProvider[providerKey]
		if !exists || len(zones) == 0 {
			log(LogContext{
				Level:   LogWarn,
				Action:  ActionZone,
				Domain:  cfg.DomainConfigs[i].FQDN,
				Message: fmt.Sprintf(T.ProviderReturnedNoZonesCheckAPIKey, providerKey),
			})
		}
	}

	cache, err := loadRecordsWithCache(ctx, zonesByProvider, forced)
	if err != nil {
		lastOk.Store(false)
		debugLog("CACHE", "", fmt.Sprintf(T.CacheLoadFailed, err))
		return
	}

	for i := range cfg.DomainConfigs {
		if cfg.DomainConfigs[i].Provider == ProviderIPv64 {
			if err := ensureIPv64DomainsFresh(ctx, &cfg.DomainConfigs[i], forced); err != nil {
				debugLog("CACHE", "", fmt.Sprintf(T.IPv64CacheError, err))
			}
			break
		}
	}

	saveCachesToDisk(zonesByProvider, cache)

	if firstRun {
		printGroupedDomains()
		printInfrastructure(ctx, zonesByProvider)
	}

	successCount := processDomains(ctx, zonesByProvider, cache, currentIPv4, currentIPv6)
	debugLog("SCHEDULER", "", fmt.Sprintf(T.SchedulerCompleted, successCount))
	runCleanupIfNeeded(ctx, zonesByProvider, cache)
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
		debugLog("SCHEDULER", "", fmt.Sprintf(T.UsingZoneCacheAge, cacheAge.Round(time.Second)))

		zoneCacheMutex.RLock()
		zones := cachedZones
		zoneCacheMutex.RUnlock()

		return zones, nil
	}

	switch {
	case forceRefresh:
		debugLog("SCHEDULER", "", T.ForcedRefreshLoadZones)
	case !hasCachedZones:
		debugLog("SCHEDULER", "", T.NoZoneCacheInitialLoad)
	default:
		debugLog("SCHEDULER", "", fmt.Sprintf(T.ZoneCacheTooOldReload, cacheAge.Round(time.Second)))
	}

	if !forceRefresh && !hasCachedZones {
		if zonesFromDisk, err := loadZonesFromDiskCache(); err == nil && len(zonesFromDisk) > 0 {
			debugLog("SCHEDULER", "", T.ZonesLoadedFromDiskNoAPICall)

			zoneCacheMutex.Lock()
			cachedZones = zonesFromDisk
			lastZoneLoad = time.Now().Local()
			zoneCacheMutex.Unlock()

			return zonesFromDisk, nil
		}
	}

	zonesByProvider, err := doSingleflight(ctx, &zonesLoadGroup, "zones_api", func() (map[string][]Zone, error) {
		return loadAllProviderZones(ctx)
	})

	if err != nil {
		debugLog("SCHEDULER", "", fmt.Sprintf(T.ZoneAPILoadFailed, err))
		debugLog("SCHEDULER", "", T.TryingDiskCacheFallback)

		zonesByProvider, err = loadZonesFromDiskCache()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", T.APIAndDiskCacheFailed, err)
		}
		debugLog("SCHEDULER", "", T.ZonesLoadedFromDisk)
	} else {
		debugLog("SCHEDULER", "", T.ZonesLoadedFromAPI)
	}

	zoneCacheMutex.Lock()
	cachedZones = zonesByProvider
	lastZoneLoad = time.Now().Local()
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
		debugLog("SCHEDULER", "", fmt.Sprintf(T.UsingRecordCacheAge, cacheAge.Round(time.Second)))

		zoneCacheMutex.RLock()
		cache := cachedRecords
		zoneCacheMutex.RUnlock()

		return cache, nil
	}

	switch {
	case forceRefresh:
		debugLog("SCHEDULER", "", T.ForcedRefreshLoadRecords)
	case !hasCachedRecords:
		debugLog("SCHEDULER", "", T.NoRecordCacheInitialLoad)
	default:
		debugLog("SCHEDULER", "", fmt.Sprintf(T.RecordCacheTooOldReload, cacheAge.Round(time.Second)))
	}

	if !forceRefresh && !hasCachedRecords {
		if cacheFromDisk, err := loadRecordCacheFromDisk(zonesByProvider); err == nil && cacheFromDisk != nil {
			debugLog("SCHEDULER", "", T.RecordCacheLoadedFromDiskNoAPICall)

			zoneCacheMutex.Lock()
			cachedRecords = cacheFromDisk
			lastRecordLoad = time.Now().Local()
			zoneCacheMutex.Unlock()

			return cacheFromDisk, nil
		}
	}

	cache, err := doSingleflight(ctx, &recordsLoadGroup, "records_api", func() (*ZoneRecordCache, error) {
		return loadZoneCache(ctx, zonesByProvider)
	})

	if err != nil {
		debugLog("CACHE", "", fmt.Sprintf(T.RecordCacheError, err))
		debugLog("CACHE", "", T.TryingLoadRecordCacheFromDisk)

		cache, err = loadRecordCacheFromDisk(zonesByProvider)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", T.RecordCacheCouldNotBeLoaded, err)
		}
		debugLog("CACHE", "", T.RecordCacheLoadedFromDisk)
	} else {
		debugLog("CACHE", "", T.RecordsLoadedSuccessfully)
	}

	zoneCacheMutex.Lock()
	cachedRecords = cache
	lastRecordLoad = time.Now().Local()
	zoneCacheMutex.Unlock()

	return cache, nil
}

// ============================================================================
// CACHE ZU DISK SPEICHERN
// ============================================================================
func saveCachesToDisk(zonesByProvider map[string][]Zone, cache *ZoneRecordCache) {
	zoneCacheMutex.RLock()
	zoneLoadTs := lastZoneLoad
	recordLoadTs := lastRecordLoad
	zoneCacheMutex.RUnlock()

	diskPersistMutex.Lock()
	needsPersist := zoneLoadTs.After(lastDiskPersistZone) || recordLoadTs.After(lastDiskPersistRecord)
	if !needsPersist {
		diskPersistMutex.Unlock()
		debugLog("CACHE", "", T.DiskCachePersistSkipped)
		return
	}
	diskPersistMutex.Unlock()

	cacheWriteMutex.Lock()
	defer cacheWriteMutex.Unlock()

	savedZone := false
	savedRecord := false

	for providerStr, zones := range zonesByProvider {
		if len(zones) == 0 || cache == nil {
			continue
		}

		pType := ProviderType(providerStr)

		switch pType {
		case ProviderIONOS:
			if err := saveIONOSCacheToFile(zones, cache); err != nil {
				debugLog("CACHE", "", fmt.Sprintf(T.IonosCacheSaveFailed, err))
			} else {
				savedZone = true
				savedRecord = true
			}

		case ProviderCloudflare:
			if err := saveCloudflareCacheToFile(zones, cache); err != nil {
				debugLog("CACHE", "", fmt.Sprintf(T.CloudflareCacheSaveFailed, err))
			} else {
				savedZone = true
				savedRecord = true
			}

		case ProviderIPv64:
			if err := saveIPv64Cache(); err != nil {
				debugLog("CACHE", "", fmt.Sprintf("⚠️ IPv64 cache save failed: %v", err))
			} else {
				savedZone = true
				savedRecord = true
			}

		}
	}

	if savedZone || savedRecord {
		diskPersistMutex.Lock()
		if savedZone {
			lastDiskPersistZone = zoneLoadTs
		}
		if savedRecord {
			lastDiskPersistRecord = recordLoadTs
		}
		diskPersistMutex.Unlock()
	}
}

// ============================================================================
// CLEANUP NUR WENN NÖTIG
// ============================================================================
func runCleanupIfNeeded(ctx context.Context, zonesByProvider map[string][]Zone, cache *ZoneRecordCache) {
	timeSinceLastCleanup := time.Since(lastCleanup)

	if timeSinceLastCleanup < CleanupInterval {
		debugLog("MAINTENANCE", "", fmt.Sprintf(T.CleanupSkippedLastRun, timeSinceLastCleanup.Round(time.Minute)))
		return
	}

	debugLog("MAINTENANCE", "", fmt.Sprintf(T.CleanupStartingLastRun, timeSinceLastCleanup.Round(time.Minute)))
	lastCleanup = time.Now().Local()

	for providerStr, zones := range zonesByProvider {
		pType := ProviderType(providerStr)

		switch pType {
		case ProviderIONOS:
			cleanupIONOSRecords(ctx, zones, cache)

		case ProviderCloudflare:
			cleanupCloudflareRecords(ctx, zones, cache)

		case ProviderIPv64:
			var ipv64Config *DomainConfig
			for i := range cfg.DomainConfigs {
				if cfg.DomainConfigs[i].Provider == ProviderIPv64 {
					ipv64Config = &cfg.DomainConfigs[i]
					break
				}
			}
			if ipv64Config != nil {
				debugLog("MAINTENANCE", "", T.CheckingIPv64OrphanedRecords)
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
	seen := make(map[ProviderType]bool)

	for i := range cfg.DomainConfigs {
		provider := cfg.DomainConfigs[i].Provider
		if seen[provider] {
			continue
		}
		seen[provider] = true

		switch provider {
		case ProviderIONOS:
			if zones, _, err := loadIONOSCacheFromFile(); err == nil && len(zones) > 0 {
				zonesByProvider[string(ProviderIONOS)] = zones
				debugLog("CACHE", "", fmt.Sprintf(T.IonosZonesLoadedFromDisk, len(zones)))
			}
		case ProviderCloudflare:
			if zones, _, err := loadCloudflareCacheFromFile(); err == nil && len(zones) > 0 {
				zonesByProvider[string(ProviderCloudflare)] = zones
				debugLog("CACHE", "", fmt.Sprintf(T.CloudflareZonesLoadedFromDisk, len(zones)))
			}
		case ProviderIPv64:
			if err := loadIPv64CacheFromDisk(); err == nil {
				providerCache.RLock()
				zones := make([]Zone, 0, len(providerCache.ipv64Records))
				for domainName := range providerCache.ipv64Records {
					zones = append(zones, Zone{ID: domainName, Name: domainName})
				}
				providerCache.RUnlock()
				if len(zones) > 0 {
					zonesByProvider[string(ProviderIPv64)] = zones
					debugLog("CACHE", "", fmt.Sprintf(T.IPv64ZonesLoadedFromDisk, len(zones)))
				}
			}
		}
	}

	if len(zonesByProvider) == 0 {
		return nil, fmt.Errorf("%s", T.NoProviderCacheOnDiskFound)
	}

	return zonesByProvider, nil
}

func loadRecordCacheFromDisk(zonesByProvider map[string][]Zone) (*ZoneRecordCache, error) {
	cache := NewZoneRecordCache()
	loadedAny := false

	for providerStr, zones := range zonesByProvider {
		pType := ProviderType(providerStr)

		switch pType {
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

		}
	}

	if !loadedAny {
		return nil, fmt.Errorf("%s", T.NoRecordCachesFound)
	}

	return cache, nil
}
