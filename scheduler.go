// Package main
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
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

	domainConfigs := snapshotDomainConfigs()

	ctx, ipCtx, cancel, ipCancel := createRunUpdateContexts(len(domainConfigs))
	defer cancel()
	defer ipCancel()

	currentIPv4, currentIPv6, ok := resolveCurrentIPs(ipCtx, firstRun, forced)
	if !ok {
		return
	}

	zonesByProvider, ok := loadRunUpdateZones(ctx, forced)
	if !ok {
		return
	}

	logMissingProviderZones(zonesByProvider, domainConfigs)

	cache, ok := loadRunUpdateRecords(ctx, zonesByProvider, forced)
	if !ok {
		return
	}

	refreshIPv64DomainsIfNeeded(ctx, forced, domainConfigs)
	saveCachesToDisk(zonesByProvider, cache)

	if firstRun {
		printGroupedDomains()
		printInfrastructure(ctx, zonesByProvider)
	}

	successCount := processDomains(ctx, zonesByProvider, cache, currentIPv4, currentIPv6)
	debugLog("SCHEDULER", "", fmt.Sprintf(T.SchedulerCompleted, successCount))

	runCleanupIfNeeded(ctx, zonesByProvider, cache, domainConfigs)
}

func createRunUpdateContexts(domainCount int) (context.Context, context.Context, context.CancelFunc, context.CancelFunc) {
	baseTimeout := BaseUpdateTimeout
	perDomainTimeout := time.Duration(domainCount) * PerDomainTimeout
	buffer := UpdateBufferTimeout
	totalTimeout := min(max(baseTimeout+perDomainTimeout+buffer, MinUpdateTimeout), MaxUpdateTimeout)

	debugLog("SCHEDULER", "", fmt.Sprintf(T.ContextTimeoutForDomains, totalTimeout, domainCount))

	ctx, cancel := context.WithTimeout(shutdownCtx, totalTimeout)
	ipCtx, ipCancel := context.WithTimeout(shutdownCtx, 60*time.Second)

	return ctx, ipCtx, cancel, ipCancel
}

func resolveCurrentIPs(ipCtx context.Context, firstRun, forced bool) (string, string, bool) {
	type ipPair struct{ v4, v6 string }

	var (
		ips ipPair
		err error
	)

	if forced {
		v4, v6, fetchErr := fetchCurrentIPs(ipCtx)
		ips = ipPair{v4: v4, v6: v6}
		err = fetchErr
	} else {
		ips, err = doSingleflight(ipCtx, &ipLoadGroup, "current_ips", func() (ipPair, error) {
			v4, v6, err := fetchCurrentIPs(ipCtx)
			return ipPair{v4: v4, v6: v6}, err
		})
	}

	if err != nil {
		return handleCurrentIPsError(err, firstRun)
	}

	currentIPv4, currentIPv6 := ips.v4, ips.v6
	logChangedIPs(currentIPv4, currentIPv6)

	return currentIPv4, currentIPv6, true
}

func handleCurrentIPsError(err error, firstRun bool) (string, string, bool) {
	if !firstRun {
		lastOk.Store(false)
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: fmt.Sprintf(T.IPFetchFailed, err),
		})
		return "", "", false
	}

	fallbackV4, fallbackV6 := loadLastKnownIPs()
	if fallbackV4 == "" && fallbackV6 == "" {
		lastOk.Store(false)
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: fmt.Sprintf(T.IPFetchFailed, err),
		})
		return "", "", false
	}

	log(LogContext{
		Level:   LogWarn,
		Action:  ActionError,
		Message: fmt.Sprintf(T.IPFetchFailedFallback, err),
	})

	return fallbackV4, fallbackV6, true
}

func logChangedIPs(currentIPv4, currentIPv6 string) {
	lastV4, lastV6 := loadLastKnownIPs()

	if lastV4 != "" && currentIPv4 != "" && lastV4 != currentIPv4 {
		log(LogContext{
			Level:   LogInfo,
			Action:  ActionInfo,
			Message: fmt.Sprintf(T.IPv4Changed, lastV4, currentIPv4),
		})
	}

	if lastV6 != "" && currentIPv6 != "" && lastV6 != currentIPv6 {
		log(LogContext{
			Level:   LogInfo,
			Action:  ActionInfo,
			Message: fmt.Sprintf(T.IPv6Changed, lastV6, currentIPv6),
		})
	}
}

func loadRunUpdateZones(ctx context.Context, forced bool) (map[string][]Zone, bool) {
	zonesByProvider, err := loadZonesWithCache(ctx, forced)
	if err != nil {
		lastOk.Store(false)
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: t(T.NoZoneFound, "No zone found"),
			Error:   fmt.Errorf("%s: %w", T.ZoneLoadingFailed, err),
		})
		return nil, false
	}

	return zonesByProvider, true
}

func logMissingProviderZones(zonesByProvider map[string][]Zone, domainConfigs []DomainConfig) {
	for i := range domainConfigs {
		providerKey := string(domainConfigs[i].Provider)
		zones, exists := zonesByProvider[providerKey]
		if exists && len(zones) > 0 {
			continue
		}

		log(LogContext{
			Level:   LogWarn,
			Action:  ActionZone,
			Domain:  domainConfigs[i].FQDN,
			Message: fmt.Sprintf(T.ProviderReturnedNoZonesCheckAPIKey, providerKey),
		})
	}
}

func loadRunUpdateRecords(
	ctx context.Context,
	zonesByProvider map[string][]Zone,
	forced bool,
) (*ZoneRecordCache, bool) {
	cache, err := loadRecordsWithCache(ctx, zonesByProvider, forced)
	if err != nil {
		lastOk.Store(false)
		debugLog("CACHE", "", fmt.Sprintf(T.CacheLoadFailed, err))
		return nil, false
	}

	return cache, true
}

func refreshIPv64DomainsIfNeeded(ctx context.Context, forced bool, domainConfigs []DomainConfig) {
	ipv64Config := findProviderDomainConfig(domainConfigs, ProviderIPv64)
	if ipv64Config == nil {
		return
	}

	if err := ensureIPv64DomainsFresh(ctx, ipv64Config, forced); err != nil {
		debugLog("CACHE", "", fmt.Sprintf(T.IPv64CacheError, err))
	}
}

func loadLastKnownIPs() (ipv4, ipv6 string) {
	statusMutex.Lock()
	defer statusMutex.Unlock()

	b, err := os.ReadFile(updatePath)
	if err != nil {
		return "", ""
	}

	var domains map[string]DomainHistory
	if err := json.Unmarshal(b, &domains); err != nil {
		return "", ""
	}

	for _, h := range domains {
		if len(h.IPs) == 0 {
			continue
		}
		latest := h.IPs[len(h.IPs)-1]
		if latest.IPv4 != "" {
			ipv4 = latest.IPv4
		}
		if latest.IPv6 != "" {
			ipv6 = latest.IPv6
		}
		if ipv4 != "" && ipv6 != "" {
			break
		}
	}
	return ipv4, ipv6
}

// ============================================================================
// CACHE-FIRST ZONE LOADING
// ============================================================================
func getCachedZonesState() (map[string][]Zone, time.Duration, bool) {
	zoneCacheMutex.RLock()
	defer zoneCacheMutex.RUnlock()

	return cachedZones, time.Since(lastZoneLoad), len(cachedZones) > 0
}

func setCachedZones(zones map[string][]Zone) {
	zoneCacheMutex.Lock()
	defer zoneCacheMutex.Unlock()

	cachedZones = zones
	lastZoneLoad = time.Now()
}

func getCachedRecordsState() (*ZoneRecordCache, time.Duration, bool) {
	zoneCacheMutex.RLock()
	defer zoneCacheMutex.RUnlock()

	return cachedRecords, time.Since(lastRecordLoad), cachedRecords != nil
}

func setCachedRecords(cache *ZoneRecordCache) {
	zoneCacheMutex.Lock()
	defer zoneCacheMutex.Unlock()

	cachedRecords = cache
	lastRecordLoad = time.Now()
}

func loadZonesWithCache(ctx context.Context, forceRefresh bool) (map[string][]Zone, error) {
	cached, cacheAge, hasCachedZones := getCachedZonesState()

	if !forceRefresh && hasCachedZones && cacheAge < ZoneCacheTTL {
		debugLog("SCHEDULER", "", fmt.Sprintf(T.UsingZoneCacheAge, cacheAge.Round(time.Second)))

		return cached, nil
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

			setCachedZones(zonesFromDisk)

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

	setCachedZones(zonesByProvider)

	return zonesByProvider, nil
}

// ============================================================================
// CACHE-FIRST RECORD LOADING
// ============================================================================
func loadRecordsWithCache(ctx context.Context, zonesByProvider map[string][]Zone, forceRefresh bool) (*ZoneRecordCache, error) {
	cached, cacheAge, hasCachedRecords := getCachedRecordsState()

	if !forceRefresh && hasCachedRecords && cacheAge < RecordCacheTTL {
		debugLog("SCHEDULER", "", fmt.Sprintf(T.UsingRecordCacheAge, cacheAge.Round(time.Second)))

		return cached, nil
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

			setCachedRecords(cacheFromDisk)

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

	setCachedRecords(cache)

	return cache, nil
}

// ============================================================================
// CACHE ZU DISK SPEICHERN
// ============================================================================
type cacheSaveJob struct {
	provider ProviderType
	zones    []Zone
}

func buildCacheSaveJobs(zonesByProvider map[string][]Zone) []cacheSaveJob {
	jobs := make([]cacheSaveJob, 0, len(zonesByProvider))

	for provider, zones := range zonesByProvider {
		jobs = append(jobs, cacheSaveJob{
			provider: ProviderType(provider),
			zones:    zones,
		})
	}

	return jobs
}

func saveProviderCacheJob(job cacheSaveJob, cache *ZoneRecordCache) bool {
	switch job.provider {
	case ProviderIONOS:
		if err := saveIONOSCacheToFile(job.zones, cache); err != nil {
			debugLog("CACHE", "", fmt.Sprintf(T.IonosCacheSaveFailed, err))
			return false
		}
		return true

	case ProviderCloudflare:
		if err := saveCloudflareCacheToFile(job.zones, cache); err != nil {
			debugLog("CACHE", "", fmt.Sprintf(T.CloudflareCacheSaveFailed, err))
			return false
		}
		return true

	case ProviderIPv64:
		if err := saveIPv64Cache(); err != nil {
			debugLog("CACHE", "", fmt.Sprintf(T.IPv64CacheSaveFailed, err))
			return false
		}
		return true

	case ProviderHetzner:
		if err := saveHetznerDNSCacheToFile(job.zones, cache); err != nil {
			debugLog("CACHE", "", fmt.Sprintf(T.HetznerDNSCacheSaveFailed, err))
			return false
		}
		return true

	case ProviderHetznerCloud:
		if err := saveHetznerCloudCacheToFile(job.zones, cache); err != nil {
			debugLog("CACHE", "", fmt.Sprintf(T.HetznerCloudCacheSaveFailed, err))
			return false
		}
		return true

	default:
		return false
	}
}

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
	jobs := buildCacheSaveJobs(zonesByProvider)
	cacheWriteMutex.Unlock()

	saved := false
	for _, job := range jobs {
		if saveProviderCacheJob(job, cache) {
			saved = true
		}
	}

	if !saved {
		return
	}

	diskPersistMutex.Lock()
	lastDiskPersistZone = zoneLoadTs
	lastDiskPersistRecord = recordLoadTs
	diskPersistMutex.Unlock()
}

// ============================================================================
// CLEANUP
// ============================================================================
func runCleanupIfNeeded(
	ctx context.Context,
	zonesByProvider map[string][]Zone,
	cache *ZoneRecordCache,
	domainConfigs []DomainConfig,
) {
	lastNano := lastCleanupNano.Load()
	var timeSinceLastCleanup time.Duration
	if lastNano == 0 {
		timeSinceLastCleanup = CleanupInterval + 1
	} else {
		timeSinceLastCleanup = time.Since(time.Unix(0, lastNano))
	}

	if timeSinceLastCleanup < CleanupInterval {
		debugLog("MAINTENANCE", "", fmt.Sprintf(T.CleanupSkippedLastRun, timeSinceLastCleanup.Round(time.Minute)))
		return
	}

	debugLog("MAINTENANCE", "", fmt.Sprintf(T.CleanupStartingLastRun, timeSinceLastCleanup.Round(time.Minute)))
	lastCleanupNano.Store(time.Now().UnixNano())

	hasIPv64Config := findProviderDomainConfig(domainConfigs, ProviderIPv64) != nil

	for providerStr, zones := range zonesByProvider {
		pType := ProviderType(providerStr)

		switch pType {
		case ProviderIONOS:
			cleanupIONOSRecords(ctx, zones, cache)

		case ProviderCloudflare:
			cleanupCloudflareRecords(ctx, zones, cache)

		case ProviderHetzner:
			cleanupHetznerDNSRecords(ctx, zones, cache)

		case ProviderHetznerCloud:
			cleanupHetznerCloudRecords(ctx, zones, cache)

		case ProviderIPv64:
			if hasIPv64Config {
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

	domainConfigs := snapshotDomainConfigs()

	for i := range domainConfigs {
		provider := domainConfigs[i].Provider
		if seen[provider] {
			continue
		}
		seen[provider] = true

		zones, ok := loadProviderZonesFromDisk(provider)
		if !ok {
			continue
		}

		zonesByProvider[string(provider)] = zones
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

		providerLoaded, err := loadProviderRecordCacheFromDisk(cache, pType, zones)
		if err != nil {
			continue
		}
		if providerLoaded {
			loadedAny = true
		}
	}

	if !loadedAny {
		return nil, fmt.Errorf("%s", T.NoRecordCachesFound)
	}

	return cache, nil
}

func loadProviderRecordCacheFromDisk(
	cache *ZoneRecordCache,
	pType ProviderType,
	zones []Zone,
) (bool, error) {
	switch pType {
	case ProviderIONOS:
		return loadProviderRecordCache(cache, zones, loadIONOSCacheFromFile)

	case ProviderCloudflare:
		return loadProviderRecordCache(cache, zones, loadCloudflareCacheFromFile)

	case ProviderIPv64:
		return loadIPv64RecordCacheFromDisk(cache, zones), nil

	case ProviderHetzner:
		return loadProviderRecordCache(cache, zones, loadHetznerDNSCacheFromFile)

	case ProviderHetznerCloud:
		return loadProviderRecordCache(cache, zones, loadHetznerCloudCacheFromFile)

	default:
		return false, nil
	}
}

type providerCacheLoader func() ([]Zone, *ZoneRecordCache, error)

func loadProviderRecordCache(
	cache *ZoneRecordCache,
	zones []Zone,
	loader providerCacheLoader,
) (bool, error) {
	_, recordCache, err := loader()
	if err != nil || recordCache == nil {
		return false, err
	}

	loadedAny := false
	for _, zone := range zones {
		records, exists := recordCache.Get(zone.ID)
		if !exists {
			continue
		}

		cache.Set(zone.ID, records)
		loadedAny = true
	}

	return loadedAny, nil
}

func loadIPv64RecordCacheFromDisk(cache *ZoneRecordCache, zones []Zone) bool {
	providerCache.RLock()
	defer providerCache.RUnlock()

	loadedAny := false

	for _, z := range zones {
		domain, ok := providerCache.ipv64Records[z.Name]
		if !ok {
			continue
		}

		records := convertIPv64DomainRecords(domain)
		cache.Set(z.ID, records)
		loadedAny = true
	}

	return loadedAny
}

func loadProviderZonesFromDisk(provider ProviderType) ([]Zone, bool) {
	switch provider {
	case ProviderIONOS:
		zones, _, err := loadIONOSCacheFromFile()
		if err == nil && len(zones) > 0 {
			debugLog("CACHE", "", fmt.Sprintf(T.IonosZonesLoadedFromDisk, len(zones)))
			return zones, true
		}

	case ProviderCloudflare:
		zones, _, err := loadCloudflareCacheFromFile()
		if err == nil && len(zones) > 0 {
			debugLog("CACHE", "", fmt.Sprintf(T.CloudflareZonesLoadedFromDisk, len(zones)))
			return zones, true
		}

	case ProviderIPv64:
		zones, ok := loadIPv64ZonesFromDiskCache()
		if ok {
			debugLog("CACHE", "", fmt.Sprintf(T.IPv64ZonesLoadedFromDisk, len(zones)))
			return zones, true
		}

	case ProviderHetzner:
		zones, _, err := loadHetznerDNSCacheFromFile()
		if err == nil && len(zones) > 0 {
			debugLog("CACHE", "", fmt.Sprintf(T.HetznerDNSZonesLoadedFromDisk, len(zones)))
			return zones, true
		}

	case ProviderHetznerCloud:
		zones, _, err := loadHetznerCloudCacheFromFile()
		if err == nil && len(zones) > 0 {
			debugLog("CACHE", "", fmt.Sprintf(T.HetznerCloudZonesLoadedFromDisk, len(zones)))
			return zones, true
		}
	}

	return nil, false
}

func loadIPv64ZonesFromDiskCache() ([]Zone, bool) {
	if err := loadIPv64CacheFromDisk(); err != nil {
		return nil, false
	}

	providerCache.RLock()
	defer providerCache.RUnlock()

	zones := make([]Zone, 0, len(providerCache.ipv64Records))
	for domainName := range providerCache.ipv64Records {
		zones = append(zones, Zone{
			ID:   domainName,
			Name: domainName,
		})
	}

	return zones, len(zones) > 0
}
