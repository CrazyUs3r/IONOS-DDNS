// Package main

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// ============================================================================
// UPDATE ORCHESTRATION
// ============================================================================

func tryClaimUpdate() bool {
	return updateInProgress.CompareAndSwap(false, true)
}

func runUpdate(firstRun bool) {
	if !tryClaimUpdate() {
		debugLog("SCHEDULER", "", phrases().UpdateAlreadyRunning)

		return
	}

	runClaimedUpdate(firstRun)
}

func runClaimedUpdate(firstRun bool) {
	defer updateInProgress.Store(false)

	activeUpdates.Add(1)
	defer activeUpdates.Add(-1)

	forceRequested := forceNextUpdate.Swap(false)
	forced := firstRun || forceRequested

	debugLog("SCHEDULER", "", fmt.Sprintf(phrases().SchedulerStarted, firstRun))

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

	logMissingProviderZones(
		zonesByProvider,
		domainConfigs,
	)

	cache, ok := loadRunUpdateRecords(
		ctx,
		zonesByProvider,
		forced,
	)
	if !ok {
		return
	}

	refreshIPv64DomainsIfNeeded(
		ctx,
		forced,
		domainConfigs,
	)

	saveCachesToDisk(zonesByProvider, cache)

	if firstRun {
		printGroupedDomains()
		printInfrastructure(
			ctx,
			zonesByProvider,
			cache,
		)
	}

	successCount := processDomains(
		ctx,
		zonesByProvider,
		cache,
		currentIPv4,
		currentIPv6,
	)

	debugLog("SCHEDULER", "", fmt.Sprintf(phrases().SchedulerCompleted, successCount))

	runCleanupIfNeeded(
		ctx,
		zonesByProvider,
		cache,
		domainConfigs,
	)
}

func createRunUpdateContexts(domainCount int) (context.Context, context.Context, context.CancelFunc, context.CancelFunc) {
	baseTimeout := BaseUpdateTimeout
	perDomainTimeout := time.Duration(domainCount) * PerDomainTimeout
	buffer := UpdateBufferTimeout
	totalTimeout := min(max(baseTimeout+perDomainTimeout+buffer, MinUpdateTimeout), MaxUpdateTimeout)

	debugLog("SCHEDULER", "", fmt.Sprintf(phrases().ContextTimeoutForDomains, totalTimeout, domainCount))

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
			Message: fmt.Sprintf(phrases().IPFetchFailed, err),
		})

		return "", "", false
	}

	fallbackV4, fallbackV6 := loadLastKnownIPs()
	if fallbackV4 == "" && fallbackV6 == "" {
		lastOk.Store(false)
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: fmt.Sprintf(phrases().IPFetchFailed, err),
		})

		return "", "", false
	}

	log(LogContext{
		Level:   LogWarn,
		Action:  ActionError,
		Message: fmt.Sprintf(phrases().IPFetchFailedFallback, err),
	})

	return fallbackV4, fallbackV6, true
}

func logChangedIPs(currentIPv4, currentIPv6 string) {
	lastV4, lastV6 := loadLastKnownIPs()

	if lastV4 != "" && currentIPv4 != "" && lastV4 != currentIPv4 {
		log(LogContext{
			Level:   LogInfo,
			Action:  ActionInfo,
			Message: fmt.Sprintf(phrases().IPv4Changed, lastV4, currentIPv4),
		})
	}

	if lastV6 != "" && currentIPv6 != "" && lastV6 != currentIPv6 {
		log(LogContext{
			Level:   LogInfo,
			Action:  ActionInfo,
			Message: fmt.Sprintf(phrases().IPv6Changed, lastV6, currentIPv6),
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
			Message: t(phrases().NoZoneFound, "No zone found"),
			Error:   fmt.Errorf("%s: %w", phrases().ZoneLoadingFailed, err),
		})

		return nil, false
	}

	return zonesByProvider, true
}

func logMissingProviderZones(zonesByProvider map[string][]Zone, domainConfigs []DomainConfig) {
	missingCounts := make(map[string]int)

	for i := range domainConfigs {
		providerKey := string(domainConfigs[i].Provider)
		zones, exists := zonesByProvider[providerKey]
		if exists && len(zones) > 0 {
			continue
		}
		missingCounts[providerKey]++
	}

	if len(missingCounts) == 0 {
		return
	}

	providers := make([]string, 0, len(missingCounts))
	for provider := range missingCounts {
		providers = append(providers, provider)
	}
	sort.Strings(providers)

	for _, provider := range providers {
		if providerZoneFailureActive(ProviderType(provider)) {
			// The provider-level outage tracker already owns persistent logging
			// for this condition. Avoid a duplicate warning every scheduler run.
			continue
		}

		log(LogContext{
			Level:  LogWarn,
			Action: ActionZone,
			Message: fmt.Sprintf(
				"Provider %s has no usable zones; %d configured domain(s) affected",
				provider,
				missingCounts[provider],
			),
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
		debugLog("CACHE", "", fmt.Sprintf(phrases().CacheLoadFailed, err))

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
		debugLog("CACHE", "", fmt.Sprintf(phrases().IPv64CacheError, err))
	}
}

type lastKnownIPState struct {
	ipv4Time time.Time
	ipv6Time time.Time
	ipv4     string
	ipv6     string
	ipv4Seq  int
	ipv6Seq  int
}

func loadLastKnownIPs() (ipv4, ipv6 string) {
	domains, err := readDomainHistories()
	if err != nil {
		return "", ""
	}

	state := findLastKnownIPs(domains)

	return state.ipv4, state.ipv6
}

func readDomainHistories() (
	map[string]DomainHistory,
	error,
) {
	statusMutex.Lock()
	defer statusMutex.Unlock()

	data, err := os.ReadFile(updatePath)
	if err != nil {
		return nil, err
	}

	var domains map[string]DomainHistory
	if err := json.Unmarshal(data, &domains); err != nil {
		return nil, err
	}

	return domains, nil
}

func findLastKnownIPs(
	domains map[string]DomainHistory,
) lastKnownIPState {
	state := lastKnownIPState{
		ipv4Seq: -1,
		ipv6Seq: -1,
	}

	domainNames := sortedHistoryDomainNames(domains)
	sequence := 0

	for _, domainName := range domainNames {
		history := domains[domainName]

		for _, entry := range history.IPs {
			sequence++

			state.consider(
				entry,
				parseHistoryIPTime(entry.Time),
				sequence,
			)
		}
	}

	return state
}

func sortedHistoryDomainNames(
	domains map[string]DomainHistory,
) []string {
	names := make([]string, 0, len(domains))

	for domainName := range domains {
		names = append(names, domainName)
	}

	sort.Strings(names)

	return names
}

func (state *lastKnownIPState) consider(
	entry IPEntry,
	entryTime time.Time,
	sequence int,
) {
	if isNewerIPCandidate(
		entry.IPv4,
		state.ipv4,
		entryTime,
		state.ipv4Time,
		sequence,
		state.ipv4Seq,
	) {
		state.ipv4 = entry.IPv4
		state.ipv4Time = entryTime
		state.ipv4Seq = sequence
	}

	if isNewerIPCandidate(
		entry.IPv6,
		state.ipv6,
		entryTime,
		state.ipv6Time,
		sequence,
		state.ipv6Seq,
	) {
		state.ipv6 = entry.IPv6
		state.ipv6Time = entryTime
		state.ipv6Seq = sequence
	}
}

func isNewerIPCandidate(
	value string,
	currentValue string,
	candidateTime time.Time,
	currentTime time.Time,
	candidateSequence int,
	currentSequence int,
) bool {
	switch {
	case value == "":
		return false

	case currentValue == "":
		return true

	case candidateTime.After(currentTime):
		return true

	case candidateTime.Before(currentTime):
		return false

	default:
		return candidateSequence > currentSequence
	}
}

func parseHistoryIPTime(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}

	layouts := [...]string{
		time.RFC3339Nano,
		time.RFC3339,
		statusTimestampLayoutT,
		statusTimestampLayout,
		statusTimestampLayoutwS,
	}

	for _, layout := range layouts {
		parsed, err := time.ParseInLocation(
			layout,
			value,
			time.Local,
		)
		if err == nil {
			return parsed
		}
	}

	return time.Time{}
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
	setCachedZonesAt(zones, time.Now())
}

func setCachedZonesAt(
	zones map[string][]Zone,
	loadedAt time.Time,
) {
	zoneCacheMutex.Lock()
	defer zoneCacheMutex.Unlock()

	cachedZones = zones
	lastZoneLoad = loadedAt
}

func getCachedRecordsState() (*ZoneRecordCache, time.Duration, bool) {
	zoneCacheMutex.RLock()
	defer zoneCacheMutex.RUnlock()

	return cachedRecords, time.Since(lastRecordLoad), cachedRecords != nil
}

func setCachedRecords(cache *ZoneRecordCache) {
	loadedAt := time.Now()

	if cache != nil {
		if oldest, exists := cache.OldestStoredAt(); exists {
			loadedAt = oldest
		}
	}

	zoneCacheMutex.Lock()
	defer zoneCacheMutex.Unlock()

	cachedRecords = cache
	lastRecordLoad = loadedAt
}

func cloneZonesByProvider(src map[string][]Zone) map[string][]Zone {
	out := make(map[string][]Zone, len(src))
	for provider, zones := range src {
		out[provider] = append([]Zone(nil), zones...)
	}
	return out
}

func mergeFailedProviderZoneFallbacks(
	fresh map[string][]Zone,
	cached map[string][]Zone,
	failures map[string]error,
) map[string][]Zone {
	merged := cloneZonesByProvider(fresh)

	for provider := range failures {
		if zones := cached[provider]; len(zones) > 0 {
			merged[provider] = append([]Zone(nil), zones...)
			debugLog("CACHE", "", fmt.Sprintf("Using stale in-memory zones for provider %s after API failure", provider))
			continue
		}

		zones, ok := loadProviderZonesFromDisk(ProviderType(provider))
		if !ok || len(zones) == 0 {
			continue
		}

		merged[provider] = append([]Zone(nil), zones...)
		debugLog("CACHE", "", fmt.Sprintf("Using stale disk zones for provider %s after API failure", provider))
	}

	return merged
}

func failedProviderNames(failures map[string]error) []string {
	names := make([]string, 0, len(failures))
	for provider := range failures {
		names = append(names, provider)
	}
	sort.Strings(names)
	return names
}

func loadZonesWithCache(ctx context.Context, forceRefresh bool) (map[string][]Zone, error) {
	cached, cacheAge, hasCachedZones := getCachedZonesState()

	if !forceRefresh && hasCachedZones && cacheAge < ZoneCacheTTL {
		debugLog("SCHEDULER", "", fmt.Sprintf(phrases().UsingZoneCacheAge, cacheAge.Round(time.Second)))
		return cached, nil
	}

	switch {
	case forceRefresh:
		debugLog("SCHEDULER", "", phrases().ForcedRefreshLoadZones)
	case !hasCachedZones:
		debugLog("SCHEDULER", "", phrases().NoZoneCacheInitialLoad)
	default:
		debugLog("SCHEDULER", "", fmt.Sprintf(phrases().ZoneCacheTooOldReload, cacheAge.Round(time.Second)))
	}

	if !forceRefresh && !hasCachedZones {
		if zonesFromDisk, err := loadZonesFromDiskCache(); err == nil && len(zonesFromDisk) > 0 {
			debugLog("SCHEDULER", "", phrases().ZonesLoadedFromDiskNoAPICall)
			setCachedZonesAt(zonesFromDisk, time.Time{})
			return zonesFromDisk, nil
		}
	}

	snapshot, err := doSingleflight(
		ctx,
		&zonesLoadGroup,
		"zones_api",
		func() (providerZoneLoadSnapshot, error) {
			return loadAllProviderZones(ctx)
		},
	)
	if err != nil {
		debugLog("SCHEDULER", "", fmt.Sprintf(phrases().ZoneAPILoadFailed, err))

		if hasCachedZones {
			zonesByProvider := cloneZonesByProvider(cached)
			setCachedZonesAt(zonesByProvider, time.Time{})
			debugLog("SCHEDULER", "", "Using stale in-memory zone cache; retry on next scheduler run")
			return zonesByProvider, nil
		}

		debugLog("SCHEDULER", "", phrases().TryingDiskCacheFallback)
		zonesByProvider, diskErr := loadZonesFromDiskCache()
		if diskErr != nil {
			return nil, fmt.Errorf("%s: %w", phrases().APIAndDiskCacheFailed, diskErr)
		}

		setCachedZonesAt(zonesByProvider, time.Time{})
		debugLog("SCHEDULER", "", phrases().ZonesLoadedFromDisk)
		return zonesByProvider, nil
	}

	zonesByProvider := snapshot.Zones
	if len(snapshot.Failures) > 0 {
		zonesByProvider = mergeFailedProviderZoneFallbacks(zonesByProvider, cached, snapshot.Failures)

		// Partial provider failures are intentionally kept stale. This makes the
		// next normal scheduler run retry provider APIs instead of waiting for the
		// healthy 60-minute ZoneCacheTTL.
		setCachedZonesAt(zonesByProvider, time.Time{})

		debugLog(
			"SCHEDULER",
			"",
			fmt.Sprintf(
				"Zone cache degraded; failed providers=%s; retry on next scheduler run",
				strings.Join(failedProviderNames(snapshot.Failures), ","),
			),
		)
		return zonesByProvider, nil
	}

	setCachedZones(zonesByProvider)
	debugLog("SCHEDULER", "", phrases().ZonesLoadedFromAPI)
	return zonesByProvider, nil
}

// ============================================================================
// CACHE-FIRST RECORD LOADING
// ============================================================================

func loadRecordsWithCache(ctx context.Context, zonesByProvider map[string][]Zone, forceRefresh bool) (*ZoneRecordCache, error) {
	cached, cacheAge, hasCachedRecords := getCachedRecordsState()

	// When at least one provider's zone API is degraded, keep the last known
	// record cache instead of repeatedly refreshing healthy providers every
	// scheduler interval. As soon as a provider recovers, noteProviderZoneSuccess
	// marks lastRecordLoad stale so this function performs an immediate full
	// refresh in that same run.
	if hasActiveProviderZoneFailures() {
		if hasCachedRecords {
			debugLog("CACHE", "", "Provider zone API degraded; retaining last known record cache")
			return cached, nil
		}

		if cacheFromDisk, err := loadRecordCacheFromDisk(zonesByProvider); err == nil && cacheFromDisk != nil {
			debugLog("CACHE", "", "Provider zone API degraded; using record cache from disk")
			setCachedRecords(cacheFromDisk)
			return cacheFromDisk, nil
		}
	}

	if !forceRefresh && hasCachedRecords && cacheAge < RecordCacheTTL {
		debugLog("SCHEDULER", "", fmt.Sprintf(phrases().UsingRecordCacheAge, cacheAge.Round(time.Second)))
		return cached, nil
	}

	switch {
	case forceRefresh:
		debugLog("SCHEDULER", "", phrases().ForcedRefreshLoadRecords)
	case !hasCachedRecords:
		debugLog("SCHEDULER", "", phrases().NoRecordCacheInitialLoad)
	default:
		debugLog("SCHEDULER", "", fmt.Sprintf(phrases().RecordCacheTooOldReload, cacheAge.Round(time.Second)))
	}

	if !forceRefresh && !hasCachedRecords {
		if cacheFromDisk, err := loadRecordCacheFromDisk(zonesByProvider); err == nil && cacheFromDisk != nil {
			debugLog("SCHEDULER", "", phrases().RecordCacheLoadedFromDiskNoAPICall)
			setCachedRecords(cacheFromDisk)
			return cacheFromDisk, nil
		}
	}

	cache, err := doSingleflight(ctx, &recordsLoadGroup, "records_api", func() (*ZoneRecordCache, error) {
		return loadZoneCache(ctx, zonesByProvider)
	})
	if err != nil {
		debugLog("CACHE", "", fmt.Sprintf(phrases().RecordCacheError, err))

		if hasCachedRecords {
			debugLog("CACHE", "", "Record API refresh failed; retaining stale in-memory record cache")
			return cached, nil
		}

		debugLog("CACHE", "", phrases().TryingLoadRecordCacheFromDisk)
		cache, err = loadRecordCacheFromDisk(zonesByProvider)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", phrases().RecordCacheCouldNotBeLoaded, err)
		}
		debugLog("CACHE", "", phrases().RecordCacheLoadedFromDisk)
	} else {
		debugLog("CACHE", "", phrases().RecordsLoadedSuccessfully)
	}

	setCachedRecords(cache)
	return cache, nil
}

// ============================================================================
// CACHE To DISK SAVE
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
			debugLog("CACHE", "", fmt.Sprintf(phrases().IonosCacheSaveFailed, err))

			return false
		}

		return true

	case ProviderCloudflare:
		if err := saveCloudflareCacheToFile(job.zones, cache); err != nil {
			debugLog("CACHE", "", fmt.Sprintf(phrases().CloudflareCacheSaveFailed, err))

			return false
		}

		return true

	case ProviderIPv64:
		if err := saveIPv64Cache(); err != nil {
			debugLog("CACHE", "", fmt.Sprintf(phrases().IPv64CacheSaveFailed, err))

			return false
		}

		return true

	case ProviderHetzner:
		if err := saveHetznerDNSCacheToFile(job.zones, cache); err != nil {
			debugLog("CACHE", "", fmt.Sprintf(phrases().HetznerDNSCacheSaveFailed, err))

			return false
		}

		return true

	case ProviderHetznerCloud:
		if err := saveHetznerCloudCacheToFile(job.zones, cache); err != nil {
			debugLog("CACHE", "", fmt.Sprintf(phrases().HetznerCloudCacheSaveFailed, err))

			return false
		}

		return true

	case ProviderFebas:
		// Febas zones are generated from config and records are resolved live.
		return true

	case ProviderDNScale:
		if err := saveDNScaleCacheToFile(job.zones, cache); err != nil {
			debugLog("CACHE", "", fmt.Sprintf(phrases().DNScaleCacheSaveFailed, err))

			return false
		}

		return true

	default:
		return false
	}
}

func saveCachesToDisk(
	zonesByProvider map[string][]Zone,
	cache *ZoneRecordCache,
) {
	zoneCacheMutex.RLock()
	zoneLoadTS := lastZoneLoad
	recordLoadTS := lastRecordLoad
	zoneCacheMutex.RUnlock()

	diskPersistMutex.Lock()
	needsPersist := zoneLoadTS.After(lastDiskPersistZone) ||
		recordLoadTS.After(lastDiskPersistRecord)
	diskPersistMutex.Unlock()

	if !needsPersist {
		debugLog("CACHE", "", phrases().DiskCachePersistSkipped)

		return
	}

	cacheWriteMutex.Lock()
	defer cacheWriteMutex.Unlock()

	jobs := buildCacheSaveJobs(zonesByProvider)
	if len(jobs) == 0 {
		return
	}

	allSaved := true

	for _, job := range jobs {
		if !saveProviderCacheJob(job, cache) {
			allSaved = false
		}
	}

	if !allSaved {
		return
	}

	diskPersistMutex.Lock()
	lastDiskPersistZone = zoneLoadTS
	lastDiskPersistRecord = recordLoadTS
	diskPersistMutex.Unlock()
}

// ============================================================================
// CLEANUP
// ============================================================================

func isCleanupEligibleRecordType(recordType string) bool {
	switch strings.ToUpper(strings.TrimSpace(recordType)) {
	case RecordTypeA, RecordTypeAAAA, RecordTypeCNAME:
		return true
	default:
		return false
	}
}

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
		debugLog("MAINTENANCE", "", fmt.Sprintf(phrases().CleanupSkippedLastRun, timeSinceLastCleanup.Round(time.Minute)))

		return
	}

	debugLog("MAINTENANCE", "", fmt.Sprintf(phrases().CleanupStartingLastRun, timeSinceLastCleanup.Round(time.Minute)))
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
				debugLog("MAINTENANCE", "", phrases().CheckingIPv64OrphanedRecords)
				cleanupIPv64Records(ctx)
			}
		case ProviderDNScale:
			cleanupDNScaleRecords(ctx, zones, cache)
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
		return nil, fmt.Errorf("%s", phrases().NoProviderCacheOnDiskFound)
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
		return nil, fmt.Errorf("%s", phrases().NoRecordCachesFound)
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

	case ProviderFebas:
		for _, zone := range zones {
			cache.Set(zone.ID, []Record{})
		}

		return len(zones) > 0, nil

	case ProviderDNScale:
		return loadProviderRecordCache(cache, zones, loadDNScaleCacheFromFile)

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
	if err != nil {
		return false, err
	}

	if recordCache == nil {
		return false, nil
	}

	loadedAny := false

	for _, zone := range zones {
		records, storedAt, exists := recordCache.GetWithStoredAt(zone.ID)

		if !exists {
			continue
		}

		cache.SetAt(
			zone.ID,
			records,
			storedAt,
		)

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

type providerZoneDiskSource struct {
	loader        providerCacheLoader
	loadedMessage string
}

func loadProviderZonesFromDisk(provider ProviderType) ([]Zone, bool) {
	switch provider {
	case ProviderIPv64:
		return loadIPv64ProviderZonesFromDisk()
	case ProviderFebas:
		return loadFebasProviderZonesFromDisk()
	default:
		source, ok := providerZoneDiskSourceFor(provider)
		if !ok {
			return nil, false
		}

		return loadFileBackedProviderZonesFromDisk(source)
	}
}

func providerZoneDiskSourceFor(provider ProviderType) (providerZoneDiskSource, bool) {
	switch provider {
	case ProviderIONOS:
		return providerZoneDiskSource{loadIONOSCacheFromFile, phrases().IonosZonesLoadedFromDisk}, true
	case ProviderCloudflare:
		return providerZoneDiskSource{loadCloudflareCacheFromFile, phrases().CloudflareZonesLoadedFromDisk}, true
	case ProviderHetzner:
		return providerZoneDiskSource{loadHetznerDNSCacheFromFile, phrases().HetznerDNSZonesLoadedFromDisk}, true
	case ProviderHetznerCloud:
		return providerZoneDiskSource{loadHetznerCloudCacheFromFile, phrases().HetznerCloudZonesLoadedFromDisk}, true
	case ProviderDNScale:
		return providerZoneDiskSource{loadDNScaleCacheFromFile, phrases().DNScaleZonesLoadedFromDisk}, true
	default:
		return providerZoneDiskSource{}, false
	}
}

func loadFileBackedProviderZonesFromDisk(source providerZoneDiskSource) ([]Zone, bool) {
	zones, _, err := source.loader()
	if err != nil || len(zones) == 0 {
		return nil, false
	}

	debugLog("CACHE", "", fmt.Sprintf(source.loadedMessage, len(zones)))

	return zones, true
}

func loadIPv64ProviderZonesFromDisk() ([]Zone, bool) {
	zones, ok := loadIPv64ZonesFromDiskCache()
	if !ok {
		return nil, false
	}

	debugLog("CACHE", "", fmt.Sprintf(phrases().IPv64ZonesLoadedFromDisk, len(zones)))

	return zones, true
}

func loadFebasProviderZonesFromDisk() ([]Zone, bool) {
	domainConfigs := snapshotDomainConfigs()
	if findProviderDomainConfig(domainConfigs, ProviderFebas) == nil {
		return nil, false
	}

	zones, err := loadFebasZones(context.Background())

	return zones, err == nil && len(zones) > 0
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
