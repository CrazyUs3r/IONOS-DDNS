// Package main
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ============================================================================.
func NewZoneRecordCache() *ZoneRecordCache {
	return &ZoneRecordCache{
		data: make(map[string]cacheEntry),
	}
}

func (c *ZoneRecordCache) Set(zoneID string, records []Record) {
	c.SetAt(zoneID, records, time.Now())
}

func (c *ZoneRecordCache) SetAt(
	zoneID string,
	records []Record,
	storedAt time.Time,
) {
	c.Lock()
	defer c.Unlock()

	c.data[zoneID] = cacheEntry{
		records:  slices.Clone(records),
		storedAt: storedAt,
	}
}

func (c *ZoneRecordCache) Get(
	zoneID string,
) ([]Record, bool) {
	c.RLock()
	defer c.RUnlock()

	entry, exists := c.data[zoneID]
	if !exists {
		return nil, false
	}

	return slices.Clone(entry.records), true
}

func (c *ZoneRecordCache) GetWithStoredAt(
	zoneID string,
) ([]Record, time.Time, bool) {
	c.RLock()
	defer c.RUnlock()

	entry, exists := c.data[zoneID]
	if !exists {
		return nil, time.Time{}, false
	}

	return slices.Clone(entry.records), entry.storedAt, true
}

func (c *ZoneRecordCache) OldestStoredAt() (time.Time, bool) {
	c.RLock()
	defer c.RUnlock()

	var oldest time.Time

	for _, entry := range c.data {
		if entry.storedAt.IsZero() {
			return time.Time{}, true
		}

		if oldest.IsZero() || entry.storedAt.Before(oldest) {
			oldest = entry.storedAt
		}
	}

	return oldest, !oldest.IsZero()
}

func (c *ZoneRecordCache) Age(zoneID string) time.Duration {
	c.RLock()
	defer c.RUnlock()
	entry, exists := c.data[zoneID]
	if !exists {
		return -1
	}

	return time.Since(entry.storedAt)
}

func loadZoneCache(
	ctx context.Context,
	zonesByProvider map[string][]Zone,
) (*ZoneRecordCache, error) {
	cache := NewZoneRecordCache()

	var cacheWg sync.WaitGroup
	var cacheErrors []string
	var cacheErrorsMu sync.Mutex

	attemptedLoads := 0

	domainConfigs := snapshotDomainConfigs()

	for providerStr, zones := range zonesByProvider {
		provider := ProviderType(providerStr)

		if provider == ProviderIPv64 {
			loadIPv64ZoneCache(cache, zones)

			continue
		}

		domainConfig := findProviderDomainConfig(
			domainConfigs,
			provider,
		)
		if domainConfig == nil {
			continue
		}

		for _, zone := range zones {
			if !zoneNeededForProvider(
				domainConfigs,
				provider,
				zone,
			) {
				continue
			}

			if shouldSkipZoneCacheLoad(cache, zone) {
				continue
			}

			attemptedLoads++

			startZoneCacheLoad(
				ctx,
				&cacheWg,
				&cacheErrors,
				&cacheErrorsMu,
				cache,
				zone,
				domainConfig,
				provider,
			)
		}
	}

	cacheWg.Wait()

	if err := finalizeZoneCacheErrors(
		cacheErrors,
		attemptedLoads,
	); err != nil {
		return nil, err
	}

	return cache, nil
}

func loadIPv64ZoneCache(cache *ZoneRecordCache, zones []Zone) {
	ensureIPv64CacheLoaded()

	providerCache.RLock()
	defer providerCache.RUnlock()

	for _, z := range zones {
		domain, ok := providerCache.ipv64Records[z.Name]
		if !ok {
			debugLog("CACHE", z.Name, phrases().IPv64CacheNoData)

			continue
		}

		records := convertIPv64DomainRecords(domain)
		cache.Set(z.ID, records)

		debugLog("CACHE", z.Name, fmt.Sprintf(phrases().IPv64CacheRecordsLoaded, len(records)))
	}
}

func ensureIPv64CacheLoaded() {
	providerCache.RLock()
	hasData := len(providerCache.ipv64Records) > 0
	providerCache.RUnlock()

	if hasData {
		return
	}

	debugLog("CACHE", "", phrases().IPv64CacheLoadDisk)
	if err := loadIPv64CacheFromDisk(); err != nil {
		debugLog("CACHE", "", fmt.Sprintf(phrases().IPv64CacheLoadDiskFailed, err))
	}
}

func convertIPv64DomainRecords(domain IPv64Domain) []Record {
	records := make([]Record, 0, len(domain.Records))

	for _, rec := range domain.Records {
		records = append(records, Record{
			ID:      strconv.Itoa(rec.RecordID),
			Name:    ipv64RecordName(domain.Domain, rec.Praefix),
			Type:    rec.Type,
			Content: rec.Content,
		})
	}

	return records
}

func ipv64RecordName(domain, prefix string) string {
	domain = strings.TrimSuffix(
		strings.TrimSpace(domain),
		".",
	)

	prefix = strings.TrimSuffix(
		strings.TrimSpace(prefix),
		".",
	)

	switch {
	case prefix == "", prefix == "@":
		return domain

	case prefix == domain:
		return domain

	case strings.HasSuffix(prefix, "."+domain):
		return prefix

	default:
		return prefix + "." + domain
	}
}

func findProviderDomainConfig(domainConfigs []DomainConfig, provider ProviderType) *DomainConfig {
	for i := range domainConfigs {
		if domainConfigs[i].Provider == provider {
			return &domainConfigs[i]
		}
	}

	return nil
}

func zoneNeededForProvider(domainConfigs []DomainConfig, provider ProviderType, zone Zone) bool {
	zn := normalizeZoneCacheName(zone.Name)

	for _, configDc := range domainConfigs {
		if configDc.Provider != provider {
			continue
		}

		dn := normalizeZoneCacheName(configDc.FQDN)
		if dn == zn || strings.HasSuffix(dn, "."+zn) {
			return true
		}
	}

	return false
}

func normalizeZoneCacheName(name string) string {
	return strings.TrimSuffix(strings.ToLower(name), ".")
}

func shouldSkipZoneCacheLoad(cache *ZoneRecordCache, z Zone) bool {
	existingRecords, hit := cache.Get(z.ID)
	if !hit || len(existingRecords) == 0 {
		return false
	}

	debugLog(
		"CACHE",
		z.Name,
		fmt.Sprintf(
			t(phrases().ZoneCacheHitSkipAPI, "✅ Zone bereits im Cache (%d Records) – überspringe API-Call"),
			len(existingRecords),
		),
	)

	return true
}

func startZoneCacheLoad(
	ctx context.Context,
	cacheWg *sync.WaitGroup,
	cacheErrors *[]string,
	cacheErrorsMu *sync.Mutex,
	cache *ZoneRecordCache,
	z Zone,
	dc *DomainConfig,
	provider ProviderType,
) {
	cacheWg.Add(1)

	go func(zone Zone, domainConfig *DomainConfig, prov ProviderType) {
		defer cacheWg.Done()

		if workerLimiter != nil {
			if !workerLimiter.Acquire(ctx) {
				err := ctx.Err()
				if err == nil {
					err = context.Canceled
				}

				recordZoneCacheError(
					cacheErrors,
					cacheErrorsMu,
					zone,
					err,
				)

				return
			}

			defer workerLimiter.Release()
		}

		records, err := loadZoneRecordsForProvider(
			ctx,
			domainConfig,
			zone,
			prov,
		)
		if err != nil {
			recordZoneCacheError(cacheErrors, cacheErrorsMu, zone, err)
			debugLog("CACHE", zone.Name, fmt.Sprintf(phrases().CacheLoadError, err))

			return
		}

		cache.Set(zone.ID, records)
		debugLog("CACHE", zone.Name, fmt.Sprintf(phrases().CacheRecordsLoaded, len(records)))
	}(z, dc, provider)
}

func loadZoneRecordsForProvider(
	ctx context.Context,
	domainConfig *DomainConfig,
	zone Zone,
	provider ProviderType,
) ([]Record, error) {
	switch provider {
	case ProviderCloudflare:
		return loadCloudflareRecords(ctx, domainConfig, zone.ID)

	case ProviderHetzner:
		return loadHetznerDNSZoneRecords(ctx, domainConfig, zone.ID)

	case ProviderHetznerCloud:
		return loadHetznerCloudZoneRecords(ctx, domainConfig, zone.ID)

	case ProviderFebas:
		return loadFebasZoneRecords(ctx, zone)

	case ProviderDNScale:
		return loadDNScaleInfrastructureRecords(ctx, domainConfig, zone.ID)

	case ProviderIONOS:
		return loadIonosZoneRecords(ctx, domainConfig, zone.ID)

	default:
		return nil, fmt.Errorf("unknown provider: %s", provider)
	}
}

func loadIonosZoneRecords(ctx context.Context, domainConfig *DomainConfig, zoneID string) ([]Record, error) {
	detailData, err := ionosAPI(ctx, domainConfig, MethodGET, ionosBaseURL+"/"+zoneID, nil)
	if err != nil {
		return nil, err
	}

	var detail struct {
		Records []Record `json:"records"`
	}
	if err := json.Unmarshal(detailData, &detail); err != nil {
		return nil, err
	}

	return detail.Records, nil
}

func recordZoneCacheError(
	cacheErrors *[]string,
	cacheErrorsMu *sync.Mutex,
	zone Zone,
	err error,
) {
	errMsg := fmt.Sprintf("Zone %s (%s): %v", zone.Name, zone.ID, err)

	cacheErrorsMu.Lock()
	*cacheErrors = append(*cacheErrors, errMsg)
	cacheErrorsMu.Unlock()
}

func finalizeZoneCacheErrors(
	cacheErrors []string,
	attemptedLoads int,
) error {
	if len(cacheErrors) == 0 {
		return nil
	}

	details := strings.Join(cacheErrors, "; ")

	log(LogContext{
		Level:  LogWarn,
		Action: ActionError,
		Message: fmt.Sprintf(
			phrases().RecordCacheErrorZone,
			len(cacheErrors),
			details,
		),
	})

	if attemptedLoads > 0 &&
		len(cacheErrors) >= attemptedLoads {
		return fmt.Errorf(
			"all %d zone record loads failed: %s",
			attemptedLoads,
			details,
		)
	}

	return nil
}
