// Package main
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

// ============================================================================
// ZONE & CACHE
// ============================================================================
func NewZoneRecordCache() *ZoneRecordCache {
	return &ZoneRecordCache{
		data: make(map[string][]Record),
	}
}

func (c *ZoneRecordCache) Set(zoneID string, records []Record) {
	c.Lock()
	defer c.Unlock()
	c.data[zoneID] = records
}

func (c *ZoneRecordCache) Get(zoneID string) ([]Record, bool) {
	c.RLock()
	defer c.RUnlock()
	records, exists := c.data[zoneID]
	return records, exists
}

func loadZoneCache(ctx context.Context, zonesByProvider map[string][]Zone) (*ZoneRecordCache, error) {
	cache := NewZoneRecordCache()

	var cacheWg sync.WaitGroup
	var cacheErrors []string
	var cacheErrorsMu sync.Mutex

	domainConfigs := snapshotDomainConfigs()

	for providerStr, zones := range zonesByProvider {
		provider := ProviderType(providerStr)

		if provider == ProviderIPv64 {
			loadIPv64ZoneCache(cache, zones)
			continue
		}

		dc := findProviderDomainConfig(domainConfigs, provider)
		if dc == nil {
			continue
		}

		for _, z := range zones {
			if !zoneNeededForProvider(domainConfigs, provider, z) {
				continue
			}

			if shouldSkipZoneCacheLoad(cache, z) {
				continue
			}

			startZoneCacheLoad(ctx, &cacheWg, &cacheErrors, &cacheErrorsMu, cache, z, dc, provider)
		}
	}

	cacheWg.Wait()

	if err := finalizeZoneCacheErrors(cacheErrors, zonesByProvider); err != nil {
		return nil, err
	}

	return cache, nil
}

func snapshotDomainConfigs() []DomainConfig {
	cfgMu.RLock()
	defer cfgMu.RUnlock()

	domainConfigs := make([]DomainConfig, len(cfg.DomainConfigs))
	copy(domainConfigs, cfg.DomainConfigs)

	return domainConfigs
}

func loadIPv64ZoneCache(cache *ZoneRecordCache, zones []Zone) {
	ensureIPv64CacheLoaded()

	providerCache.RLock()
	defer providerCache.RUnlock()

	for _, z := range zones {
		domain, ok := providerCache.ipv64Records[z.Name]
		if !ok {
			debugLog("CACHE", z.Name, T.IPv64CacheNoData)
			continue
		}

		records := convertIPv64DomainRecords(domain)
		cache.Set(z.ID, records)

		debugLog("CACHE", z.Name, fmt.Sprintf(T.IPv64CacheRecordsLoaded, len(records)))
	}
}

func ensureIPv64CacheLoaded() {
	providerCache.RLock()
	hasData := len(providerCache.ipv64Records) > 0
	providerCache.RUnlock()

	if hasData {
		return
	}

	debugLog("CACHE", "", T.IPv64CacheLoadDisk)
	if err := loadIPv64CacheFromDisk(); err != nil {
		debugLog("CACHE", "", fmt.Sprintf(T.IPv64CacheLoadDiskFailed, err))
	}
}

func convertIPv64DomainRecords(domain IPv64Domain) []Record {
	records := make([]Record, 0, len(domain.Records))
	for _, rec := range domain.Records {
		records = append(records, Record{
			ID:      fmt.Sprintf("%d", rec.RecordID),
			Type:    rec.Type,
			Content: rec.Content,
		})
	}
	return records
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
			t(T.ZoneCacheHitSkipAPI, "✅ Zone bereits im Cache (%d Records) – überspringe API-Call"),
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

		records, err := loadZoneRecordsForProvider(ctx, domainConfig, zone, prov)
		if err != nil {
			recordZoneCacheError(cacheErrors, cacheErrorsMu, zone, err)
			debugLog("CACHE", zone.Name, fmt.Sprintf(T.CacheLoadError, err))
			return
		}

		cache.Set(zone.ID, records)
		debugLog("CACHE", zone.Name, fmt.Sprintf(T.CacheRecordsLoaded, len(records)))
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
	default:
		return loadIonosZoneRecords(ctx, domainConfig, zone.ID)
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

func finalizeZoneCacheErrors(cacheErrors []string, zonesByProvider map[string][]Zone) error {
	if len(cacheErrors) == 0 {
		return nil
	}

	log(LogContext{
		Level:   LogWarn,
		Action:  ActionError,
		Message: fmt.Sprintf(T.RecordCacheErrorZone, len(cacheErrors), strings.Join(cacheErrors, "; ")),
	})

	totalZones := countTotalZones(zonesByProvider)
	if len(cacheErrors) >= totalZones {
		return fmt.Errorf("all zone record loads failed: %s", strings.Join(cacheErrors, "; "))
	}

	return nil
}

func countTotalZones(zonesByProvider map[string][]Zone) int {
	totalZones := 0
	for _, zones := range zonesByProvider {
		totalZones += len(zones)
	}
	return totalZones
}
