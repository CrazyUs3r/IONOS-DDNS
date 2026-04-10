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

	for providerStr, zones := range zonesByProvider {
		provider := ProviderType(providerStr)

		if provider == ProviderIPv64 {
			providerCache.RLock()
			hasData := len(providerCache.ipv64Records) > 0
			providerCache.RUnlock()

			if !hasData {
				debugLog("CACHE", "", T.IPv64CacheLoadDisk)
				if err := loadIPv64CacheFromDisk(); err != nil {
					debugLog("CACHE", "", fmt.Sprintf(T.IPv64CacheLoadDiskFailed, err))
				}
			}

			providerCache.RLock()
			for _, z := range zones {
				domain, ok := providerCache.ipv64Records[z.Name]
				if !ok {
					debugLog("CACHE", z.Name, T.IPv64CacheNoData)
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
				debugLog(
					"CACHE",
					z.Name,
					fmt.Sprintf(T.IPv64CacheRecordsLoaded, len(records)),
				)
			}
			providerCache.RUnlock()
			continue
		}

		var dc *DomainConfig
		for i := range cfg.DomainConfigs {
			if cfg.DomainConfigs[i].Provider == provider {
				dc = &cfg.DomainConfigs[i]
				break
			}
		}

		if dc == nil {
			continue
		}

		for _, z := range zones {
			needed := false
			for _, configDc := range cfg.DomainConfigs {
				if configDc.Provider != provider {
					continue
				}

				dn := strings.TrimSuffix(strings.ToLower(configDc.FQDN), ".")
				zn := strings.TrimSuffix(strings.ToLower(z.Name), ".")
				if dn == zn || strings.HasSuffix(dn, "."+zn) {
					needed = true
					break
				}
			}

			if !needed {
				continue
			}

			if existingRecords, hit := cache.Get(z.ID); hit && len(existingRecords) > 0 {
				debugLog("CACHE", z.Name, fmt.Sprintf("✅ Zone bereits im Cache (%d Records) – überspringe API-Call", len(existingRecords)))
				continue
			}

			cacheWg.Add(1)
			go func(zone Zone, domainConfig *DomainConfig, prov ProviderType) {
				defer cacheWg.Done()

				var records []Record
				var err error

				if prov == ProviderCloudflare {
					records, err = loadCloudflareRecords(ctx, domainConfig, zone.ID)
				} else {
					var detailData []byte
					detailData, err = ionosAPI(ctx, domainConfig, "GET", ionosBaseURL+"/"+zone.ID, nil)
					if err == nil {
						var detail struct {
							Records []Record `json:"records"`
						}
						err = json.Unmarshal(detailData, &detail)
						if err == nil {
							records = detail.Records
						}
					}
				}

				if err != nil {
					errMsg := fmt.Sprintf("Zone %s (%s): %v", zone.Name, zone.ID, err)
					cacheErrorsMu.Lock()
					cacheErrors = append(cacheErrors, errMsg)
					cacheErrorsMu.Unlock()
					debugLog("CACHE", zone.Name, fmt.Sprintf(T.CacheLoadError, err))
					return
				}

				cache.Set(zone.ID, records)
				debugLog("CACHE", zone.Name, fmt.Sprintf(T.CacheRecordsLoaded, len(records)))
			}(z, dc, provider)
		}
	}

	cacheWg.Wait()

	if len(cacheErrors) > 0 {
		log(LogContext{
			Level:   LogWarn,
			Action:  ActionError,
			Message: fmt.Sprintf("Cache-Fehler bei %d Zone(n): %s", len(cacheErrors), strings.Join(cacheErrors, "; ")),
		})
	}

	return cache, nil
}
