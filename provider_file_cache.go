// Pachage main
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type dnsProviderFileCache struct {
	Version    int                 `json:"version"`
	Zones      []Zone              `json:"zones"`
	Records    map[string][]Record `json:"records"`
	LastUpdate time.Time           `json:"last_update"`
}

// ============================================================================
// CACHE FILE SYSTEM
// ============================================================================
func saveDNSProviderCacheToFile(providerName, cachePath string, zones []Zone, recordCache *ZoneRecordCache) error {
	if recordCache == nil {
		return fmt.Errorf("%s", T.ErrRecordCacheNil)
	}

	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		return fmt.Errorf("%s: %w", T.ErrCacheDirCreate, err)
	}

	cache := dnsProviderFileCache{
		Version:    1,
		Zones:      zones,
		Records:    make(map[string][]Record),
		LastUpdate: time.Now().Local(),
	}

	totalRecords := 0
	for _, zone := range zones {
		if records, exists := recordCache.Get(zone.ID); exists {
			cache.Records[zone.ID] = records
			totalRecords += len(records)
		}
	}

	jsonData, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return fmt.Errorf("%s: %w", T.ErrCacheMarshal, err)
	}

	tmpPath := cachePath + ".tmp"
	if err := os.WriteFile(tmpPath, jsonData, 0o600); err != nil {
		return fmt.Errorf("%s: %w", T.ErrCacheWrite, err)
	}

	if err := os.Rename(tmpPath, cachePath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("%s: %w", T.ErrCacheRename, err)
	}

	debugLog("CACHE", "", fmt.Sprintf(T.CacheSavedZones, providerName, len(zones), totalRecords))
	return nil
}

func loadDNSProviderCacheFromFile(providerName, cachePath string) ([]Zone, *ZoneRecordCache, error) {
	data, err := os.ReadFile(cachePath)
	if err != nil {
		if os.IsNotExist(err) {
			debugLog("CACHE", "", fmt.Sprintf(T.CacheFileNotFound, providerName))
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("%s: %w", T.ErrBodyRead, err)
	}

	var cache dnsProviderFileCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", T.ErrCacheMarshal, err)
	}

	if cache.Version == 0 {
		cache.Version = 1
	}

	if cache.Version != 1 {
		return nil, nil, fmt.Errorf(T.ErrAPIGeneric+": unsupported version %d", cache.Version)
	}

	recordCache := NewZoneRecordCache()
	for zoneID, records := range cache.Records {
		recordCache.Set(zoneID, records)
	}

	age := time.Since(cache.LastUpdate)
	debugLog("CACHE", "", fmt.Sprintf(T.CacheLoadedZones, providerName, len(cache.Zones), age.Round(time.Second)))

	return cache.Zones, recordCache, nil
}
