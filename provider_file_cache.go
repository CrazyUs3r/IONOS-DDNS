// Package main
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type dnsProviderFileCache struct {
	LastUpdate time.Time            `json:"last_update"`
	StoredAt   map[string]time.Time `json:"stored_at,omitempty"`
	Records    map[string][]Record  `json:"records"`
	Zones      []Zone               `json:"zones"`
	Version    int                  `json:"version"`
}

// ============================================================================
// CACHE FILE SYSTEM
// ============================================================================

func saveDNSProviderCacheToFile(providerName, cachePath string, zones []Zone, recordCache *ZoneRecordCache) error {
	if recordCache == nil {
		return fmt.Errorf("%s", phrases().ErrRecordCacheNil)
	}

	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		return fmt.Errorf("%s: %w", phrases().ErrCacheDirCreate, err)
	}

	cache := dnsProviderFileCache{
		Version:    1,
		Zones:      zones,
		Records:    make(map[string][]Record),
		StoredAt:   make(map[string]time.Time),
		LastUpdate: time.Now(),
	}

	totalRecords := 0
	for _, zone := range zones {
		if records, storedAt, exists := recordCache.GetWithStoredAt(zone.ID); exists {
			cache.Records[zone.ID] = records
			cache.StoredAt[zone.ID] = storedAt
			totalRecords += len(records)
		}
	}

	jsonData, err := json.MarshalIndent(cache, "", " ")
	if err != nil {
		return fmt.Errorf("%s: %w", phrases().ErrCacheMarshal, err)
	}

	if err := writeFileAtomic(cachePath, jsonData); err != nil {
		return fmt.Errorf("%s: %w", phrases().ErrCacheWrite, err)
	}

	debugLog("CACHE", "", fmt.Sprintf(phrases().CacheSavedZones, providerName, len(zones), totalRecords))

	return nil
}

func loadDNSProviderCacheFromFile(providerName, cachePath string) ([]Zone, *ZoneRecordCache, error) {
	data, err := os.ReadFile(cachePath)
	if err != nil {
		if os.IsNotExist(err) {
			debugLog("CACHE", "", fmt.Sprintf(phrases().CacheFileNotFound, providerName))

			return nil, nil, nil
		}

		return nil, nil, fmt.Errorf("%s: %w", phrases().ErrBodyRead, err)
	}

	var cache dnsProviderFileCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", phrases().ErrCacheMarshal, err)
	}

	if cache.Version == 0 {
		cache.Version = 1
	}

	if cache.Version != 1 {
		return nil, nil, fmt.Errorf(phrases().ErrAPIGeneric+": unsupported version %d", cache.Version)
	}

	recordCache := NewZoneRecordCache()
	for zoneID, records := range cache.Records {
		storedAt := cache.LastUpdate
		if ts, ok := cache.StoredAt[zoneID]; ok && !ts.IsZero() {
			storedAt = ts
		}
		recordCache.SetAt(zoneID, records, storedAt)
	}

	age := time.Since(cache.LastUpdate)
	debugLog("CACHE", "", fmt.Sprintf(phrases().CacheLoadedZones, providerName, len(cache.Zones), age.Round(time.Second)))

	return cache.Zones, recordCache, nil
}
