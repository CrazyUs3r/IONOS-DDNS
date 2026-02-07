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

	zonesByProvider, err := loadAllProviderZones(ctx)
	if err != nil {
		// Bei Fehler: Versuche Caches von Disk zu laden (Fallback)
		debugLog("SCHEDULER", "", fmt.Sprintf("⚠️ API-Fehler beim Laden der Zones: %v", err))
		debugLog("SCHEDULER", "", "🔄 Versuche Fallback auf Disk-Caches...")
		
		zonesByProvider, err = loadZonesFromDiskCache()
		if err != nil {
			lastOk.Store(false)
			log(LogContext{
				Level:   LogError,
				Action:  ActionError,
				Message: T.NoZones,
				Error:   fmt.Errorf("API und Disk-Cache fehlgeschlagen: %w", err),
			})
			return
		}
		debugLog("SCHEDULER", "", "✅ Zones erfolgreich von Disk-Cache geladen")
	}

	cache, err := loadZoneCache(ctx, zonesByProvider)
	if err != nil {
		// Bei Cache-Fehler: Versuche von Disk zu laden
		debugLog("CACHE", "", fmt.Sprintf("⚠️ Cache-Fehler: %v", err))
		debugLog("CACHE", "", "🔄 Versuche Record-Cache von Disk zu laden...")
		
		cache, err = loadRecordCacheFromDisk(zonesByProvider)
		if err != nil {
			lastOk.Store(false)
			debugLog("CACHE", "", fmt.Sprintf("❌ Konnte Record-Cache nicht laden: %v", err))
			return
		}
		debugLog("CACHE", "", "✅ Record-Cache erfolgreich von Disk geladen")
	}

	// IPv64 Cache laden/aktualisieren
	for i := range cfg.DomainConfigs {
		if cfg.DomainConfigs[i].Provider == ProviderIPv64 {
			if err := loadAllIPv64Domains(ctx, &cfg.DomainConfigs[i]); err != nil {
				debugLog("CACHE", "", fmt.Sprintf("IPv64 Cache-Fehler: %v", err))
			}
			// IPv64 Cache wird bereits in loadAllIPv64Domains() gespeichert
			break
		}
	}

	// Cloudflare & IONOS Caches speichern nach erfolgreichem Laden
	for providerStr, zones := range zonesByProvider {
		pType := ProviderType(providerStr)

		switch pType {
		case ProviderCloudflare:
			// Cache nur speichern wenn Zones erfolgreich geladen wurden
			if len(zones) > 0 && cache != nil {
				if err := saveCloudflareCacheToFile(zones, cache); err != nil {
					debugLog("CACHE", "", fmt.Sprintf("⚠️ Konnte Cloudflare Cache nicht speichern: %v", err))
				}
			}

		case ProviderIONOS:
			// Cache nur speichern wenn Zones erfolgreich geladen wurden
			if len(zones) > 0 && cache != nil {
				if err := saveIONOSCacheToFile(zones, cache); err != nil {
					debugLog("CACHE", "", fmt.Sprintf("⚠️ Konnte IONOS Cache nicht speichern: %v", err))
				}
			}
		}
	}

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

	if firstRun {
		printGroupedDomains()
		printInfrastructure(ctx, zonesByProvider)
	}

	successCount := processDomains(ctx, zonesByProvider, cache, currentIPv4, currentIPv6)

	debugLog("SCHEDULER", "", fmt.Sprintf(T.SchedulerCompleted, successCount))
}

// ============================================================================
// DISK CACHE FALLBACK
// ============================================================================
func loadZonesFromDiskCache() (map[string][]Zone, error) {
	zonesByProvider := make(map[string][]Zone)
	loadedAny := false

	// IPv64 von Disk laden
	for i := range cfg.DomainConfigs {
		if cfg.DomainConfigs[i].Provider == ProviderIPv64 {
			if err := loadIPv64CacheFromDisk(); err == nil {
				// Zones aus dem geladenen Cache erstellen
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

	// Cloudflare von Disk laden
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

	// IONOS von Disk laden
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
			// IPv64 Records aus dem bereits geladenen providerCache holen
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
				// Records aus dem geladenen Cache in unseren Cache übertragen
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
				// Records aus dem geladenen Cache in unseren Cache übertragen
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