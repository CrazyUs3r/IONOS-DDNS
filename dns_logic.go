package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

func processDomains(
	ctx context.Context,
	zonesByProvider map[string][]Zone,
	cache *ZoneRecordCache,
	ipv4, ipv6 string,
) int {

	var wg sync.WaitGroup
	results := make(chan domainUpdateResult, len(cfg.DomainConfigs))

domainLoop:
	for i := range cfg.DomainConfigs {
		dc := &cfg.DomainConfigs[i]

		select {
		case <-ctx.Done():
			debugLog("SCHEDULER", "", "Domain-Loop abgebrochen: Context cancelled")
			break domainLoop
		default:
		}

		wg.Add(1)
		go func(domainConfig *DomainConfig) {
			defer wg.Done()

			defer func() {
				if r := recover(); r != nil {
					log(LogContext{
						Level:   LogError,
						Action:  ActionError,
						Domain:  domainConfig.FQDN,
						Message: fmt.Sprintf("Panic: %v", r),
					})
				}
			}()

			if ctx.Err() != nil {
				return
			}

			select {
			case workerSemaphore <- struct{}{}:
				debugLog("WORKER", domainConfig.FQDN, T.WorkerSlotAcquired)
			case <-ctx.Done():
				debugLog("WORKER", domainConfig.FQDN, "Abgebrochen: Context cancelled")
				return
			}

			defer func() {
				debugLog("WORKER", domainConfig.FQDN, T.WorkerSlotReleased)
				<-workerSemaphore
			}()

			if ctx.Err() != nil {
				debugLog("WORKER", domainConfig.FQDN, T.ContextExpired)
				return
			}

			zones, exists := zonesByProvider[string(domainConfig.Provider)]
			if !exists || len(zones) == 0 {
				debugLog("DNS-LOGIC", domainConfig.FQDN, T.NoZoneFoundForDomain)
				results <- domainUpdateResult{
					Domain: domainConfig.FQDN,
					Error:  fmt.Errorf("no zones found for provider %s", domainConfig.Provider),
				}
				return
			}

			var matchedZone *Zone
			dn := strings.TrimSuffix(strings.ToLower(domainConfig.FQDN), ".")
			for i := range zones {
				zn := strings.TrimSuffix(strings.ToLower(zones[i].Name), ".")
				if dn == zn || strings.HasSuffix(dn, "."+zn) {
					matchedZone = &zones[i]
					break
				}
			}

			if matchedZone == nil {
				debugLog("DNS-LOGIC", domainConfig.FQDN, T.NoZoneFoundForDomain)
				results <- domainUpdateResult{
					Domain: domainConfig.FQDN,
					Error:  fmt.Errorf("no zone found"),
				}
				return
			}

			zoneID := matchedZone.ID
			if zoneID == "" {
				results <- domainUpdateResult{
					Domain: domainConfig.FQDN,
					Error:  fmt.Errorf("matched zone has empty ID"),
				}
				return
			}

			records, exists := cache.Get(zoneID)
			if !exists && domainConfig.Provider != ProviderIPv64 {
				debugLog("DNS-LOGIC", domainConfig.FQDN, T.NoRecordsInCache)
				results <- domainUpdateResult{
					Domain: domainConfig.FQDN,
					Error:  fmt.Errorf("no records in cache"),
				}
				return
			}

			job := domainUpdateJob{
				Domain:   domainConfig.FQDN,
				ZoneID:   zoneID,
				ZoneName: matchedZone.Name,
				Records:  records,
				IPv4:     ipv4,
				IPv6:     ipv6,
			}

			result := processDomainUpdate(ctx, domainConfig, job)
			results <- result

			providerName := string(domainConfig.Provider)

			if result.Changed && !cfg.DryRun {
				debugLog("STATUS", domainConfig.FQDN, T.ChangesDetected)
				updateStatusFile(domainConfig.FQDN, ipv4, ipv6, providerName)
			} else if result.Error == nil {
				debugLog("STATUS", domainConfig.FQDN, T.NoChangesNeeded)
			}
		}(dc)
	}

	wg.Wait()
	close(results)

	successCount := 0
	hasErrors := false

	for result := range results {
		if result.Error != nil {
			hasErrors = true
		} else if result.Changed {
			successCount++
		}
	}

	lastOk.Store(!hasErrors)
	return successCount
}

func processDomainUpdate(ctx context.Context, dc *DomainConfig, job domainUpdateJob) domainUpdateResult {
	result := domainUpdateResult{Domain: job.Domain}

	v4Changed, v6Changed := false, false

	if cfg.IPMode != "IPV6" && job.IPv4 != "" {
		debugLog("DNS-LOGIC", job.Domain, T.CheckingIpv4)

		var changed bool
		var err error

		switch dc.Provider {
		case ProviderCloudflare:
			changed, err = updateCloudflareDNS(ctx, dc, job.Domain, "A", job.IPv4, job.Records, job.ZoneID)
		case ProviderIPv64:
			changed, err = updateIPv64DNS(ctx, dc, job.Domain, "A", job.IPv4)
		default:
			changed, err = updateDNS(ctx, dc, job.Domain, "A", job.IPv4, job.Records, job.ZoneID, job.ZoneName)
		}

		if err != nil {
			if isNonRecoverableError(err) {
				result.Error = fmt.Errorf("non-recoverable IPv4 error: %w", err)
				return result
			}
			debugLog("DNS-LOGIC", job.Domain, fmt.Sprintf("%s IPv4: %v", T.UpdateFailed, err))
		}
		v4Changed = changed
	}

	if cfg.IPMode != "IPV4" && job.IPv6 != "" {
		debugLog("DNS-LOGIC", job.Domain, T.CheckingIpv6)

		var changed bool
		var err error

		switch dc.Provider {
		case ProviderCloudflare:
			changed, err = updateCloudflareDNS(ctx, dc, job.Domain, "AAAA", job.IPv6, job.Records, job.ZoneID)
		case ProviderIPv64:
			changed, err = updateIPv64DNS(ctx, dc, job.Domain, "AAAA", job.IPv6)
		default:
			changed, err = updateDNS(ctx, dc, job.Domain, "AAAA", job.IPv6, job.Records, job.ZoneID, job.ZoneName)
		}

		if err != nil {
			if isNonRecoverableError(err) {
				result.Error = fmt.Errorf("non-recoverable IPv6 error: %w", err)
				return result
			}
			debugLog("DNS-LOGIC", job.Domain, fmt.Sprintf("%s IPv6: %v", T.UpdateFailed, err))
		}
		v6Changed = changed
	}

	result.Changed = v4Changed || v6Changed
	return result
}

func cleanupOldRecords(ctx context.Context, zones []Zone, recordCache *ZoneRecordCache) {
	var ionosDC *DomainConfig
	for i := range cfg.DomainConfigs {
		if cfg.DomainConfigs[i].Provider == ProviderIONOS {
			ionosDC = &cfg.DomainConfigs[i]
			break
		}
	}

	if ionosDC == nil {
		return
	}

	debugLog("MAINTENANCE", "", "🧹 Starte Bereinigung verwaister DNS-Records...")

	configDomains := make(map[string]struct{})
	for _, dc := range cfg.DomainConfigs {
		if dc.Provider == ProviderIONOS {
			configDomains[strings.ToLower(strings.TrimSuffix(dc.FQDN, "."))] = struct{}{}
		}
	}

	for _, zone := range zones {
		records, exists := recordCache.Get(zone.ID)
		if !exists {
			continue
		}

		zoneName := strings.ToLower(strings.TrimSuffix(zone.Name, "."))

		for _, rec := range records {
			if rec.Type != "A" && rec.Type != "AAAA" {
				continue
			}

			var fqdn string

			switch {
			case rec.Name == "@":
				fqdn = zoneName
			case rec.Name == zoneName:
				fqdn = zoneName
			case strings.HasSuffix(rec.Name, "."+zoneName):
				fqdn = rec.Name
			default:
				fqdn = rec.Name + "." + zoneName
			}

			fqdn = strings.ToLower(strings.TrimSuffix(fqdn, "."))

			if _, ok := configDomains[fqdn]; ok {
				continue
			}

			debugLog(
				"MAINTENANCE",
				fqdn,
				fmt.Sprintf("🗑️ Entferne verwaisten %s Record (ID: %s)", rec.Type, rec.ID),
			)

			if cfg.DryRun {
				log(LogContext{
					Level:   LogInfo,
					Action:  ActionCleanup,
					Domain:  fqdn,
					Message: "⚠️ Dry-Run: Record wäre gelöscht worden",
				})
				continue
			}

			url := fmt.Sprintf("%s/%s/records/%s", ionosBaseURL, zone.ID, rec.ID)

			if _, err := ionosAPI(ctx, ionosDC, "DELETE", url, nil); err != nil {
				debugLog("MAINTENANCE", fqdn, fmt.Sprintf("❌ Fehler beim Löschen: %v", err))
			} else {
				log(LogContext{
					Level:   LogInfo,
					Action:  ActionCleanup,
					Domain:  fqdn,
					Message: fmt.Sprintf("✅ %s Record entfernt (nicht mehr konfiguriert)", rec.Type),
				})
			}
		}
	}
}
