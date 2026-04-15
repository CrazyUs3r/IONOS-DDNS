// Package main
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
			debugLog("SCHEDULER", "", t(T.DomainLoopCancelled, "Domain loop aborted: context cancelled"))
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
						Message: fmt.Sprintf(t(T.PanicOccurred, "Panic: %v"), r),
					})
				}
			}()

			if ctx.Err() != nil {
				return
			}

			select {
			case workerSemaphore <- struct{}{}:
				debugLog("WORKER", domainConfig.FQDN, t(T.WorkerSlotAcquired, "Worker slot acquired"))
			case <-ctx.Done():
				debugLog("WORKER", domainConfig.FQDN, t(T.WorkerCancelledContext, "Cancelled: context cancelled"))
				return
			}

			defer func() {
				debugLog("WORKER", domainConfig.FQDN, t(T.WorkerSlotReleased, "Worker slot released"))
				<-workerSemaphore
			}()

			if ctx.Err() != nil {
				debugLog("WORKER", domainConfig.FQDN, t(T.ContextExpired, "Timeout (Context Expired)"))
				return
			}

			zones, exists := zonesByProvider[string(domainConfig.Provider)]
			if !exists || len(zones) == 0 {
				debugLog("DNS-LOGIC", domainConfig.FQDN, T.NoZoneFoundForDomain)
				results <- domainUpdateResult{
					Domain: domainConfig.FQDN,
					Error:  fmt.Errorf(t(T.NoZonesFoundForProvider, "No zones found for provider %s"), domainConfig.Provider),
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
					Error:  fmt.Errorf("%s", t(T.NoZoneFound, "No zone found")),
				}
				return
			}

			zoneID := matchedZone.ID
			if zoneID == "" {
				results <- domainUpdateResult{
					Domain: domainConfig.FQDN,
					Error:  fmt.Errorf("%s", t(T.MatchedZoneEmptyID, "Matched zone has empty ID")),
				}
				return
			}

			records, exists := cache.Get(zoneID)
			if !exists && domainConfig.Provider != ProviderIPv64 {
				debugLog("DNS-LOGIC", domainConfig.FQDN, T.NoRecordsInCache)
				results <- domainUpdateResult{
					Domain: domainConfig.FQDN,
					Error:  fmt.Errorf("%s", t(T.NoRecordsInCache, "no records in cache")),
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

			result := processDomainUpdate(ctx, domainConfig, job, cache)

			providerName := string(domainConfig.Provider)

			if result.Changed && !cfg.DryRun {
				debugLog("STATUS", domainConfig.FQDN, T.ChangesDetected)
				v4 := result.IPv4
				v6 := result.IPv6
				if v4 == "" {
					v4 = ipv4
				}
				if v6 == "" {
					v6 = ipv6
				}
				updateStatusFile(domainConfig.FQDN, v4, v6, providerName)
			} else if result.Error == nil {
				debugLog("STATUS", domainConfig.FQDN, T.NoChangesNeeded)
			}
			results <- result
		}(dc)
	}

	wg.Wait()
	close(results)

	successCount := 0
	errorCount := 0
	totalDomains := len(cfg.DomainConfigs)

	for result := range results {
		if result.Error != nil {
			errorCount++
			log(LogContext{
				Level:   LogError,
				Action:  ActionError,
				Domain:  result.Domain,
				Message: fmt.Sprintf("%s: %v", T.UpdateFailed, result.Error),
			})
		} else if result.Changed {
			successCount++
		}
	}
	allOk := errorCount == 0 && totalDomains > 0
	lastOk.Store(allOk)
	schedulerRanOnce.Store(true)

	if errorCount > 0 {
		debugLog("SCHEDULER", "",
			fmt.Sprintf("⚠️ %d/%d domains failed", errorCount, totalDomains))
	}

	return successCount

}

func processDomainUpdate(ctx context.Context, dc *DomainConfig, job domainUpdateJob, cache *ZoneRecordCache) domainUpdateResult {
	result := domainUpdateResult{
		Domain: job.Domain,
		IPv4:   job.IPv4,
		IPv6:   job.IPv6,
	}
	if dc.Provider == ProviderIPv64 {
		ipv4 := ""
		ipv6 := ""
		if cfg.IPMode != "IPV6" {
			ipv4 = job.IPv4
		}
		if cfg.IPMode != "IPV4" {
			ipv6 = job.IPv6
		}

		changed, err := updateIPv64DNS(ctx, job.Domain, ipv4, ipv6)
		if err != nil {
			if isNonRecoverableError(err) {
				result.Error = fmt.Errorf(t(T.NonRecoverableIPv64Error, "Non-recoverable IPv64 error: %w"), err)
				return result
			}
			debugLog("DNS-LOGIC", job.Domain, fmt.Sprintf("%s IPv64: %v", T.UpdateFailed, err))
		}
		result.Changed = changed
		return result
	}

	v4Changed, v6Changed := false, false

	if cfg.IPMode != "IPV6" && job.IPv4 != "" {
		debugLog("DNS-LOGIC", job.Domain, T.CheckingIPv4)

		var changed bool
		var err error

		switch dc.Provider {
		case ProviderCloudflare:
			changed, err = updateCloudflareDNS(ctx, dc, job.Domain, "A", job.IPv4, job.Records, job.ZoneID)
		default:
			changed, err = updateDNS(ctx, dc, job.Domain, "A", job.IPv4, job.Records, job.ZoneID, job.ZoneName, cache)
		}

		if err != nil {
			if isNonRecoverableError(err) {
				result.Error = fmt.Errorf(t(T.NonRecoverableIPv4Error, "Non-recoverable IPv4 error: %w"), err)
				return result
			}
			debugLog("DNS-LOGIC", job.Domain, fmt.Sprintf("%s IPv4: %v", T.UpdateFailed, err))
		}
		v4Changed = changed
	}

	if cfg.IPMode != "IPV4" && job.IPv6 != "" {
		debugLog("DNS-LOGIC", job.Domain, T.CheckingIPv6)

		var changed bool
		var err error

		switch dc.Provider {
		case ProviderCloudflare:
			changed, err = updateCloudflareDNS(ctx, dc, job.Domain, "AAAA", job.IPv6, job.Records, job.ZoneID)
		default:
			changed, err = updateDNS(ctx, dc, job.Domain, "AAAA", job.IPv6, job.Records, job.ZoneID, job.ZoneName, cache)
		}

		if err != nil {
			if isNonRecoverableError(err) {
				result.Error = fmt.Errorf(t(T.NonRecoverableIPv6Error, "Non-recoverable IPv6 error: %w"), err)
				return result
			}
			debugLog("DNS-LOGIC", job.Domain, fmt.Sprintf("%s IPv6: %v", T.UpdateFailed, err))
		}
		v6Changed = changed
	}

	result.Changed = v4Changed || v6Changed
	return result
}
