// Package main
package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// ============================================================================
// DNS INITIALIZATION
// ============================================================================

func processDomains(
	ctx context.Context,
	zonesByProvider map[string][]Zone,
	cache *ZoneRecordCache,
	ipv4, ipv6 string,
) int {
	domains, dryRun := snapshotProcessDomainsConfig()

	var wg sync.WaitGroup
	results := make(chan domainUpdateResult, len(domains))

	for i := range domains {
		if shouldStopDomainLoop(ctx) {
			break
		}

		dc := &domains[i]
		startDomainWorker(ctx, &wg, results, dc, zonesByProvider, cache, ipv4, ipv6, dryRun)
	}

	wg.Wait()
	close(results)

	return finalizeDomainResults(results, len(domains))
}

func processDomainUpdate(ctx context.Context, dc *DomainConfig, job domainUpdateJob, cache *ZoneRecordCache) domainUpdateResult {
	ipMode := domainIPMode(dc)

	result := domainUpdateResult{
		Domain: job.Domain,
		IPv4:   job.IPv4,
		IPv6:   job.IPv6,
	}

	if dc.Provider == ProviderIPv64 {
		return processIPv64DomainUpdate(ctx, dc, job, result, ipMode)
	}

	v4Changed, err := processDomainIPv4Update(ctx, dc, job, cache, ipMode)
	if err != nil {
		result.Error = err
		return result
	}

	v6Changed, err := processDomainIPv6Update(ctx, dc, job, cache, ipMode)
	if err != nil {
		result.Error = err
		return result
	}

	result.Changed = v4Changed || v6Changed
	return result
}

func snapshotProcessDomainsConfig() ([]DomainConfig, bool) {
	cfgMu.RLock()
	defer cfgMu.RUnlock()

	domains := make([]DomainConfig, len(cfg.DomainConfigs))
	copy(domains, cfg.DomainConfigs)

	return domains, cfg.DryRun
}

func shouldStopDomainLoop(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		debugLog("SCHEDULER", "", t(T.DomainLoopCancelled, "Domain loop aborted: context cancelled"))
		return true
	default:
		return false
	}
}

func startDomainWorker(
	ctx context.Context,
	wg *sync.WaitGroup,
	results chan<- domainUpdateResult,
	dc *DomainConfig,
	zonesByProvider map[string][]Zone,
	cache *ZoneRecordCache,
	ipv4, ipv6 string,
	dryRun bool,
) {
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

				results <- domainUpdateResult{
					Domain: domainConfig.FQDN,
					Error:  fmt.Errorf("panic in domain worker: %v", r),
				}
			}
		}()

		if ctx.Err() != nil {
			return
		}
		if !acquireWorkerSlot(ctx, domainConfig.FQDN) {
			return
		}
		defer releaseWorkerSlot(domainConfig.FQDN)
		job, err := buildDomainUpdateJob(domainConfig, zonesByProvider, cache, ipv4, ipv6)
		if err != nil {
			results <- domainUpdateResult{
				Domain: domainConfig.FQDN,
				Error:  err,
			}
			return
		}

		result := processDomainUpdate(ctx, domainConfig, job, cache)
		result = handleDomainResultStatus(domainConfig, result, ipv4, ipv6, dryRun)
		results <- result
	}(dc)
}

func acquireWorkerSlot(ctx context.Context, fqdn string) bool {
	select {
	case workerSemaphore <- struct{}{}:
		debugLog("WORKER", fqdn, t(T.WorkerSlotAcquired, "Worker slot acquired"))
		return true
	case <-ctx.Done():
		debugLog("WORKER", fqdn, t(T.WorkerCancelledContext, "Cancelled: context cancelled"))
		return false
	}
}

func releaseWorkerSlot(fqdn string) {
	debugLog("WORKER", fqdn, t(T.WorkerSlotReleased, "Worker slot released"))
	<-workerSemaphore
}

func buildDomainUpdateJob(
	dc *DomainConfig,
	zonesByProvider map[string][]Zone,
	cache *ZoneRecordCache,
	ipv4, ipv6 string,
) (domainUpdateJob, error) {
	zones, exists := zonesByProvider[string(dc.Provider)]
	if !exists || len(zones) == 0 {
		debugLog("DNS-LOGIC", dc.FQDN, T.NoZoneFoundForDomain)
		return domainUpdateJob{}, fmt.Errorf(
			t(T.NoZonesFoundForProvider, "No zones found for provider %s"),
			dc.Provider,
		)
	}

	matchedZone := findMatchedZoneForDomain(dc.FQDN, zones)
	if matchedZone == nil {
		debugLog("DNS-LOGIC", dc.FQDN, T.NoZoneFoundForDomain)
		return domainUpdateJob{}, fmt.Errorf("%s", t(T.NoZoneFound, "No zone found"))
	}

	if matchedZone.ID == "" {
		return domainUpdateJob{}, fmt.Errorf("%s", t(T.MatchedZoneEmptyID, "Matched zone has empty ID"))
	}

	records, exists := cache.Get(matchedZone.ID)
	if !exists && dc.Provider != ProviderIPv64 {
		debugLog("DNS-LOGIC", dc.FQDN, T.NoRecordsInCache)
		return domainUpdateJob{}, fmt.Errorf("%s", t(T.NoRecordsInCache, "no records in cache"))
	}

	return domainUpdateJob{
		Domain:   dc.FQDN,
		ZoneID:   matchedZone.ID,
		ZoneName: matchedZone.Name,
		Records:  records,
		IPv4:     ipv4,
		IPv6:     ipv6,
	}, nil
}

func findMatchedZoneForDomain(fqdn string, zones []Zone) *Zone {
	dn := normalizeDomainName(fqdn)

	for i := range zones {
		zn := normalizeDomainName(zones[i].Name)
		if dn == zn || strings.HasSuffix(dn, "."+zn) {
			return &zones[i]
		}
	}

	return nil
}

func normalizeDomainName(name string) string {
	return strings.TrimSuffix(strings.ToLower(name), ".")
}

func handleDomainResultStatus(
	dc *DomainConfig,
	result domainUpdateResult,
	ipv4, ipv6 string,
	dryRun bool,
) domainUpdateResult {
	providerName := string(dc.Provider)

	if result.Error == nil && result.Changed && !dryRun {
		debugLog("STATUS", dc.FQDN, T.ChangesDetected)

		v4 := result.IPv4
		v6 := result.IPv6
		if v4 == "" {
			v4 = ipv4
		}
		if v6 == "" {
			v6 = ipv6
		}

		if err := updateStatusFile(dc.FQDN, v4, v6, providerName); err != nil {
			result.Error = fmt.Errorf("DNS updated, but update.json was not written: %w", err)
		}

		return result
	}

	if result.Error == nil {
		debugLog("STATUS", dc.FQDN, T.NoChangesNeeded)
	}

	return result
}

func finalizeDomainResults(results <-chan domainUpdateResult, totalDomains int) int {
	successCount := 0
	errorCount := 0

	for result := range results {
		if result.Error != nil {
			errorCount++
			log(LogContext{
				Level:   LogError,
				Action:  ActionError,
				Domain:  result.Domain,
				Message: fmt.Sprintf("%s: %v", T.UpdateFailed, result.Error),
			})
			continue
		}

		if result.Changed {
			successCount++
		}
	}

	allOk := errorCount == 0 && totalDomains > 0
	lastOk.Store(allOk)
	schedulerRanOnce.Store(true)

	if errorCount > 0 {
		debugLog("SCHEDULER", "", fmt.Sprintf("⚠️ %d/%d domains failed", errorCount, totalDomains))
	}

	return successCount
}

func currentIPMode() string {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	return cfg.IPMode
}

func processIPv64DomainUpdate(
	ctx context.Context,
	_ *DomainConfig,
	job domainUpdateJob,
	result domainUpdateResult,
	ipMode string,
) domainUpdateResult {
	ipv4 := ""
	ipv6 := ""

	if ipMode != IPModeV6 {
		ipv4 = job.IPv4
	}
	if ipMode != IPModeV4 {
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

func processDomainIPv4Update(
	ctx context.Context,
	dc *DomainConfig,
	job domainUpdateJob,
	cache *ZoneRecordCache,
	ipMode string,
) (bool, error) {
	if ipMode == IPModeV6 || job.IPv4 == "" {
		return false, nil
	}

	debugLog("DNS-LOGIC", job.Domain, T.CheckingIPv4)

	changed, err := updateDomainRecord(ctx, dc, job, cache, RecordTypeA, job.IPv4)
	if err != nil {
		if isNonRecoverableError(err) {
			return false, fmt.Errorf(t(T.NonRecoverableIPv4Error, "Non-recoverable IPv4 error: %w"), err)
		}
		debugLog("DNS-LOGIC", job.Domain, fmt.Sprintf("%s IPv4: %v", T.UpdateFailed, err))
	}

	return changed, nil
}

func processDomainIPv6Update(
	ctx context.Context,
	dc *DomainConfig,
	job domainUpdateJob,
	cache *ZoneRecordCache,
	ipMode string,
) (bool, error) {
	if ipMode == IPModeV4 || job.IPv6 == "" {
		return false, nil
	}

	debugLog("DNS-LOGIC", job.Domain, T.CheckingIPv6)

	changed, err := updateDomainRecord(ctx, dc, job, cache, RecordTypeAAAA, job.IPv6)
	if err != nil {
		if isNonRecoverableError(err) {
			return false, fmt.Errorf(t(T.NonRecoverableIPv6Error, "Non-recoverable IPv6 error: %w"), err)
		}
		debugLog("DNS-LOGIC", job.Domain, fmt.Sprintf("%s IPv6: %v", T.UpdateFailed, err))
	}

	return changed, nil
}

func updateDomainRecord(
	ctx context.Context,
	dc *DomainConfig,
	job domainUpdateJob,
	cache *ZoneRecordCache,
	recordType, ip string,
) (bool, error) {
	switch dc.Provider {
	case ProviderCloudflare:
		return updateCloudflareDNS(ctx, dc, job.Domain, recordType, ip, job.Records, job.ZoneID)
	case ProviderIONOS:
		return updateIonosDNS(ctx, dc, job.Domain, recordType, ip, job.Records, job.ZoneID, job.ZoneName, cache)
	case ProviderHetzner:
		return updateHetznerDNS(ctx, dc, job.Domain, recordType, ip, job.Records, job.ZoneID, job.ZoneName, cache)
	case ProviderHetznerCloud:
		return updateHetznerCloudDNS(ctx, dc, job.Domain, recordType, ip, job.Records, job.ZoneID, job.ZoneName, cache)
	default:
		return false, fmt.Errorf("unknown provider: %s", dc.Provider)
	}
}

func domainIPMode(dc *DomainConfig) string {
	if dc != nil && dc.IPMode != "" {
		m := strings.ToUpper(dc.IPMode)
		if m == IPModeV4 || m == IPModeV6 || m == IPModeBoth {
			return m
		}
	}
	return currentIPMode()
}
