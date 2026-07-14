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
	result := domainUpdateResult{
		Domain: job.Domain,
		IPv4:   job.IPv4,
		IPv6:   job.IPv6,
	}

	if isCNAMEDomainConfig(dc) {
		if !dc.CNAMEPending {
			debugLog("DNS-LOGIC", job.Domain, "CNAME unchanged; automatic scheduler update skipped")
			return result
		}
		return processCNAMEDomainUpdate(ctx, dc, job, result, cache)
	}

	ipMode := domainIPMode(dc)

	if dc.Provider == ProviderIPv64 {
		return processIPv64DomainUpdate(ctx, dc, job, result, ipMode)
	}

	if dc.Provider == ProviderFebas {
		return processFebasDomainUpdate(ctx, dc, job, result, ipMode, cache)
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

// ============================================================================
// CNAME SUPPORT
// ============================================================================

// isCNAMEDomainConfig reports whether a domain is configured to receive a
// static CNAME record instead of the usual A/AAAA address records.
func isCNAMEDomainConfig(dc *DomainConfig) bool {
	if dc == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(dc.RecordMode), RecordModeCNAME) &&
		strings.TrimSpace(dc.CNAMETarget) != ""
}

// cnameCapableProviders lists the providers whose update functions accept an
// arbitrary record type/value pair. Febas and IPv64 speak classic
// IP-only DynDNS update protocols and cannot represent a CNAME target.
func cnameCapableProvider(provider ProviderType) bool {
	switch provider {
	case ProviderCloudflare, ProviderIONOS, ProviderHetzner, ProviderHetznerCloud, ProviderDNScale:
		return true
	default:
		return false
	}
}

func processCNAMEDomainUpdate(
	ctx context.Context,
	dc *DomainConfig,
	job domainUpdateJob,
	result domainUpdateResult,
	cache *ZoneRecordCache,
) domainUpdateResult {
	if !cnameCapableProvider(dc.Provider) {
		result.Error = fmt.Errorf("provider %s does not support CNAME records", dc.Provider)
		return result
	}

	target := normalizeDomainName(strings.TrimSpace(dc.CNAMETarget))
	if target == "" {
		result.Error = fmt.Errorf("CNAME target is empty for %s", job.Domain)
		return result
	}

	debugLog("DNS-LOGIC", job.Domain, fmt.Sprintf("CNAME mode: %s -> %s", job.Domain, target))

	changed, err := updateDomainRecord(ctx, dc, job, cache, RecordTypeCNAME, target)
	if err != nil {
		if isNonRecoverableError(err) {
			result.Error = fmt.Errorf("non-recoverable CNAME error: %w", err)
			return result
		}
		result.Error = fmt.Errorf("CNAME update failed: %w", err)
		return result
	}

	result.Changed = changed

	if err := markCNAMEApplied(job.Domain, dc.Provider, target); err != nil {
		result.Error = fmt.Errorf("CNAME was applied, but its pending state could not be saved: %w", err)
		return result
	}

	return result
}

// markCNAMEApplied clears the one-shot update flag only if the dashboard
// configuration still points to the value that was just confirmed at the
// provider. A concurrent dashboard change therefore remains pending.
func markCNAMEApplied(fqdn string, provider ProviderType, target string) error {
	wantedFQDN := normalizeDomainName(fqdn)
	wantedTarget := normalizeDomainName(target)
	found := false

	cfgMu.Lock()
	for i := range cfg.DomainConfigs {
		dc := &cfg.DomainConfigs[i]
		if normalizeDomainName(dc.FQDN) != wantedFQDN || dc.Provider != provider {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(dc.RecordMode), RecordModeCNAME) ||
			normalizeDomainName(dc.CNAMETarget) != wantedTarget {
			break
		}

		dc.CNAMEPending = false
		found = true
		break
	}
	cfgMu.Unlock()

	if !found {
		return nil
	}
	return saveConfigToFile()
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
		debugLog("SCHEDULER", "", t(phrases().DomainLoopCancelled, "Domain loop aborted: context cancelled"))
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
					Message: fmt.Sprintf(t(phrases().PanicOccurred, "Panic: %v"), r),
				})

				results <- domainUpdateResult{
					Domain: domainConfig.FQDN,
					Error:  fmt.Errorf("panic in domain worker: %v", r),
				}
			}
		}()

		if err := ctx.Err(); err != nil {
			results <- domainUpdateResult{
				Domain: domainConfig.FQDN,
				Error:  fmt.Errorf("domain update cancelled before start: %w", err),
			}
			return
		}
		if !acquireWorkerSlot(ctx, domainConfig.FQDN) {
			err := ctx.Err()
			if err == nil {
				err = context.Canceled
			}
			results <- domainUpdateResult{
				Domain: domainConfig.FQDN,
				Error:  fmt.Errorf("worker slot acquisition cancelled: %w", err),
			}
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
	if workerLimiter.Acquire(ctx) {
		debugLog("WORKER", fqdn, t(phrases().WorkerSlotAcquired, "Worker slot acquired"))
		return true
	}

	debugLog("WORKER", fqdn, t(phrases().WorkerCancelledContext, "Cancelled: context cancelled"))
	return false
}

func releaseWorkerSlot(fqdn string) {
	debugLog("WORKER", fqdn, t(phrases().WorkerSlotReleased, "Worker slot released"))
	workerLimiter.Release()
}

func buildDomainUpdateJob(
	dc *DomainConfig,
	zonesByProvider map[string][]Zone,
	cache *ZoneRecordCache,
	ipv4, ipv6 string,
) (domainUpdateJob, error) {
	zones, exists := zonesByProvider[string(dc.Provider)]
	if !exists || len(zones) == 0 {
		debugLog("DNS-LOGIC", dc.FQDN, phrases().NoZoneFoundForDomain)
		return domainUpdateJob{}, fmt.Errorf(
			t(phrases().NoZonesFoundForProvider, "No zones found for provider %s"),
			dc.Provider,
		)
	}

	matchedZone := findMatchedZoneForDomain(dc.FQDN, zones)
	if matchedZone == nil {
		debugLog("DNS-LOGIC", dc.FQDN, phrases().NoZoneFoundForDomain)
		return domainUpdateJob{}, fmt.Errorf("%s", t(phrases().NoZoneFound, "No zone found"))
	}

	if matchedZone.ID == "" {
		return domainUpdateJob{}, fmt.Errorf("%s", t(phrases().MatchedZoneEmptyID, "Matched zone has empty ID"))
	}

	records, exists := cache.Get(matchedZone.ID)
	if !exists && dc.Provider != ProviderIPv64 {
		debugLog("DNS-LOGIC", dc.FQDN, phrases().NoRecordsInCache)
		return domainUpdateJob{}, fmt.Errorf("%s", t(phrases().NoRecordsInCache, "no records in cache"))
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
	bestIndex := -1
	bestNameLength := -1

	for i := range zones {
		zn := normalizeDomainName(zones[i].Name)
		if zn == "" || (dn != zn && !strings.HasSuffix(dn, "."+zn)) {
			continue
		}

		if len(zn) > bestNameLength {
			bestIndex = i
			bestNameLength = len(zn)
		}
	}

	if bestIndex < 0 {
		return nil
	}
	return &zones[bestIndex]
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
		debugLog("STATUS", dc.FQDN, phrases().ChangesDetected)

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
		debugLog("STATUS", dc.FQDN, phrases().NoChangesNeeded)
	}

	return result
}

func finalizeDomainResults(results <-chan domainUpdateResult, totalDomains int) int {
	successCount := 0
	errorCount := 0
	receivedCount := 0

	for result := range results {
		receivedCount++
		if result.Error != nil {
			errorCount++
			log(LogContext{
				Level:   LogError,
				Action:  ActionError,
				Domain:  result.Domain,
				Message: fmt.Sprintf("%s: %v", phrases().UpdateFailed, result.Error),
			})
			continue
		}
		if result.Changed {
			successCount++
		}
	}

	missingResults := totalDomains - receivedCount
	if missingResults > 0 {
		errorCount += missingResults
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: fmt.Sprintf("%d domain worker result(s) missing", missingResults),
		})
	}

	if totalDomains > 0 {
		lastOk.Store(errorCount == 0 && receivedCount == totalDomains)
	}
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
	dc *DomainConfig,
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

	changed, err := updateIPv64DNS(ctx, dc, job.Domain, ipv4, ipv6)
	result.Changed = changed
	if err != nil {
		if isNonRecoverableError(err) {
			result.Error = fmt.Errorf(t(phrases().NonRecoverableIPv64Error, "Non-recoverable IPv64 error: %w"), err)
			return result
		}
		result.Error = fmt.Errorf("IPv64 update failed: %w", err)
		return result
	}

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

	debugLog("DNS-LOGIC", job.Domain, phrases().CheckingIPv4)

	changed, err := updateDomainRecord(ctx, dc, job, cache, RecordTypeA, job.IPv4)
	if err != nil {
		if isNonRecoverableError(err) {
			return changed, fmt.Errorf(t(phrases().NonRecoverableIPv4Error, "Non-recoverable IPv4 error: %w"), err)
		}
		return changed, fmt.Errorf("IPv4 update failed: %w", err)
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

	debugLog("DNS-LOGIC", job.Domain, phrases().CheckingIPv6)

	changed, err := updateDomainRecord(ctx, dc, job, cache, RecordTypeAAAA, job.IPv6)
	if err != nil {
		if isNonRecoverableError(err) {
			return changed, fmt.Errorf(t(phrases().NonRecoverableIPv6Error, "Non-recoverable IPv6 error: %w"), err)
		}
		return changed, fmt.Errorf("IPv6 update failed: %w", err)
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
	case ProviderDNScale:
		return updateDNScaleDNS(ctx, dc, job.Domain, recordType, ip, job.Records, job.ZoneID, job.ZoneName, cache)
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
