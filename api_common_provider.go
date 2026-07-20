// Package main
package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

// ============================================================================
// COMMON PROVIDER CACHE PERSISTENCE
// ============================================================================

func providerCachePath(filename string) string {
	cfgMu.RLock()
	logDir := cfg.LogDir
	cfgMu.RUnlock()

	return filepath.Join(logDir, filename)
}

func saveProviderCacheToFile(providerLabel, filename string, zones []Zone, recordCache *ZoneRecordCache) error {
	return saveDNSProviderCacheToFile(providerLabel, providerCachePath(filename), zones, recordCache)
}

func loadProviderCacheFromFile(providerLabel, filename string) ([]Zone, *ZoneRecordCache, error) {
	return loadDNSProviderCacheFromFile(providerLabel, providerCachePath(filename))
}

// ============================================================================
// COMMON PROVIDER CONFIG / DNS HELPERS
// ============================================================================

func normalizeProviderFQDN(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

func isAddressRecord(recordType string) bool {
	return recordType == RecordTypeA || recordType == RecordTypeAAAA
}

func managedRecordKey(fqdn, recordType string) string {
	return normalizeProviderFQDN(fqdn) + "\x00" + strings.ToUpper(strings.TrimSpace(recordType))
}

func buildProviderConfigRecords(provider ProviderType) map[string]struct{} {
	cfgMu.RLock()
	defer cfgMu.RUnlock()

	out := make(map[string]struct{})
	for i := range cfg.DomainConfigs {
		dc := &cfg.DomainConfigs[i]
		if dc.Provider != provider {
			continue
		}

		fqdn := normalizeProviderFQDN(dc.FQDN)
		if fqdn == "" {
			continue
		}

		if isCNAMEDomainConfig(dc) {
			out[managedRecordKey(fqdn, RecordTypeCNAME)] = struct{}{}

			continue
		}

		switch domainIPMode(dc) {
		case IPModeV4:
			out[managedRecordKey(fqdn, RecordTypeA)] = struct{}{}
		case IPModeV6:
			out[managedRecordKey(fqdn, RecordTypeAAAA)] = struct{}{}
		default:
			out[managedRecordKey(fqdn, RecordTypeA)] = struct{}{}
			out[managedRecordKey(fqdn, RecordTypeAAAA)] = struct{}{}
		}
	}

	return out
}

func dnsRecordContentEqual(recordType, current, desired string) bool {
	current = strings.TrimSpace(current)
	desired = strings.TrimSpace(desired)

	if strings.EqualFold(strings.TrimSpace(recordType), RecordTypeCNAME) {
		return normalizeDomainName(current) == normalizeDomainName(desired)
	}

	return current == desired
}

func findProviderConfigForCleanup(provider ProviderType) *DomainConfig {
	cfgMu.RLock()
	defer cfgMu.RUnlock()

	for i := range cfg.DomainConfigs {
		if cfg.DomainConfigs[i].Provider == provider {
			dc := cfg.DomainConfigs[i]

			return &dc
		}
	}

	return nil
}

func buildProviderManagedDomains(provider ProviderType) map[string]struct{} {
	managed := make(map[string]struct{})

	domains, err := snapshotStatusDomains()
	if err != nil {
		debugLog("MAINTENANCE", "", fmt.Sprintf("%s managed-domain snapshot failed: %v", provider, err))

		return managed
	}

	for fqdn, history := range domains {
		if strings.EqualFold(strings.TrimSpace(history.Provider), string(provider)) {
			managed[normalizeDomainName(fqdn)] = struct{}{}
		}
	}

	return managed
}

// ============================================================================
// COMMON HTTP BODY / RETRY HANDLING
// ============================================================================

func readResponseBody(res *http.Response) ([]byte, error) {
	return io.ReadAll(res.Body)
}

func providerRetryWait(apiErr *APIError, attempt, statusCode int) time.Duration {
	if apiErr != nil && apiErr.RetryAfter > 0 {
		return apiErr.RetryAfter
	}

	serverBusy := statusCode == http.StatusTooManyRequests || statusCode >= 500

	return calculateRetryDelay(attempt, serverBusy)
}

func handleProviderNetworkError(
	ctx context.Context,
	providerName, method string,
	err error,
	duration time.Duration,
	attempt, maxAttempts int,
	serverBusy bool,
) (bool, error) {
	debugLog("HTTP", "", fmt.Sprintf("❌ %s network error: %v | latency: %v", providerName, err, duration))
	apiMetrics.RecordError(method, 0, err, duration)

	handledErr := fmt.Errorf("%s: %w", phrases().ErrNetworkError, err)
	if !canRetryAPIAttempt(attempt, maxAttempts) {
		return false, handledErr
	}

	wait := calculateRetryDelay(attempt, serverBusy)
	debugLog("HTTP", "", fmt.Sprintf("⏱️  %s %v", phrases().RetryIn, wait))

	if !sleepOrCancel(ctx, wait) {
		return false, fmt.Errorf("%s: %w", phrases().ErrContextCancelled, ctx.Err())
	}

	return true, handledErr
}

func handleProviderReadError(
	ctx context.Context,
	providerName, method string,
	statusCode int,
	err error,
	duration time.Duration,
	attempt, maxAttempts int,
) (bool, error) {
	debugLog("HTTP", "", fmt.Sprintf("❌ %s body read error: %v", providerName, err))
	apiMetrics.RecordError(method, statusCode, err, duration)

	handledErr := fmt.Errorf("%s: %w", phrases().ErrBodyRead, err)
	if !canRetryAPIAttempt(attempt, maxAttempts) {
		return false, handledErr
	}

	wait := calculateRetryDelay(attempt, false)
	if !sleepOrCancel(ctx, wait) {
		return false, fmt.Errorf("%s: %w", phrases().ErrContextCancelled, ctx.Err())
	}

	return true, handledErr
}

func handleProviderHTTPResponse(
	ctx context.Context,
	providerName string,
	maxAttemptsPrefix string,
	res *http.Response,
	method, apiURL string,
	duration time.Duration,
	attempt, maxAttempts int,
) ([]byte, bool, error) {
	respBody, readErr := readResponseBody(res)
	if readErr != nil {
		retry, handledErr := handleProviderReadError(ctx, providerName, method, res.StatusCode, readErr, duration, attempt, maxAttempts)

		return nil, retry, handledErr
	}

	if res.StatusCode >= 200 && res.StatusCode < 300 {
		apiMetrics.RecordSuccess(method, duration)
		lastErrorMsg.Set("")
		debugLog("HTTP", "", fmt.Sprintf("✅ %s success: %d bytes", providerName, len(respBody)))

		return respBody, false, nil
	}

	apiErr := classifyAPIErrorWithHeaders(res.StatusCode, method, apiURL, string(respBody), res.Header)
	retry, handledErr := handleProviderAPIError(ctx, providerName, maxAttemptsPrefix, apiErr, method, res.StatusCode, duration, attempt, maxAttempts)

	return nil, retry, handledErr
}

func handleProviderAPIError(
	ctx context.Context,
	providerName string,
	maxAttemptsPrefix string,
	apiErr *APIError,
	method string,
	statusCode int,
	duration time.Duration,
	attempt, maxAttempts int,
) (bool, error) {
	apiMetrics.RecordError(method, statusCode, apiErr, duration)
	lastErrorMsg.Set(sanitizeError(apiErr))

	if statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden {
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: fmt.Sprintf("🚨 %s auth error: %v", providerName, apiErr),
		})
	}

	debugLog("HTTP", "", fmt.Sprintf("%s retryable: %v", providerName, apiErr.IsRetryable()))

	if !apiErr.IsRetryable() {
		return false, apiErr
	}

	if !canRetryAPIAttempt(attempt, maxAttempts) {
		if maxAttemptsPrefix != "" {
			return false, fmt.Errorf("%s: %w", maxAttemptsPrefix, apiErr)
		}

		return false, apiErr
	}

	wait := providerRetryWait(apiErr, attempt, statusCode)
	debugLog("HTTP", "", fmt.Sprintf("🔄 %s retry #%d in %v", providerName, attempt+2, wait))

	if !sleepOrCancel(ctx, wait) {
		return false, fmt.Errorf("%s: %w", phrases().ErrContextCancelled, ctx.Err())
	}

	return true, apiErr
}

// ============================================================================
// COMMON ZONE RECORD CACHE UPDATE
// ============================================================================

type (
	cachedRecordMatchFunc  func(Record) bool
	cachedRecordUpdateFunc func(*Record)
	cachedRecordCreateFunc func(existingRecords []Record) *Record
)

func updateCachedZoneRecord(
	cache *ZoneRecordCache,
	zoneID string,
	match cachedRecordMatchFunc,
	update cachedRecordUpdateFunc,
	create cachedRecordCreateFunc,
) bool {
	if cache == nil {
		return false
	}

	records, ok := cache.Get(zoneID)
	if !ok {
		return false
	}

	for i := range records {
		if match(records[i]) {
			update(&records[i])
			cache.Set(zoneID, records)

			return true
		}
	}

	if create == nil {
		return false
	}

	newRecord := create(records)
	if newRecord == nil {
		return false
	}

	records = append(records, *newRecord)
	cache.Set(zoneID, records)

	return true
}

func syntheticCachedRecordID(records []Record) string {
	return fmt.Sprintf("new-%d", len(records))
}
