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
	return filepath.Join(cfg.LogDir, filename)
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

func buildProviderConfigDomains(provider ProviderType) map[string]struct{} {
	cfgMu.RLock()
	defer cfgMu.RUnlock()

	out := make(map[string]struct{})
	for _, dc := range cfg.DomainConfigs {
		if dc.Provider != provider {
			continue
		}

		fqdn := normalizeProviderFQDN(dc.FQDN)
		if fqdn != "" {
			out[fqdn] = struct{}{}
		}
	}

	return out
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
	attempt int,
	serverBusy bool,
) (bool, error) {
	debugLog("HTTP", "", fmt.Sprintf("❌ %s network error: %v | latency: %v", providerName, err, duration))
	apiMetrics.RecordError(method, 0, err, duration)

	wait := calculateRetryDelay(attempt, serverBusy)
	debugLog("HTTP", "", fmt.Sprintf("⏱️  %s %v", T.RetryIn, wait))

	if !sleepOrCancel(ctx, wait) {
		return false, fmt.Errorf("%s: %w", T.ErrContextCancelled, ctx.Err())
	}

	return true, fmt.Errorf("%s: %w", T.ErrNetworkError, err)
}

func handleProviderReadError(
	ctx context.Context,
	providerName, method string,
	statusCode int,
	err error,
	duration time.Duration,
	attempt int,
) (bool, error) {
	debugLog("HTTP", "", fmt.Sprintf("❌ %s body read error: %v", providerName, err))
	apiMetrics.RecordError(method, statusCode, err, duration)

	wait := calculateRetryDelay(attempt, false)
	if !sleepOrCancel(ctx, wait) {
		return false, fmt.Errorf("%s: %w", T.ErrContextCancelled, ctx.Err())
	}

	return true, fmt.Errorf("%s: %w", T.ErrBodyRead, err)
}

func handleProviderHTTPResponse(
	ctx context.Context,
	providerName string,
	maxAttemptsPrefix string,
	res *http.Response,
	method, apiURL string,
	duration time.Duration,
	attempt int,
) ([]byte, bool, error) {
	respBody, readErr := readResponseBody(res)
	if readErr != nil {
		retry, handledErr := handleProviderReadError(ctx, providerName, method, res.StatusCode, readErr, duration, attempt)
		return nil, retry, handledErr
	}

	if res.StatusCode >= 200 && res.StatusCode < 300 {
		apiMetrics.RecordSuccess(method, duration)
		lastErrorMsg.Set("")
		debugLog("HTTP", "", fmt.Sprintf("✅ %s success: %d bytes", providerName, len(respBody)))
		return respBody, false, nil
	}

	apiErr := classifyAPIErrorWithHeaders(res.StatusCode, method, apiURL, string(respBody), res.Header)
	retry, handledErr := handleProviderAPIError(ctx, providerName, maxAttemptsPrefix, apiErr, method, res.StatusCode, duration, attempt)
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
	attempt int,
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

	if attempt >= cfg.MaxAPIRetries-1 {
		if maxAttemptsPrefix != "" {
			return false, fmt.Errorf("%s: %w", maxAttemptsPrefix, apiErr)
		}
		return false, apiErr
	}

	wait := providerRetryWait(apiErr, attempt, statusCode)
	debugLog("HTTP", "", fmt.Sprintf("🔄 %s retry #%d in %v", providerName, attempt+2, wait))

	if !sleepOrCancel(ctx, wait) {
		return false, fmt.Errorf("%s: %w", T.ErrContextCancelled, ctx.Err())
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
