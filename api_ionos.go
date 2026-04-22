// Package main
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ============================================================================
// CACHE PERSISTENCE - IONOS
// ============================================================================
func getIONOSCachePath() string {
	return filepath.Join(cfg.LogDir, "ionos_cache.json")
}

func saveIONOSCacheToFile(zones []Zone, recordCache *ZoneRecordCache) error {
	if recordCache == nil {
		return fmt.Errorf("%s", T.ErrRecordCacheNil)
	}

	cachePath := getIONOSCachePath()
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		return fmt.Errorf("%s: %w", T.ErrCacheDirCreate, err)
	}

	cache := IONOSCache{
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

	debugLog("CACHE", "", fmt.Sprintf(T.CacheSavedZones, "IONOS", len(zones), totalRecords))
	return nil
}

func loadIONOSCacheFromFile() ([]Zone, *ZoneRecordCache, error) {
	cachePath := getIONOSCachePath()

	data, err := os.ReadFile(cachePath)
	if err != nil {
		if os.IsNotExist(err) {
			debugLog("CACHE", "", fmt.Sprintf(T.CacheFileNotFound, "IONOS"))
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("failed to read cache: %w", err)
	}

	var cache IONOSCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal cache: %w", err)
	}

	recordCache := NewZoneRecordCache()
	for zoneID, records := range cache.Records {
		recordCache.Set(zoneID, records)
	}

	age := time.Since(cache.LastUpdate)
	debugLog("CACHE", "", fmt.Sprintf(T.CacheLoadedZones, "IONOS", len(cache.Zones), age.Round(time.Second)))

	return cache.Zones, recordCache, nil
}

// ============================================================================
// API - IONOS
// ============================================================================
func ionosAPI(ctx context.Context, dc *DomainConfig, method, url string, body interface{}) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", T.ErrContextError, err)
	}

	maxRetries := cfg.MaxAPIRetries
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		respBody, retry, err := ionosAPIAttempt(ctx, dc, method, url, body, attempt, maxRetries)
		if err == nil {
			return respBody, nil
		}

		lastErr = err
		if !retry {
			return nil, err
		}
	}

	return nil, fmt.Errorf("%s: %w", fmt.Sprintf(T.IonosAPIFailed, maxRetries), lastErr)
}

func ionosAPIAttempt(
	ctx context.Context,
	dc *DomainConfig,
	method, url string,
	body interface{},
	attempt, maxRetries int,
) ([]byte, bool, error) {
	debugLog("HTTP", "", fmt.Sprintf(
		T.IonosAttempt,
		T.Attempt, attempt+1, maxRetries, method, url,
	))

	bodyBytes, err := marshalIonosBody(body)
	if err != nil {
		return nil, false, err
	}

	req, err := buildIonosRequest(ctx, dc, method, url, body, bodyBytes)
	if err != nil {
		return nil, false, err
	}

	start := time.Now().Local()
	res, err := getHTTPClient().Do(req)
	duration := time.Since(start)

	if err != nil {
		retry, handledErr := handleIonosNetworkError(ctx, method, err, duration, attempt)
		return nil, retry, handledErr
	}

	debugLog("HTTP", "", fmt.Sprintf("✅ Status: %d | %s: %v", res.StatusCode, T.AvgLatency, duration))
	return handleIonosResponse(ctx, res, method, url, duration, attempt)
}

func marshalIonosBody(body interface{}) ([]byte, error) {
	if body == nil {
		return nil, nil
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", T.ErrJSONMarshal, err)
	}

	debugLog("HTTP", "", fmt.Sprintf("📤 %s: %s", T.PayloadSent, string(bodyBytes)))
	return bodyBytes, nil
}

func buildIonosRequest(
	ctx context.Context,
	dc *DomainConfig,
	method, url string,
	body interface{},
	bodyBytes []byte,
) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", T.ErrRequestCreate, err)
	}

	if body != nil {
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(bodyBytes)), nil
		}
	}

	apiKey := strings.TrimSpace(dc.APIPrefix) + "." + strings.TrimSpace(dc.APISecret)
	req.Header.Set("X-Api-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("User-Agent", ManagedComment)

	return req, nil
}

func handleIonosNetworkError(
	ctx context.Context,
	method string,
	err error,
	duration time.Duration,
	attempt int,
) (bool, error) {
	debugLog("HTTP", "", fmt.Sprintf("❌ %s: %v | %s: %v", T.NetworkError, err, T.AvgLatency, duration))
	apiMetrics.RecordError(method, 0, err, duration)

	lastErr := fmt.Errorf("%s: %w", T.ErrNetworkError, err)
	wait := calculateRetryDelay(attempt, false)
	debugLog("HTTP", "", fmt.Sprintf("⏱️  %s %v", T.RetryIn, wait))

	if !sleepOrCancel(ctx, wait) {
		return false, fmt.Errorf("%s: %w", T.ErrContextCancelled, ctx.Err())
	}

	return true, lastErr
}

func handleIonosResponse(
	ctx context.Context,
	res *http.Response,
	method, url string,
	duration time.Duration,
	attempt int,
) ([]byte, bool, error) {
	respBody, err := io.ReadAll(res.Body)
	closeErr := res.Body.Close()
	if closeErr != nil {
		debugLog("HTTP", "", fmt.Sprintf(T.ErrBodyClose+": %v", closeErr))
	}

	if err != nil {
		retry, handledErr := handleIonosReadError(ctx, res.StatusCode, method, err, duration, attempt)
		return nil, retry, handledErr
	}

	if res.StatusCode >= 200 && res.StatusCode < 300 {
		apiMetrics.RecordSuccess(method, duration)

		if errVal := lastErrorMsg.Get(); errVal != "" {
			lastErrorMsg.Set("")
		}

		debugLog("HTTP", "", fmt.Sprintf("✅ %s: %d Bytes", T.Success, len(respBody)))
		return respBody, false, nil
	}

	retry, handledErr := handleIonosAPIError(ctx, res.StatusCode, method, url, respBody, duration, attempt)
	return nil, retry, handledErr
}

func handleIonosReadError(
	ctx context.Context,
	statusCode int,
	method string,
	err error,
	duration time.Duration,
	attempt int,
) (bool, error) {
	apiMetrics.RecordError(method, statusCode, err, duration)
	debugLog("HTTP", "", fmt.Sprintf("❌ %s: %v", T.BodyReadError, err))

	lastErr := fmt.Errorf("%s: %w", T.ErrBodyRead, err)
	wait := calculateRetryDelay(attempt, false)

	if !sleepOrCancel(ctx, wait) {
		return false, fmt.Errorf("%s: %w", T.ErrContextCancelled, ctx.Err())
	}

	return true, lastErr
}

func handleIonosAPIError(
	ctx context.Context,
	statusCode int,
	method, url string,
	respBody []byte,
	duration time.Duration,
	attempt int,
) (bool, error) {
	apiErr := classifyAPIError(statusCode, method, url, string(respBody))
	apiMetrics.RecordError(method, statusCode, apiErr, duration)

	if statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden {
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: fmt.Sprintf("🚨 %s: %v", T.CriticalAPIError, apiErr),
		})
	}

	debugLog("HTTP", "", fmt.Sprintf(T.IonosRetryable, apiErr.Message, apiErr.Retryable))
	lastErrorMsg.Set(sanitizeError(apiErr))

	if !apiErr.IsRetryable() {
		debugLog("HTTP", "", fmt.Sprintf("❌ %s: %s", T.NonRetryableError, apiErr.Message))
		return false, apiErr
	}

	if attempt >= cfg.MaxAPIRetries-1 {
		debugLog("HTTP", "", fmt.Sprintf("❌ %s (%d)", T.MaxAttemptsReached, cfg.MaxAPIRetries))
		return false, fmt.Errorf("%s: %w", T.IonosMaxAttempts, apiErr)
	}

	wait := ionosRetryWait(apiErr, attempt, statusCode)
	debugLog("HTTP", "", fmt.Sprintf("🔄 %s #%d in %v...", T.RetryScheduled, attempt+2, wait))

	if !sleepOrCancel(ctx, wait) {
		debugLog("HTTP", "", "❌ "+T.ContextCancelled)
		return false, fmt.Errorf("%s: %w", T.ErrContextCancelled, ctx.Err())
	}

	return true, apiErr
}

func ionosRetryWait(apiErr *APIError, attempt, statusCode int) time.Duration {
	if apiErr.RetryAfter > 0 {
		return apiErr.RetryAfter
	}
	return calculateRetryDelay(attempt, statusCode >= 500)
}

// ============================================================================
// DNS LOGIC - IONOS
// ============================================================================
func updateDNS(
	ctx context.Context,
	dc *DomainConfig,
	fqdn, recordType, newIP string,
	records []Record,
	zoneID string,
	zoneName string,
	cache *ZoneRecordCache,
) (bool, error) {
	recordName := recordNameFromFQDN(fqdn, zoneName)
	existing := findIonosExistingRecord(records, fqdn, recordName, recordType)

	if shouldSkipIonosUpdate(fqdn, recordType, newIP, existing) {
		return false, nil
	}

	if cfg.DryRun {
		log(LogContext{
			Level:   LogWarn,
			Action:  ActionDryRun,
			Domain:  fqdn,
			Message: fmt.Sprintf("⚠️ %s %s %s", T.WouldSet, recordType, newIP),
		})
		return true, nil
	}

	method, url, actionType, payload := buildIonosUpdateRequest(dc, fqdn, recordType, newIP, zoneID, existing)
	debugIonosUpdateRequest(fqdn, method, url, zoneName, recordType)

	if err := executeIonosDNSUpdate(ctx, dc, fqdn, recordType, newIP, method, url, payload); err != nil {
		return false, err
	}

	log(LogContext{
		Level:   LogInfo,
		Action:  actionType,
		Domain:  fqdn,
		Message: fmt.Sprintf("🔄 %s -> %s %s", recordType, newIP, T.Update),
	})

	if zoneName == "" {
		return false, fmt.Errorf(T.ErrZoneNameEmpty, fqdn)
	}

	updateIONOSCache(cache, zoneID, recordName, fqdn, recordType, newIP, existing)
	return true, nil
}

func findIonosExistingRecord(records []Record, fqdn, recordName, recordType string) *Record {
	for i := range records {
		if (records[i].Name == fqdn || records[i].Name == recordName) && records[i].Type == recordType {
			existing := &records[i]
			debugLog("DNS-LOGIC", fqdn,
				fmt.Sprintf("📌 %s: %s (ID: %s)", T.RecordFound, existing.Content, existing.ID))
			return existing
		}
	}
	return nil
}

func shouldSkipIonosUpdate(fqdn, recordType, newIP string, existing *Record) bool {
	if existing != nil && existing.Content == newIP {
		debugLog("DNS-LOGIC", fqdn, fmt.Sprintf("✅ %s: %s = %s", T.RecordCurrent, recordType, newIP))
		log(LogContext{
			Level:   LogInfo,
			Action:  ActionCurrent,
			Domain:  fqdn,
			Message: fmt.Sprintf("%-4s %s %s", recordType, newIP, T.Current),
		})
		return true
	}

	if existing == nil {
		debugLog("DNS-LOGIC", fqdn, fmt.Sprintf("🆕 %s: %s", T.NoRecordFound, recordType))
	} else {
		debugLog("DNS-LOGIC", fqdn, fmt.Sprintf("🔄 %s: %s -> %s", T.RecordUpdateNeeded, existing.Content, newIP))
	}

	return false
}

func buildIonosUpdateRequest(
	dc *DomainConfig,
	fqdn, recordType, newIP, zoneID string,
	existing *Record,
) (string, string, string, interface{}) {
	if existing != nil {
		return MethodPUT,
			fmt.Sprintf("%s/%s/records/%s", ionosBaseURL, zoneID, existing.ID),
			ActionUpdate,
			map[string]interface{}{
				"name":    fqdn,
				"type":    recordType,
				"content": newIP,
				"ttl":     effectiveTTL(dc),
			}
	}

	return MethodPOST,
		fmt.Sprintf("%s/%s/records", ionosBaseURL, zoneID),
		ActionCreate,
		[]DNSRecord{
			{
				Name:    fqdn,
				Type:    recordType,
				Content: newIP,
				TTL:     effectiveTTL(dc),
			},
		}
}

func debugIonosUpdateRequest(fqdn, method, url, zoneName, recordType string) {
	debugLog("DNS-LOGIC", fqdn, fmt.Sprintf("📡 %s: %s %s", T.APICall, method, url))
	debugLog("DNS-LOGIC", fqdn, fmt.Sprintf(T.IonosPayload, zoneName, fqdn, recordType))
}

func executeIonosDNSUpdate(
	ctx context.Context,
	dc *DomainConfig,
	fqdn, recordType, newIP, method, url string,
	payload interface{},
) error {
	_, err := ionosAPI(ctx, dc, method, url, payload)
	if err == nil {
		debugLog("DNS-LOGIC", fqdn, fmt.Sprintf(T.IonosRecordArrow, T.Success, recordType, newIP))
		return nil
	}

	var apiErrPtr *APIError
	if errors.As(err, &apiErrPtr) && apiErrPtr != nil {
		return handleIonosDNSAPIError(fqdn, recordType, newIP, apiErrPtr, err)
	}

	debugLog("DNS-LOGIC", fqdn, fmt.Sprintf("❌ %s: %v", T.UpdateFailed, err))
	return err
}

func handleIonosDNSAPIError(fqdn, recordType, newIP string, apiErrPtr *APIError, err error) error {
	switch apiErrPtr.StatusCode {
	case 401, 403:
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Domain:  fqdn,
			Message: fmt.Sprintf("%s: %s!", recordType, T.APIErrorForbidden),
		})
		return fmt.Errorf("%s: %w", T.ErrAuthFailed, err)

	case 404:
		log(LogContext{
			Level:   LogError,
			Action:  ActionZone,
			Domain:  fqdn,
			Message: fmt.Sprintf("%s: %s!", recordType, T.APIErrorNotFound),
		})
		return fmt.Errorf("%s: %w", T.ErrResourceNotFound, err)

	case 422:
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Domain:  fqdn,
			Message: fmt.Sprintf("%s: %s (IP: %s)", recordType, T.APIErrorUnprocessableEntity, newIP),
		})
		return fmt.Errorf("%s: %w", T.ErrValidationFailed, err)

	case 429:
		log(LogContext{
			Level:   LogWarn,
			Action:  ActionRetry,
			Domain:  fqdn,
			Message: fmt.Sprintf("⏳ %s: %s...", recordType, T.APIErrorRateLimitExceeded),
		})
		return err

	default:
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Domain:  fqdn,
			Message: fmt.Sprintf("%s: API-Fehler %d", recordType, apiErrPtr.StatusCode),
		})

		debugLog("DNS-LOGIC", fqdn, fmt.Sprintf(T.IonosErrDetail, err, err))
		return err
	}
}

// ============================================================================
// CACHE UPDATE - IONOS
// ============================================================================
func updateIONOSCache(cache *ZoneRecordCache, zoneID, recordName, fqdn, recordType, newIP string, existing *Record) {
	if cache == nil {
		return
	}

	records, exists := cache.Get(zoneID)
	if !exists {
		debugLog("CACHE", fqdn, T.IonosCacheZoneNotFound)
		return
	}

	updated := false

	if existing != nil {
		for i := range records {
			if records[i].ID == existing.ID {
				records[i].Content = newIP
				updated = true
				debugLog("CACHE", fqdn, fmt.Sprintf(T.IonosCacheUpdated, recordType, newIP))
				break
			}
		}
	} else {
		newRecord := Record{
			ID:      fmt.Sprintf("new-%d", len(records)),
			Name:    recordName,
			Type:    recordType,
			Content: newIP,
		}
		records = append(records, newRecord)
		updated = true
		debugLog("CACHE", fqdn, fmt.Sprintf(T.IonosCacheRecordAdded, recordType, newIP))
	}

	if updated {
		cache.Set(zoneID, records)
	}
}

// ============================================================================
// CLEANUP - IONOS
// ============================================================================
func cleanupIONOSRecords(ctx context.Context, zones []Zone, recordCache *ZoneRecordCache) {
	ionosDC := findIONOSConfigForCleanup()
	if ionosDC == nil {
		return
	}

	debugLog("MAINTENANCE", "", T.CleanupStartIonos)
	configDomains := buildIONOSConfigDomains()

	for _, zone := range zones {
		cleanupIONOSZoneRecords(ctx, ionosDC, zone, recordCache, configDomains)
	}
}

func findIONOSConfigForCleanup() *DomainConfig {
	cfgMu.RLock()
	defer cfgMu.RUnlock()

	for i := range cfg.DomainConfigs {
		if cfg.DomainConfigs[i].Provider == ProviderIONOS {
			dc := cfg.DomainConfigs[i]
			return &dc
		}
	}

	return nil
}

func buildIONOSConfigDomains() map[string]struct{} {
	cfgMu.RLock()
	defer cfgMu.RUnlock()

	configDomains := make(map[string]struct{})

	for _, dc := range cfg.DomainConfigs {
		if dc.Provider != ProviderIONOS {
			continue
		}

		fqdn := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(dc.FQDN), "."))
		if fqdn != "" {
			configDomains[fqdn] = struct{}{}
		}
	}

	return configDomains
}

func cleanupIONOSZoneRecords(
	ctx context.Context,
	ionosDC *DomainConfig,
	zone Zone,
	recordCache *ZoneRecordCache,
	configDomains map[string]struct{},
) {
	records, exists := recordCache.Get(zone.ID)
	if !exists {
		return
	}

	zoneName := strings.ToLower(strings.TrimSuffix(zone.Name, "."))

	for _, rec := range records {
		cleanupSingleIONOSRecord(ctx, ionosDC, zone, zoneName, rec, configDomains)
	}
}

func cleanupSingleIONOSRecord(
	ctx context.Context,
	ionosDC *DomainConfig,
	zone Zone,
	zoneName string,
	rec Record,
	configDomains map[string]struct{},
) {
	fqdn, shouldDelete := shouldCleanupIONOSRecord(zoneName, rec, configDomains)
	if !shouldDelete {
		return
	}

	debugLog("MAINTENANCE", fqdn, fmt.Sprintf(T.CleanupOrphanedIonos, rec.Type, rec.ID))

	if cfg.DryRun {
		log(LogContext{
			Level:   LogInfo,
			Action:  ActionCleanup,
			Domain:  fqdn,
			Message: T.CleanupDryRun,
		})
		return
	}

	url := fmt.Sprintf("%s/%s/records/%s", ionosBaseURL, zone.ID, rec.ID)
	if _, err := ionosAPI(ctx, ionosDC, MethodDELETE, url, nil); err != nil {
		debugLog("MAINTENANCE", fqdn, fmt.Sprintf(T.CleanupDeleteError, err))
		return
	}

	log(LogContext{
		Level:   LogInfo,
		Action:  ActionCleanup,
		Domain:  fqdn,
		Message: fmt.Sprintf(T.CleanupRecordRemoved, rec.Type),
	})
}

func shouldCleanupIONOSRecord(
	zoneName string,
	rec Record,
	configDomains map[string]struct{},
) (string, bool) {
	if rec.Type != RecordTypeA && rec.Type != RecordTypeAAAA {
		return "", false
	}

	fqdn := ionosRecordFQDN(zoneName, rec.Name)
	if _, ok := configDomains[fqdn]; ok {
		return "", false
	}

	return fqdn, true
}

func ionosRecordFQDN(zoneName, recordName string) string {
	var fqdn string

	switch {
	case recordName == "@":
		fqdn = zoneName
	case recordName == zoneName:
		fqdn = zoneName
	case strings.HasSuffix(recordName, "."+zoneName):
		fqdn = recordName
	default:
		fqdn = recordName + "." + zoneName
	}

	return strings.ToLower(strings.TrimSuffix(fqdn, "."))
}
