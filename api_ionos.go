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
	if err := os.MkdirAll(filepath.Dir(cachePath), 0755); err != nil {
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
	if err := os.WriteFile(tmpPath, jsonData, 0644); err != nil {
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

	var lastErr error

	for attempt := 0; attempt < cfg.MaxAPIRetries; attempt++ {
		debugLog("HTTP", "", fmt.Sprintf(
			T.IonosAttempt,
			T.Attempt, attempt+1, cfg.MaxAPIRetries, method, url,
		))

		var bodyBytes []byte
		var err error

		if body != nil {
			bodyBytes, err = json.Marshal(body)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", T.ErrJSONMarshal, err)
			}
			debugLog("HTTP", "", fmt.Sprintf("📤 %s: %s", T.PayloadSent, string(bodyBytes)))
		}

		req, err := http.NewRequestWithContext(
			ctx,
			method,
			url,
			bytes.NewReader(bodyBytes),
		)
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

		start := time.Now().Local()
		res, err := getHTTPClient().Do(req)
		duration := time.Since(start)

		if err != nil {
			debugLog("HTTP", "", fmt.Sprintf("❌ %s: %v | %s: %v", T.NetworkError, err, T.AvgLatency, duration))
			apiMetrics.RecordError(method, 0, err, duration)
			lastErr = fmt.Errorf("%s: %w", T.ErrNetworkError, err)

			wait := calculateRetryDelay(attempt, false)
			debugLog("HTTP", "", fmt.Sprintf("⏱️  %s %v", T.RetryIn, wait))

			if !sleepOrCancel(ctx, wait) {
				return nil, fmt.Errorf("%s: %w", T.ErrContextCancelled, ctx.Err())
			}
			continue
		}
		debugLog("HTTP", "", fmt.Sprintf("✅ Status: %d | %s: %v", res.StatusCode, T.AvgLatency, duration))

		respBody, err := io.ReadAll(res.Body)
		closeErr := res.Body.Close()
		if closeErr != nil {
			debugLog("HTTP", "", fmt.Sprintf(T.ErrBodyClose+": %v", closeErr))
		}

		if err != nil {
			apiMetrics.RecordError(method, res.StatusCode, err, duration)
			debugLog("HTTP", "", fmt.Sprintf("❌ %s: %v", T.BodyReadError, err))
			lastErr = fmt.Errorf("%s: %w", T.ErrBodyRead, err)

			wait := calculateRetryDelay(attempt, false)
			if !sleepOrCancel(ctx, wait) {
				return nil, fmt.Errorf("%s: %w", T.ErrContextCancelled, ctx.Err())
			}
			continue
		}

		if res.StatusCode >= 200 && res.StatusCode < 300 {
			apiMetrics.RecordSuccess(method, duration)

			if errVal := lastErrorMsg.Get(); errVal != "" {
				lastErrorMsg.Set("")
			}
			debugLog("HTTP", "", fmt.Sprintf("✅ %s: %d Bytes", T.Success, len(respBody)))
			return respBody, nil
		}

		apiErr := classifyAPIError(res.StatusCode, method, url, string(respBody))
		apiMetrics.RecordError(method, res.StatusCode, apiErr, duration)

		if res.StatusCode == 401 || res.StatusCode == 403 {
			log(LogContext{
				Level:   LogError,
				Action:  ActionError,
				Message: fmt.Sprintf("🚨 %s: %v", T.CriticalAPIError, apiErr),
			})
		}

		debugLog("HTTP", "", fmt.Sprintf(T.IonosRetryable, apiErr.Message, apiErr.Retryable))
		lastErr = apiErr
		lastErrorMsg.Set(sanitizeError(lastErr))

		if !apiErr.IsRetryable() {
			debugLog("HTTP", "", fmt.Sprintf("❌ %s: %s", T.NonRetryableError, apiErr.Message))
			return nil, apiErr
		}

		if attempt >= cfg.MaxAPIRetries-1 {
			debugLog("HTTP", "", fmt.Sprintf("❌ %s (%d)", T.MaxAttemptsReached, cfg.MaxAPIRetries))
			return nil, fmt.Errorf("%s: %w", T.IonosMaxAttempts, apiErr)
		}

		var wait time.Duration
		if apiErr.RetryAfter > 0 {
			wait = apiErr.RetryAfter
		} else {
			wait = calculateRetryDelay(attempt, res.StatusCode >= 500)
		}

		debugLog("HTTP", "", fmt.Sprintf("🔄 %s #%d in %v...", T.RetryScheduled, attempt+2, wait))

		if !sleepOrCancel(ctx, wait) {
			debugLog("HTTP", "", "❌ "+T.ContextCancelled)
			return nil, fmt.Errorf("%s: %w", T.ErrContextCancelled, ctx.Err())
		}
	}

	return nil, fmt.Errorf("%s: %w", fmt.Sprintf(T.IonosAPIFailed, cfg.MaxAPIRetries), lastErr)
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

	var existing *Record

	for i := range records {
		if (records[i].Name == fqdn || records[i].Name == recordName) && records[i].Type == recordType {
			existing = &records[i]
			debugLog("DNS-LOGIC", fqdn,
				fmt.Sprintf("📌 %s: %s (ID: %s)", T.RecordFound, existing.Content, existing.ID))

			break
		}
	}

	if existing != nil && existing.Content == newIP {
		debugLog("DNS-LOGIC", fqdn,
			fmt.Sprintf("✅ %s: %s = %s",
				T.RecordCurrent, recordType, newIP))
		log(LogContext{Level: LogInfo, Action: ActionCurrent, Domain: fqdn, Message: fmt.Sprintf("%-4s %s %s", recordType, newIP, T.Current)})
		return false, nil
	}

	if existing == nil {
		debugLog("DNS-LOGIC", fqdn,
			fmt.Sprintf("🆕 %s: %s", T.NoRecordFound, recordType))
	} else {
		debugLog("DNS-LOGIC", fqdn,
			fmt.Sprintf("🔄 %s: %s -> %s",
				T.RecordUpdateNeeded, existing.Content, newIP))
	}

	if cfg.DryRun {
		log(LogContext{
			Level:  LogWarn,
			Action: ActionDryRun,
			Domain: fqdn,
			Message: fmt.Sprintf("⚠️ %s %s %s",
				T.WouldSet, recordType, newIP),
		})
		return true, nil
	}
	var (
		method     string
		url        string
		actionType string
		payload    interface{}
	)

	if existing != nil {
		method = MethodPUT
		url = fmt.Sprintf("%s/%s/records/%s", ionosBaseURL, zoneID, existing.ID)
		actionType = ActionUpdate

		payload = map[string]interface{}{
			"name":    fqdn,
			"type":    recordType,
			"content": newIP,
			"ttl":     effectiveTTL(dc),
		}
	} else {
		method = MethodPOST
		url = fmt.Sprintf("%s/%s/records", ionosBaseURL, zoneID)
		actionType = ActionCreate

		payload = []DNSRecord{
			{
				Name:    fqdn,
				Type:    recordType,
				Content: newIP,
				TTL:     effectiveTTL(dc),
			},
		}
	}

	debugLog("DNS-LOGIC", fqdn,
		fmt.Sprintf("📡 %s: %s %s", T.APICall, method, url))

	debugLog("DNS-LOGIC", fqdn,
		fmt.Sprintf(T.IonosPayload, zoneName, fqdn, recordType))

	_, err := ionosAPI(ctx, dc, method, url, payload)
	if err != nil {
		var apiErrPtr *APIError
		if errors.As(err, &apiErrPtr) && apiErrPtr != nil {
			switch apiErrPtr.StatusCode {
			case 401, 403:
				log(LogContext{
					Level:   LogError,
					Action:  ActionError,
					Domain:  fqdn,
					Message: fmt.Sprintf("%s: %s!", recordType, T.Forbidden),
				})
				return false, fmt.Errorf("%s: %w", T.ErrAuthFailed, err)

			case 404:
				log(LogContext{
					Level:   LogError,
					Action:  ActionZone,
					Domain:  fqdn,
					Message: fmt.Sprintf("%s: %s!", recordType, T.NotFound),
				})
				return false, fmt.Errorf("%s: %w", T.ErrResourceNotFound, err)

			case 422:
				log(LogContext{
					Level:  LogError,
					Action: ActionError,
					Domain: fqdn,
					Message: fmt.Sprintf("%s: %s (IP: %s)",
						recordType, T.UnprocessableEntity, newIP),
				})
				return false, fmt.Errorf("%s: %w", T.ErrValidationFailed, err)

			case 429:
				log(LogContext{
					Level:  LogWarn,
					Action: ActionRetry,
					Domain: fqdn,
					Message: fmt.Sprintf("⏳ %s: %s...",
						recordType, T.RateLimitExceeded),
				})
				return false, err

			default:
				log(LogContext{
					Level:  LogError,
					Action: ActionError,
					Domain: fqdn,
					Message: fmt.Sprintf("%s: API-Fehler %d",
						recordType, apiErrPtr.StatusCode),
				})

				debugLog("DNS-LOGIC", fqdn, fmt.Sprintf(T.IonosErrDetail, err, err))

				return false, err
			}
		}

		debugLog("DNS-LOGIC", fqdn,
			fmt.Sprintf("❌ %s: %v", T.UpdateFailed, err))
		return false, err
	}

	debugLog("DNS-LOGIC", fqdn,
		fmt.Sprintf(T.IonosRecordArrow, T.Success, recordType, newIP))

	log(LogContext{
		Level:  LogInfo,
		Action: actionType,
		Domain: fqdn,
		Message: fmt.Sprintf("🔄 %s -> %s %s",
			recordType, newIP, T.Update),
	})

	if zoneName == "" {
		return false, fmt.Errorf(T.ErrZoneNameEmpty, fqdn)
	}

	updateIONOSCache(cache, zoneID, recordName, fqdn, recordType, newIP, existing)

	return true, nil
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

	debugLog("MAINTENANCE", "", T.CleanupStartIonos)

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
				fmt.Sprintf(T.CleanupOrphanedIonos, rec.Type, rec.ID),
			)

			if cfg.DryRun {
				log(LogContext{
					Level:   LogInfo,
					Action:  ActionCleanup,
					Domain:  fqdn,
					Message: T.CleanupDryRun,
				})
				continue
			}

			url := fmt.Sprintf("%s/%s/records/%s", ionosBaseURL, zone.ID, rec.ID)

			if _, err := ionosAPI(ctx, ionosDC, MethodDELETE, url, nil); err != nil {
				debugLog("MAINTENANCE", fqdn, fmt.Sprintf(T.CleanupDeleteError, err))
			} else {
				log(LogContext{
					Level:   LogInfo,
					Action:  ActionCleanup,
					Domain:  fqdn,
					Message: fmt.Sprintf(T.CleanupRecordRemoved, rec.Type),
				})
			}
		}
	}
}
