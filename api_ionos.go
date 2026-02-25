// Package main
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
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
		return fmt.Errorf("recordCache is nil")
	}

	cachePath := getIONOSCachePath()
	if err := os.MkdirAll(filepath.Dir(cachePath), 0755); err != nil {
		return fmt.Errorf("failed to create cache dir: %w", err)
	}

	cache := IONOSCache{
		Zones:      zones,
		Records:    make(map[string][]Record),
		LastUpdate: time.Now().Local(),
	}

	for _, zone := range zones {
		if records, exists := recordCache.Get(zone.ID); exists {
			cache.Records[zone.ID] = records
		}
	}

	jsonData, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal cache: %w", err)
	}

	tmpPath := cachePath + ".tmp"
	if err := os.WriteFile(tmpPath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write cache: %w", err)
	}

	if err := os.Rename(tmpPath, cachePath); err != nil {
		return fmt.Errorf("failed to rename cache: %w", err)
	}

	debugLog("CACHE", "", fmt.Sprintf("💾 IONOS Cache gespeichert (%d zones, %d records)",
		len(zones), len(cache.Records)))
	return nil
}

func loadIONOSCacheFromFile() ([]Zone, *ZoneRecordCache, error) {
	cachePath := getIONOSCachePath()

	data, err := os.ReadFile(cachePath)
	if err != nil {
		if os.IsNotExist(err) {
			debugLog("CACHE", "", "ℹ️ Keine IONOS Cache-Datei gefunden (erster Start)")
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
	debugLog("CACHE", "", fmt.Sprintf("📂 IONOS Cache von Disk geladen (%d zones, Alter: %v)",
		len(cache.Zones), age.Round(time.Second)))

	return cache.Zones, recordCache, nil
}

// ============================================================================
// API - IONOS
// ============================================================================
func calculateRetryDelay(attempt int, isServerError bool) time.Duration {
	baseWait := time.Duration(math.Pow(RetryExponentBase, float64(attempt+1))) * RetryBaseDelay
	if baseWait < RetryBaseDelay {
		baseWait = RetryBaseDelay
	}
	if baseWait > RetryMaxDelay {
		baseWait = RetryMaxDelay
	}

	jitter := time.Duration(rng.Intn(RetryJitterMaxMs)) * time.Millisecond
	wait := baseWait + jitter

	if isServerError {
		wait *= 2
		if wait > RetryMaxDelay {
			wait = RetryMaxDelay
		}
	}

	return wait
}

func ionosAPI(ctx context.Context, dc *DomainConfig, method, url string, body interface{}) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context error: %w", err)
	}

	var lastErr error

	for attempt := 0; attempt < cfg.MaxAPIRetries; attempt++ {
		debugLog("HTTP", "", fmt.Sprintf(
			"🔄 %s %d/%d: %s %s",
			T.Attempt, attempt+1, cfg.MaxAPIRetries, method, url,
		))

		var bodyBytes []byte
		var err error

		if body != nil {
			bodyBytes, err = json.Marshal(body)
			if err != nil {
				return nil, fmt.Errorf("json marshal failed: %w", err)
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
			return nil, fmt.Errorf("request creation failed: %w", err)
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
			lastErr = fmt.Errorf("network error: %w", err)

			wait := calculateRetryDelay(attempt, false)
			debugLog("HTTP", "", fmt.Sprintf("⏱️  %s %v", T.RetryIn, wait))

			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
			}
			continue
		}
		debugLog("HTTP", "", fmt.Sprintf("✅ Status: %d | %s: %v", res.StatusCode, T.AvgLatency, duration))

		respBody, err := io.ReadAll(res.Body)
		closeErr := res.Body.Close()
		if closeErr != nil {
			debugLog("HTTP", "", fmt.Sprintf("Warning: failed to close response body: %v", closeErr))
		}

		if err != nil {
			apiMetrics.RecordError(method, res.StatusCode, err, duration)
			debugLog("HTTP", "", fmt.Sprintf("❌ %s: %v", T.BodyReadError, err))
			lastErr = fmt.Errorf("failed to read response body: %w", err)

			wait := calculateRetryDelay(attempt, false)
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
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

		debugLog("HTTP", "", fmt.Sprintf("⚠️  %s (Retryable: %v)", apiErr.Message, apiErr.Retryable))
		lastErr = apiErr
		lastErrorMsg.Set(sanitizeError(lastErr))

		if !apiErr.IsRetryable() {
			debugLog("HTTP", "", fmt.Sprintf("❌ %s: %s", T.NonRetryableError, apiErr.Message))
			return nil, apiErr
		}

		if attempt >= cfg.MaxAPIRetries-1 {
			debugLog("HTTP", "", fmt.Sprintf("❌ %s (%d)", T.MaxAttemptsReached, cfg.MaxAPIRetries))
			return nil, fmt.Errorf("maximale Versuche erreicht: %w", apiErr)
		}

		var wait time.Duration
		if apiErr.RetryAfter > 0 {
			wait = apiErr.RetryAfter
		} else {
			wait = calculateRetryDelay(attempt, res.StatusCode >= 500)
		}

		debugLog("HTTP", "", fmt.Sprintf("🔄 %s #%d in %v...", T.RetryScheduled, attempt+2, wait))

		select {
		case <-time.After(wait):
		case <-ctx.Done():
			debugLog("HTTP", "", "❌ "+T.ContextCancelled)
			return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
		}
	}

	return nil, fmt.Errorf("API fehlgeschlagen nach %d Versuchen: %w", cfg.MaxAPIRetries, lastErr)
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
		log(LogContext{Level: LogInfo, Action: ActionCurrent, Message: fmt.Sprintf("%s %-4s: %s %s", fqdn, recordType, newIP, T.Current)})
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
		method = "PUT"
		url = fmt.Sprintf("%s/%s/records/%s", ionosBaseURL, zoneID, existing.ID)
		actionType = ActionUpdate

		payload = map[string]interface{}{
			"name":    fqdn,
			"type":    recordType,
			"content": newIP,
			"ttl":     60,
		}
	} else {
		method = "POST"
		url = fmt.Sprintf("%s/%s/records", ionosBaseURL, zoneID)
		actionType = ActionCreate

		payload = []DNSRecord{
			{
				Name:    fqdn,
				Type:    recordType,
				Content: newIP,
				TTL:     60,
			},
		}
	}

	debugLog("DNS-LOGIC", fqdn,
		fmt.Sprintf("📡 %s: %s %s", T.APICall, method, url))

	debugLog("DNS-LOGIC", fqdn,
		fmt.Sprintf("📦 Payload: zone=%s name=%s type=%s",
			zoneName, fqdn, recordType))

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
				return false, fmt.Errorf("authorization failed: %w", err)

			case 404:
				log(LogContext{
					Level:   LogError,
					Action:  ActionZone,
					Domain:  fqdn,
					Message: fmt.Sprintf("%s: %s!", recordType, T.NotFound),
				})
				return false, fmt.Errorf("resource not found: %w", err)

			case 422:
				log(LogContext{
					Level:  LogError,
					Action: ActionError,
					Domain: fqdn,
					Message: fmt.Sprintf("%s: %s (IP: %s)",
						recordType, T.UnprocessableEntity, newIP),
				})
				return false, fmt.Errorf("validation failed: %w", err)

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

				debugLog("DNS-LOGIC", fqdn, fmt.Sprintf("❌ err=%T %v", err, err))

				return false, err
			}
		}

		debugLog("DNS-LOGIC", fqdn,
			fmt.Sprintf("❌ %s: %v", T.UpdateFailed, err))
		return false, err
	}

	debugLog("DNS-LOGIC", fqdn,
		fmt.Sprintf("🔄 %s: %s -> %s",
			T.Success, recordType, newIP))

	log(LogContext{
		Level:  LogInfo,
		Action: actionType,
		Domain: fqdn,
		Message: fmt.Sprintf("🔄 %s -> %s %s",
			recordType, newIP, T.Update),
	})

	if zoneName == "" {
		return false, fmt.Errorf("zoneName is empty for fqdn %s", fqdn)
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
		debugLog("CACHE", fqdn, "⚠️ Zone nicht im Cache gefunden")
		return
	}

	updated := false

	if existing != nil {
		for i := range records {
			if records[i].ID == existing.ID {
				records[i].Content = newIP
				updated = true
				debugLog("CACHE", fqdn, fmt.Sprintf("✅ Cache aktualisiert: %s -> %s", recordType, newIP))
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
		debugLog("CACHE", fqdn, fmt.Sprintf("✅ Cache: Neuer %s Record hinzugefügt: %s", recordType, newIP))
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
