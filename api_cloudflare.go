package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ============================================================================
// CACHE PERSISTENCE - CLOUDFLARE
// ============================================================================

func getCloudflareCachePath() string {
	return filepath.Join(cfg.LogDir, "cloudflare_cache.json")
}

func saveCloudflareCacheToFile(zones []Zone, recordCache *ZoneRecordCache) error {
	if recordCache == nil {
		return fmt.Errorf("recordCache is nil")
	}

	cachePath := getCloudflareCachePath()
	
	cache := CloudflareCache{
		Zones:      zones,
		Records:    make(map[string][]Record),
		LastUpdate: time.Now(),
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

	debugLog("CACHE", "", fmt.Sprintf("💾 Cloudflare Cache gespeichert (%d zones, %d records)", 
		len(zones), len(cache.Records)))
	return nil
}

func loadCloudflareCacheFromFile() ([]Zone, *ZoneRecordCache, error) {
	cachePath := getCloudflareCachePath()
	
	data, err := os.ReadFile(cachePath)
	if err != nil {
		if os.IsNotExist(err) {
			debugLog("CACHE", "", "ℹ️ Keine Cloudflare Cache-Datei gefunden (erster Start)")
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("failed to read cache: %w", err)
	}

	var cache CloudflareCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal cache: %w", err)
	}

	recordCache := NewZoneRecordCache()
	for zoneID, records := range cache.Records {
		recordCache.Set(zoneID, records)
	}

	age := time.Since(cache.LastUpdate)
	debugLog("CACHE", "", fmt.Sprintf("📂 Cloudflare Cache von Disk geladen (%d zones, Alter: %v)", 
		len(cache.Zones), age.Round(time.Second)))
	
	return cache.Zones, recordCache, nil
}

// ============================================================================
// API - CLOUDFLARE
// ============================================================================
func cloudflareAPI(ctx context.Context, dc *DomainConfig, method, endpoint string, body interface{}) ([]byte, error) {
	url := cloudflareAPIBase + endpoint

	var lastErr error
	for attempt := 0; attempt < MaxAPIRetries; attempt++ {
		start := time.Now().Local()
		debugLog("HTTP", "", fmt.Sprintf("🔄 Cloudflare %s %d/%d: %s %s",
			T.Attempt, attempt+1, MaxAPIRetries, method, url))

		var bodyBytes []byte
		var err error

		if body != nil {
			bodyBytes, err = json.Marshal(body)
			if err != nil {
				return nil, fmt.Errorf("json marshal failed: %w", err)
			}
		}

		var bodyReader io.Reader
		if body != nil {
			bodyReader = bytes.NewReader(bodyBytes)
		}

		req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
		if err != nil {
			return nil, fmt.Errorf("request creation failed: %w", err)
		}

		req.Header.Set("User-Agent", "Go-DynDNS/2.0")
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		if dc.CFToken != "" {
			token := strings.TrimSpace(dc.CFToken)
			token = strings.Trim(token, `"'`)
			token = strings.TrimPrefix(token, "Bearer ")
			token = strings.TrimSpace(token)
			token = strings.Map(func(r rune) rune {
				if r < 32 || r == 127 {
					return -1
				}
				return r
			}, token)

			if token == "" {
				return nil, fmt.Errorf("CFToken is set but empty after sanitizing")
			}

			req.Header.Set("Authorization", "Bearer "+token)
		} else if dc.CFEmail != "" && dc.CFSecret != "" {
			req.Header.Set("X-Auth-Email", strings.TrimSpace(dc.CFEmail))
			req.Header.Set("X-Auth-Key", strings.TrimSpace(dc.CFSecret))
		} else {
			return nil, fmt.Errorf("no Cloudflare credentials configured")
		}

		res, err := getHTTPClient().Do(req)
		duration := time.Since(start)

		if err != nil {
			debugLog("HTTP", "", fmt.Sprintf("❌ %s: %v | %s: %v", T.NetworkError, err, T.AvgLatency, duration))
			apiMetrics.RecordError(0, err, duration)
			lastErr = fmt.Errorf("network error: %w", err)

			wait := calculateRetryDelay(attempt, false)
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
			}
			continue
		}
		respBody, err := io.ReadAll(res.Body)
		res.Body.Close()

		if err != nil {
			apiMetrics.RecordError(res.StatusCode, err, duration)
			lastErr = fmt.Errorf("failed to read response: %w", err)
			continue
		}

		var cfResp CloudflareResponse
		if err := json.Unmarshal(respBody, &cfResp); err != nil {
			// HTML-Antwort erkennen und loggen
			if len(respBody) > 0 && respBody[0] == '<' {
				preview := string(respBody)
				if len(preview) > 200 {
					preview = preview[:200] + "..."
				}
				debugLog("CACHE", "", fmt.Sprintf("Cloudflare API returned HTML: %s", preview))
			}
			
			apiErr := classifyAPIError(res.StatusCode, method, url, string(respBody))
			if apiErr == nil {
				apiErr = &APIError{
					StatusCode: res.StatusCode,
					Method:     method,
					URL:        url,
					Message:    "invalid json response",
					Retryable:  res.StatusCode >= 500,
				}
			}
			apiMetrics.RecordError(res.StatusCode, apiErr, duration)
			lastErr = apiErr

			if attempt >= MaxAPIRetries-1 || !apiErr.IsRetryable() {
				return nil, apiErr
			}

			wait := calculateRetryDelay(attempt, res.StatusCode >= 500)
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
			}
			continue
		}

		if !cfResp.Success {
			errMsg := "unknown error"
			if len(cfResp.Errors) > 0 {
				errMsg = cfResp.Errors[0].Message
			}

			apiErr := classifyAPIError(res.StatusCode, method, url, errMsg)
			if apiErr == nil {
				apiErr = &APIError{
					StatusCode: res.StatusCode,
					Method:     method,
					URL:        url,
					Message:    errMsg,
					Retryable:  false,
				}
			}

			apiMetrics.RecordError(res.StatusCode, apiErr, duration)
			lastErr = apiErr

			if attempt >= MaxAPIRetries-1 {
				return nil, fmt.Errorf("max attempts reached: %w", apiErr)
			}

			wait := calculateRetryDelay(attempt, res.StatusCode >= 500)
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
			}
			continue
		}
		apiMetrics.RecordSuccess(duration)
		return respBody, nil
	}

	return nil, fmt.Errorf("cloudflare api failed after %d attempts: %w", MaxAPIRetries, lastErr)
}

func loadCloudflareZones(ctx context.Context, dc *DomainConfig) ([]Zone, error) {
	data, err := cloudflareAPI(ctx, dc, "GET", "/zones", nil)
	if err != nil {
		debugLog("CACHE", "", fmt.Sprintf("⚠️ Cloudflare API-Fehler beim Laden von Zones: %v", err))
		return nil, fmt.Errorf("failed to load cloudflare zones: %w", err)
	}

	var resp struct {
		Result []CloudflareZone `json:"result"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		debugLog("CACHE", "", fmt.Sprintf("⚠️ Cloudflare Parse-Fehler: %v", err))
		return nil, fmt.Errorf("failed to parse zones: %w", err)
	}

	zones := make([]Zone, len(resp.Result))
	for i, z := range resp.Result {
		zones[i] = Zone{ID: z.ID, Name: z.Name}
	}

	return zones, nil
}

func loadCloudflareRecords(ctx context.Context, dc *DomainConfig, zoneID string) ([]Record, error) {
	endpoint := fmt.Sprintf("/zones/%s/dns_records", zoneID)
	data, err := cloudflareAPI(ctx, dc, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load records: %w", err)
	}

	var resp struct {
		Result []CloudflareRecord `json:"result"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse records: %w", err)
	}

	records := make([]Record, len(resp.Result))
	for i, r := range resp.Result {
		records[i] = Record{
			ID:      r.ID,
			Name:    r.Name,
			Type:    r.Type,
			Content: r.Content,
			Comment: r.Comment,
		}
	}

	return records, nil
}

// ============================================================================
// DNS LOGIC - CLOUDFLARE
// ============================================================================
func updateCloudflareDNS(ctx context.Context, dc *DomainConfig, fqdn, recordType, newIP string,
	records []Record, zoneID string) (bool, error) {

	var existing *Record
	for i := range records {
		if strings.EqualFold(strings.TrimSuffix(records[i].Name, "."), strings.TrimSuffix(fqdn, ".")) &&
			records[i].Type == recordType {
			existing = &records[i]
			break
		}
	}

	if existing != nil && existing.Content == newIP {
		debugLog("DNS-LOGIC", fqdn, fmt.Sprintf("✅ %s: %s = %s",
			T.RecordCurrent, recordType, newIP))
		writeLog("CURRENT", ActionCurrent, fqdn,
			fmt.Sprintf("%-4s %s %s", recordType, newIP, T.Current))
		return false, nil
	}

	if existing != nil && strings.TrimSpace(existing.Comment) != cfManagedComment {
		msg := fmt.Sprintf("⚠️ Cloudflare %s-Record existiert, aber ist nicht 'managed' (comment=%q). Überspringe Update.",
			recordType, strings.TrimSpace(existing.Comment))

		debugLog("DNS-LOGIC", fqdn, msg)
		log(LogContext{
			Level:   LogWarn,
			Action:  ActionSkip,
			Domain:  fqdn,
			Message: msg,
		})
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

	payload := map[string]interface{}{
		"type":    recordType,
		"name":    fqdn,
		"content": newIP,
		"ttl":     60,
		"proxied": false,
		"comment": cfManagedComment,
	}

	var endpoint string
	var method string
	var actionType string

	if existing != nil {
		method = "PUT"
		endpoint = fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, existing.ID)
		actionType = ActionUpdate
	} else {
		method = "POST"
		endpoint = fmt.Sprintf("/zones/%s/dns_records", zoneID)
		actionType = ActionCreate
	}

	_, err := cloudflareAPI(ctx, dc, method, endpoint, payload)
	if err != nil {
		return false, err
	}

	log(LogContext{
		Level:   LogInfo,
		Action:  actionType,
		Domain:  fqdn,
		Message: fmt.Sprintf("🔄 %s -> %s %s", recordType, newIP, T.Update),
	})

	return true, nil
}

// ============================================================================
// CLEANUP - CLOUDFLARE
// ============================================================================

func cleanupCloudflareRecords(ctx context.Context, zones []Zone, recordCache *ZoneRecordCache) {
	var cfDC *DomainConfig
	for i := range cfg.DomainConfigs {
		if cfg.DomainConfigs[i].Provider == ProviderCloudflare {
			cfDC = &cfg.DomainConfigs[i]
			break
		}
	}
	if cfDC == nil {
		return
	}

	debugLog("MAINTENANCE", "", "🧹 Starte Bereinigung verwaister Cloudflare DNS-Records...")

	configDomains := make(map[string]struct{})
	for _, dc := range cfg.DomainConfigs {
		if dc.Provider != ProviderCloudflare {
			continue
		}
		fqdn := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(dc.FQDN), "."))
		if fqdn != "" {
			configDomains[fqdn] = struct{}{}
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

			if strings.TrimSpace(rec.Comment) != cfManagedComment {
				continue
			}

			fqdn := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rec.Name), "."))
			if fqdn == "" {
				continue
			}

			if fqdn != zoneName && !strings.HasSuffix(fqdn, "."+zoneName) {
				continue
			}

			if _, ok := configDomains[fqdn]; ok {
				continue
			}

			debugLog(
				"MAINTENANCE",
				fqdn,
				fmt.Sprintf("🗑️ Entferne verwaisten %s Record (ID: %s) in Zone %s", rec.Type, rec.ID, zone.Name),
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

			endpoint := fmt.Sprintf("/zones/%s/dns_records/%s", zone.ID, rec.ID)
			if _, err := cloudflareAPI(ctx, cfDC, "DELETE", endpoint, nil); err != nil {
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