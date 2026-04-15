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
	"net/url"
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
		return fmt.Errorf("%s", T.ErrRecordCacheNil)
	}

	if err := os.MkdirAll(cfg.LogDir, 0755); err != nil {
		return fmt.Errorf("%s: %w", T.ErrCacheDirCreate, err)
	}

	cachePath := getCloudflareCachePath()

	cache := CloudflareCache{
		Version:    1,
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

	debugLog("CACHE", "", fmt.Sprintf(T.CacheSavedZones, "Cloudflare", len(zones), totalRecords))
	return nil
}

func loadCloudflareCacheFromFile() ([]Zone, *ZoneRecordCache, error) {
	cachePath := getCloudflareCachePath()

	data, err := os.ReadFile(cachePath)
	if err != nil {
		if os.IsNotExist(err) {
			debugLog("CACHE", "", fmt.Sprintf(T.CacheFileNotFound, "Cloudflare"))
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("%s: %w", T.ErrBodyRead, err)
	}

	var cache CloudflareCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", T.ErrCacheMarshal, err)
	}

	if cache.Version == 0 {
		cache.Version = 1
	}

	if cache.Version != 1 {
		return nil, nil, fmt.Errorf(T.ErrAPIGeneric+": unsupported version %d", cache.Version)
	}

	recordCache := NewZoneRecordCache()
	for zoneID, records := range cache.Records {
		recordCache.Set(zoneID, records)
	}

	age := time.Since(cache.LastUpdate)
	debugLog("CACHE", "", fmt.Sprintf(T.CacheLoadedZones, "Cloudflare", len(cache.Zones), age.Round(time.Second)))

	return cache.Zones, recordCache, nil
}

// ============================================================================
// API - CLOUDFLARE
// ============================================================================
func cloudflareAPI(ctx context.Context, dc *DomainConfig, method, endpoint string, body interface{}) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", T.ErrContextError, err)
	}

	fullURL := cloudflareAPIBase + endpoint

	var lastErr error
	for attempt := 0; attempt < cfg.MaxAPIRetries; attempt++ {

		debugLog("HTTP", "", fmt.Sprintf(T.CFAttempt,
			T.Attempt, attempt+1, cfg.MaxAPIRetries, method, fullURL))

		var bodyReader io.Reader
		if body != nil {
			bodyBytes, err := json.Marshal(body)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", T.ErrJSONMarshal, err)
			}
			bodyReader = bytes.NewReader(bodyBytes)
		}

		req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", T.ErrRequestCreate, err)
		}

		req.Header.Set("User-Agent", ManagedComment)
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		switch {
		case dc.CFToken != "":
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
				return nil, fmt.Errorf("%s", T.CFTokenEmpty)
			}

			req.Header.Set("Authorization", "Bearer "+token)

		case dc.CFEmail != "" && dc.CFSecret != "":
			req.Header.Set("X-Auth-Email", strings.TrimSpace(dc.CFEmail))
			req.Header.Set("X-Auth-Key", strings.TrimSpace(dc.CFSecret))

		default:
			return nil, fmt.Errorf("%s", T.CFNoCredentials)
		}

		start := time.Now().Local()
		res, err := getHTTPClient().Do(req)
		duration := time.Since(start)

		if err != nil {
			debugLog("HTTP", "", fmt.Sprintf("❌ %s: %v | %s: %v", T.NetworkError, err, T.AvgLatency, duration))
			apiMetrics.RecordError(method, 0, err, duration)
			lastErr = fmt.Errorf("%s: %w", T.ErrNetworkError, err)

			if !sleepOrCancel(ctx, calculateRetryDelay(attempt, true)) {
				return nil, fmt.Errorf("%s: %w", T.ErrContextCancelled, ctx.Err())
			}
			continue
		}

		respBody, readErr := io.ReadAll(res.Body)
		closeErr := res.Body.Close()
		if closeErr != nil {
			debugLog("HTTP", "", fmt.Sprintf(T.ErrBodyClose+": %v", closeErr))
		}

		if readErr != nil {
			apiMetrics.RecordError(method, res.StatusCode, readErr, duration)
			lastErr = fmt.Errorf("%s: %w", T.ErrBodyRead, readErr)

			serverBusy := res.StatusCode == 429 || res.StatusCode >= 500
			if !sleepOrCancel(ctx, calculateRetryDelay(attempt, serverBusy)) {
				return nil, fmt.Errorf("%s: %w", T.ErrContextCancelled, ctx.Err())
			}
			continue
		}

		if res.StatusCode == http.StatusTooManyRequests {
			apiErr := classifyCloudflareAPIError(res.StatusCode, method, fullURL, respBody, nil, res.Header)
			apiMetrics.RecordError(method, res.StatusCode, apiErr, duration)
			lastErr = apiErr

			wait := apiErr.RetryAfter
			if wait <= 0 {
				wait = calculateRetryDelay(attempt, true)
			}
			if !sleepOrCancel(ctx, wait) {
				return nil, fmt.Errorf("%s: %w", T.ErrContextCancelled, ctx.Err())
			}
			continue
		}

		var cfResp CloudflareResponse
		if err := json.Unmarshal(respBody, &cfResp); err != nil {
			if len(respBody) > 0 && respBody[0] == '<' {
				preview := string(respBody)
				if len(preview) > 200 {
					preview = preview[:200] + "..."
				}
				debugLog("HTTP", "", fmt.Sprintf(T.CFHTMLResponse, res.StatusCode, preview))
			}

			apiErr := classifyAPIError(res.StatusCode, method, fullURL, string(respBody))
			if apiErr == nil {
				apiErr = &APIError{
					StatusCode: res.StatusCode,
					Method:     method,
					URL:        fullURL,
					Message:    T.CFInvalidJSON,
					Retryable:  res.StatusCode >= 500,
				}
			}
			apiMetrics.RecordError(method, res.StatusCode, apiErr, duration)
			lastErr = apiErr

			if res.StatusCode == 401 || res.StatusCode == 403 {
				return nil, apiErr
			}
			if attempt >= cfg.MaxAPIRetries-1 || !apiErr.IsRetryable() {
				return nil, apiErr
			}

			serverBusy := res.StatusCode == 429 || res.StatusCode >= 500
			if !sleepOrCancel(ctx, calculateRetryDelay(attempt, serverBusy)) {
				return nil, fmt.Errorf("%s: %w", T.ErrContextCancelled, ctx.Err())
			}
			continue
		}

		if !cfResp.Success {
			apiErr := classifyCloudflareAPIError(res.StatusCode, method, fullURL, respBody, &cfResp, res.Header)

			apiMetrics.RecordError(method, res.StatusCode, apiErr, duration)
			lastErr = apiErr

			if attempt >= cfg.MaxAPIRetries-1 || !apiErr.IsRetryable() {
				return nil, apiErr
			}

			wait := apiErr.RetryAfter
			if wait <= 0 {
				serverBusy := res.StatusCode == 429 || res.StatusCode >= 500
				wait = calculateRetryDelay(attempt, serverBusy)
			}
			if !sleepOrCancel(ctx, wait) {
				return nil, fmt.Errorf("%s: %w", T.ErrContextCancelled, ctx.Err())
			}
			continue
		}

		apiMetrics.RecordSuccess(method, duration)
		return respBody, nil
	}

	return nil, fmt.Errorf("%s: %w", fmt.Sprintf(T.CFAPIFailed, cfg.MaxAPIRetries), lastErr)
}

func loadCloudflareZones(ctx context.Context, dc *DomainConfig) ([]Zone, error) {
	var out []Zone
	page := 1
	perPage := 50

	for {
		endpoint := fmt.Sprintf("/zones?page=%d&per_page=%d", page, perPage)
		data, err := cloudflareAPI(ctx, dc, "GET", endpoint, nil)
		if err != nil {
			debugLog("CACHE", "", fmt.Sprintf(T.CFZoneLoadError+": %v", err))
			return nil, fmt.Errorf("%s: %w", T.CFZoneLoadError, err)
		}

		var resp struct {
			Result     []CloudflareZone `json:"result"`
			ResultInfo struct {
				Page       int `json:"page"`
				PerPage    int `json:"per_page"`
				TotalPages int `json:"total_pages"`
			} `json:"result_info"`
		}
		if err := json.Unmarshal(data, &resp); err != nil {
			debugLog("CACHE", "", fmt.Sprintf(T.CFZoneParseError+": %v", err))
			return nil, fmt.Errorf("%s: %w", T.CFZoneParseError, err)
		}

		for _, z := range resp.Result {
			out = append(out, Zone{ID: z.ID, Name: z.Name})
		}

		if resp.ResultInfo.TotalPages == 0 || page >= resp.ResultInfo.TotalPages {
			break
		}
		page++
	}

	return out, nil
}

func loadCloudflareRecords(ctx context.Context, dc *DomainConfig, zoneID string) ([]Record, error) {
	var out []Record
	page := 1
	perPage := 100

	for {
		endpoint := fmt.Sprintf("/zones/%s/dns_records?page=%d&per_page=%d", zoneID, page, perPage)
		data, err := cloudflareAPI(ctx, dc, "GET", endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", T.ErrBodyRead, err)
		}

		var resp struct {
			Result     []CloudflareRecord `json:"result"`
			ResultInfo struct {
				Page       int `json:"page"`
				PerPage    int `json:"per_page"`
				TotalPages int `json:"total_pages"`
			} `json:"result_info"`
		}
		if err := json.Unmarshal(data, &resp); err != nil {
			return nil, fmt.Errorf("%s: %w", T.ErrBodyRead, err)
		}

		for _, r := range resp.Result {
			out = append(out, Record{ID: r.ID, Name: r.Name, Type: r.Type, Content: r.Content, Comment: r.Comment})
		}

		if resp.ResultInfo.TotalPages == 0 || page >= resp.ResultInfo.TotalPages {
			break
		}
		page++
	}
	return out, nil
}

// ============================================================================
// DNS LOGIC - CLOUDFLARE
// ============================================================================
func updateCloudflareDNS(ctx context.Context, dc *DomainConfig, fqdn, recordType, newIP string,
	records []Record, zoneID string,
) (bool, error) {
	var existing *Record
	for i := range records {
		if strings.EqualFold(strings.TrimSuffix(records[i].Name, "."), strings.TrimSuffix(fqdn, ".")) &&
			records[i].Type == recordType {
			existing = &records[i]
			break
		}
	}

	if existing == nil {
		rec, err := findCloudflareRecord(ctx, dc, zoneID, fqdn, recordType)
		if err != nil {
			return false, err
		}
		existing = rec
	}

	if existing != nil && existing.Content == newIP {
		debugLog("DNS-LOGIC", fqdn, fmt.Sprintf("✅ %s: %s = %s",
			T.RecordCurrent, recordType, newIP))
		log(LogContext{Level: LogInfo, Action: ActionCurrent, Domain: fqdn, Message: fmt.Sprintf("%-4s  %s %s", recordType, newIP, T.Current)})
		return false, nil
	}

	if existing != nil && strings.TrimSpace(existing.Comment) != ManagedComment {
		msg := fmt.Sprintf(T.CFUnmanagedRecord,
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
		"comment": ManagedComment,
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
		var apiErr *APIError
		if method == "PUT" && errors.As(err, &apiErr) && apiErr.StatusCode == 404 {
			rec, ferr := findCloudflareRecord(ctx, dc, zoneID, fqdn, recordType)
			if ferr != nil {
				return false, ferr
			}
			if rec == nil {
				createEndpoint := fmt.Sprintf("/zones/%s/dns_records", zoneID)
				if _, cerr := cloudflareAPI(ctx, dc, "POST", createEndpoint, payload); cerr != nil {
					return false, cerr
				}
				actionType = ActionCreate
			} else {
				putEndpoint := fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, rec.ID)
				if _, uerr := cloudflareAPI(ctx, dc, "PUT", putEndpoint, payload); uerr != nil {
					return false, uerr
				}
				actionType = ActionUpdate
			}
		} else {
			return false, err
		}
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
func cloudflareDCForZone(zoneName string) *DomainConfig {
	zoneName = strings.ToLower(strings.TrimSuffix(zoneName, "."))
	for i := range cfg.DomainConfigs {
		dc := &cfg.DomainConfigs[i]
		if dc.Provider != ProviderCloudflare {
			continue
		}
		fqdn := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(dc.FQDN), "."))
		if fqdn == "" {
			continue
		}
		if fqdn == zoneName || strings.HasSuffix(fqdn, "."+zoneName) {
			return dc
		}
	}
	return nil
}

func cleanupCloudflareRecords(ctx context.Context, zones []Zone, recordCache *ZoneRecordCache) {
	debugLog("MAINTENANCE", "", T.CleanupStartCF)
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
		cfDC := cloudflareDCForZone(zone.Name)
		if cfDC == nil {
			continue
		}

		records, exists := recordCache.Get(zone.ID)
		if !exists {
			continue
		}

		zoneName := strings.ToLower(strings.TrimSuffix(zone.Name, "."))

		for _, rec := range records {
			if rec.Type != "A" && rec.Type != "AAAA" {
				continue
			}

			if strings.TrimSpace(rec.Comment) != ManagedComment {
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
				fmt.Sprintf(T.CleanupOrphanedCF, rec.Type, rec.ID, zone.Name),
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

			endpoint := fmt.Sprintf("/zones/%s/dns_records/%s", zone.ID, rec.ID)
			if _, err := cloudflareAPI(ctx, cfDC, "DELETE", endpoint, nil); err != nil {
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

// ============================================================================
// Helper - CLOUDFLARE
// ============================================================================
func classifyCloudflareAPIError(
	statusCode int,
	method, url string,
	responseBody []byte,
	cfResp *CloudflareResponse,
	headers http.Header,
) *APIError {
	msg := strings.TrimSpace(string(responseBody))

	if cfResp != nil && !cfResp.Success {
		msg = cfErrorMessage(cfResp, msg)
	}

	if msg == "" {
		msg = http.StatusText(statusCode)
	}

	effectiveStatus := statusCode
	if effectiveStatus >= 200 && effectiveStatus < 300 && cfResp != nil && !cfResp.Success {
		effectiveStatus = 422
	}

	apiErr := classifyAPIErrorWithHeaders(effectiveStatus, method, url, msg, headers)
	if apiErr == nil {
		apiErr = &APIError{
			StatusCode: statusCode,
			Method:     method,
			URL:        url,
			Message:    msg,
			Retryable:  false,
		}
	}

	apiErr.StatusCode = statusCode
	return apiErr
}

func cfErrorMessage(cfResp *CloudflareResponse, fallback string) string {
	if cfResp == nil {
		return fallback
	}
	if len(cfResp.Errors) == 0 {
		if fallback != "" {
			return fallback
		}
		return "unknown error"
	}
	var parts []string
	for i, e := range cfResp.Errors {
		if i >= 3 {
			break
		}
		if e.Message != "" {
			parts = append(parts, e.Message)
		}
	}
	if len(parts) > 0 {
		return strings.Join(parts, "; ")
	}
	return fallback
}

func findCloudflareRecord(ctx context.Context, dc *DomainConfig, zoneID, fqdn, recordType string) (*Record, error) {
	name := strings.TrimSuffix(strings.TrimSpace(fqdn), ".")
	wantName := strings.TrimSuffix(name, ".")

	page := 1
	perPage := 100

	for {
		endpoint := fmt.Sprintf("/zones/%s/dns_records?type=%s&name=%s&page=%d&per_page=%d",
			zoneID, recordType, url.QueryEscape(name), page, perPage)

		data, err := cloudflareAPI(ctx, dc, "GET", endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", T.ErrBodyRead, err)
		}

		var resp struct {
			Result     []CloudflareRecord `json:"result"`
			ResultInfo struct {
				Page       int `json:"page"`
				PerPage    int `json:"per_page"`
				TotalPages int `json:"total_pages"`
			} `json:"result_info"`
		}
		if err := json.Unmarshal(data, &resp); err != nil {
			return nil, fmt.Errorf("%s: %w", T.CFRecordsParseError, err)
		}

		for _, r := range resp.Result {
			if r.Type != recordType {
				continue
			}
			if strings.EqualFold(strings.TrimSuffix(r.Name, "."), wantName) {
				return &Record{
					ID:      r.ID,
					Name:    r.Name,
					Type:    r.Type,
					Content: r.Content,
					Comment: r.Comment,
				}, nil
			}
		}

		if resp.ResultInfo.TotalPages == 0 || page >= resp.ResultInfo.TotalPages {
			break
		}
		page++
	}

	return nil, nil
}
