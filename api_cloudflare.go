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

	if err := os.MkdirAll(cfg.LogDir, 0o755); err != nil {
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
	if err := os.WriteFile(tmpPath, jsonData, 0o600); err != nil {
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
	maxRetries := cfg.MaxAPIRetries

	var lastErr error
	for attempt := range maxRetries {
		respBody, retry, err := cloudflareAPIAttempt(ctx, dc, method, fullURL, body, attempt, maxRetries)
		if err == nil {
			return respBody, nil
		}

		lastErr = err
		if !retry {
			return nil, err
		}
	}

	return nil, fmt.Errorf("%s: %w", fmt.Sprintf(T.CFAPIFailed, maxRetries), lastErr)
}

func cloudflareAPIAttempt(
	ctx context.Context,
	dc *DomainConfig,
	method, fullURL string,
	body interface{},
	attempt, maxRetries int,
) ([]byte, bool, error) {
	debugLog("HTTP", "", fmt.Sprintf(T.CFAttempt,
		T.Attempt, attempt+1, maxRetries, method, fullURL))

	req, err := buildCloudflareRequest(ctx, dc, method, fullURL, body)
	if err != nil {
		return nil, false, err
	}

	start := time.Now().Local()
	res, err := getHTTPClient().Do(req)
	duration := time.Since(start)

	if err != nil {
		retry, handledErr := handleCloudflareNetworkError(ctx, method, err, duration, attempt)
		return nil, retry, handledErr
	}

	return handleCloudflareResponse(ctx, res, method, fullURL, duration, attempt)
}

func buildCloudflareRequest(
	ctx context.Context,
	dc *DomainConfig,
	method, fullURL string,
	body interface{},
) (*http.Request, error) {
	bodyReader, err := cloudflareRequestBodyReader(body)
	if err != nil {
		return nil, err
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

	if err := applyCloudflareAuthHeaders(req, dc); err != nil {
		return nil, err
	}

	return req, nil
}

func cloudflareRequestBodyReader(body interface{}) (io.Reader, error) {
	if body == nil {
		return nil, nil
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", T.ErrJSONMarshal, err)
	}

	return bytes.NewReader(bodyBytes), nil
}

func applyCloudflareAuthHeaders(req *http.Request, dc *DomainConfig) error {
	switch {
	case dc.CFToken != "":
		token := normalizeCloudflareToken(dc.CFToken)
		if token == "" {
			return fmt.Errorf("%s", T.CFTokenEmpty)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		return nil

	case dc.CFEmail != "" && dc.CFSecret != "":
		req.Header.Set("X-Auth-Email", strings.TrimSpace(dc.CFEmail))
		req.Header.Set("X-Auth-Key", strings.TrimSpace(dc.CFSecret))
		return nil

	default:
		return fmt.Errorf("%s", T.CFNoCredentials)
	}
}

func normalizeCloudflareToken(token string) string {
	token = strings.TrimSpace(token)
	token = strings.Trim(token, `"'`)
	token = strings.TrimPrefix(token, "Bearer ")
	token = strings.TrimSpace(token)

	token = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, token)

	return token
}

func handleCloudflareNetworkError(
	ctx context.Context,
	method string,
	err error,
	duration time.Duration,
	attempt int,
) (bool, error) {
	debugLog("HTTP", "", fmt.Sprintf("❌ %s: %v | %s: %v", T.NetworkError, err, T.AvgLatency, duration))
	apiMetrics.RecordError(method, 0, err, duration)

	lastErr := fmt.Errorf("%s: %w", T.ErrNetworkError, err)
	if !sleepOrCancel(ctx, calculateRetryDelay(attempt, true)) {
		return false, fmt.Errorf("%s: %w", T.ErrContextCancelled, ctx.Err())
	}

	return true, lastErr
}

func handleCloudflareResponse(
	ctx context.Context,
	res *http.Response,
	method, fullURL string,
	duration time.Duration,
	attempt int,
) ([]byte, bool, error) {
	respBody, readErr := io.ReadAll(res.Body)
	closeErr := res.Body.Close()
	if closeErr != nil {
		debugLog("HTTP", "", fmt.Sprintf(T.ErrBodyClose+": %v", closeErr))
	}

	if readErr != nil {
		retry, handledErr := handleCloudflareReadError(ctx, res, method, readErr, duration, attempt)
		return nil, retry, handledErr
	}

	if res.StatusCode == http.StatusTooManyRequests {
		retry, handledErr := handleCloudflareRateLimit(ctx, res, method, fullURL, respBody, duration, attempt)
		return nil, retry, handledErr
	}

	var cfResp CloudflareResponse
	if err := json.Unmarshal(respBody, &cfResp); err != nil {
		retry, handledErr := handleCloudflareInvalidJSON(ctx, res, method, fullURL, respBody, duration, attempt)
		return nil, retry, handledErr
	}

	if !cfResp.Success {
		retry, handledErr := handleCloudflareAPIFailure(ctx, res, method, fullURL, respBody, &cfResp, duration, attempt)
		return nil, retry, handledErr
	}

	apiMetrics.RecordSuccess(method, duration)
	return respBody, false, nil
}

func handleCloudflareReadError(
	ctx context.Context,
	res *http.Response,
	method string,
	readErr error,
	duration time.Duration,
	attempt int,
) (bool, error) {
	apiMetrics.RecordError(method, res.StatusCode, readErr, duration)

	lastErr := fmt.Errorf("%s: %w", T.ErrBodyRead, readErr)
	serverBusy := res.StatusCode == http.StatusTooManyRequests || res.StatusCode >= 500

	if !sleepOrCancel(ctx, calculateRetryDelay(attempt, serverBusy)) {
		return false, fmt.Errorf("%s: %w", T.ErrContextCancelled, ctx.Err())
	}

	return true, lastErr
}

func handleCloudflareRateLimit(
	ctx context.Context,
	res *http.Response,
	method, fullURL string,
	respBody []byte,
	duration time.Duration,
	attempt int,
) (bool, error) {
	apiErr := classifyCloudflareAPIError(res.StatusCode, method, fullURL, respBody, nil, res.Header)
	apiMetrics.RecordError(method, res.StatusCode, apiErr, duration)

	wait := apiErr.RetryAfter
	if wait <= 0 {
		wait = calculateRetryDelay(attempt, true)
	}

	if !sleepOrCancel(ctx, wait) {
		return false, fmt.Errorf("%s: %w", T.ErrContextCancelled, ctx.Err())
	}

	return true, apiErr
}

func handleCloudflareInvalidJSON(
	ctx context.Context,
	res *http.Response,
	method, fullURL string,
	respBody []byte,
	duration time.Duration,
	attempt int,
) (bool, error) {
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

	if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
		return false, apiErr
	}

	if !apiErr.IsRetryable() || attempt >= cfg.MaxAPIRetries-1 {
		return false, apiErr
	}

	serverBusy := res.StatusCode == http.StatusTooManyRequests || res.StatusCode >= 500
	if !sleepOrCancel(ctx, calculateRetryDelay(attempt, serverBusy)) {
		return false, fmt.Errorf("%s: %w", T.ErrContextCancelled, ctx.Err())
	}

	return true, apiErr
}

func handleCloudflareAPIFailure(
	ctx context.Context,
	res *http.Response,
	method, fullURL string,
	respBody []byte,
	cfResp *CloudflareResponse,
	duration time.Duration,
	attempt int,
) (bool, error) {
	apiErr := classifyCloudflareAPIError(res.StatusCode, method, fullURL, respBody, cfResp, res.Header)
	apiMetrics.RecordError(method, res.StatusCode, apiErr, duration)

	if !apiErr.IsRetryable() || attempt >= cfg.MaxAPIRetries-1 {
		return false, apiErr
	}

	wait := apiErr.RetryAfter
	if wait <= 0 {
		serverBusy := res.StatusCode == http.StatusTooManyRequests || res.StatusCode >= 500
		wait = calculateRetryDelay(attempt, serverBusy)
	}

	if !sleepOrCancel(ctx, wait) {
		return false, fmt.Errorf("%s: %w", T.ErrContextCancelled, ctx.Err())
	}

	return true, apiErr
}

func loadCloudflareZones(ctx context.Context, dc *DomainConfig) ([]Zone, error) {
	var out []Zone
	page := 1
	perPage := 50

	for {
		endpoint := fmt.Sprintf("/zones?page=%d&per_page=%d", page, perPage)
		data, err := cloudflareAPI(ctx, dc, MethodGET, endpoint, nil)
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
		data, err := cloudflareAPI(ctx, dc, MethodGET, endpoint, nil)
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
func updateCloudflareDNS(
	ctx context.Context,
	dc *DomainConfig,
	fqdn, recordType, newIP string,
	records []Record,
	zoneID string,
) (bool, error) {
	existing, err := resolveCloudflareExistingRecord(ctx, dc, zoneID, fqdn, recordType, records)
	if err != nil {
		return false, err
	}

	if shouldSkipCloudflareUpdate(fqdn, recordType, newIP, existing) {
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

	payload := buildCloudflareRecordPayload(dc, fqdn, recordType, newIP)

	actionType, err := upsertCloudflareRecord(ctx, dc, zoneID, fqdn, recordType, existing, payload)
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

func resolveCloudflareExistingRecord(
	ctx context.Context,
	dc *DomainConfig,
	zoneID, fqdn, recordType string,
	records []Record,
) (*Record, error) {
	existing := findMatchingCloudflareRecord(records, fqdn, recordType)
	if existing != nil {
		return existing, nil
	}

	return findCloudflareRecord(ctx, dc, zoneID, fqdn, recordType)
}

func findMatchingCloudflareRecord(records []Record, fqdn, recordType string) *Record {
	wantName := strings.TrimSuffix(fqdn, ".")

	for i := range records {
		if !strings.EqualFold(strings.TrimSuffix(records[i].Name, "."), wantName) {
			continue
		}
		if records[i].Type != recordType {
			continue
		}
		return &records[i]
	}

	return nil
}

func shouldSkipCloudflareUpdate(fqdn, recordType, newIP string, existing *Record) bool {
	if existing == nil {
		return false
	}

	if existing.Content == newIP {
		debugLog("DNS-LOGIC", fqdn, fmt.Sprintf("✅ %s: %s = %s", T.RecordCurrent, recordType, newIP))
		log(LogContext{
			Level:   LogInfo,
			Action:  ActionCurrent,
			Domain:  fqdn,
			Message: fmt.Sprintf("%-4s  %s %s", recordType, newIP, T.Current),
		})
		return true
	}

	if strings.TrimSpace(existing.Comment) != ManagedComment {
		msg := fmt.Sprintf(T.CFUnmanagedRecord, recordType, strings.TrimSpace(existing.Comment))

		debugLog("DNS-LOGIC", fqdn, msg)
		log(LogContext{
			Level:   LogWarn,
			Action:  ActionSkip,
			Domain:  fqdn,
			Message: msg,
		})
		return true
	}

	return false
}

func buildCloudflareRecordPayload(dc *DomainConfig, fqdn, recordType, newIP string) map[string]interface{} {
	return map[string]interface{}{
		"type":    recordType,
		"name":    fqdn,
		"content": newIP,
		"ttl":     effectiveTTL(dc),
		"proxied": dc.CFProxied,
		"comment": ManagedComment,
	}
}

func upsertCloudflareRecord(
	ctx context.Context,
	dc *DomainConfig,
	zoneID, fqdn, recordType string,
	existing *Record,
	payload map[string]interface{},
) (string, error) {
	if existing != nil {
		actionType, err := updateCloudflareRecord(ctx, dc, zoneID, existing.ID, payload)
		if !shouldRetryCloudflareUpdateAsCreate(err) {
			return actionType, err
		}

		return recoverCloudflareMissingRecord(ctx, dc, zoneID, fqdn, recordType, payload)
	}

	if err := createCloudflareRecord(ctx, dc, zoneID, payload); err != nil {
		return "", err
	}

	return ActionCreate, nil
}

func updateCloudflareRecord(
	ctx context.Context,
	dc *DomainConfig,
	zoneID, recordID string,
	payload map[string]interface{},
) (string, error) {
	endpoint := fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, recordID)
	_, err := cloudflareAPI(ctx, dc, MethodPUT, endpoint, payload)
	if err != nil {
		return "", err
	}
	return ActionUpdate, nil
}

func createCloudflareRecord(
	ctx context.Context,
	dc *DomainConfig,
	zoneID string,
	payload map[string]interface{},
) error {
	endpoint := fmt.Sprintf("/zones/%s/dns_records", zoneID)
	_, err := cloudflareAPI(ctx, dc, MethodPOST, endpoint, payload)
	return err
}

func shouldRetryCloudflareUpdateAsCreate(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound
}

func recoverCloudflareMissingRecord(
	ctx context.Context,
	dc *DomainConfig,
	zoneID, fqdn, recordType string,
	payload map[string]interface{},
) (string, error) {
	rec, err := findCloudflareRecord(ctx, dc, zoneID, fqdn, recordType)
	if err != nil {
		return "", err
	}

	if rec == nil {
		if err := createCloudflareRecord(ctx, dc, zoneID, payload); err != nil {
			return "", err
		}
		return ActionCreate, nil
	}

	if _, err := updateCloudflareRecord(ctx, dc, zoneID, rec.ID, payload); err != nil {
		return "", err
	}

	return ActionUpdate, nil
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

	configDomains := buildCloudflareConfigDomains()

	for _, zone := range zones {
		cleanupCloudflareZoneRecords(ctx, zone, recordCache, configDomains)
	}
}

func buildCloudflareConfigDomains() map[string]struct{} {
	configDomains := make(map[string]struct{})

	for _, dc := range cfg.DomainConfigs {
		if dc.Provider != ProviderCloudflare {
			continue
		}

		fqdn := normalizeCloudflareName(dc.FQDN)
		if fqdn != "" {
			configDomains[fqdn] = struct{}{}
		}
	}

	return configDomains
}

func cleanupCloudflareZoneRecords(
	ctx context.Context,
	zone Zone,
	recordCache *ZoneRecordCache,
	configDomains map[string]struct{},
) {
	cfDC := cloudflareDCForZone(zone.Name)
	if cfDC == nil {
		return
	}

	records, exists := recordCache.Get(zone.ID)
	if !exists {
		return
	}

	zoneName := normalizeCloudflareName(zone.Name)

	for _, rec := range records {
		cleanupSingleCloudflareRecord(ctx, cfDC, zone, zoneName, rec, configDomains)
	}
}

func cleanupSingleCloudflareRecord(
	ctx context.Context,
	cfDC *DomainConfig,
	zone Zone,
	zoneName string,
	rec Record,
	configDomains map[string]struct{},
) {
	fqdn, shouldDelete := shouldCleanupCloudflareRecord(rec, zoneName, configDomains)
	if !shouldDelete {
		return
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
		return
	}

	deleteCloudflareRecord(ctx, cfDC, zone.ID, fqdn, rec)
}

func shouldCleanupCloudflareRecord(
	rec Record,
	zoneName string,
	configDomains map[string]struct{},
) (string, bool) {
	if rec.Type != RecordTypeA && rec.Type != RecordTypeAAAA {
		return "", false
	}

	if strings.TrimSpace(rec.Comment) != ManagedComment {
		return "", false
	}

	fqdn := normalizeCloudflareName(rec.Name)
	if fqdn == "" {
		return "", false
	}

	if fqdn != zoneName && !strings.HasSuffix(fqdn, "."+zoneName) {
		return "", false
	}

	if _, ok := configDomains[fqdn]; ok {
		return "", false
	}

	return fqdn, true
}

func deleteCloudflareRecord(
	ctx context.Context,
	cfDC *DomainConfig,
	zoneID, fqdn string,
	rec Record,
) {
	endpoint := fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, rec.ID)

	if _, err := cloudflareAPI(ctx, cfDC, MethodDELETE, endpoint, nil); err != nil {
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

func normalizeCloudflareName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
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

		data, err := cloudflareAPI(ctx, dc, MethodGET, endpoint, nil)
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
