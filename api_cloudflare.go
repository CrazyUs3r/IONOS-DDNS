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
	"strings"
	"time"
)

func saveCloudflareCacheToFile(zones []Zone, recordCache *ZoneRecordCache) error {
	return saveProviderCacheToFile("Cloudflare", "cloudflare_cache.json", zones, recordCache)
}

func loadCloudflareCacheFromFile() ([]Zone, *ZoneRecordCache, error) {
	return loadProviderCacheFromFile("Cloudflare", "cloudflare_cache.json")
}

// ============================================================================.
func cloudflareAPI(ctx context.Context, dc *DomainConfig, method, endpoint string, body any) ([]byte, error) {
	fullURL := cloudflareAPIBase + endpoint

	return apiWithRetry(ctx, "Cloudflare", phrases().CFAPIFailed, func(attempt, maxRetries int) ([]byte, bool, error) {
		return cloudflareAPIAttempt(ctx, dc, method, fullURL, body, attempt, maxRetries)
	})
}

func cloudflareAPIAttempt(
	ctx context.Context,
	dc *DomainConfig,
	method, fullURL string,
	body any,
	attempt, maxRetries int,
) ([]byte, bool, error) {
	debugLog("HTTP", "", fmt.Sprintf(phrases().CFAttempt,
		phrases().Attempt, attempt+1, maxRetries, method, fullURL))

	req, err := buildCloudflareRequest(ctx, dc, method, fullURL, body)
	if err != nil {
		return nil, false, err
	}

	start := time.Now()
	res, err := getHTTPClient().Do(req)
	duration := time.Since(start)

	if err != nil {
		retry, handledErr := handleProviderNetworkError(ctx, "Cloudflare", method, err, duration, attempt, maxRetries, true)

		return nil, retry, handledErr
	}

	defer func() {
		if err := res.Body.Close(); err != nil {
			debugLog("HTTP", "", fmt.Sprintf(phrases().ErrBodyClose+": %v", err))
		}
	}()

	return handleCloudflareResponse(ctx, res, method, fullURL, duration, attempt, maxRetries)
}

func buildCloudflareRequest(
	ctx context.Context,
	dc *DomainConfig,
	method, fullURL string,
	body any,
) (*http.Request, error) {
	bodyReader, err := cloudflareRequestBodyReader(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", phrases().ErrRequestCreate, err)
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

func cloudflareRequestBodyReader(body any) (io.Reader, error) {
	if body == nil {
		return bytes.NewReader([]byte{}), nil
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", phrases().ErrJSONMarshal, err)
	}

	return bytes.NewReader(bodyBytes), nil
}

func applyCloudflareAuthHeaders(req *http.Request, dc *DomainConfig) error {
	switch {
	case dc.CFToken != "":
		token := normalizeCloudflareToken(dc.CFToken)
		if token == "" {
			return fmt.Errorf("%s", phrases().CFTokenEmpty)
		}
		req.Header.Set("Authorization", "Bearer "+token)

		return nil

	case dc.CFEmail != "" && dc.CFSecret != "":
		req.Header.Set("X-Auth-Email", strings.TrimSpace(dc.CFEmail))
		req.Header.Set("X-Auth-Key", strings.TrimSpace(dc.CFSecret))

		return nil

	default:
		return fmt.Errorf("%s", phrases().CFNoCredentials)
	}
}

func normalizeCloudflareToken(token string) string {
	token = strings.TrimSpace(token)
	token = strings.Trim(token, `"'`)
	if len(token) >= len("Bearer ") && strings.EqualFold(token[:len("Bearer ")], "Bearer ") {
		token = token[len("Bearer "):]
	}
	token = strings.TrimSpace(token)

	token = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}

		return r
	}, token)

	return token
}

func handleCloudflareResponse(
	ctx context.Context,
	res *http.Response,
	method, fullURL string,
	duration time.Duration,
	attempt, maxAttempts int,
) ([]byte, bool, error) {
	respBody, readErr := io.ReadAll(res.Body)

	if readErr != nil {
		retry, handledErr := handleCloudflareReadError(ctx, res, method, readErr, duration, attempt, maxAttempts)

		return nil, retry, handledErr
	}

	if res.StatusCode == http.StatusTooManyRequests {
		retry, handledErr := handleCloudflareRateLimit(ctx, res, method, fullURL, respBody, duration, attempt, maxAttempts)

		return nil, retry, handledErr
	}

	var cfResp CloudflareResponse
	if err := json.Unmarshal(respBody, &cfResp); err != nil {
		retry, handledErr := handleCloudflareInvalidJSON(ctx, res, method, fullURL, respBody, duration, attempt, maxAttempts)

		return nil, retry, handledErr
	}

	if !cfResp.Success {
		retry, handledErr := handleCloudflareAPIFailure(ctx, res, method, fullURL, respBody, &cfResp, duration, attempt, maxAttempts)

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
	attempt, maxAttempts int,
) (bool, error) {
	apiMetrics.RecordError(method, res.StatusCode, readErr, duration)

	lastErr := fmt.Errorf("%s: %w", phrases().ErrBodyRead, readErr)
	if !canRetryAPIAttempt(attempt, maxAttempts) {
		return false, lastErr
	}

	serverBusy := res.StatusCode == http.StatusTooManyRequests || res.StatusCode >= 500

	if !sleepOrCancel(ctx, calculateRetryDelay(attempt, serverBusy)) {
		return false, fmt.Errorf("%s: %w", phrases().ErrContextCancelled, ctx.Err())
	}

	return true, lastErr
}

func handleCloudflareRateLimit(
	ctx context.Context,
	res *http.Response,
	method, fullURL string,
	respBody []byte,
	duration time.Duration,
	attempt, maxAttempts int,
) (bool, error) {
	apiErr := classifyCloudflareAPIError(res.StatusCode, method, fullURL, respBody, nil, res.Header)
	apiMetrics.RecordError(method, res.StatusCode, apiErr, duration)
	if !canRetryAPIAttempt(attempt, maxAttempts) {
		return false, apiErr
	}

	wait := apiErr.RetryAfter
	if wait <= 0 {
		wait = calculateRetryDelay(attempt, true)
	}

	if !sleepOrCancel(ctx, wait) {
		return false, fmt.Errorf("%s: %w", phrases().ErrContextCancelled, ctx.Err())
	}

	return true, apiErr
}

func handleCloudflareInvalidJSON(
	ctx context.Context,
	res *http.Response,
	method, fullURL string,
	respBody []byte,
	duration time.Duration,
	attempt, maxAttempts int,
) (bool, error) {
	if len(respBody) > 0 && respBody[0] == '<' {
		preview := string(respBody)
		if len(preview) > 200 {
			preview = preview[:200] + "..."
		}
		debugLog("HTTP", "", fmt.Sprintf(phrases().CFHTMLResponse, res.StatusCode, preview))
	}

	apiErr := classifyAPIErrorWithHeaders(res.StatusCode, method, fullURL, string(respBody), res.Header)
	if apiErr == nil {
		apiErr = &APIError{
			StatusCode: res.StatusCode,
			Method:     method,
			URL:        fullURL,
			Message:    phrases().CFInvalidJSON,
			Retryable:  res.StatusCode >= 500,
		}
	}

	apiMetrics.RecordError(method, res.StatusCode, apiErr, duration)

	if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
		return false, apiErr
	}

	if !apiErr.IsRetryable() || !canRetryAPIAttempt(attempt, maxAttempts) {
		return false, apiErr
	}

	wait := apiErr.RetryAfter
	if wait <= 0 {
		serverBusy := res.StatusCode == http.StatusTooManyRequests || res.StatusCode >= 500
		wait = calculateRetryDelay(attempt, serverBusy)
	}

	if !sleepOrCancel(ctx, wait) {
		return false, fmt.Errorf("%s: %w", phrases().ErrContextCancelled, ctx.Err())
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
	attempt, maxAttempts int,
) (bool, error) {
	apiErr := classifyCloudflareAPIError(res.StatusCode, method, fullURL, respBody, cfResp, res.Header)
	apiMetrics.RecordError(method, res.StatusCode, apiErr, duration)

	if !apiErr.IsRetryable() || !canRetryAPIAttempt(attempt, maxAttempts) {
		return false, apiErr
	}

	wait := apiErr.RetryAfter
	if wait <= 0 {
		serverBusy := res.StatusCode == http.StatusTooManyRequests || res.StatusCode >= 500
		wait = calculateRetryDelay(attempt, serverBusy)
	}

	if !sleepOrCancel(ctx, wait) {
		return false, fmt.Errorf("%s: %w", phrases().ErrContextCancelled, ctx.Err())
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
			debugLog("CACHE", "", fmt.Sprintf(phrases().CFZoneLoadError+": %v", err))

			return nil, fmt.Errorf("%s: %w", phrases().CFZoneLoadError, err)
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
			debugLog("CACHE", "", fmt.Sprintf(phrases().CFZoneParseError+": %v", err))

			return nil, fmt.Errorf("%s: %w", phrases().CFZoneParseError, err)
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
			return nil, fmt.Errorf("%s: %w", phrases().ErrBodyRead, err)
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
			return nil, fmt.Errorf("%s: %w", phrases().ErrBodyRead, err)
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

// ============================================================================.
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

	if dryRunEnabled() {
		log(LogContext{
			Level:   LogWarn,
			Action:  ActionDryRun,
			Domain:  fqdn,
			Message: fmt.Sprintf("⚠️ %s %s %s", phrases().WouldSet, recordType, newIP),
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
		Message: fmt.Sprintf("🔄 %s -> %s %s", recordType, newIP, phrases().Update),
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

	if dnsRecordContentEqual(recordType, existing.Content, newIP) {
		debugLog("DNS-LOGIC", fqdn, fmt.Sprintf("✅ %s: %s = %s", phrases().RecordCurrent, recordType, newIP))
		log(LogContext{
			Level:   LogInfo,
			Action:  ActionCurrent,
			Domain:  fqdn,
			Message: fmt.Sprintf("%-4s  %s %s", recordType, newIP, phrases().Current),
		})

		return true
	}

	if strings.TrimSpace(existing.Comment) != ManagedComment {
		msg := fmt.Sprintf(phrases().CFUnmanagedRecord, recordType, strings.TrimSpace(existing.Comment))

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

func buildCloudflareRecordPayload(dc *DomainConfig, fqdn, recordType, newIP string) map[string]any {
	return map[string]any{
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
	payload map[string]any,
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
	payload map[string]any,
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
	payload map[string]any,
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
	payload map[string]any,
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

// ============================================================================.
func cloudflareDCForZone(zoneName string) *DomainConfig {
	zoneName = strings.ToLower(strings.TrimSuffix(zoneName, "."))
	for _, dc := range snapshotDomainConfigs() {
		if dc.Provider != ProviderCloudflare {
			continue
		}
		fqdn := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(dc.FQDN), "."))
		if fqdn == "" {
			continue
		}
		if fqdn == zoneName || strings.HasSuffix(fqdn, "."+zoneName) {
			return &dc
		}
	}

	return nil
}

func cleanupCloudflareRecords(ctx context.Context, zones []Zone, recordCache *ZoneRecordCache) {
	debugLog("MAINTENANCE", "", phrases().CleanupStartCF)

	configRecords := buildCloudflareConfigRecords()
	managedDomains := buildProviderManagedDomains(ProviderCloudflare)

	for _, zone := range zones {
		cleanupCloudflareZoneRecords(ctx, zone, recordCache, configRecords, managedDomains)
	}
}

func buildCloudflareConfigRecords() map[string]struct{} {
	return buildProviderConfigRecords(ProviderCloudflare)
}

func cleanupCloudflareZoneRecords(
	ctx context.Context,
	zone Zone,
	recordCache *ZoneRecordCache,
	configRecords map[string]struct{},
	managedDomains map[string]struct{},
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
		cleanupSingleCloudflareRecord(ctx, cfDC, zone, zoneName, rec, configRecords, managedDomains)
	}
}

func cleanupSingleCloudflareRecord(
	ctx context.Context,
	cfDC *DomainConfig,
	zone Zone,
	zoneName string,
	rec Record,
	configRecords map[string]struct{},
	managedDomains map[string]struct{},
) {
	fqdn, shouldDelete := shouldCleanupCloudflareRecord(rec, zoneName, configRecords, managedDomains)
	if !shouldDelete {
		return
	}

	debugLog("MAINTENANCE", fqdn, fmt.Sprintf(phrases().CleanupOrphanedCF, rec.Type, rec.ID, zone.Name))

	if dryRunEnabled() {
		log(LogContext{
			Level:   LogInfo,
			Action:  ActionCleanup,
			Domain:  fqdn,
			Message: phrases().CleanupDryRun,
		})

		return
	}

	deleteCloudflareRecord(ctx, cfDC, zone.ID, fqdn, rec)
}

func shouldCleanupCloudflareRecord(
	rec Record,
	zoneName string,
	configRecords map[string]struct{},
	managedDomains map[string]struct{},
) (string, bool) {
	if !isCleanupEligibleRecordType(rec.Type) {
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

	if _, ok := configRecords[managedRecordKey(fqdn, rec.Type)]; ok {
		return "", false
	}
	if _, owned := managedDomains[fqdn]; !owned {
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
		debugLog("MAINTENANCE", fqdn, fmt.Sprintf(phrases().CleanupDeleteError, err))

		return
	}

	log(LogContext{
		Level:   LogInfo,
		Action:  ActionCleanup,
		Domain:  fqdn,
		Message: fmt.Sprintf(phrases().CleanupRecordRemoved, rec.Type),
	})
}

func normalizeCloudflareName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// ============================================================================.
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
			return nil, fmt.Errorf("%s: %w", phrases().ErrBodyRead, err)
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
			return nil, fmt.Errorf("%s: %w", phrases().CFRecordsParseError, err)
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

	return nil, fmt.Errorf("%s", phrases().ErrRecordNotFound)
}
