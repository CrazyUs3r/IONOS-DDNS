package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ============================================================================
// API - CLOUDFLARE
// ============================================================================

func cloudflareAPI(ctx context.Context, dc *DomainConfig, method, endpoint string, body interface{}) ([]byte, error) {
	url := cloudflareAPIBase + endpoint

	var lastErr error
	for attempt := 0; attempt < MaxAPIRetries; attempt++ {
		start := time.Now()
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

		req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, fmt.Errorf("request creation failed: %w", err)
		}

		if dc.CFToken != "" {
			req.Header.Set("Authorization", "Bearer "+dc.CFToken)
		} else if dc.CFEmail != "" && dc.CFSecret != "" {
			req.Header.Set("X-Auth-Email", dc.CFEmail)
			req.Header.Set("X-Auth-Key", dc.CFSecret)
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Go-DynDNS/2.0")

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
		return nil, fmt.Errorf("failed to load cloudflare zones: %w", err)
	}

	var resp struct {
		Result []CloudflareZone `json:"result"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
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
		if records[i].Name == fqdn && records[i].Type == recordType {
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
