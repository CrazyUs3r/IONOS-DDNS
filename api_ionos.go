package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

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

	jitter := time.Duration(rand.Intn(RetryJitterMaxMs)) * time.Millisecond
	wait := baseWait + jitter

	if isServerError {
		wait = wait * 2
		if wait > RetryMaxDelay {
			wait = RetryMaxDelay
		}
	}

	return wait
}

func ionosAPI(ctx context.Context, dc *DomainConfig, method, url string, body interface{}) ([]byte, error) {
	var lastErr error

	for attempt := 0; attempt < MaxAPIRetries; attempt++ {
		start := time.Now()
		debugLog("HTTP", "", fmt.Sprintf(
			"🔄 %s %d/%d: %s %s",
			T.Attempt, attempt+1, MaxAPIRetries, method, url,
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
		req.Header.Set("User-Agent", "Go-DynDNS/2.0")

		res, err := getHTTPClient().Do(req)
		duration := time.Since(start)

		if err != nil {
			debugLog("HTTP", "", fmt.Sprintf("❌ %s: %v | %s: %v", T.NetworkError, err, T.AvgLatency, duration))
			apiMetrics.RecordError(0, err, duration)
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
		res.Body.Close()

		if err != nil {
			apiMetrics.RecordError(res.StatusCode, err, duration)
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
			apiMetrics.RecordSuccess(duration)

			if errVal := lastErrorMsg.Get(); errVal != "" {
				lastErrorMsg.Set("")
			}
			debugLog("HTTP", "", fmt.Sprintf("✅ %s: %d Bytes", T.Success, len(respBody)))
			return respBody, nil
		}

		apiErr := classifyAPIError(res.StatusCode, method, url, string(respBody))
		apiMetrics.RecordError(res.StatusCode, apiErr, duration)

		if res.StatusCode == 401 || res.StatusCode == 403 {
			log(LogContext{
				Level:   LogError,
				Action:  ActionError,
				Message: fmt.Sprintf("🚨 KRITISCHER API-FEHLER: %v", apiErr),
			})
		}

		debugLog("HTTP", "", fmt.Sprintf("⚠️  %s (Retryable: %v)", apiErr.Message, apiErr.Retryable))
		lastErr = apiErr
		lastErrorMsg.Set(sanitizeError(lastErr))

		if !apiErr.IsRetryable() {
			debugLog("HTTP", "", fmt.Sprintf("❌ %s: %s", T.NonRetryableError, apiErr.Message))
			return nil, apiErr
		}

		if attempt >= MaxAPIRetries-1 {
			debugLog("HTTP", "", fmt.Sprintf("❌ %s (%d)", T.MaxAttemptsReached, MaxAPIRetries))
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

	return nil, fmt.Errorf("API fehlgeschlagen nach %d Versuchen: %w", MaxAPIRetries, lastErr)
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
		writeLog("CURRENT", ActionCurrent, fqdn,
			fmt.Sprintf("%-4s %s %s", recordType, newIP, T.Current))
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
		var apiErr *APIError
		if errors.As(err, &apiErr) {
			switch apiErr.StatusCode {
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
						recordType, apiErr.StatusCode),
				})
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

	return true, nil
}
