package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ============================================================================
// API - IPV64
// ============================================================================
func splitIPv64FQDN(fqdn string) (baseDomain, praefix string) {
	parts := strings.Split(fqdn, ".")
	if len(parts) < 4 {
		return fqdn, ""
	}
	return strings.Join(parts[1:], "."), parts[0]
}

func ipv64API(ctx context.Context, dc *DomainConfig, endpoint string, params map[string]string) ([]byte, error) {
	// IPv64 API verwendet api.php als Basis-Endpoint
	fullURL := "https://ipv64.net/api.php"

	// Bestimme HTTP-Methode basierend auf dem ersten Parameter
	method := "GET"
	var bodyData string

	if len(params) > 0 {
		// Für get_domains: GET mit Query-Parameter
		if _, hasGetDomains := params["get_domains"]; hasGetDomains {
			method = "GET"
			q := url.Values{}
			for k, v := range params {
				q.Set(k, v)
			}
			fullURL += "?" + q.Encode()
		} else if hasAddDomain := params["add_domain"]; hasAddDomain != "" {
			// add_domain → POST
			method = "POST"
			bodyData = fmt.Sprintf(
				"add_domain=%s",
				url.QueryEscape(hasAddDomain),
			)
		} else if delRecord := params["del_record"]; delRecord != "" {
			// del_record → DELETE mit Body-Data
			method = "DELETE"
			bodyData = fmt.Sprintf(
				"del_record=%s",
				url.QueryEscape(delRecord),
			)
		} else if delDomain := params["del_domain"]; delDomain != "" {
			// del_domain → DELETE mit Body-Data
			method = "DELETE"
			bodyData = fmt.Sprintf(
				"del_domain=%s",
				url.QueryEscape(delDomain),
			)
		} else if _, hasAddRecord := params["add_record"]; hasAddRecord {
			// add_record → POST
			method = "POST"
			values := url.Values{}
			for k, v := range params {
				values.Set(k, v)
			}
			bodyData = values.Encode()
		} else {
			// Fallback: GET mit Query-Parametern
			q := url.Values{}
			for k, v := range params {
				q.Set(k, v)
			}
			fullURL += "?" + q.Encode()
		}
	}

	var lastErr error
	for attempt := 0; attempt < MaxAPIRetries; attempt++ {
		start := time.Now()
		debugLog("HTTP", "", fmt.Sprintf("🔄 IPv64 %s %d/%d: %s %s",
			T.Attempt, attempt+1, MaxAPIRetries, method, fullURL))

		var req *http.Request
		var err error

		if bodyData != "" {
			req, err = http.NewRequestWithContext(ctx, method, fullURL, strings.NewReader(bodyData))
			if err == nil {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
		} else {
			req, err = http.NewRequestWithContext(ctx, method, fullURL, nil)
		}

		if err != nil {
			return nil, fmt.Errorf("request creation failed: %w", err)
		}

		if dc != nil && dc.IPv64Token != "" {
			req.Header.Set("Authorization", "Bearer "+dc.IPv64Token)
		}
		req.Header.Set("User-Agent", "Go-DynDNS/2.0")

		res, err := getHTTPClient().Do(req)
		duration := time.Since(start)

		if err != nil {
			debugLog("HTTP", "", fmt.Sprintf("❌ %s: %v", T.NetworkError, err))
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

		var ipv64Resp IPv64Response
		if err := json.Unmarshal(respBody, &ipv64Resp); err != nil {
			return nil, fmt.Errorf("failed to parse ipv64 response: %w", err)
		}

		infoLower := strings.ToLower(ipv64Resp.Info)
		if strings.Contains(infoLower, "error") || strings.Contains(infoLower, "invalid") {
			apiErr := &APIError{
				StatusCode: res.StatusCode,
				Message:    ipv64Resp.Info,
				Retryable:  false,
			}
			apiMetrics.RecordError(res.StatusCode, apiErr, duration)
			return nil, apiErr
		}

		apiMetrics.RecordSuccess(duration)
		return respBody, nil
	}

	return nil, fmt.Errorf("ipv64 api failed after %d attempts: %w", MaxAPIRetries, lastErr)
}

func loadIPv64Domains(ctx context.Context, dc *DomainConfig) ([]Zone, error) {
	params := map[string]string{
		"get_domains": dc.IPv64Token,
	}

	data, err := ipv64API(ctx, dc, "", params)
	if err != nil {
		return nil, fmt.Errorf("failed to load ipv64 domains: %w", err)
	}

	var resp IPv64Response
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse domains: %w", err)
	}

	zones := make([]Zone, 0, len(resp.Subdomains))

	for domainName, domainData := range resp.Subdomains {
		zone := Zone{
			ID:   domainName,
			Name: domainName,
		}

		for _, rec := range domainData.Records {
			zone.Records = append(zone.Records, Record{
				ID:      fmt.Sprintf("%d", rec.RecordID),
				Type:    rec.Type,
				Content: rec.Content,
			})
		}

		zones = append(zones, zone)
	}

	return zones, nil
}

func loadAllIPv64Domains(ctx context.Context, dc *DomainConfig) error {
	params := map[string]string{
		"get_domains": dc.IPv64Token,
	}

	data, err := ipv64API(ctx, dc, "", params)
	if err != nil {
		return err
	}

	var resp IPv64Response
	if err := json.Unmarshal(data, &resp); err != nil {
		return fmt.Errorf("failed to parse ipv64 response: %w", err)
	}

	providerCache.Lock()
	defer providerCache.Unlock()

	for domainName, subdomain := range resp.Subdomains {
		domain := IPv64Domain{
			Domain:           domainName,
			DomainUpdateHash: subdomain.DomainUpdateHash,
			Records:          make([]IPv64Record, 0),
		}

		for _, rec := range subdomain.Records {
			if rec.Deactivated == 1 {
				continue
			}
			domain.Records = append(domain.Records, rec)
		}

		providerCache.ipv64Records[domainName] = domain

		debugLog(
			"CACHE",
			domainName,
			fmt.Sprintf(
				"✅ Cached IPv64 domain (%d records, hash %s***)",
				len(domain.Records),
				subdomain.DomainUpdateHash[:8],
			),
		)
	}

	return nil
}

// ============================================================================
// DNS LOGIC - IPV64
// ============================================================================
func updateIPv64DNS(
	ctx context.Context,
	dc *DomainConfig,
	fqdn, recordType, newIP string,
) (bool, error) {

	baseDomain, praefix := splitIPv64FQDN(fqdn)

	providerCache.RLock()
	domain, exists := providerCache.ipv64Records[baseDomain]
	providerCache.RUnlock()

	if !exists {
		return false, fmt.Errorf("ipv64 base domain not found: %s", baseDomain)
	}

	// Aktuelle IP aus Records ermitteln
	currentIP := ""
	for _, rec := range domain.Records {
		if rec.Praefix == praefix && rec.Type == recordType {
			currentIP = rec.Content
			break
		}
	}

	if currentIP == newIP {
		writeLog("CURRENT", ActionCurrent, fqdn,
			fmt.Sprintf("%-4s %s %s", recordType, newIP, T.Current))
		return false, nil
	}

	// IPv64 Cooldown
	ipv64Mutex.Lock()
	if time.Since(lastIPv64Update) < 12*time.Second {
		wait := 12*time.Second - time.Since(lastIPv64Update)
		ipv64Mutex.Unlock()

		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return false, ctx.Err()
		}

		ipv64Mutex.Lock()
	}
	lastIPv64Update = time.Now()
	ipv64Mutex.Unlock()

	if cfg.DryRun {
		log(LogContext{
			Level:   LogWarn,
			Action:  ActionDryRun,
			Domain:  fqdn,
			Message: fmt.Sprintf("⚠️ %s %s %s", T.WouldSet, recordType, newIP),
		})
		return true, nil
	}

	// Update-Request
	q := url.Values{}
	q.Set("key", domain.DomainUpdateHash)
	q.Set("domain", fqdn)

	switch recordType {
	case "A":
		q.Set("ipv4", newIP)
	case "AAAA":
		q.Set("ipv6", newIP)
	}

	updateURL := "https://ipv64.net/nic/update?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", updateURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", "Go-DynDNS/2.0")

	start := time.Now()
	res, err := getHTTPClient().Do(req)
	duration := time.Since(start)

	if err != nil {
		apiMetrics.RecordError(0, err, duration)
		return false, err
	}
	defer res.Body.Close()

	body, _ := io.ReadAll(res.Body)
	resp := strings.ToLower(strings.TrimSpace(string(body)))

	if res.StatusCode != 200 {
		return false, fmt.Errorf("ipv64 http %d: %s", res.StatusCode, resp)
	}

	if strings.Contains(resp, "good") || strings.Contains(resp, "nochg") {
		apiMetrics.RecordSuccess(duration)
		log(LogContext{
			Level:   LogInfo,
			Action:  ActionUpdate,
			Domain:  fqdn,
			Message: fmt.Sprintf("🔄 %s -> %s %s", recordType, newIP, T.Update),
		})
		return true, nil
	}

	return false, fmt.Errorf("ipv64 update failed: %s", resp)
}

// ============================================================================
// CLEANUP - IPV64
// ============================================================================

func deleteIPv64Record(
	ctx context.Context,
	dc *DomainConfig,
	baseDomain string,
	record IPv64Record,
) error {

	// Nach IPv64 API: DELETE Request mit del_record
	params := map[string]string{
		"del_record": fmt.Sprintf("%d", record.RecordID),
	}

	data, err := ipv64API(ctx, dc, "", params)
	if err != nil {
		return fmt.Errorf(
			"failed to delete ipv64 record %d (%s.%s): %w",
			record.RecordID,
			record.Praefix,
			baseDomain,
			err,
		)
	}

	debugLog("HTTP", baseDomain, fmt.Sprintf("📥 IPv64 delete response: %s", string(data)))

	return nil
}