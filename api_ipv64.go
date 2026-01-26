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

func ipv64API(ctx context.Context, dc *DomainConfig, endpoint string, params map[string]string) ([]byte, error) {
	fullURL := ipv64APIBase + endpoint

	if len(params) > 0 {
		q := url.Values{}
		for k, v := range params {
			q.Set(k, v)
		}
		fullURL += "?" + q.Encode()
	}

	var lastErr error
	for attempt := 0; attempt < MaxAPIRetries; attempt++ {
		start := time.Now()
		debugLog("HTTP", "", fmt.Sprintf("🔄 IPv64 %s %d/%d: GET %s",
			T.Attempt, attempt+1, MaxAPIRetries, endpoint))

		req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
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
	params := map[string]string{"get_domains": dc.IPv64Token}
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
			Updates:          subdomain.Updates,
			Wildcard:         subdomain.Wildcard,
			Deactivated:      subdomain.Deactivated,
		}

		for _, rec := range subdomain.Records {
			if rec.Deactivated == 1 {
				continue
			}

			switch rec.Type {
			case "A":
				domain.IPv4 = rec.Content
			case "AAAA":
				domain.IPv6 = rec.Content
			}
		}

		providerCache.ipv64Records[domainName] = domain

		debugLog("CACHE", domainName, fmt.Sprintf("✅ Cached - IPv4: %s, IPv6: %s, Hash: %s***",
			domain.IPv4, domain.IPv6, subdomain.DomainUpdateHash[:8]))
	}

	return nil
}

// ============================================================================
// DNS LOGIC - IPV64
// ============================================================================

func updateIPv64DNS(ctx context.Context, _ *DomainConfig, fqdn, recordType, newIP string) (bool, error) {
	// Domain aus Cache holen
	providerCache.RLock()
	domain, exists := providerCache.ipv64Records[fqdn]
	providerCache.RUnlock()

	if !exists {
		return false, fmt.Errorf("domain %s not found in ipv64 cache", fqdn)
	}

	if domain.DomainUpdateHash == "" {
		return false, fmt.Errorf("no domain_update_hash found for %s", fqdn)
	}

	currentIP := ""
	switch recordType {
	case "A":
		currentIP = domain.IPv4
	case "AAAA":
		currentIP = domain.IPv6
	}

	if currentIP == newIP {
		debugLog("DNS-LOGIC", fqdn, fmt.Sprintf("✅ %s: %s = %s", T.RecordCurrent, recordType, newIP))
		writeLog("CURRENT", ActionCurrent, fqdn, fmt.Sprintf("%-4s %s %s", recordType, newIP, T.Current))
		return false, nil
	}

	debugLog("DNS-LOGIC", fqdn, fmt.Sprintf("🔄 %s: %s -> %s", T.RecordUpdateNeeded, currentIP, newIP))

	ipv64Mutex.Lock()
	if time.Since(lastIPv64Update) < 12*time.Second {
		waitTime := 12*time.Second - time.Since(lastIPv64Update)
		debugLog("HTTP", fqdn, fmt.Sprintf("⏳ IPv64 Cooldown: Warte %v...", waitTime.Round(time.Second)))

		timer := time.NewTimer(waitTime)
		ipv64Mutex.Unlock()

		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
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

	updateURL := "https://ipv64.net/nic/update"

	q := url.Values{}
	q.Set("key", domain.DomainUpdateHash)
	q.Set("domain", fqdn)

	switch recordType {
	case "A":
		q.Set("ipv4", newIP)
	case "AAAA":
		q.Set("ipv6", newIP)
	}

	fullUpdateURL := updateURL + "?" + q.Encode()

	debugLog("HTTP", fqdn, fmt.Sprintf("📡 IPv64 Update URL: %s",
		strings.Replace(fullUpdateURL, domain.DomainUpdateHash, "***TOKEN***", 1)))

	req, err := http.NewRequestWithContext(ctx, "GET", fullUpdateURL, nil)
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

	respBody, _ := io.ReadAll(res.Body)
	responseText := strings.TrimSpace(string(respBody))

	debugLog("HTTP", fqdn, fmt.Sprintf("📥 IPv64 Response [%d]: %s (Latency: %v)",
		res.StatusCode, responseText, duration))

	if res.StatusCode == 401 {
		apiMetrics.RecordError(401, fmt.Errorf("unauthorized"), duration)
		return false, fmt.Errorf("ipv64 authentication failed - domain_update_hash incorrect")
	}

	if res.StatusCode != 200 {
		apiMetrics.RecordError(res.StatusCode, fmt.Errorf("http %d", res.StatusCode), duration)
		return false, fmt.Errorf("ipv64 returned status %d: %s", res.StatusCode, responseText)
	}

	responseLower := strings.ToLower(responseText)

	if strings.Contains(responseLower, "good") || strings.Contains(responseLower, "nochg") {
		apiMetrics.RecordSuccess(duration)

		log(LogContext{
			Level:   LogInfo,
			Action:  ActionUpdate,
			Domain:  fqdn,
			Message: fmt.Sprintf("🔄 %s -> %s %s", recordType, newIP, T.Update),
		})

		providerCache.Lock()
		if cachedDomain, ok := providerCache.ipv64Records[fqdn]; ok {
			switch recordType {
			case "A":
				cachedDomain.IPv4 = newIP
			case "AAAA":
				cachedDomain.IPv6 = newIP
			}
			providerCache.ipv64Records[fqdn] = cachedDomain
		}
		providerCache.Unlock()

		return true, nil
	}

	apiMetrics.RecordError(res.StatusCode, fmt.Errorf("ipv64: %s", responseText), duration)

	if strings.Contains(responseLower, "badauth") {
		return false, fmt.Errorf("ipv64 authentication failed: invalid update hash")
	}
	if strings.Contains(responseLower, "abuse") {
		return false, fmt.Errorf("ipv64 abuse: too many requests")
	}

	return false, fmt.Errorf("ipv64 update failed: %s", responseText)
}
