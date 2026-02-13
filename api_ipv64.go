package main

import (
	"context"
	"encoding/json"
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
// API - IPV64
// ============================================================================
func splitIPv64FQDN(fqdn string) (baseDomain, praefix string) {
	parts := strings.Split(fqdn, ".")
	if len(parts) < 4 {
		return fqdn, ""
	}
	return strings.Join(parts[1:], "."), parts[0]
}

func ipv64API(ctx context.Context, dc *DomainConfig, params map[string]string) ([]byte, error) {
	method := "GET"
	var bodyData string
	apiURL := ipv64APIBase

	if len(params) > 0 {
		if _, hasGetDomains := params["get_domains"]; hasGetDomains {
			method = "GET"
			q := url.Values{}
			for k, v := range params {
				q.Set(k, v)
			}
			apiURL += "?" + q.Encode()
		} else if hasAddDomain := params["add_domain"]; hasAddDomain != "" {
			method = "POST"
			bodyData = fmt.Sprintf(
				"add_domain=%s",
				url.QueryEscape(hasAddDomain),
			)
		} else if delRecord := params["del_record"]; delRecord != "" {
			method = "DELETE"
			bodyData = fmt.Sprintf(
				"del_record=%s",
				url.QueryEscape(delRecord),
			)
		} else if delDomain := params["del_domain"]; delDomain != "" {
			method = "DELETE"
			bodyData = fmt.Sprintf(
				"del_domain=%s",
				url.QueryEscape(delDomain),
			)
		} else if _, hasAddRecord := params["add_record"]; hasAddRecord {
			method = "POST"
			values := url.Values{}
			for k, v := range params {
				values.Set(k, v)
			}
			bodyData = values.Encode()
		} else {
			q := url.Values{}
			for k, v := range params {
				q.Set(k, v)
			}
			apiURL += "?" + q.Encode()
		}
	}

	var lastErr error
	for attempt := 0; attempt < MaxAPIRetries; attempt++ {
		start := time.Now().Local()
		debugLog("HTTP", "", fmt.Sprintf("🔄 IPv64 %s %d/%d: %s %s",
			T.Attempt, attempt+1, MaxAPIRetries, method, apiURL))

		var req *http.Request
		var err error

		if bodyData != "" {
			req, err = http.NewRequestWithContext(ctx, method, apiURL, strings.NewReader(bodyData))
			if err == nil {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
		} else {
			req, err = http.NewRequestWithContext(ctx, method, apiURL, nil)
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

		respBody, readErr := io.ReadAll(res.Body)
		_, _ = io.Copy(io.Discard, res.Body)
		closeErr := res.Body.Close()

		if closeErr != nil {
			debugLog("HTTP", "", fmt.Sprintf("Body close failed: %v", closeErr))
		}

		if readErr != nil {
			apiMetrics.RecordError(res.StatusCode, readErr, duration)
			lastErr = fmt.Errorf("failed to read response: %w", readErr)
			continue
		}

		if apiErr := classifyAPIError(res.StatusCode, method, apiURL, string(respBody)); apiErr != nil {
			apiMetrics.RecordError(res.StatusCode, apiErr, duration)
			return nil, apiErr
		}

		var ipv64Resp IPv64Response
		if err := json.Unmarshal(respBody, &ipv64Resp); err != nil {
			apiMetrics.RecordError(res.StatusCode, err, duration)
			if len(respBody) > 0 && respBody[0] == '<' {
				preview := string(respBody)
				if len(preview) > 200 {
					preview = preview[:200] + "..."
				}
				debugLog("HTTP", "", fmt.Sprintf("IPv64 API returned HTML instead of JSON: %s", preview))
			}

			return nil, fmt.Errorf("failed to parse ipv64 response: %w", err)
		}

		infoLower := strings.ToLower(ipv64Resp.Info)
		if strings.Contains(infoLower, "error") || strings.Contains(infoLower, "invalid") {
			apiErr := &APIError{
				StatusCode: res.StatusCode,
				Message:    ipv64Resp.Info,
				Retryable:  false,
			}
			log(LogContext{
				Level:   LogError,
				Action:  ActionAPI,
				Message: "IPv64 API Error: " + ipv64Resp.Info,
			})
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

	data, err := ipv64API(ctx, dc, params)
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

// ============================================================================
// CACHE PERSISTENCE
// ============================================================================
func getIPv64CachePath() string {
	return filepath.Join(cfg.LogDir, "ipv64_cache.json")
}

func saveIPv64Cache() error {
	cachePath := getIPv64CachePath()

	providerCache.RLock()
	data := providerCache.ipv64Records
	providerCache.RUnlock()

	jsonData, err := json.MarshalIndent(data, "", "  ")
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

	debugLog("CACHE", "", fmt.Sprintf("💾 IPv64 Cache gespeichert (%d domains)", len(data)))
	return nil
}

func loadIPv64CacheFromDisk() error {
	cachePath := getIPv64CachePath()

	data, err := os.ReadFile(cachePath)
	if err != nil {
		if os.IsNotExist(err) {
			debugLog("CACHE", "", "ℹ️ Keine IPv64 Cache-Datei gefunden (erster Start)")
			return nil
		}
		return fmt.Errorf("failed to read cache: %w", err)
	}

	var cached map[string]IPv64Domain
	if err := json.Unmarshal(data, &cached); err != nil {
		return fmt.Errorf("failed to unmarshal cache: %w", err)
	}

	providerCache.Lock()
	providerCache.ipv64Records = cached
	providerCache.Unlock()

	debugLog("CACHE", "", fmt.Sprintf("📂 IPv64 Cache von Disk geladen (%d domains)", len(cached)))
	return nil
}

// ============================================================================
// LOAD ALL IPV64 DOMAINS - VERBESSERT
// ============================================================================
func loadAllIPv64Domains(ctx context.Context, dc *DomainConfig) error {
	params := map[string]string{
		"get_domains": dc.IPv64Token,
	}

	data, err := ipv64API(ctx, dc, params)
	if err != nil {
		debugLog("CACHE", "", fmt.Sprintf("⚠️ IPv64 API-Fehler, behalte alten Cache: %v", err))
		providerCache.RLock()
		hasCachedData := len(providerCache.ipv64Records) > 0
		providerCache.RUnlock()

		if !hasCachedData {
			if loadErr := loadIPv64CacheFromDisk(); loadErr != nil {
				debugLog("CACHE", "", fmt.Sprintf("⚠️ Konnte auch keinen Cache von Disk laden: %v", loadErr))
			} else {
				debugLog("CACHE", "", "✅ Fallback auf persistierten Cache erfolgreich")
			}
		}

		return err
	}

	var resp IPv64Response
	if err := json.Unmarshal(data, &resp); err != nil {
		debugLog("CACHE", "", fmt.Sprintf("⚠️ IPv64 Parse-Fehler (vermutlich HTML statt JSON), behalte alten Cache: %v", err))
		if len(data) > 0 && data[0] == '<' {
			preview := string(data)
			if len(preview) > 200 {
				preview = preview[:200] + "..."
			}
			debugLog("CACHE", "", fmt.Sprintf("API returned HTML: %s", preview))
		}

		return fmt.Errorf("failed to parse ipv64 response: %w", err)
	}

	providerCache.Lock()

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

	providerCache.Unlock()

	if err := saveIPv64Cache(); err != nil {
		debugLog("CACHE", "", fmt.Sprintf("⚠️ Konnte Cache nicht speichern: %v", err))
	}

	return nil
}

// ============================================================================
// DNS LOGIC - IPV64
// ============================================================================
func updateIPv64DNS(
	ctx context.Context,
	fqdn, recordType, newIP string,
) (bool, error) {

	baseDomain, praefix := splitIPv64FQDN(fqdn)

	providerCache.RLock()
	domain, exists := providerCache.ipv64Records[baseDomain]
	providerCache.RUnlock()

	if !exists {
		return false, fmt.Errorf("ipv64 base domain not found: %s", baseDomain)
	}

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
	lastIPv64Update = time.Now().Local()
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

	start := time.Now().Local()
	res, err := getHTTPClient().Do(req)
	duration := time.Since(start)

	if err != nil {
		apiMetrics.RecordError(0, err, duration)
		return false, err
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			debugLog("HTTP", "", fmt.Sprintf("Body close failed: %v", err))
		}
	}()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		apiMetrics.RecordError(res.StatusCode, err, duration)
		return false, fmt.Errorf("failed to read ipv64 response: %w", err)
	}
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
func cleanupIPv64Records(ctx context.Context) {
	var ipv64DC *DomainConfig
	for i := range cfg.DomainConfigs {
		if cfg.DomainConfigs[i].Provider == ProviderIPv64 {
			ipv64DC = &cfg.DomainConfigs[i]
			break
		}
	}

	if ipv64DC == nil {
		return
	}

	debugLog("MAINTENANCE", "", "🧹 Starte Bereinigung verwaister IPv64-Records...")

	configDomains := make(map[string]struct{})
	for _, dc := range cfg.DomainConfigs {
		if dc.Provider == ProviderIPv64 {
			configDomains[strings.ToLower(strings.TrimSuffix(dc.FQDN, "."))] = struct{}{}
		}
	}

	providerCache.RLock()
	defer providerCache.RUnlock()

	for baseDomain, domain := range providerCache.ipv64Records {
		for _, rec := range domain.Records {
			if rec.Type != "A" && rec.Type != "AAAA" {
				continue
			}

			fqdn := baseDomain
			if rec.Praefix != "" {
				fqdn = rec.Praefix + "." + baseDomain
			}
			fqdn = strings.ToLower(strings.TrimSuffix(fqdn, "."))

			if _, ok := configDomains[fqdn]; ok {
				continue
			}

			debugLog(
				"MAINTENANCE",
				fqdn,
				fmt.Sprintf("🗑️ Entferne verwaisten %s Record (ID: %d)", rec.Type, rec.RecordID),
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

			if err := deleteIPv64Record(ctx, ipv64DC, baseDomain, rec); err != nil {
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

func deleteIPv64Record(
	ctx context.Context,
	dc *DomainConfig,
	baseDomain string,
	record IPv64Record,
) error {

	params := map[string]string{
		"del_record": fmt.Sprintf("%d", record.RecordID),
	}

	data, err := ipv64API(ctx, dc, params)
	if err != nil {
		return fmt.Errorf(
			"failed to delete ipv64 record %d (%s.%s): %w",
			record.RecordID,
			record.Praefix,
			baseDomain,
			err,
		)
	}

	debugLog("HTTP", baseDomain, fmt.Sprintf("🔥 IPv64 delete response: %s", string(data)))

	return nil
}
