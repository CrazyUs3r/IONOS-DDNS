// Package main
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
	"strconv"
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
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", T.ErrContextError, err)
	}

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
	for attempt := 0; attempt < cfg.MaxAPIRetries; attempt++ {
		debugLog("HTTP", "", fmt.Sprintf(T.IPv64Attempt,
			T.Attempt, attempt+1, cfg.MaxAPIRetries, method, apiURL))

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
			return nil, fmt.Errorf("%s: %w", T.ErrRequestCreate, err)
		}

		if dc != nil && dc.IPv64Token != "" {
			req.Header.Set("Authorization", "Bearer "+dc.IPv64Token)
		}
		req.Header.Set("User-Agent", ManagedComment)

		start := time.Now().Local()
		res, err := getHTTPClient().Do(req)
		duration := time.Since(start)

		if err != nil {
			debugLog("HTTP", "", fmt.Sprintf("❌ %s: %v", T.NetworkError, err))
			apiMetrics.RecordError(method, 0, err, duration)
			lastErr = fmt.Errorf("%s: %w", T.ErrNetworkError, err)

			wait := calculateRetryDelay(attempt, false)
			select {
			case <-time.After(wait):
			case <-ctx.Done():
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
			lastErr = fmt.Errorf("failed to read response: %w", readErr)
			continue
		}

		if res.StatusCode == 429 {
			apiMetrics.RecordError(method, res.StatusCode, fmt.Errorf("%s", T.ErrRateLimit), duration)
			retryAfter := res.Header.Get("Retry-After")
			var waitDuration time.Duration

			if retryAfter != "" {
				if seconds, err := strconv.Atoi(retryAfter); err == nil {
					waitDuration = time.Duration(seconds) * time.Second
					debugLog("HTTP", "", fmt.Sprintf(T.IPv64RateLimitHeader, seconds))
				}
			}

			if waitDuration == 0 {
				baseWait := time.Duration(60+attempt*30) * time.Second
				if baseWait > 5*time.Minute {
					baseWait = 5 * time.Minute
				}
				waitDuration = baseWait
				debugLog("HTTP", "", fmt.Sprintf(T.IPv64RateLimitBackoff, waitDuration))
			}

			lastErr = fmt.Errorf("%s", T.ErrRateLimit)

			if attempt < cfg.MaxAPIRetries-1 {
				debugLog("HTTP", "", fmt.Sprintf(T.IPv64RetriableWait, waitDuration))
				select {
				case <-time.After(waitDuration):
				case <-ctx.Done():
					return nil, fmt.Errorf("%s: %w", T.ErrContextCancelled, ctx.Err())
				}
				continue
			}

			return nil, lastErr
		}

		if apiErr := classifyAPIError(res.StatusCode, method, apiURL, string(respBody)); apiErr != nil {
			apiMetrics.RecordError(method, res.StatusCode, apiErr, duration)

			if apiErr.Retryable && attempt < cfg.MaxAPIRetries-1 {
				wait := calculateRetryDelay(attempt, res.StatusCode >= 500)
				debugLog("HTTP", "", fmt.Sprintf(T.IPv64RetriableWait, wait))
				select {
				case <-time.After(wait):
				case <-ctx.Done():
					return nil, fmt.Errorf("%s: %w", T.ErrContextCancelled, ctx.Err())
				}
				lastErr = apiErr
				continue
			}

			return nil, apiErr
		}

		var ipv64Resp IPv64Response
		if err := json.Unmarshal(respBody, &ipv64Resp); err != nil {
			apiMetrics.RecordError(method, res.StatusCode, err, duration)
			if len(respBody) > 0 && respBody[0] == '<' {
				preview := string(respBody)
				if len(preview) > 200 {
					preview = preview[:200] + "..."
				}
				debugLog("HTTP", "", fmt.Sprintf(T.IPv64HTMLResponse, preview))
			}

			return nil, fmt.Errorf("%s: %w", T.IPv64ParseError, err)
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
				Message: fmt.Sprintf(T.IPv64APIError, ipv64Resp.Info),
			})
			apiMetrics.RecordError(method, res.StatusCode, apiErr, duration)
			return nil, apiErr
		}

		apiMetrics.RecordSuccess(method, duration)
		return respBody, nil
	}

	return nil, fmt.Errorf(T.IPv64ApiFailed+": %w", cfg.MaxAPIRetries, lastErr)
}

func loadIPv64Domains(ctx context.Context, dc *DomainConfig) ([]Zone, error) {
	providerCache.RLock()
	hasCached := len(providerCache.ipv64Records) > 0
	providerCache.RUnlock()

	if hasCached {
		providerCache.RLock()
		zones := make([]Zone, 0, len(providerCache.ipv64Records))
		for domainName, domain := range providerCache.ipv64Records {
			zone := Zone{
				ID:   domainName,
				Name: domainName,
			}
			for _, rec := range domain.Records {
				zone.Records = append(zone.Records, Record{
					ID:      fmt.Sprintf("%d", rec.RecordID),
					Type:    rec.Type,
					Content: rec.Content,
				})
			}
			zones = append(zones, zone)
		}
		providerCache.RUnlock()
		debugLog("CACHE", "", fmt.Sprintf(T.IPv64CacheBuilt, len(zones)))
		return zones, nil
	}

	params := map[string]string{
		"get_domains": dc.IPv64Token,
	}

	data, err := ipv64API(ctx, dc, params)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", T.IPv64ParseError, err)
	}

	var resp IPv64Response
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("%s: %w", T.IPv64ParseError, err)
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
		return fmt.Errorf("%s: %w", T.ErrCacheMarshal, err)
	}

	tmpPath := cachePath + ".tmp"
	if err := os.WriteFile(tmpPath, jsonData, 0644); err != nil {
		return fmt.Errorf("%s: %w", T.ErrCacheWrite, err)
	}

	if err := os.Rename(tmpPath, cachePath); err != nil {
		return fmt.Errorf("%s: %w", T.ErrCacheRename, err)
	}

	debugLog("CACHE", "", fmt.Sprintf(T.CacheSavedDomains, "IPv64", len(data)))
	return nil
}

func loadIPv64CacheFromDisk() error {
	cachePath := getIPv64CachePath()

	data, err := os.ReadFile(cachePath)
	if err != nil {
		if os.IsNotExist(err) {
			debugLog("CACHE", "", fmt.Sprintf(T.CacheFileNotFound, "IPv64"))
			return nil
		}
		return fmt.Errorf("%s: %w", T.ErrBodyRead, err)
	}

	var cached map[string]IPv64Domain
	if err := json.Unmarshal(data, &cached); err != nil {
		return fmt.Errorf("%s: %w", T.ErrCacheMarshal, err)
	}

	providerCache.Lock()
	providerCache.ipv64Records = cached
	providerCache.Unlock()

	debugLog("CACHE", "", fmt.Sprintf(T.CacheLoadedDomains, "IPv64", len(cached)))
	lastIPv64DomainsLoad = time.Now().Local()
	return nil
}

func ensureIPv64DomainsFresh(ctx context.Context, dc *DomainConfig, force bool) error {
	providerCache.RLock()
	hasData := len(providerCache.ipv64Records) > 0
	age := time.Since(lastIPv64DomainsLoad)
	providerCache.RUnlock()

	if !force && hasData && !lastIPv64DomainsLoad.IsZero() && age < ipv64DomainsCacheTTL {
		debugLog("SCHEDULER", "", fmt.Sprintf(T.IPv64CacheUsed, age.Round(time.Second)))
		return nil
	}

	if !hasData {
		debugLog("CACHE", "", T.IPv64CacheLoadDisk)
		if err := loadIPv64CacheFromDisk(); err == nil {
			lastIPv64DomainsLoad = time.Now().Local()
			providerCache.RLock()
			hasData = len(providerCache.ipv64Records) > 0
			providerCache.RUnlock()

			if !force && hasData {
				debugLog("SCHEDULER", "", T.IPv64CacheLoadedDisk)
				return nil
			}
		}
	}

	if err := loadAllIPv64Domains(ctx, dc); err != nil {
		return err
	}

	lastIPv64DomainsLoad = time.Now().Local()
	return nil
}

// ============================================================================
// LOAD ALL IPV64 DOMAINS
// ============================================================================
func loadAllIPv64Domains(ctx context.Context, dc *DomainConfig) error {
	params := map[string]string{
		"get_domains": dc.IPv64Token,
	}

	data, err := ipv64API(ctx, dc, params)
	if err != nil {
		debugLog("CACHE", "", fmt.Sprintf(T.IPv64CacheAPIError, err))
		providerCache.RLock()
		hasCachedData := len(providerCache.ipv64Records) > 0
		providerCache.RUnlock()

		if !hasCachedData {
			if loadErr := loadIPv64CacheFromDisk(); loadErr != nil {
				debugLog("CACHE", "", fmt.Sprintf(T.IPv64CacheDiskError, loadErr))
			} else {
				debugLog("CACHE", "", T.IPv64CacheFallback)
			}
		}

		return err
	}

	var resp IPv64Response
	if err := json.Unmarshal(data, &resp); err != nil {
		debugLog("CACHE", "", fmt.Sprintf(T.IPv64ParseHTMLCache, err))
		if len(data) > 0 && data[0] == '<' {
			preview := string(data)
			if len(preview) > 200 {
				preview = preview[:200] + "..."
			}
			debugLog("CACHE", "", fmt.Sprintf(T.IPv64HTMLResponse, preview))
		}

		return fmt.Errorf("%s: %w", T.IPv64ParseError, err)
	}

	providerCache.Lock()

	for domainName, subdomain := range resp.Subdomains {
		domain := IPv64Domain{
			Domain:           domainName,
			DomainUpdateHash: subdomain.DomainUpdateHash,
			Records:          make([]IPv64Record, 0),
		}

		domain.Records = append(domain.Records, subdomain.Records...)

		providerCache.ipv64Records[domainName] = domain

		debugLog(
			"CACHE",
			domainName,
			fmt.Sprintf(
				T.IPv64CachedDomain,
				len(domain.Records),
				subdomain.DomainUpdateHash[:8],
			),
		)
	}

	providerCache.Unlock()

	if err := saveIPv64Cache(); err != nil {
		debugLog("CACHE", "", fmt.Sprintf(T.IPv64CacheSaveError, err))
	}

	lastIPv64DomainsLoad = time.Now().Local()

	return nil
}

// ============================================================================
// DNS LOGIC - IPV64
// ============================================================================
func ipv64OwnIPs(domain IPv64Domain, praefix, recordType string) (own []string, cdn []string) {
	for _, rec := range domain.Records {
		if rec.Praefix != praefix || rec.Type != recordType {
			continue
		}
		if rec.TTL <= 10 || rec.FailoverPolicy != "0" {
			cdn = append(cdn, rec.Content)
		} else {
			own = append(own, rec.Content)
		}
	}
	return own, cdn
}

func updateIPv64DNS(
	ctx context.Context,
	fqdn, ipv4, ipv6 string,
) (bool, error) {
	baseDomain, praefix := splitIPv64FQDN(fqdn)

	providerCache.RLock()
	domain, exists := providerCache.ipv64Records[baseDomain]
	providerCache.RUnlock()

	if !exists {
		return false, fmt.Errorf(T.IPv64BaseDomainNotFound, baseDomain)
	}

	needV4 := false
	needV6 := false

	if ipv4 != "" {
		ownV4, cdnV4 := ipv64OwnIPs(domain, praefix, "A")
		if len(cdnV4) > 0 {
			debugLog("DNS-LOGIC", fqdn, fmt.Sprintf(T.IPv64CDNIgnoredV4, cdnV4))
		}
		alreadyCurrent := false
		for _, ip := range ownV4 {
			if ip == ipv4 {
				alreadyCurrent = true
				break
			}
		}
		if alreadyCurrent {
			log(LogContext{Level: LogInfo, Action: ActionCurrent, Domain: fqdn, Message: fmt.Sprintf("%-4s %s %s", "A", ipv4, T.Current)})
		} else {
			needV4 = true
			if len(ownV4) > 0 {
				debugLog("DNS-LOGIC", fqdn, fmt.Sprintf(T.IPv64RecordUpdated, ownV4[0], ipv4))
			}
		}
	}

	if ipv6 != "" {
		ownV6, cdnV6 := ipv64OwnIPs(domain, praefix, "AAAA")
		if len(cdnV6) > 0 {
			debugLog("DNS-LOGIC", fqdn, fmt.Sprintf(T.IPv64CDNIgnoredV6, cdnV6))
		}
		alreadyCurrent := false
		for _, ip := range ownV6 {
			if ip == ipv6 {
				alreadyCurrent = true
				break
			}
		}
		if alreadyCurrent {
			log(LogContext{Level: LogInfo, Action: ActionCurrent, Domain: fqdn, Message: fmt.Sprintf("%-4s %s %s", "AAAA", ipv6, T.Current)})
		} else {
			needV6 = true
			if len(ownV6) > 0 {
				debugLog("DNS-LOGIC", fqdn, fmt.Sprintf(T.IPv64RecordUpdatedV6, ownV6[0], ipv6))
			}
		}
	}

	if !needV4 && !needV6 {
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
		msg := ""
		if needV4 {
			msg += fmt.Sprintf("A %s ", ipv4)
		}
		if needV6 {
			msg += fmt.Sprintf("AAAA %s", ipv6)
		}
		log(LogContext{
			Level:   LogWarn,
			Action:  ActionDryRun,
			Domain:  fqdn,
			Message: fmt.Sprintf("⚠️ %s %s", T.WouldSet, strings.TrimSpace(msg)),
		})
		return true, nil
	}

	q := url.Values{}
	q.Set("key", domain.DomainUpdateHash)
	q.Set("domain", fqdn)
	if needV4 {
		q.Set("ip", ipv4)
	}
	if needV6 {
		q.Set("ip6", ipv6)
	}

	updateURL := "https://ipv64.net/nic/update?" + q.Encode()
	debugLog("DNS-LOGIC", fqdn, fmt.Sprintf(T.IPv64UpdateURL, updateURL))

	req, err := http.NewRequestWithContext(ctx, "GET", updateURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", ManagedComment)

	start := time.Now().Local()
	res, err := getHTTPClient().Do(req)
	duration := time.Since(start)

	if err != nil {
		apiMetrics.RecordError("NIC", 0, err, duration)
		return false, err
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			debugLog("HTTP", "", fmt.Sprintf(T.ErrBodyClose+": %v", err))
		}
	}()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		apiMetrics.RecordError("NIC", res.StatusCode, err, duration)
		return false, fmt.Errorf("%s: %w", T.IPv64ParseError, err)
	}
	resp := strings.ToLower(strings.TrimSpace(string(body)))

	if res.StatusCode != 200 {
		return false, fmt.Errorf(T.IPv64HTTPError, res.StatusCode, resp)
	}

	if !strings.Contains(resp, "good") && !strings.Contains(resp, "nochg") {
		return false, fmt.Errorf(T.IPv64UpdateFailed, resp)
	}

	apiMetrics.RecordSuccess("NIC", duration)

	updateIPv64Cache(baseDomain, praefix, ipv4, ipv6, needV4, needV6)

	if needV4 {
		log(LogContext{
			Level:   LogInfo,
			Action:  ActionUpdate,
			Domain:  fqdn,
			Message: fmt.Sprintf("🔄 A -> %s %s", ipv4, T.Update),
		})
	}
	if needV6 {
		log(LogContext{
			Level:   LogInfo,
			Action:  ActionUpdate,
			Domain:  fqdn,
			Message: fmt.Sprintf("🔄 AAAA -> %s %s", ipv6, T.Update),
		})
	}

	return true, nil
}

func updateIPv64Cache(baseDomain, praefix, ipv4, ipv6 string, needV4, needV6 bool) {
	providerCache.Lock()
	defer providerCache.Unlock()

	domain, exists := providerCache.ipv64Records[baseDomain]
	if !exists {
		return
	}

	updated := false
	for i := range domain.Records {
		rec := &domain.Records[i]
		if rec.Praefix != praefix {
			continue
		}
		isCDN := rec.TTL <= 10 || rec.FailoverPolicy != "0"
		if isCDN {
			continue
		}
		if needV4 && rec.Type == "A" {
			rec.Content = ipv4
			updated = true
		}
		if needV6 && rec.Type == "AAAA" {
			rec.Content = ipv6
			updated = true
		}
	}

	if updated {
		providerCache.ipv64Records[baseDomain] = domain
		debugLog("CACHE", baseDomain, fmt.Sprintf(T.IPv64CacheUpdated, praefix))
	}
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

	debugLog("MAINTENANCE", "", T.CleanupStartIPv64)
	configuredFQDNs := make(map[string]struct{})
	ourBaseDomains := make(map[string]struct{})

	for _, dc := range cfg.DomainConfigs {
		if dc.Provider != ProviderIPv64 {
			continue
		}
		fqdn := strings.ToLower(strings.TrimSuffix(dc.FQDN, "."))
		configuredFQDNs[fqdn] = struct{}{}

		_, base := splitIPv64FQDN(fqdn)
		if base == "" {
			base = fqdn
		}
		ourBaseDomains[base] = struct{}{}
	}

	providerCache.RLock()
	defer providerCache.RUnlock()

	for baseDomain, domain := range providerCache.ipv64Records {
		if _, ours := ourBaseDomains[baseDomain]; !ours {
			debugLog("MAINTENANCE", baseDomain, T.CleanupSkipForeignBase)
			continue
		}

		for _, rec := range domain.Records {
			if rec.Type != "A" && rec.Type != "AAAA" {
				continue
			}

			if rec.TTL <= 10 || rec.FailoverPolicy != "0" {
				debugLog("MAINTENANCE", baseDomain,
					fmt.Sprintf(T.CleanupSkipCDN, rec.RecordID, rec.TTL, rec.FailoverPolicy))
				continue
			}

			if rec.Deactivated != 0 {
				debugLog("MAINTENANCE", baseDomain,
					fmt.Sprintf(T.CleanupSkipDeactivated, rec.RecordID))
				continue
			}

			fqdn := baseDomain
			if rec.Praefix != "" {
				fqdn = rec.Praefix + "." + baseDomain
			}
			fqdn = strings.ToLower(strings.TrimSuffix(fqdn, "."))

			if _, ok := configuredFQDNs[fqdn]; ok {
				continue
			}

			debugLog("MAINTENANCE", fqdn,
				fmt.Sprintf(T.CleanupSkipOrphaned, rec.Type, rec.RecordID))

			if cfg.DryRun {
				log(LogContext{
					Level:   LogInfo,
					Action:  ActionCleanup,
					Domain:  fqdn,
					Message: fmt.Sprintf(T.CleanupDryRun+" (%s ID %d)", rec.Type, rec.RecordID),
				})
				continue
			}

			if err := deleteIPv64Record(ctx, ipv64DC, baseDomain, rec); err != nil {
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

	debugLog("HTTP", baseDomain, fmt.Sprintf(T.IPv64DeleteResponse, string(data)))

	return nil
}
