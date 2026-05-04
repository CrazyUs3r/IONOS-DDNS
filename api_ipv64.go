// Package main
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
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
	method, apiURL, bodyData := buildIPv64RequestData(params)

	return apiWithRetry(ctx, "IPv64", T.IPv64APIFailed, func(attempt, maxRetries int) ([]byte, bool, error) {
		return ipv64APIAttempt(ctx, dc, method, apiURL, bodyData, attempt, maxRetries)
	})
}

func buildIPv64RequestData(params map[string]string) (method, apiURL, bodyData string) {
	method = MethodGET
	apiURL = ipv64APIBase

	if len(params) == 0 {
		return method, apiURL, ""
	}

	switch {
	case hasIPv64Param(params, "get_domains"):
		return MethodGET, buildIPv64URLWithQuery(apiURL, params), ""

	case getIPv64Param(params, "add_domain") != "":
		return MethodPOST, apiURL, fmt.Sprintf("add_domain=%s", url.QueryEscape(getIPv64Param(params, "add_domain")))

	case getIPv64Param(params, "del_record") != "":
		return MethodDELETE, apiURL, fmt.Sprintf("del_record=%s", url.QueryEscape(getIPv64Param(params, "del_record")))

	case getIPv64Param(params, "del_domain") != "":
		return MethodDELETE, apiURL, fmt.Sprintf("del_domain=%s", url.QueryEscape(getIPv64Param(params, "del_domain")))

	case hasIPv64Param(params, "add_record"):
		return MethodPOST, apiURL, encodeIPv64Form(params)

	default:
		return MethodGET, buildIPv64URLWithQuery(apiURL, params), ""
	}
}

func hasIPv64Param(params map[string]string, key string) bool {
	_, ok := params[key]
	return ok
}

func getIPv64Param(params map[string]string, key string) string {
	return params[key]
}

func buildIPv64URLWithQuery(baseURL string, params map[string]string) string {
	q := url.Values{}
	for k, v := range params {
		q.Set(k, v)
	}
	return baseURL + "?" + q.Encode()
}

func encodeIPv64Form(params map[string]string) string {
	values := url.Values{}
	for k, v := range params {
		values.Set(k, v)
	}
	return values.Encode()
}

func ipv64APIAttempt(
	ctx context.Context,
	dc *DomainConfig,
	method, apiURL, bodyData string,
	attempt, maxRetries int,
) ([]byte, bool, error) {
	debugLog("HTTP", "", fmt.Sprintf(T.IPv64Attempt,
		T.Attempt, attempt+1, maxRetries, method, apiURL))

	req, err := buildIPv64Request(ctx, dc, method, apiURL, bodyData)
	if err != nil {
		return nil, false, err
	}

	start := time.Now().Local()
	res, err := getHTTPClient().Do(req)
	duration := time.Since(start)

	if err != nil {
		retry, handledErr := handleIPv64NetworkError(ctx, method, err, duration, attempt)
		return nil, retry, handledErr
	}

	return handleIPv64Response(ctx, res, method, apiURL, duration, attempt)
}

func buildIPv64Request(
	ctx context.Context,
	dc *DomainConfig,
	method, apiURL, bodyData string,
) (*http.Request, error) {
	var (
		req *http.Request
		err error
	)

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

	return req, nil
}

func handleIPv64NetworkError(
	ctx context.Context,
	method string,
	err error,
	duration time.Duration,
	attempt int,
) (bool, error) {
	debugLog("HTTP", "", fmt.Sprintf("❌ %s: %v", T.NetworkError, err))
	apiMetrics.RecordError(method, 0, err, duration)

	lastErr := fmt.Errorf("%s: %w", T.ErrNetworkError, err)
	if !sleepOrCancel(ctx, calculateRetryDelay(attempt, false)) {
		return false, fmt.Errorf("%s: %w", T.ErrContextCancelled, ctx.Err())
	}

	return true, lastErr
}

func handleIPv64Response(
	ctx context.Context,
	res *http.Response,
	method, apiURL string,
	duration time.Duration,
	attempt int,
) ([]byte, bool, error) {
	respBody, readErr := io.ReadAll(res.Body)
	closeErr := res.Body.Close()
	if closeErr != nil {
		debugLog("HTTP", "", fmt.Sprintf(T.ErrBodyClose+": %v", closeErr))
	}

	if readErr != nil {
		retry, handledErr := handleIPv64ReadError(method, res.StatusCode, readErr, duration)
		return nil, retry, handledErr
	}

	if res.StatusCode == http.StatusTooManyRequests {
		retry, handledErr := handleIPv64RateLimit(ctx, res, method, duration, attempt)
		return nil, retry, handledErr
	}

	if apiErr := classifyAPIError(res.StatusCode, method, apiURL, string(respBody)); apiErr != nil {
		retry, handledErr := handleIPv64APIError(ctx, apiErr, method, res.StatusCode, duration, attempt)
		return nil, retry, handledErr
	}

	if err := validateIPv64ResponseBody(respBody, res.StatusCode, method, duration); err != nil {
		return nil, false, err
	}

	apiMetrics.RecordSuccess(method, duration)
	return respBody, false, nil
}

func handleIPv64ReadError(
	method string,
	statusCode int,
	readErr error,
	duration time.Duration,
) (bool, error) {
	apiMetrics.RecordError(method, statusCode, readErr, duration)
	return false, fmt.Errorf("failed to read response: %w", readErr)
}

func handleIPv64RateLimit(
	ctx context.Context,
	res *http.Response,
	method string,
	duration time.Duration,
	attempt int,
) (bool, error) {
	apiMetrics.RecordError(method, res.StatusCode, fmt.Errorf("%s", T.ErrRateLimit), duration)

	waitDuration := ipv64RateLimitWait(res.Header.Get("Retry-After"), attempt)
	lastErr := fmt.Errorf("%s", T.ErrRateLimit)

	if attempt < cfg.MaxAPIRetries-1 {
		debugLog("HTTP", "", fmt.Sprintf(T.IPv64RetriableWait, waitDuration))
		if !sleepOrCancel(ctx, waitDuration) {
			return false, fmt.Errorf("%s: %w", T.ErrContextCancelled, ctx.Err())
		}
		return true, lastErr
	}

	return false, lastErr
}

func ipv64RateLimitWait(retryAfter string, attempt int) time.Duration {
	if retryAfter != "" {
		if seconds, err := strconv.Atoi(retryAfter); err == nil {
			waitDuration := time.Duration(seconds) * time.Second
			debugLog("HTTP", "", fmt.Sprintf(T.IPv64RateLimitHeader, seconds))
			return waitDuration
		}
	}

	baseWait := min(time.Duration(60+attempt*30)*time.Second, 5*time.Minute)
	debugLog("HTTP", "", fmt.Sprintf(T.IPv64RateLimitBackoff, baseWait))
	return baseWait
}

func handleIPv64APIError(
	ctx context.Context,
	apiErr *APIError,
	method string,
	statusCode int,
	duration time.Duration,
	attempt int,
) (bool, error) {
	apiMetrics.RecordError(method, statusCode, apiErr, duration)

	if apiErr.Retryable && attempt < cfg.MaxAPIRetries-1 {
		wait := calculateRetryDelay(attempt, statusCode >= 500)
		debugLog("HTTP", "", fmt.Sprintf(T.IPv64RetriableWait, wait))
		if !sleepOrCancel(ctx, wait) {
			return false, fmt.Errorf("%s: %w", T.ErrContextCancelled, ctx.Err())
		}
		return true, apiErr
	}

	return false, apiErr
}

func validateIPv64ResponseBody(
	respBody []byte,
	statusCode int,
	method string,
	duration time.Duration,
) error {
	var ipv64Resp IPv64Response
	if err := json.Unmarshal(respBody, &ipv64Resp); err != nil {
		apiMetrics.RecordError(method, statusCode, err, duration)

		if len(respBody) > 0 && respBody[0] == '<' {
			preview := string(respBody)
			if len(preview) > 200 {
				preview = preview[:200] + "..."
			}
			debugLog("HTTP", "", fmt.Sprintf(T.IPv64HTMLResponse, preview))
		}

		return fmt.Errorf("%s: %w", T.IPv64ParseError, err)
	}

	infoLower := strings.ToLower(ipv64Resp.Info)
	if strings.Contains(infoLower, "error") || strings.Contains(infoLower, "invalid") {
		apiErr := &APIError{
			StatusCode: statusCode,
			Message:    ipv64Resp.Info,
			Retryable:  false,
		}

		log(LogContext{
			Level:   LogError,
			Action:  ActionAPI,
			Message: fmt.Sprintf(T.IPv64APIError, ipv64Resp.Info),
		})
		apiMetrics.RecordError(method, statusCode, apiErr, duration)
		return apiErr
	}

	return nil
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
	snapshot := make(map[string]IPv64Domain, len(providerCache.ipv64Records))
	maps.Copy(snapshot, providerCache.ipv64Records)
	providerCache.RUnlock()

	jsonData, err := json.MarshalIndent(snapshot, "", " ")
	if err != nil {
		return fmt.Errorf("%s: %w", T.ErrCacheMarshal, err)
	}

	tmpPath := cachePath + ".tmp"
	if err := os.WriteFile(tmpPath, jsonData, 0o600); err != nil {
		return fmt.Errorf("%s: %w", T.ErrCacheWrite, err)
	}

	if err := os.Rename(tmpPath, cachePath); err != nil {
		return fmt.Errorf("%s: %w", T.ErrCacheRename, err)
	}

	debugLog("CACHE", "", fmt.Sprintf(T.CacheSavedDomains, "IPv64", len(snapshot)))
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
	lastIPv64DomainsLoadNano.Store(time.Now().UnixNano())
	return nil
}

func ensureIPv64DomainsFresh(ctx context.Context, dc *DomainConfig, force bool) error {
	providerCache.RLock()
	hasData := len(providerCache.ipv64Records) > 0
	lastNano := lastIPv64DomainsLoadNano.Load()
	isZero := lastNano == 0
	age := time.Duration(0)
	if !isZero {
		age = time.Since(time.Unix(0, lastNano))
	}

	providerCache.RUnlock()

	if !force && hasData && !isZero && age < ipv64DomainsCacheTTL {
		debugLog("SCHEDULER", "", fmt.Sprintf(T.IPv64CacheUsed, age.Round(time.Second)))
		return nil
	}

	if !hasData {
		debugLog("CACHE", "", T.IPv64CacheLoadDisk)
		if err := loadIPv64CacheFromDisk(); err == nil {
			lastIPv64DomainsLoadNano.Store(time.Now().UnixNano())
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

	lastIPv64DomainsLoadNano.Store(time.Now().UnixNano())
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
				func() string {
					h := subdomain.DomainUpdateHash
					if len(h) < 8 {
						return h
					}
					return h[:8]
				}(),
			),
		)
	}

	providerCache.Unlock()

	if err := saveIPv64Cache(); err != nil {
		debugLog("CACHE", "", fmt.Sprintf(T.IPv64CacheSaveError, err))
	}

	lastIPv64DomainsLoadNano.Store(time.Now().UnixNano())

	return nil
}

// ============================================================================
// DNS LOGIC - IPV64
// ============================================================================
func ipv64OwnIPs(domain IPv64Domain, praefix, recordType string) (own, cdn []string) {
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

	domain, err := getIPv64DomainFromCache(baseDomain)
	if err != nil {
		return false, err
	}

	needV4, needV6 := evaluateIPv64UpdateNeed(fqdn, domain, praefix, ipv4, ipv6)
	if !needV4 && !needV6 {
		return false, nil
	}

	if err := waitForIPv64UpdateWindow(ctx); err != nil {
		return false, err
	}

	if cfg.DryRun {
		logIPv64DryRun(fqdn, ipv4, ipv6, needV4, needV6)
		return true, nil
	}

	if err := performIPv64NICUpdate(ctx, fqdn, domain.DomainUpdateHash, ipv4, ipv6, needV4, needV6); err != nil {
		return false, err
	}

	updateIPv64Cache(baseDomain, praefix, ipv4, ipv6, needV4, needV6)
	logIPv64UpdateResults(fqdn, ipv4, ipv6, needV4, needV6)

	return true, nil
}

func getIPv64DomainFromCache(baseDomain string) (IPv64Domain, error) {
	providerCache.RLock()
	domain, exists := providerCache.ipv64Records[baseDomain]
	providerCache.RUnlock()

	if !exists {
		return IPv64Domain{}, fmt.Errorf(T.IPv64BaseDomainNotFound, baseDomain)
	}

	return domain, nil
}

func evaluateIPv64UpdateNeed(
	fqdn string,
	domain IPv64Domain,
	praefix, ipv4, ipv6 string,
) (bool, bool) {
	needV4 := false
	needV6 := false

	if ipv4 != "" {
		needV4 = evaluateIPv64RecordNeed(fqdn, domain, praefix, RecordTypeA, ipv4, T.IPv64CDNIgnoredV4, T.IPv64RecordUpdated)
	}

	if ipv6 != "" {
		needV6 = evaluateIPv64RecordNeed(fqdn, domain, praefix, RecordTypeAAAA, ipv6, T.IPv64CDNIgnoredV6, T.IPv64RecordUpdatedV6)
	}

	return needV4, needV6
}

func evaluateIPv64RecordNeed(
	fqdn string,
	domain IPv64Domain,
	praefix, recordType, newIP, cdnMsg, updateMsg string,
) bool {
	ownIPs, cdnIPs := ipv64OwnIPs(domain, praefix, recordType)

	if len(cdnIPs) > 0 {
		debugLog("DNS-LOGIC", fqdn, fmt.Sprintf(cdnMsg, cdnIPs))
	}

	if slices.Contains(ownIPs, newIP) {
		log(LogContext{
			Level:   LogInfo,
			Action:  ActionCurrent,
			Domain:  fqdn,
			Message: fmt.Sprintf("%-4s %s %s", recordType, newIP, T.Current),
		})
		return false
	}

	if len(ownIPs) > 0 {
		debugLog("DNS-LOGIC", fqdn, fmt.Sprintf(updateMsg, ownIPs[0], newIP))
	}

	return true
}

func waitForIPv64UpdateWindow(ctx context.Context) error {
	ipv64Mutex.Lock()
	wait := time.Duration(0)
	if since := time.Since(lastIPv64Update); since < 12*time.Second {
		wait = 12*time.Second - since
	}
	lastIPv64Update = time.Now().Local()
	ipv64Mutex.Unlock()

	if wait > 0 {
		if !sleepOrCancel(ctx, wait) {
			return ctx.Err()
		}
	}

	return nil
}

func logIPv64DryRun(fqdn, ipv4, ipv6 string, needV4, needV6 bool) {
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
}

func performIPv64NICUpdate(
	ctx context.Context,
	fqdn, updateHash, ipv4, ipv6 string,
	needV4, needV6 bool,
) error {
	updateURL := buildIPv64UpdateURL(fqdn, updateHash, ipv4, ipv6, needV4, needV6)
	debugLog("DNS-LOGIC", fqdn, fmt.Sprintf(T.IPv64UpdateURL, updateURL))

	req, err := http.NewRequestWithContext(ctx, MethodGET, updateURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", ManagedComment)

	start := time.Now().Local()
	res, err := getHTTPClient().Do(req)
	duration := time.Since(start)

	if err != nil {
		apiMetrics.RecordError(MethodNIC, 0, err, duration)
		return err
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			debugLog("HTTP", "", fmt.Sprintf(T.ErrBodyClose+": %v", err))
		}
	}()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		apiMetrics.RecordError(MethodNIC, res.StatusCode, err, duration)
		return fmt.Errorf("%s: %w", T.IPv64ParseError, err)
	}

	if err := validateIPv64NICResponse(res.StatusCode, body); err != nil {
		return err
	}

	apiMetrics.RecordSuccess(MethodNIC, duration)
	return nil
}

func buildIPv64UpdateURL(
	fqdn, updateHash, ipv4, ipv6 string,
	needV4, needV6 bool,
) string {
	q := url.Values{}
	q.Set("key", updateHash)
	q.Set("domain", fqdn)

	if needV4 {
		q.Set("ip", ipv4)
	}
	if needV6 {
		q.Set("ip6", ipv6)
	}

	return "https://ipv64.net/nic/update?" + q.Encode()
}

func validateIPv64NICResponse(statusCode int, body []byte) error {
	resp := strings.ToLower(strings.TrimSpace(string(body)))

	if statusCode != http.StatusOK {
		return fmt.Errorf(T.IPv64HTTPError, statusCode, resp)
	}

	if !strings.Contains(resp, "good") && !strings.Contains(resp, "nochg") {
		return fmt.Errorf(T.IPv64UpdateFailed, resp)
	}

	return nil
}

func logIPv64UpdateResults(fqdn, ipv4, ipv6 string, needV4, needV6 bool) {
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
		if needV4 && rec.Type == RecordTypeA {
			rec.Content = ipv4
			updated = true
		}
		if needV6 && rec.Type == RecordTypeAAAA {
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
	ipv64DC := findIPv64DomainConfig()
	if ipv64DC == nil {
		return
	}

	debugLog("MAINTENANCE", "", T.CleanupStartIPv64)

	configuredFQDNs, ourBaseDomains := collectIPv64ConfiguredDomains()

	providerCache.RLock()
	defer providerCache.RUnlock()

	for baseDomain, domain := range providerCache.ipv64Records {
		cleanupIPv64DomainRecords(ctx, ipv64DC, baseDomain, domain, configuredFQDNs, ourBaseDomains)
	}
}

func findIPv64DomainConfig() *DomainConfig {
	for i := range cfg.DomainConfigs {
		if cfg.DomainConfigs[i].Provider == ProviderIPv64 {
			return &cfg.DomainConfigs[i]
		}
	}
	return nil
}

func collectIPv64ConfiguredDomains() (map[string]struct{}, map[string]struct{}) {
	configuredFQDNs := make(map[string]struct{})
	ourBaseDomains := make(map[string]struct{})

	for _, dc := range cfg.DomainConfigs {
		if dc.Provider != ProviderIPv64 {
			continue
		}

		fqdn := normalizeIPv64FQDN(dc.FQDN)
		configuredFQDNs[fqdn] = struct{}{}

		_, base := splitIPv64FQDN(fqdn)
		if base == "" {
			base = fqdn
		}
		ourBaseDomains[base] = struct{}{}
	}

	return configuredFQDNs, ourBaseDomains
}

func cleanupIPv64DomainRecords(
	ctx context.Context,
	ipv64DC *DomainConfig,
	baseDomain string,
	domain IPv64Domain,
	configuredFQDNs, ourBaseDomains map[string]struct{},
) {
	if _, ours := ourBaseDomains[baseDomain]; !ours {
		debugLog("MAINTENANCE", baseDomain, T.CleanupSkipForeignBase)
		return
	}

	for _, rec := range domain.Records {
		cleanupSingleIPv64Record(ctx, ipv64DC, baseDomain, rec, configuredFQDNs)
	}
}

func cleanupSingleIPv64Record(
	ctx context.Context,
	ipv64DC *DomainConfig,
	baseDomain string,
	rec IPv64Record,
	configuredFQDNs map[string]struct{},
) {
	fqdn, shouldDelete := shouldCleanupIPv64Record(baseDomain, rec, configuredFQDNs)
	if !shouldDelete {
		return
	}

	debugLog("MAINTENANCE", fqdn, fmt.Sprintf(T.CleanupSkipOrphaned, rec.Type, rec.RecordID))

	if cfg.DryRun {
		log(LogContext{
			Level:   LogInfo,
			Action:  ActionCleanup,
			Domain:  fqdn,
			Message: fmt.Sprintf(T.CleanupDryRun+" (%s ID %d)", rec.Type, rec.RecordID),
		})
		return
	}

	if err := deleteIPv64Record(ctx, ipv64DC, baseDomain, rec); err != nil {
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

func shouldCleanupIPv64Record(
	baseDomain string,
	rec IPv64Record,
	configuredFQDNs map[string]struct{},
) (string, bool) {
	if rec.Type != RecordTypeA && rec.Type != RecordTypeAAAA {
		return "", false
	}

	if rec.TTL <= 10 || rec.FailoverPolicy != "0" {
		debugLog("MAINTENANCE", baseDomain,
			fmt.Sprintf(T.CleanupSkipCDN, rec.RecordID, rec.TTL, rec.FailoverPolicy))
		return "", false
	}

	if rec.Deactivated != 0 {
		debugLog("MAINTENANCE", baseDomain,
			fmt.Sprintf(T.CleanupSkipDeactivated, rec.RecordID))
		return "", false
	}

	fqdn := buildIPv64RecordFQDN(baseDomain, rec.Praefix)

	if _, ok := configuredFQDNs[fqdn]; ok {
		return "", false
	}

	return fqdn, true
}

func buildIPv64RecordFQDN(baseDomain, praefix string) string {
	fqdn := baseDomain
	if praefix != "" {
		fqdn = praefix + "." + baseDomain
	}
	return normalizeIPv64FQDN(fqdn)
}

func normalizeIPv64FQDN(fqdn string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(fqdn), "."))
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
