// Package main
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// ============================================================================
// API - IPV64
// ============================================================================
func splitIPv64FQDN(fqdn string) (baseDomain, praefix string) {
	fqdn = normalizeIPv64FQDN(fqdn)

	providerCache.RLock()
	defer providerCache.RUnlock()

	if _, exists := providerCache.ipv64Records[fqdn]; exists {
		return fqdn, ""
	}

	parts := strings.Split(fqdn, ".")
	for i := 1; i < len(parts); i++ {
		possibleBase := strings.Join(parts[i:], ".")
		if _, exists := providerCache.ipv64Records[possibleBase]; exists {
			praefix = strings.Join(parts[:i], ".")
			return possibleBase, praefix
		}
	}

	parts = strings.Split(fqdn, ".")
	if len(parts) > 2 {
		return strings.Join(parts[1:], "."), parts[0]
	}
	return fqdn, ""
}

func ipv64API(ctx context.Context, dc *DomainConfig, params map[string]string) ([]byte, error) {
	method, apiURL, bodyData := buildIPv64RequestData(params)
	return apiWithRetry(ctx, "IPv64", phrases().IPv64APIFailed, func(attempt, maxRetries int) ([]byte, bool, error) {
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
	debugLog("HTTP", "", fmt.Sprintf(phrases().IPv64Attempt,
		phrases().Attempt, attempt+1, maxRetries, method, sanitizeURLStringForLogging(apiURL)))

	req, err := buildIPv64Request(ctx, dc, method, apiURL, bodyData)
	if err != nil {
		return nil, false, err
	}

	start := time.Now()
	res, err := getHTTPClient().Do(req)
	duration := time.Since(start)

	if err != nil {
		retry, handledErr := handleProviderNetworkError(ctx, "IPv64", method, err, duration, attempt, maxRetries, false)
		return nil, retry, handledErr
	}

	defer func() {
		if err := res.Body.Close(); err != nil {
			debugLog("HTTP", "", fmt.Sprintf(phrases().ErrBodyClose+": %v", err))
		}
	}()

	return handleIPv64Response(ctx, res, method, apiURL, duration, attempt, maxRetries)
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
		return nil, fmt.Errorf("%s: %w", phrases().ErrRequestCreate, err)
	}

	if dc != nil && dc.IPv64Token != "" {
		req.Header.Set("Authorization", "Bearer "+dc.IPv64Token)
	}

	req.Header.Set("User-Agent", ManagedComment)
	return req, nil
}

func handleIPv64Response(
	ctx context.Context,
	res *http.Response,
	method, apiURL string,
	duration time.Duration,
	attempt, maxAttempts int,
) ([]byte, bool, error) {
	respBody, readErr := io.ReadAll(res.Body)

	if readErr != nil {
		retry, handledErr := handleIPv64ReadError(
			ctx, method, res.StatusCode, readErr, duration, attempt, maxAttempts,
		)
		return nil, retry, handledErr
	}

	if res.StatusCode == http.StatusTooManyRequests {
		retry, handledErr := handleIPv64RateLimit(ctx, res, method, duration, attempt, maxAttempts)
		return nil, retry, handledErr
	}

	if apiErr := classifyAPIErrorWithHeaders(res.StatusCode, method, apiURL, string(respBody), res.Header); apiErr != nil {
		retry, handledErr := handleIPv64APIError(ctx, apiErr, method, res.StatusCode, duration, attempt, maxAttempts)
		return nil, retry, handledErr
	}

	if err := validateIPv64ResponseBody(respBody, res.StatusCode, method, duration); err != nil {
		return nil, false, err
	}

	apiMetrics.RecordSuccess(method, duration)
	return respBody, false, nil
}

func handleIPv64ReadError(
	ctx context.Context,
	method string,
	statusCode int,
	readErr error,
	duration time.Duration,
	attempt, maxAttempts int,
) (bool, error) {
	apiMetrics.RecordError(method, statusCode, readErr, duration)

	handledErr := fmt.Errorf("%s: %w", phrases().ErrBodyRead, readErr)
	if !canRetryAPIAttempt(attempt, maxAttempts) {
		return false, handledErr
	}

	serverBusy := statusCode == http.StatusTooManyRequests || statusCode >= 500
	wait := calculateRetryDelay(attempt, serverBusy)
	debugLog("HTTP", "", fmt.Sprintf(phrases().IPv64RetriableWait, wait))

	if !sleepOrCancel(ctx, wait) {
		return false, fmt.Errorf("%s: %w", phrases().ErrContextCancelled, ctx.Err())
	}

	return true, handledErr
}

func handleIPv64RateLimit(
	ctx context.Context,
	res *http.Response,
	method string,
	duration time.Duration,
	attempt, maxAttempts int,
) (bool, error) {
	apiMetrics.RecordError(method, res.StatusCode, fmt.Errorf("%s", phrases().ErrRateLimit), duration)

	waitDuration := ipv64RateLimitWait(res.Header, attempt)
	lastErr := fmt.Errorf("%s", phrases().ErrRateLimit)

	if canRetryAPIAttempt(attempt, maxAttempts) {
		debugLog("HTTP", "", fmt.Sprintf(phrases().IPv64RetriableWait, waitDuration))
		if !sleepOrCancel(ctx, waitDuration) {
			return false, fmt.Errorf("%s: %w", phrases().ErrContextCancelled, ctx.Err())
		}
		return true, lastErr
	}

	return false, lastErr
}

func ipv64RateLimitWait(headers http.Header, attempt int) time.Duration {
	if d, ok := parseRetryAfter(headers); ok {
		debugLog("HTTP", "", fmt.Sprintf(phrases().IPv64RateLimitHeader, int(d.Seconds())))
		return d
	}

	baseWait := min(time.Duration(60+attempt*30)*time.Second, 5*time.Minute)
	debugLog("HTTP", "", fmt.Sprintf(phrases().IPv64RateLimitBackoff, baseWait))
	return baseWait
}

func handleIPv64APIError(
	ctx context.Context,
	apiErr *APIError,
	method string,
	statusCode int,
	duration time.Duration,
	attempt, maxAttempts int,
) (bool, error) {
	apiMetrics.RecordError(method, statusCode, apiErr, duration)

	if apiErr.Retryable && canRetryAPIAttempt(attempt, maxAttempts) {
		wait := apiErr.RetryAfter
		if wait <= 0 {
			wait = calculateRetryDelay(attempt, statusCode >= 500)
		}
		debugLog("HTTP", "", fmt.Sprintf(phrases().IPv64RetriableWait, wait))

		if !sleepOrCancel(ctx, wait) {
			return false, fmt.Errorf("%s: %w", phrases().ErrContextCancelled, ctx.Err())
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
			preview := sanitizeHTTPDebugBody(string(respBody))
			if len(preview) > 200 {
				preview = preview[:200] + "..."
			}
			debugLog("HTTP", "", fmt.Sprintf(phrases().IPv64HTMLResponse, preview))
		}

		return fmt.Errorf("%s: %w", phrases().IPv64ParseError, err)
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
			Message: fmt.Sprintf(phrases().IPv64APIError, ipv64Resp.Info),
		})

		apiMetrics.RecordError(method, statusCode, apiErr, duration)
		return apiErr
	}

	return nil
}

// ============================================================================
// CACHE PERSISTENCE - IPV64
// ============================================================================

const ipv64CacheMetaRecordType = "__IPV64_META"

type ipv64FileCacheRecordMeta struct {
	DomainUpdateHash string `json:"domain_update_hash,omitempty"`
	RecordID         int    `json:"record_id,omitempty"`
	Praefix          string `json:"praefix,omitempty"`
	TTL              int    `json:"ttl,omitempty"`
	FailoverPolicy   string `json:"failover_policy,omitempty"`
	Deactivated      int    `json:"deactivated,omitempty"`
}

func saveIPv64CacheToFile(zones []Zone, recordCache *ZoneRecordCache) error {
	return saveProviderCacheToFile("IPv64", "ipv64_cache.json", zones, recordCache)
}

func loadIPv64CacheFromFile() ([]Zone, *ZoneRecordCache, error) {
	return loadProviderCacheFromFile("IPv64", "ipv64_cache.json")
}

func saveIPv64Cache() error {
	zones, recordCache := buildIPv64FileCacheSnapshot()
	return saveIPv64CacheToFile(zones, recordCache)
}

func loadIPv64CacheFromDisk() error {
	zones, recordCache, err := loadIPv64CacheFromFile()
	if err != nil {
		return err
	}
	if zones == nil || recordCache == nil {
		return nil
	}

	cached := buildIPv64DomainsFromFileCache(zones, recordCache)
	if len(cached) == 0 {
		return nil
	}

	providerCache.Lock()
	providerCache.ipv64Records = cached
	providerCache.Unlock()

	debugLog("CACHE", "", fmt.Sprintf(phrases().CacheLoadedDomains, "IPv64", len(cached)))
	lastIPv64DomainsLoadNano.Store(time.Now().UnixNano())
	return nil
}

func buildIPv64FileCacheSnapshot() ([]Zone, *ZoneRecordCache) {
	providerCache.RLock()
	defer providerCache.RUnlock()

	zones := make([]Zone, 0, len(providerCache.ipv64Records))
	recordCache := NewZoneRecordCache()

	domainNames := make([]string, 0, len(providerCache.ipv64Records))
	for domainName := range providerCache.ipv64Records {
		domainNames = append(domainNames, domainName)
	}
	slices.Sort(domainNames)

	for _, domainName := range domainNames {
		domain := providerCache.ipv64Records[domainName]
		zoneID := normalizeIPv64FQDN(domainName)
		zoneName := normalizeIPv64FQDN(domain.Domain)
		if zoneName == "" {
			zoneName = zoneID
		}

		zones = append(zones, Zone{ID: zoneID, Name: zoneName})

		records := make([]Record, 0, len(domain.Records))
		for _, ipv64Record := range domain.Records {
			records = append(records, buildIPv64FileCacheRecord(zoneName, domain.DomainUpdateHash, ipv64Record))
		}

		if len(records) == 0 && domain.DomainUpdateHash != "" {
			records = append(records, buildIPv64FileCacheMetaRecord(zoneName, domain.DomainUpdateHash))
		}

		recordCache.Set(zoneID, records)
	}

	return zones, recordCache
}

func buildIPv64FileCacheRecord(domainName, updateHash string, ipv64Record IPv64Record) Record {
	recordID := ""
	if ipv64Record.RecordID != 0 {
		recordID = strconv.Itoa(ipv64Record.RecordID)
	}

	return Record{
		ID:      recordID,
		Name:    buildIPv64RecordFQDN(domainName, ipv64Record.Praefix),
		Type:    ipv64Record.Type,
		Content: ipv64Record.Content,
		Comment: encodeIPv64FileCacheRecordMeta(ipv64FileCacheRecordMeta{
			DomainUpdateHash: updateHash,
			RecordID:         ipv64Record.RecordID,
			Praefix:          ipv64Record.Praefix,
			TTL:              ipv64Record.TTL,
			FailoverPolicy:   ipv64Record.FailoverPolicy,
			Deactivated:      ipv64Record.Deactivated,
		}),
	}
}

func buildIPv64FileCacheMetaRecord(domainName, updateHash string) Record {
	return Record{
		ID:      ipv64CacheMetaRecordType,
		Name:    domainName,
		Type:    ipv64CacheMetaRecordType,
		Content: updateHash,
		Comment: encodeIPv64FileCacheRecordMeta(ipv64FileCacheRecordMeta{
			DomainUpdateHash: updateHash,
		}),
	}
}

func buildIPv64DomainsFromFileCache(zones []Zone, recordCache *ZoneRecordCache) map[string]IPv64Domain {
	cached := make(map[string]IPv64Domain, len(zones))

	for _, zone := range zones {
		domainName := normalizeIPv64FQDN(zone.Name)
		if domainName == "" {
			domainName = normalizeIPv64FQDN(zone.ID)
		}
		if domainName == "" {
			continue
		}

		domain := IPv64Domain{
			Domain:  domainName,
			Records: make([]IPv64Record, 0),
		}

		records, exists := recordCache.Get(zone.ID)
		if !exists {
			records, exists = recordCache.Get(domainName)
		}
		if exists {
			domain = appendIPv64FileCacheRecords(domain, domainName, records)
		}

		cached[domainName] = domain
	}

	return cached
}

func appendIPv64FileCacheRecords(domain IPv64Domain, domainName string, records []Record) IPv64Domain {
	for _, record := range records {
		meta := decodeIPv64FileCacheRecordMeta(record.Comment)
		if domain.DomainUpdateHash == "" {
			domain.DomainUpdateHash = ipv64FirstNonEmpty(meta.DomainUpdateHash, record.Content)
		}

		if record.Type == ipv64CacheMetaRecordType {
			continue
		}

		recordID := meta.RecordID
		if record.ID != "" {
			if parsedID, err := strconv.Atoi(record.ID); err == nil {
				recordID = parsedID
			}
		}

		failoverPolicy := meta.FailoverPolicy
		if failoverPolicy == "" {
			failoverPolicy = "0"
		}

		praefix := meta.Praefix
		if praefix == "" {
			praefix = ipv64PraefixFromCachedRecordName(domainName, record.Name)
		}

		domain.Records = append(domain.Records, IPv64Record{
			RecordID:       recordID,
			Praefix:        praefix,
			Type:           record.Type,
			Content:        record.Content,
			TTL:            meta.TTL,
			FailoverPolicy: failoverPolicy,
			Deactivated:    meta.Deactivated,
		})
	}

	return domain
}

func ipv64FirstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func encodeIPv64FileCacheRecordMeta(meta ipv64FileCacheRecordMeta) string {
	data, err := json.Marshal(meta)
	if err != nil {
		return ""
	}
	return string(data)
}

func decodeIPv64FileCacheRecordMeta(comment string) ipv64FileCacheRecordMeta {
	var meta ipv64FileCacheRecordMeta
	if strings.TrimSpace(comment) == "" {
		return meta
	}
	_ = json.Unmarshal([]byte(comment), &meta)
	return meta
}

func ipv64PraefixFromCachedRecordName(domainName, recordName string) string {
	domainName = normalizeIPv64FQDN(domainName)
	recordName = normalizeIPv64FQDN(recordName)

	if recordName == "" || recordName == "@" || recordName == domainName {
		return ""
	}

	suffix := "." + domainName
	if before, ok := strings.CutSuffix(recordName, suffix); ok {
		return before
	}

	return recordName
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
		debugLog("SCHEDULER", "", fmt.Sprintf(phrases().IPv64CacheUsed, age.Round(time.Second)))
		return nil
	}

	if !hasData {
		debugLog("CACHE", "", phrases().IPv64CacheLoadDisk)
		if err := loadIPv64CacheFromDisk(); err == nil {
			lastIPv64DomainsLoadNano.Store(time.Now().UnixNano())

			providerCache.RLock()
			hasData = len(providerCache.ipv64Records) > 0
			providerCache.RUnlock()

			if !force && hasData {
				debugLog("SCHEDULER", "", phrases().IPv64CacheLoadedDisk)
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
		debugLog("CACHE", "", fmt.Sprintf(phrases().IPv64CacheAPIError, err))

		providerCache.RLock()
		hasCachedData := len(providerCache.ipv64Records) > 0
		providerCache.RUnlock()

		if !hasCachedData {
			if loadErr := loadIPv64CacheFromDisk(); loadErr != nil {
				debugLog("CACHE", "", fmt.Sprintf(phrases().IPv64CacheDiskError, loadErr))
			} else {
				debugLog("CACHE", "", phrases().IPv64CacheFallback)
			}
		}
		return err
	}

	var resp IPv64Response
	if err := json.Unmarshal(data, &resp); err != nil {
		debugLog("CACHE", "", fmt.Sprintf(phrases().IPv64ParseHTMLCache, err))

		if len(data) > 0 && data[0] == '<' {
			preview := sanitizeHTTPDebugBody(string(data))
			if len(preview) > 200 {
				preview = preview[:200] + "..."
			}
			debugLog("CACHE", "", fmt.Sprintf(phrases().IPv64HTMLResponse, preview))
		}

		return fmt.Errorf("%s: %w", phrases().IPv64ParseError, err)
	}

	freshDomains := buildIPv64DomainSnapshot(resp)

	providerCache.Lock()
	providerCache.ipv64Records = freshDomains
	providerCache.Unlock()

	for domainName, domain := range freshDomains {
		hashState := ""
		if domain.DomainUpdateHash != "" {
			hashState = "***"
		}

		debugLog(
			"CACHE",
			domainName,
			fmt.Sprintf(
				phrases().IPv64CachedDomain,
				len(domain.Records),
				hashState,
			),
		)
	}

	if err := saveIPv64Cache(); err != nil {
		debugLog("CACHE", "", fmt.Sprintf(phrases().IPv64CacheSaveError, err))
	}

	lastIPv64DomainsLoadNano.Store(time.Now().UnixNano())
	return nil
}

func buildIPv64DomainSnapshot(resp IPv64Response) map[string]IPv64Domain {
	domains := make(map[string]IPv64Domain, len(resp.Subdomains))

	for domainName, subdomain := range resp.Subdomains {
		domains[domainName] = IPv64Domain{
			Domain:           domainName,
			DomainUpdateHash: subdomain.DomainUpdateHash,
			Updates:          subdomain.Updates,
			Wildcard:         subdomain.Wildcard,
			Deactivated:      subdomain.Deactivated,
			Records:          slices.Clone(subdomain.Records),
		}
	}

	return domains
}

func loadIPv64InfrastructureRecords(z Zone) ([]Record, error) {
	providerCache.RLock()
	defer providerCache.RUnlock()

	data, ok := providerCache.ipv64Records[z.Name]
	if !ok {
		return nil, fmt.Errorf(
			phrases().NoCachedIPv64InfrastructureRecords,
			z.Name,
		)
	}

	records := make([]Record, 0, len(data.Records))

	for _, ir := range data.Records {
		name := z.Name
		if ir.Praefix != "" {
			name = ir.Praefix + "." + z.Name
		}

		records = append(records, Record{
			Name:    name,
			Type:    ir.Type,
			Content: ir.Content,
		})
	}

	return records, nil
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

func updateIPv64DNS(ctx context.Context, dc *DomainConfig, fqdn, ipv4, ipv6 string) (bool, error) {
	if dc == nil || strings.TrimSpace(dc.IPv64Token) == "" {
		return false, fmt.Errorf("no ipv64 token configured for %s", fqdn)
	}

	baseDomain, praefix := splitIPv64FQDN(fqdn)

	domain, err := getIPv64DomainFromCache(baseDomain)
	if err != nil {
		debugLog("IPv64", fqdn, fmt.Sprintf("domain %s not in cache, forcing refresh", baseDomain))
		lastIPv64DomainsLoadNano.Store(0)
		if refreshErr := loadAllIPv64Domains(ctx, dc); refreshErr != nil {
			debugLog("IPv64", fqdn, fmt.Sprintf("cache refresh failed: %v", refreshErr))
		}
		domain, err = getIPv64DomainFromCache(baseDomain)
		if err != nil {
			return false, err
		}
	}

	needV4, needV6 := evaluateIPv64UpdateNeed(fqdn, domain, praefix, ipv4, ipv6)
	if !needV4 && !needV6 {
		return false, nil
	}

	if err := waitForIPv64UpdateWindow(ctx); err != nil {
		return false, err
	}

	if dryRunEnabled() {
		logIPv64DryRun(fqdn, ipv4, ipv6, needV4, needV6)
		return true, nil
	}

	if err := performIPv64NICUpdate(ctx, fqdn, domain.DomainUpdateHash, ipv4, ipv6, needV4, needV6); err != nil {
		return false, err
	}

	if updateIPv64Cache(baseDomain, praefix, ipv4, ipv6, needV4, needV6) {
		if err := saveIPv64Cache(); err != nil {
			debugLog("CACHE", "", fmt.Sprintf(phrases().IPv64CacheSaveError, err))
		}
	}
	logIPv64UpdateResults(fqdn, ipv4, ipv6, needV4, needV6)

	return true, nil
}

func getIPv64DomainFromCache(baseDomain string) (IPv64Domain, error) {
	providerCache.RLock()
	domain, exists := providerCache.ipv64Records[baseDomain]
	providerCache.RUnlock()

	if !exists {
		return IPv64Domain{}, fmt.Errorf(phrases().IPv64BaseDomainNotFound, baseDomain)
	}
	return domain, nil
}

func evaluateIPv64UpdateNeed(fqdn string, domain IPv64Domain, praefix, ipv4, ipv6 string) (bool, bool) {
	needV4 := false
	needV6 := false

	if ipv4 != "" {
		needV4 = evaluateIPv64RecordNeed(fqdn, domain, praefix, RecordTypeA, ipv4, phrases().IPv64CDNIgnoredV4, phrases().IPv64RecordUpdated)
	}

	if ipv6 != "" {
		needV6 = evaluateIPv64RecordNeed(fqdn, domain, praefix, RecordTypeAAAA, ipv6, phrases().IPv64CDNIgnoredV6, phrases().IPv64RecordUpdatedV6)
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
			Message: fmt.Sprintf("%-4s %s %s", recordType, newIP, phrases().Current),
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

	lastIPv64Update = time.Now()
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
		Message: fmt.Sprintf("⚠️ %s %s", phrases().WouldSet, strings.TrimSpace(msg)),
	})
}

func performIPv64NICUpdate(
	ctx context.Context,
	fqdn, updateHash, ipv4, ipv6 string,
	needV4, needV6 bool,
) error {
	updateURL := buildIPv64UpdateURL(fqdn, updateHash, ipv4, ipv6, needV4, needV6)

	debugLog("DNS-LOGIC", fqdn, fmt.Sprintf(phrases().IPv64UpdateURL, sanitizeURLStringForLogging(updateURL)))

	req, err := http.NewRequestWithContext(ctx, MethodGET, updateURL, nil)
	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", ManagedComment)

	start := time.Now()
	res, err := getHTTPClient().Do(req)
	duration := time.Since(start)

	if err != nil {
		apiMetrics.RecordError(MethodNIC, 0, err, duration)
		return err
	}

	defer func() {
		if err := res.Body.Close(); err != nil {
			debugLog("HTTP", "", fmt.Sprintf(phrases().ErrBodyClose+": %v", err))
		}
	}()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		apiMetrics.RecordError(MethodNIC, res.StatusCode, err, duration)
		return fmt.Errorf("%s: %w", phrases().IPv64ParseError, err)
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

	return ipv64APINIC + q.Encode()
}

func validateIPv64NICResponse(statusCode int, body []byte) error {
	resp := strings.ToLower(strings.TrimSpace(string(body)))

	if statusCode != http.StatusOK {
		return fmt.Errorf(phrases().IPv64HTTPError, statusCode, resp)
	}

	if !strings.Contains(resp, "good") && !strings.Contains(resp, "nochg") {
		return fmt.Errorf(phrases().IPv64UpdateFailed, resp)
	}

	return nil
}

func logIPv64UpdateResults(fqdn, ipv4, ipv6 string, needV4, needV6 bool) {
	if needV4 {
		log(LogContext{
			Level:   LogInfo,
			Action:  ActionUpdate,
			Domain:  fqdn,
			Message: fmt.Sprintf("🔄 A -> %s %s", ipv4, phrases().Update),
		})
	}

	if needV6 {
		log(LogContext{
			Level:   LogInfo,
			Action:  ActionUpdate,
			Domain:  fqdn,
			Message: fmt.Sprintf("🔄 AAAA -> %s %s", ipv6, phrases().Update),
		})
	}
}

func updateIPv64Cache(baseDomain, praefix, ipv4, ipv6 string, needV4, needV6 bool) bool {
	providerCache.Lock()
	defer providerCache.Unlock()

	domain, exists := providerCache.ipv64Records[baseDomain]
	if !exists {
		return false
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
		debugLog("CACHE", baseDomain, fmt.Sprintf(phrases().IPv64CacheUpdated, praefix))
	}

	return updated
}

// ============================================================================
// CLEANUP - IPV64
// ============================================================================

func cleanupIPv64Records(ctx context.Context) {
	ipv64DC := findIPv64DomainConfig()
	if ipv64DC == nil {
		return
	}

	debugLog("MAINTENANCE", "", phrases().CleanupStartIPv64)

	configuredFQDNs, ourBaseDomains := collectIPv64ConfiguredDomains()
	for baseDomain, domain := range snapshotIPv64ProviderDomains() {
		cleanupIPv64DomainRecords(ctx, ipv64DC, baseDomain, domain, configuredFQDNs, ourBaseDomains)
	}
}

func findIPv64DomainConfig() *DomainConfig {
	for _, dc := range snapshotDomainConfigs() {
		if dc.Provider == ProviderIPv64 {
			return &dc
		}
	}
	return nil
}

func collectIPv64ConfiguredDomains() (map[string]struct{}, map[string]struct{}) {
	configuredFQDNs := make(map[string]struct{})
	ourBaseDomains := make(map[string]struct{})

	for _, dc := range snapshotDomainConfigs() {
		if dc.Provider != ProviderIPv64 {
			continue
		}

		fqdn := normalizeIPv64FQDN(dc.FQDN)
		configuredFQDNs[fqdn] = struct{}{}

		base, _ := splitIPv64FQDN(fqdn)
		if base == "" {
			base = fqdn
		}

		ourBaseDomains[base] = struct{}{}
	}

	return configuredFQDNs, ourBaseDomains
}

func snapshotIPv64ProviderDomains() map[string]IPv64Domain {
	providerCache.RLock()
	defer providerCache.RUnlock()

	domains := make(map[string]IPv64Domain, len(providerCache.ipv64Records))
	for baseDomain, domain := range providerCache.ipv64Records {
		domain.Records = slices.Clone(domain.Records)
		domains[baseDomain] = domain
	}

	return domains
}

func cleanupIPv64DomainRecords(
	ctx context.Context,
	ipv64DC *DomainConfig,
	baseDomain string,
	domain IPv64Domain,
	configuredFQDNs, ourBaseDomains map[string]struct{},
) {
	if _, ours := ourBaseDomains[baseDomain]; !ours {
		debugLog("MAINTENANCE", baseDomain, phrases().CleanupSkipForeignBase)
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

	debugLog("MAINTENANCE", fqdn, fmt.Sprintf(phrases().CleanupSkipOrphaned, rec.Type, rec.RecordID))

	if dryRunEnabled() {
		log(LogContext{
			Level:   LogInfo,
			Action:  ActionCleanup,
			Domain:  fqdn,
			Message: fmt.Sprintf(phrases().CleanupDryRun+" (%s ID %d)", rec.Type, rec.RecordID),
		})
		return
	}

	if err := deleteIPv64Record(ctx, ipv64DC, baseDomain, rec); err != nil {
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

func shouldCleanupIPv64Record(
	baseDomain string,
	rec IPv64Record,
	configuredFQDNs map[string]struct{},
) (string, bool) {
	if !isAddressRecord(rec.Type) {
		return "", false
	}

	if rec.TTL <= 10 || rec.FailoverPolicy != "0" {
		debugLog("MAINTENANCE", baseDomain,
			fmt.Sprintf(phrases().CleanupSkipCDN, rec.RecordID, rec.TTL, rec.FailoverPolicy))
		return "", false
	}

	if rec.Deactivated != 0 {
		debugLog("MAINTENANCE", baseDomain,
			fmt.Sprintf(phrases().CleanupSkipDeactivated, rec.RecordID))
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

	debugLog("HTTP", baseDomain, fmt.Sprintf(phrases().IPv64DeleteResponse, string(data)))
	return nil
}

func loadIPv64Domains(ctx context.Context, dc *DomainConfig) ([]Zone, error) {
	providerCache.RLock()
	hasCached := len(providerCache.ipv64Records) > 0
	providerCache.RUnlock()

	if hasCached {
		providerCache.RLock()
		zones := make([]Zone, 0, len(providerCache.ipv64Records))
		for domainName := range providerCache.ipv64Records {
			zones = append(zones, Zone{
				ID:   domainName,
				Name: domainName,
			})
		}
		providerCache.RUnlock()
		debugLog("CACHE", "", fmt.Sprintf(phrases().IPv64CacheBuilt, len(zones)))
		return zones, nil
	}

	params := map[string]string{
		"get_domains": dc.IPv64Token,
	}
	data, err := ipv64API(ctx, dc, params)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", phrases().IPv64ParseError, err)
	}

	var resp IPv64Response
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("%s: %w", phrases().IPv64ParseError, err)
	}

	zones := make([]Zone, 0, len(resp.Subdomains))
	for domainName := range resp.Subdomains {
		zones = append(zones, Zone{
			ID:   domainName,
			Name: domainName,
		})
	}
	return zones, nil
}

// ============================================================================
// DOMAIN MANAGEMENT (Dashboard UI only — not called from update loop)
// ============================================================================

func addIPv64Domain(ctx context.Context, dc *DomainConfig, fqdn string) error {
	fqdn = normalizeIPv64FQDN(fqdn)
	if fqdn == "" {
		return fmt.Errorf("fqdn is empty")
	}

	params := map[string]string{
		"add_domain": fqdn,
	}

	data, err := ipv64API(ctx, dc, params)
	if err != nil {
		return fmt.Errorf("add_domain %s: %w", fqdn, err)
	}

	debugLog("IPv64", fqdn, fmt.Sprintf("add_domain response: %s", string(data)))

	lastIPv64DomainsLoadNano.Store(0)
	if err := loadAllIPv64Domains(ctx, dc); err != nil {
		debugLog("IPv64", fqdn, fmt.Sprintf("cache refresh after add_domain failed: %v", err))
	}

	return nil
}

func deleteIPv64Domain(ctx context.Context, dc *DomainConfig, fqdn string) error {
	fqdn = normalizeIPv64FQDN(fqdn)
	if fqdn == "" {
		return fmt.Errorf("fqdn is empty")
	}

	params := map[string]string{
		"del_domain": fqdn,
	}

	data, err := ipv64API(ctx, dc, params)
	if err != nil {
		return fmt.Errorf("del_domain %s: %w", fqdn, err)
	}

	debugLog("IPv64", fqdn, fmt.Sprintf("del_domain response: %s", string(data)))

	providerCache.Lock()
	delete(providerCache.ipv64Records, fqdn)
	providerCache.Unlock()
	lastIPv64DomainsLoadNano.Store(0)

	return nil
}

func selectIPv64DomainConfigForAction(
	ctx context.Context,
	action string,
	fqdn string,
	apiToken string,
) (*DomainConfig, int, error) {
	fqdn = normalizeIPv64FQDN(fqdn)
	apiToken = strings.TrimSpace(apiToken)

	if fqdn == "" {
		return nil, http.StatusBadRequest, fmt.Errorf("%s", phrases().IPv64FQDNEmpty)
	}

	if apiToken != "" {
		dc := findIPv64DomainConfigForFQDN(fqdn)
		if dc == nil {
			dc = &DomainConfig{
				FQDN:     fqdn,
				Provider: ProviderIPv64,
			}
		}

		dc.IPv64Token = apiToken

		if action == MethodDELETE {
			owns, err := ipv64TokenOwnsDomain(ctx, dc, fqdn)
			if err != nil {
				return nil, http.StatusBadGateway, fmt.Errorf(phrases().IPv64TokenOwnershipVerifyFailed, fqdn, err)
			}
			if !owns {
				return nil, http.StatusForbidden, fmt.Errorf(phrases().IPv64TokenDoesNotOwnDomain, fqdn)
			}
		}

		return dc, http.StatusOK, nil
	}

	if action == MethodDELETE {
		dc, err := findIPv64DomainConfigOwningFQDN(ctx, fqdn)
		if err != nil {
			return nil, http.StatusBadGateway, err
		}
		if dc == nil {
			return nil, http.StatusBadRequest, fmt.Errorf(phrases().IPv64NoTokenOwnsDomain, fqdn)
		}
		return dc, http.StatusOK, nil
	}

	dc := findIPv64DomainConfigForFQDN(fqdn)
	if dc == nil || strings.TrimSpace(dc.IPv64Token) == "" {
		return nil, http.StatusBadRequest, fmt.Errorf(phrases().IPv64NoMatchingTokenConfigured, fqdn)
	}

	return dc, http.StatusOK, nil
}

func findIPv64DomainConfigForFQDN(fqdn string) *DomainConfig {
	fqdn = normalizeIPv64FQDN(fqdn)

	cfgMu.RLock()
	defer cfgMu.RUnlock()

	var best DomainConfig
	bestLen := -1
	found := false

	for i := range cfg.DomainConfigs {
		dc := cfg.DomainConfigs[i]
		if dc.Provider != ProviderIPv64 {
			continue
		}
		if strings.TrimSpace(dc.IPv64Token) == "" {
			continue
		}

		configFQDN := normalizeIPv64FQDN(dc.FQDN)
		if !ipv64ConfigCoversFQDN(configFQDN, fqdn) {
			continue
		}

		if len(configFQDN) > bestLen {
			best = dc
			bestLen = len(configFQDN)
			found = true
		}
	}

	if !found {
		return nil
	}

	return &best
}

func ipv64ConfigCoversFQDN(configFQDN, fqdn string) bool {
	configFQDN = normalizeIPv64FQDN(configFQDN)
	fqdn = normalizeIPv64FQDN(fqdn)

	if configFQDN == "" || fqdn == "" {
		return false
	}

	return fqdn == configFQDN || strings.HasSuffix(fqdn, "."+configFQDN)
}

func findIPv64DomainConfigOwningFQDN(ctx context.Context, fqdn string) (*DomainConfig, error) {
	fqdn = normalizeIPv64FQDN(fqdn)

	configs := ipv64DomainConfigsSnapshot()
	seenTokens := make(map[string]struct{})
	var lastErr error
	checked := 0

	for _, dc := range configs {
		token := strings.TrimSpace(dc.IPv64Token)
		if token == "" {
			continue
		}
		if _, seen := seenTokens[token]; seen {
			continue
		}
		seenTokens[token] = struct{}{}

		dcCopy := dc
		owns, err := ipv64TokenOwnsDomain(ctx, &dcCopy, fqdn)
		if err != nil {
			lastErr = err
			debugLog("IPv64", fqdn, fmt.Sprintf(phrases().IPv64OwnershipCheckFailed, err))
			continue
		}

		checked++

		if owns {
			return &dcCopy, nil
		}
	}

	if checked == 0 && lastErr != nil {
		return nil, fmt.Errorf(phrases().IPv64AnyTokenVerifyFailed, fqdn, lastErr)
	}

	return nil, nil
}

func ipv64DomainConfigsSnapshot() []DomainConfig {
	cfgMu.RLock()
	defer cfgMu.RUnlock()

	out := make([]DomainConfig, 0, len(cfg.DomainConfigs))

	for _, dc := range cfg.DomainConfigs {
		if dc.Provider != ProviderIPv64 {
			continue
		}
		if strings.TrimSpace(dc.IPv64Token) == "" {
			continue
		}

		out = append(out, dc)
	}

	return out
}

func ipv64TokenOwnsDomain(ctx context.Context, dc *DomainConfig, fqdn string) (bool, error) {
	fqdn = normalizeIPv64FQDN(fqdn)
	if fqdn == "" {
		return false, fmt.Errorf("%s", phrases().IPv64FQDNEmpty)
	}

	if dc == nil || strings.TrimSpace(dc.IPv64Token) == "" {
		return false, fmt.Errorf("%s", phrases().IPv64TokenMissing)
	}

	params := map[string]string{
		"get_domains": dc.IPv64Token,
	}

	data, err := ipv64API(ctx, dc, params)
	if err != nil {
		return false, err
	}

	var resp IPv64Response
	if err := json.Unmarshal(data, &resp); err != nil {
		return false, fmt.Errorf("%s: %w", phrases().IPv64ParseError, err)
	}

	_, ok := resp.Subdomains[fqdn]
	return ok, nil
}
