// Package main
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

// ============================================================================
// CACHE PERSISTENCE - HETZNER
// ============================================================================
func getHetznerDNSCachePath() string {
	return filepath.Join(cfg.LogDir, "hetzner_dns_cache.json")
}

func saveHetznerDNSCacheToFile(zones []Zone, recordCache *ZoneRecordCache) error {
	return saveDNSProviderCacheToFile("HETZNER", getHetznerDNSCachePath(), zones, recordCache)
}

func loadHetznerDNSCacheFromFile() ([]Zone, *ZoneRecordCache, error) {
	return loadDNSProviderCacheFromFile("HETZNER", getHetznerDNSCachePath())
}

func getHetznerCloudCachePath() string {
	return filepath.Join(cfg.LogDir, "hetzner_cloud_cache.json")
}

func saveHetznerCloudCacheToFile(zones []Zone, recordCache *ZoneRecordCache) error {
	return saveDNSProviderCacheToFile("HETZNERCLOUD", getHetznerCloudCachePath(), zones, recordCache)
}

func loadHetznerCloudCacheFromFile() ([]Zone, *ZoneRecordCache, error) {
	return loadDNSProviderCacheFromFile("HETZNERCLOUD", getHetznerCloudCachePath())
}

// ============================================================================
// SHARED API CLIENT - HETZNER
// ============================================================================
type hetznerAuthMode int

const (
	hetznerAuthAPIKey hetznerAuthMode = iota
	hetznerAuthBearer
)

func hetznerDNSAPI(ctx context.Context, dc *DomainConfig, method, endpoint string, body any) ([]byte, error) {
	return hetznerAPI(ctx, dc, "HETZNER", hetznerAuthAPIKey, method, endpoint, body)
}

func hetznerCloudAPI(ctx context.Context, dc *DomainConfig, method, endpoint string, body any) ([]byte, error) {
	return hetznerAPI(ctx, dc, "HETZNERCLOUD", hetznerAuthBearer, method, endpoint, body)
}

func hetznerAPI(
	ctx context.Context,
	dc *DomainConfig,
	providerName string,
	authMode hetznerAuthMode,
	method, endpoint string,
	body any,
) ([]byte, error) {
	return apiWithRetry(ctx, providerName, providerName+" API failed after %d attempts", func(attempt, maxRetries int) ([]byte, bool, error) {
		return hetznerAPIAttempt(ctx, dc, providerName, authMode, method, endpoint, body, attempt, maxRetries)
	})
}

func hetznerAPIAttempt(
	ctx context.Context,
	dc *DomainConfig,
	providerName string,
	authMode hetznerAuthMode,
	method, endpoint string,
	body any,
	attempt, maxRetries int,
) ([]byte, bool, error) {
	debugLog("HTTP", "", fmt.Sprintf("%s attempt %d/%d: %s %s", providerName, attempt+1, maxRetries, method, endpoint))

	bodyBytes, err := marshalHetznerBody(body)
	if err != nil {
		return nil, false, err
	}

	req, err := buildHetznerRequest(ctx, dc, authMode, method, endpoint, body, bodyBytes)
	if err != nil {
		return nil, false, err
	}

	start := time.Now()
	res, err := getHTTPClient().Do(req)
	duration := time.Since(start)
	if err != nil {
		shouldRetry, retryErr := hetznerNetworkRetry(ctx, method, err, duration, attempt)
		return nil, shouldRetry, retryErr
	}

	return handleHetznerResponse(ctx, providerName, res, method, endpoint, duration, attempt)
}

func marshalHetznerBody(body any) ([]byte, error) {
	if body == nil {
		return nil, nil
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("json marshal: %w", err)
	}
	debugLog("HTTP", "", fmt.Sprintf("📤 Payload: %s", string(bodyBytes)))
	return bodyBytes, nil
}

func buildHetznerRequest(
	ctx context.Context,
	dc *DomainConfig,
	authMode hetznerAuthMode,
	method, endpoint string,
	body any,
	bodyBytes []byte,
) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	if body != nil {
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(bodyBytes)), nil
		}
		req.Header.Set("Content-Type", "application/json")
	}

	token := hetznerToken(dc)
	if token == "" {
		return nil, fmt.Errorf("missing Hetzner API token in api_secret")
	}

	switch authMode {
	case hetznerAuthBearer:
		req.Header.Set("Authorization", "Bearer "+token)
	default:
		req.Header.Set("Auth-API-Token", token)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("User-Agent", ManagedComment)

	return req, nil
}

func hetznerToken(dc *DomainConfig) string {
	// Reuses existing DomainConfig fields so the provider can be added without a
	// schema migration: api_secret is preferred; api_prefix is accepted as alias.
	for _, candidate := range []string{dc.APISecret, dc.APIPrefix, dc.CFToken, dc.IPv64Token} {
		if token := strings.TrimSpace(candidate); token != "" {
			return token
		}
	}
	return ""
}

func hetznerNetworkRetry(
	ctx context.Context,
	method string,
	err error,
	duration time.Duration,
	attempt int,
) (bool, error) {
	debugLog("HTTP", "", fmt.Sprintf("❌ network error: %v | latency: %v", err, duration))
	apiMetrics.RecordError(method, 0, err, duration)

	wait := calculateRetryDelay(attempt, false)
	if !sleepOrCancel(ctx, wait) {
		return false, fmt.Errorf("context cancelled: %w", ctx.Err())
	}
	return true, fmt.Errorf("network error: %w", err)
}

func handleHetznerResponse(
	ctx context.Context,
	providerName string,
	res *http.Response,
	method, endpoint string,
	duration time.Duration,
	attempt int,
) ([]byte, bool, error) {
	respBody, err := io.ReadAll(res.Body)
	closeErr := res.Body.Close()
	if closeErr != nil {
		debugLog("HTTP", "", fmt.Sprintf("body close error: %v", closeErr))
	}
	if err != nil {
		apiMetrics.RecordError(method, res.StatusCode, err, duration)
		wait := calculateRetryDelay(attempt, false)
		if !sleepOrCancel(ctx, wait) {
			return nil, false, fmt.Errorf("context cancelled: %w", ctx.Err())
		}
		return nil, true, fmt.Errorf("body read error: %w", err)
	}

	if res.StatusCode >= 200 && res.StatusCode < 300 {
		apiMetrics.RecordSuccess(method, duration)
		lastErrorMsg.Set("")
		debugLog("HTTP", "", fmt.Sprintf("✅ %s success: %d bytes", providerName, len(respBody)))
		return respBody, false, nil
	}

	apiErr := classifyAPIErrorWithHeaders(res.StatusCode, method, endpoint, string(respBody), res.Header)
	apiMetrics.RecordError(method, res.StatusCode, apiErr, duration)
	lastErrorMsg.Set(sanitizeError(apiErr))

	if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
		log(LogContext{Level: LogError, Action: ActionError, Message: fmt.Sprintf("🚨 %s auth error: %v", providerName, apiErr)})
	}

	if !apiErr.IsRetryable() {
		return nil, false, apiErr
	}
	if attempt >= cfg.MaxAPIRetries-1 {
		return nil, false, apiErr
	}

	wait := apiErr.RetryAfter
	if wait <= 0 {
		wait = calculateRetryDelay(attempt, res.StatusCode >= 500)
	}
	debugLog("HTTP", "", fmt.Sprintf("🔄 %s retry in %v", providerName, wait))
	if !sleepOrCancel(ctx, wait) {
		return nil, false, fmt.Errorf("context cancelled: %w", ctx.Err())
	}
	return nil, true, apiErr
}

// ============================================================================
// ZONES & RECORD LOADING - LEGACY HETZNER DNS API
// ============================================================================
type hetznerDNSZonesResponse struct {
	Zones []hetznerDNSZone `json:"zones"`
}

type hetznerDNSZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type hetznerDNSRecordsResponse struct {
	Records []hetznerDNSRecord `json:"records"`
}

type hetznerDNSRecord struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Value  string `json:"value"`
	TTL    int    `json:"ttl,omitempty"`
	ZoneID string `json:"zone_id,omitempty"`
}

func loadHetznerDNSZones(ctx context.Context, dc *DomainConfig) ([]Zone, error) {
	data, err := hetznerDNSAPI(ctx, dc, http.MethodGet, hetznerDNSBaseURL+"/zones", nil)
	if err != nil {
		return nil, err
	}

	var resp hetznerDNSZonesResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}

	zones := make([]Zone, 0, len(resp.Zones))
	for _, z := range resp.Zones {
		if z.ID == "" || z.Name == "" {
			continue
		}
		zones = append(zones, Zone{ID: z.ID, Name: strings.TrimSuffix(strings.ToLower(z.Name), ".")})
	}
	return zones, nil
}

func loadHetznerDNSZoneRecords(ctx context.Context, dc *DomainConfig, zoneID string) ([]Record, error) {
	endpoint := hetznerDNSBaseURL + "/records?zone_id=" + url.QueryEscape(zoneID)
	data, err := hetznerDNSAPI(ctx, dc, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	var resp hetznerDNSRecordsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}

	records := make([]Record, 0, len(resp.Records))
	for _, rec := range resp.Records {
		records = append(records, Record{
			ID:      rec.ID,
			Name:    normalizeHetznerRelativeName(rec.Name),
			Type:    rec.Type,
			Content: rec.Value,
		})
	}
	return records, nil
}

// ============================================================================
// ZONES & RECORD LOADING - NEW HETZNER CLOUD DNS API
// ============================================================================
type hetznerCloudZonesResponse struct {
	Zones []hetznerCloudZone `json:"zones"`
}

type hetznerCloudZone struct {
	ID   any    `json:"id"`
	Name string `json:"name"`
}

type hetznerCloudRRSetsResponse struct {
	RRSets []hetznerCloudRRSet `json:"rrsets"`
}

type hetznerCloudRRSet struct {
	ID      any                    `json:"id,omitempty"`
	Name    string                 `json:"name"`
	Type    string                 `json:"type"`
	TTL     int                    `json:"ttl,omitempty"`
	Records []hetznerCloudRRRecord `json:"records"`
}

type hetznerCloudRRRecord struct {
	Value   string `json:"value"`
	Comment string `json:"comment,omitempty"`
}

func loadHetznerCloudZones(ctx context.Context, dc *DomainConfig) ([]Zone, error) {
	data, err := hetznerCloudAPI(ctx, dc, http.MethodGet, hetznerCloudBaseURL+"/zones", nil)
	if err != nil {
		return nil, err
	}

	var resp hetznerCloudZonesResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}

	zones := make([]Zone, 0, len(resp.Zones))
	for _, z := range resp.Zones {
		name := strings.TrimSuffix(strings.ToLower(z.Name), ".")
		id := normalizeHetznerID(z.ID)
		if id == "" {
			id = name
		}
		if name == "" {
			continue
		}
		zones = append(zones, Zone{ID: id, Name: name})
	}
	return zones, nil
}

func loadHetznerCloudZoneRecords(ctx context.Context, dc *DomainConfig, zoneID string) ([]Record, error) {
	endpoint := fmt.Sprintf("%s/zones/%s/rrsets", hetznerCloudBaseURL, escapePathSegment(zoneID))
	data, err := hetznerCloudAPI(ctx, dc, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	var resp hetznerCloudRRSetsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}

	records := make([]Record, 0, len(resp.RRSets))
	for _, rr := range resp.RRSets {
		if rr.Type != RecordTypeA && rr.Type != RecordTypeAAAA {
			continue
		}
		for idx, rec := range rr.Records {
			records = append(records, Record{
				ID:      fmt.Sprintf("%s/%s/%d", normalizeHetznerRelativeName(rr.Name), rr.Type, idx),
				Name:    normalizeHetznerRelativeName(rr.Name),
				Type:    rr.Type,
				Content: rec.Value,
			})
		}
	}
	return records, nil
}

func normalizeHetznerID(v any) string {
	switch id := v.(type) {
	case nil:
		return ""
	case string:
		return id
	case float64:
		return fmt.Sprintf("%.0f", id)
	case json.Number:
		return id.String()
	default:
		return fmt.Sprintf("%v", id)
	}
}

// ============================================================================
// DNS UPDATE LOGIC - LEGACY HETZNER DNS API
// ============================================================================
func updateHetznerDNS(
	ctx context.Context,
	dc *DomainConfig,
	fqdn, recordType, newIP string,
	records []Record,
	zoneID string,
	zoneName string,
	cache *ZoneRecordCache,
) (bool, error) {
	recordName := hetznerRecordNameFromFQDN(fqdn, zoneName)
	existing := findHetznerExistingRecord(records, fqdn, zoneName, recordName, recordType)

	if shouldSkipHetznerUpdate("HETZNER", fqdn, recordType, newIP, existing) {
		return false, nil
	}
	if cfg.DryRun {
		log(LogContext{Level: LogWarn, Action: ActionDryRun, Domain: fqdn, Message: fmt.Sprintf("⚠️ Would set %s %s", recordType, newIP)})
		return true, nil
	}

	method := http.MethodPost
	endpoint := hetznerDNSBaseURL + "/records"
	payload := hetznerDNSRecord{
		Name:   recordName,
		Type:   recordType,
		Value:  newIP,
		TTL:    effectiveTTL(dc),
		ZoneID: zoneID,
	}
	action := ActionCreate

	if existing != nil {
		method = http.MethodPut
		endpoint = hetznerDNSBaseURL + "/records/" + escapePathSegment(existing.ID)
		payload.ID = existing.ID
		action = ActionUpdate
	}

	if _, err := hetznerDNSAPI(ctx, dc, method, endpoint, payload); err != nil {
		return false, err
	}

	log(LogContext{Level: LogInfo, Action: action, Domain: fqdn, Message: fmt.Sprintf("🔄 %s -> %s Update", recordType, newIP)})
	updateHetznerRecordCache(cache, zoneID, recordName, recordType, newIP, existing)
	return true, nil
}

// ============================================================================
// DNS UPDATE LOGIC - NEW HETZNER CLOUD DNS API
// ============================================================================
func updateHetznerCloudDNS(
	ctx context.Context,
	dc *DomainConfig,
	fqdn, recordType, newIP string,
	records []Record,
	zoneID string,
	zoneName string,
	cache *ZoneRecordCache,
) (bool, error) {
	recordName := hetznerRecordNameFromFQDN(fqdn, zoneName)
	existing := findHetznerExistingRecord(records, fqdn, zoneName, recordName, recordType)

	if shouldSkipHetznerUpdate("HETZNERCLOUD", fqdn, recordType, newIP, existing) {
		return false, nil
	}
	if cfg.DryRun {
		log(LogContext{Level: LogWarn, Action: ActionDryRun, Domain: fqdn, Message: fmt.Sprintf("⚠️ Would set %s %s", recordType, newIP)})
		return true, nil
	}

	payloadRecords := []hetznerCloudRRRecord{{Value: newIP, Comment: ManagedComment}}
	method := http.MethodPost
	action := ActionCreate
	endpoint := fmt.Sprintf("%s/zones/%s/rrsets", hetznerCloudBaseURL, escapePathSegment(zoneIDOrName(zoneID, zoneName)))
	payload := any(map[string]any{
		"name":    recordName,
		"type":    recordType,
		"ttl":     effectiveTTL(dc),
		"records": payloadRecords,
		"labels":  map[string]string{},
	})

	if existing != nil {
		endpoint = fmt.Sprintf(
			"%s/zones/%s/rrsets/%s/%s/actions/set_records",
			hetznerCloudBaseURL,
			escapePathSegment(zoneIDOrName(zoneID, zoneName)),
			escapePathSegment(recordName),
			escapePathSegment(recordType),
		)
		payload = map[string]any{
			"records": payloadRecords,
		}
		action = ActionUpdate
	}

	if _, err := hetznerCloudAPI(ctx, dc, method, endpoint, payload); err != nil {
		return false, err
	}

	log(LogContext{Level: LogInfo, Action: action, Domain: fqdn, Message: fmt.Sprintf("🔄 %s -> %s Update", recordType, newIP)})
	updateHetznerRecordCache(cache, zoneID, recordName, recordType, newIP, existing)
	return true, nil
}

func findHetznerExistingRecord(records []Record, fqdn, zoneName, recordName, recordType string) *Record {
	fqdn = strings.ToLower(strings.TrimSuffix(fqdn, "."))
	for i := range records {
		if records[i].Type != recordType {
			continue
		}
		name := normalizeHetznerRelativeName(records[i].Name)
		if name == recordName || hetznerRecordFQDN(zoneName, name) == fqdn {
			existing := &records[i]
			debugLog("DNS-LOGIC", fqdn, fmt.Sprintf("📌 Record found: %s (ID: %s)", existing.Content, existing.ID))
			return existing
		}
	}
	return nil
}

func shouldSkipHetznerUpdate(providerName, fqdn, recordType, newIP string, existing *Record) bool {
	if existing != nil && existing.Content == newIP {
		debugLog("DNS-LOGIC", fqdn, fmt.Sprintf("✅ %s current: %s = %s", providerName, recordType, newIP))
		log(LogContext{Level: LogInfo, Action: ActionCurrent, Domain: fqdn, Message: fmt.Sprintf("%-4s %s Current", recordType, newIP)})
		return true
	}
	if existing == nil {
		debugLog("DNS-LOGIC", fqdn, fmt.Sprintf("🆕 %s: no %s record found", providerName, recordType))
	} else {
		debugLog("DNS-LOGIC", fqdn, fmt.Sprintf("🔄 %s update needed: %s -> %s", providerName, existing.Content, newIP))
	}
	return false
}

func updateHetznerRecordCache(cache *ZoneRecordCache, zoneID, recordName, recordType, newIP string, existing *Record) {
	if cache == nil {
		return
	}
	records, ok := cache.Get(zoneID)
	if !ok {
		return
	}

	updated := false
	if existing != nil {
		for i := range records {
			if records[i].ID == existing.ID && records[i].Type == recordType {
				records[i].Content = newIP
				updated = true
				break
			}
		}
	} else {
		records = append(records, Record{
			ID:      fmt.Sprintf("new-%d", len(records)),
			Name:    recordName,
			Type:    recordType,
			Content: newIP,
		})
		updated = true
	}

	if updated {
		cache.Set(zoneID, records)
	}
}

// ============================================================================
// CLEANUP - HETZNER
// ============================================================================
func cleanupHetznerDNSRecords(ctx context.Context, zones []Zone, recordCache *ZoneRecordCache) {
	dc := findProviderConfigForCleanup(ProviderHetzner)
	if dc == nil || recordCache == nil {
		return
	}
	cleanupHetznerRecords(ctx, dc, ProviderHetzner, zones, recordCache)
}

func cleanupHetznerCloudRecords(ctx context.Context, zones []Zone, recordCache *ZoneRecordCache) {
	dc := findProviderConfigForCleanup(ProviderHetznerCloud)
	if dc == nil || recordCache == nil {
		return
	}
	cleanupHetznerRecords(ctx, dc, ProviderHetznerCloud, zones, recordCache)
}

func cleanupHetznerRecords(
	ctx context.Context,
	dc *DomainConfig,
	provider ProviderType,
	zones []Zone,
	recordCache *ZoneRecordCache,
) {
	configDomains := buildProviderConfigDomains(provider)
	for _, zone := range zones {
		records, ok := recordCache.Get(zone.ID)
		if !ok {
			continue
		}
		zoneName := strings.ToLower(strings.TrimSuffix(zone.Name, "."))
		for _, rec := range records {
			fqdn, shouldDelete := shouldCleanupHetznerRecord(zoneName, rec, configDomains)
			if !shouldDelete {
				continue
			}
			cleanupSingleHetznerRecord(ctx, dc, provider, zone, rec, fqdn)
		}
	}
}

func cleanupSingleHetznerRecord(ctx context.Context, dc *DomainConfig, provider ProviderType, zone Zone, rec Record, fqdn string) {
	debugLog("MAINTENANCE", fqdn, fmt.Sprintf("cleanup orphaned %s record", rec.Type))
	if cfg.DryRun {
		log(LogContext{Level: LogInfo, Action: ActionCleanup, Domain: fqdn, Message: "Cleanup dry-run"})
		return
	}

	var err error
	switch provider {
	case ProviderHetzner:
		_, err = hetznerDNSAPI(ctx, dc, http.MethodDelete, hetznerDNSBaseURL+"/records/"+escapePathSegment(rec.ID), nil)
	case ProviderHetznerCloud:
		endpoint := fmt.Sprintf(
			"%s/zones/%s/rrsets/%s/%s",
			hetznerCloudBaseURL,
			escapePathSegment(zoneIDOrName(zone.ID, zone.Name)),
			escapePathSegment(normalizeHetznerRelativeName(rec.Name)),
			escapePathSegment(rec.Type),
		)
		_, err = hetznerCloudAPI(ctx, dc, http.MethodDelete, endpoint, nil)
	}
	if err != nil {
		debugLog("MAINTENANCE", fqdn, fmt.Sprintf("cleanup delete error: %v", err))
		return
	}

	log(LogContext{Level: LogInfo, Action: ActionCleanup, Domain: fqdn, Message: fmt.Sprintf("%s record removed", rec.Type)})
}

func shouldCleanupHetznerRecord(zoneName string, rec Record, configDomains map[string]struct{}) (string, bool) {
	if rec.Type != RecordTypeA && rec.Type != RecordTypeAAAA {
		return "", false
	}
	fqdn := hetznerRecordFQDN(zoneName, normalizeHetznerRelativeName(rec.Name))
	if _, ok := configDomains[fqdn]; ok {
		return "", false
	}
	return fqdn, true
}

func findProviderConfigForCleanup(provider ProviderType) *DomainConfig {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	for i := range cfg.DomainConfigs {
		if cfg.DomainConfigs[i].Provider == provider {
			dc := cfg.DomainConfigs[i]
			return &dc
		}
	}
	return nil
}

func buildProviderConfigDomains(provider ProviderType) map[string]struct{} {
	cfgMu.RLock()
	defer cfgMu.RUnlock()

	out := make(map[string]struct{})
	for _, dc := range cfg.DomainConfigs {
		if dc.Provider != provider {
			continue
		}
		fqdn := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(dc.FQDN), "."))
		if fqdn != "" {
			out[fqdn] = struct{}{}
		}
	}
	return out
}

// ============================================================================
// NAME HELPERS
// ============================================================================
func normalizeProviderName(provider string) ProviderType {
	p := strings.ToUpper(strings.TrimSpace(provider))
	p = strings.ReplaceAll(p, "-", "_")
	p = strings.ReplaceAll(p, " ", "_")

	switch p {
	case "HETZNER_DNS", "HETZNERDNS", "HETZNER_LEGACY", "HETZNERLEGACY":
		return ProviderHetzner
	case "HETZNER_CLOUD", "HETZNERCLOUD", "HCLOUD", "HETZNER_CONSOLE", "HETZNERCONSOLE":
		return ProviderHetznerCloud
	default:
		return ProviderType(p)
	}
}

func hetznerRecordNameFromFQDN(fqdn, zoneName string) string {
	fqdn = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(fqdn), "."))
	zoneName = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(zoneName), "."))
	if fqdn == "" {
		return "@"
	}
	if zoneName == "" || fqdn == zoneName {
		return "@"
	}
	if before, ok := strings.CutSuffix(fqdn, "."+zoneName); ok {
		return normalizeHetznerRelativeName(before)
	}
	return normalizeHetznerRelativeName(fqdn)
}

func normalizeHetznerRelativeName(name string) string {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" || name == "@" {
		return "@"
	}
	return name
}

func hetznerRecordFQDN(zoneName, recordName string) string {
	zoneName = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(zoneName), "."))
	recordName = normalizeHetznerRelativeName(recordName)
	switch {
	case recordName == "@" || recordName == zoneName:
		return zoneName
	case strings.HasSuffix(recordName, "."+zoneName):
		return recordName
	default:
		return strings.TrimSuffix(recordName+"."+zoneName, ".")
	}
}

func zoneIDOrName(zoneID, zoneName string) string {
	if strings.TrimSpace(zoneID) != "" {
		return zoneID
	}
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zoneName)), ".")
}

func escapePathSegment(s string) string {
	return url.PathEscape(strings.TrimSpace(s))
}
