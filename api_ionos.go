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
	"strings"
	"time"
)

func saveIONOSCacheToFile(zones []Zone, recordCache *ZoneRecordCache) error {
	return saveProviderCacheToFile("IONOS", "ionos_cache.json", zones, recordCache)
}

func loadIONOSCacheFromFile() ([]Zone, *ZoneRecordCache, error) {
	return loadProviderCacheFromFile("IONOS", "ionos_cache.json")
}

// ============================================================================
// API - IONOS
// ============================================================================
func ionosAPI(ctx context.Context, dc *DomainConfig, method, url string, body any) ([]byte, error) {
	return apiWithRetry(ctx, "IONOS", phrases().IonosAPIFailed, func(attempt, maxRetries int) ([]byte, bool, error) {
		return ionosAPIAttempt(ctx, dc, method, url, body, attempt, maxRetries)
	})
}

func ionosAPIAttempt(
	ctx context.Context,
	dc *DomainConfig,
	method, url string,
	body any,
	attempt, maxRetries int,
) ([]byte, bool, error) {
	debugLog("HTTP", "", fmt.Sprintf(
		phrases().IonosAttempt,
		phrases().Attempt, attempt+1, maxRetries, method, url,
	))

	bodyBytes, err := marshalIonosBody(body)
	if err != nil {
		return nil, false, err
	}

	req, err := buildIonosRequest(ctx, dc, method, url, body, bodyBytes)
	if err != nil {
		return nil, false, err
	}

	start := time.Now()
	res, err := getHTTPClient().Do(req)
	duration := time.Since(start)

	if err != nil {
		retry, handledErr := handleProviderNetworkError(ctx, "IONOS", method, err, duration, attempt, false)
		return nil, retry, handledErr
	}

	defer func() {
		if err := res.Body.Close(); err != nil {
			debugLog("HTTP", "", fmt.Sprintf(phrases().ErrBodyClose+": %v", err))
		}
	}()

	debugLog("HTTP", "", fmt.Sprintf("✅ Status: %d | %s: %v", res.StatusCode, phrases().AvgLatency, duration))
	return handleIonosResponse(ctx, res, method, url, duration, attempt)
}

func marshalIonosBody(body any) ([]byte, error) {
	if body == nil {
		return nil, nil
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", phrases().ErrJSONMarshal, err)
	}

	debugLog("HTTP", "", fmt.Sprintf("📤 %s: %s", phrases().PayloadSent, string(bodyBytes)))
	return bodyBytes, nil
}

func buildIonosRequest(
	ctx context.Context,
	dc *DomainConfig,
	method, url string,
	body any,
	bodyBytes []byte,
) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", phrases().ErrRequestCreate, err)
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
	req.Header.Set("User-Agent", ManagedComment)

	return req, nil
}

func handleIonosResponse(
	ctx context.Context,
	res *http.Response,
	method, url string,
	duration time.Duration,
	attempt int,
) ([]byte, bool, error) {
	return handleProviderHTTPResponse(ctx, "IONOS", phrases().IonosMaxAttempts, res, method, url, duration, attempt)
}

func loadIPv64InfrastructureRecords(z Zone) []Record {
	providerCache.RLock()
	defer providerCache.RUnlock()

	var records []Record
	if data, ok := providerCache.ipv64Records[z.Name]; ok {
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
	}

	return records
}

func loadIonosInfrastructureRecords(ctx context.Context, dc *DomainConfig, zoneID string) []Record {
	data, _ := ionosAPI(ctx, dc, MethodGET, ionosBaseURL+"/"+zoneID, nil)

	var detail struct {
		Records []Record `json:"records"`
	}
	_ = json.Unmarshal(data, &detail)

	return detail.Records
}

// ============================================================================
// DNS LOGIC - IONOS
// ============================================================================
func updateIonosDNS(
	ctx context.Context,
	dc *DomainConfig,
	fqdn, recordType, newIP string,
	records []Record,
	zoneID string,
	zoneName string,
	cache *ZoneRecordCache,
) (bool, error) {
	recordName := recordNameFromFQDN(fqdn, zoneName)
	existing := findIonosExistingRecord(records, fqdn, recordName, recordType)

	if shouldSkipIonosUpdate(fqdn, recordType, newIP, existing) {
		return false, nil
	}

	if zoneName == "" {
		return false, fmt.Errorf(phrases().ErrZoneNameEmpty, fqdn)
	}

	if cfg.DryRun {
		log(LogContext{
			Level:   LogWarn,
			Action:  ActionDryRun,
			Domain:  fqdn,
			Message: fmt.Sprintf("⚠️ %s %s %s", phrases().WouldSet, recordType, newIP),
		})
		return true, nil
	}

	method, url, actionType, payload := buildIonosUpdateRequest(dc, fqdn, recordType, newIP, zoneID, existing)
	debugIonosUpdateRequest(fqdn, method, url, zoneName, recordType)

	if err := executeIonosDNSUpdate(ctx, dc, fqdn, recordType, newIP, method, url, payload); err != nil {
		return false, err
	}

	log(LogContext{
		Level:   LogInfo,
		Action:  actionType,
		Domain:  fqdn,
		Message: fmt.Sprintf("🔄 %s -> %s %s", recordType, newIP, phrases().Update),
	})

	updateIONOSCache(cache, zoneID, recordName, fqdn, recordType, newIP, existing)
	return true, nil
}

func findIonosExistingRecord(records []Record, fqdn, recordName, recordType string) *Record {
	for i := range records {
		if (records[i].Name == fqdn || records[i].Name == recordName) && records[i].Type == recordType {
			existing := &records[i]
			debugLog("DNS-LOGIC", fqdn,
				fmt.Sprintf("📌 %s: %s (ID: %s)", phrases().RecordFound, existing.Content, existing.ID))
			return existing
		}
	}
	return nil
}

func shouldSkipIonosUpdate(fqdn, recordType, newIP string, existing *Record) bool {
	if existing != nil && existing.Content == newIP {
		debugLog("DNS-LOGIC", fqdn, fmt.Sprintf("✅ %s: %s = %s", phrases().RecordCurrent, recordType, newIP))
		log(LogContext{
			Level:   LogInfo,
			Action:  ActionCurrent,
			Domain:  fqdn,
			Message: fmt.Sprintf("%-4s %s %s", recordType, newIP, phrases().Current),
		})
		return true
	}

	if existing == nil {
		debugLog("DNS-LOGIC", fqdn, fmt.Sprintf("🆕 %s: %s", phrases().NoRecordFound, recordType))
	} else {
		debugLog("DNS-LOGIC", fqdn, fmt.Sprintf("🔄 %s: %s -> %s", phrases().RecordUpdateNeeded, existing.Content, newIP))
	}

	return false
}

func buildIonosUpdateRequest(
	dc *DomainConfig,
	fqdn, recordType, newIP, zoneID string,
	existing *Record,
) (string, string, string, any) {
	if existing != nil {
		return MethodPUT,
			fmt.Sprintf("%s/%s/records/%s", ionosBaseURL, zoneID, existing.ID),
			ActionUpdate,
			map[string]any{
				"name":    fqdn,
				"type":    recordType,
				"content": newIP,
				"ttl":     effectiveTTL(dc),
			}
	}

	return MethodPOST,
		fmt.Sprintf("%s/%s/records", ionosBaseURL, zoneID),
		ActionCreate,
		[]DNSRecord{
			{
				Name:    fqdn,
				Type:    recordType,
				Content: newIP,
				TTL:     effectiveTTL(dc),
			},
		}
}

func debugIonosUpdateRequest(fqdn, method, url, zoneName, recordType string) {
	debugLog("DNS-LOGIC", fqdn, fmt.Sprintf("📡 %s: %s %s", phrases().APICall, method, url))
	debugLog("DNS-LOGIC", fqdn, fmt.Sprintf(phrases().IonosPayload, zoneName, fqdn, recordType))
}

func executeIonosDNSUpdate(
	ctx context.Context,
	dc *DomainConfig,
	fqdn, recordType, newIP, method, url string,
	payload any,
) error {
	_, err := ionosAPI(ctx, dc, method, url, payload)
	if err == nil {
		debugLog("DNS-LOGIC", fqdn, fmt.Sprintf(phrases().IonosRecordArrow, phrases().Success, recordType, newIP))
		return nil
	}

	var apiErrPtr *APIError
	if errors.As(err, &apiErrPtr) && apiErrPtr != nil {
		return handleIonosDNSAPIError(fqdn, recordType, newIP, apiErrPtr, err)
	}

	debugLog("DNS-LOGIC", fqdn, fmt.Sprintf("❌ %s: %v", phrases().UpdateFailed, err))
	return err
}

func handleIonosDNSAPIError(fqdn, recordType, newIP string, apiErr *APIError, err error) error {
	logIonosDNSAPIError(fqdn, recordType, newIP, apiErr)

	switch apiErr.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("%s: %w", phrases().ErrAuthFailed, err)
	case http.StatusNotFound:
		return fmt.Errorf("%s: %w", phrases().ErrResourceNotFound, err)
	case http.StatusUnprocessableEntity:
		return fmt.Errorf("%s: %w", phrases().ErrValidationFailed, err)
	default:
		debugLog("DNS-LOGIC", fqdn, fmt.Sprintf(phrases().IonosErrDetail, err, err))
		return err
	}
}

func logIonosDNSAPIError(fqdn, recordType, newIP string, apiErr *APIError) {
	level := LogError
	action := ActionError
	message := fmt.Sprintf("%s: API-Fehler %d - %s", recordType, apiErr.StatusCode, apiErr.Message)

	switch apiErr.StatusCode {
	case http.StatusNotFound:
		action = ActionZone
	case http.StatusTooManyRequests:
		level = LogWarn
		action = ActionRetry
	case http.StatusUnprocessableEntity:
		message = fmt.Sprintf("%s: %s (IP: %s)", recordType, apiErr.Message, newIP)
	}

	log(LogContext{
		Level:   level,
		Action:  action,
		Domain:  fqdn,
		Message: message,
	})
}

func loadIONOSZones(ctx context.Context, dc *DomainConfig) ([]Zone, error) {
	cfgMu.RLock()
	domainConfigs := make([]DomainConfig, len(cfg.DomainConfigs))
	copy(domainConfigs, cfg.DomainConfigs)
	cfgMu.RUnlock()

	data, err := ionosAPI(ctx, dc, MethodGET, ionosBaseURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load ionos zones: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("empty response from IONOS API")
	}

	var zones []Zone
	if err := json.Unmarshal(data, &zones); err != nil {
		return nil, fmt.Errorf("failed to parse ionos zones: %w", err)
	}

	needed := make(map[string]struct{})
	for _, dc := range domainConfigs {
		if dc.Provider != ProviderIONOS {
			continue
		}
		dn := strings.TrimSuffix(strings.ToLower(dc.FQDN), ".")
		needed[dn] = struct{}{}
	}

	filtered := zones[:0]
	for _, z := range zones {
		zn := strings.TrimSuffix(strings.ToLower(z.Name), ".")
		for dn := range needed {
			if dn == zn || strings.HasSuffix(dn, "."+zn) {
				filtered = append(filtered, z)
				break
			}
		}
	}

	if len(filtered) < len(zones) {
		debugLog("ZONE", "", fmt.Sprintf("IONOS: %d von %d Zones relevant (Rest gefiltert)", len(filtered), len(zones)))
	}

	return filtered, nil
}

// ============================================================================
// CACHE UPDATE - IONOS
// ============================================================================
func updateIONOSCache(cache *ZoneRecordCache, zoneID, recordName, fqdn, recordType, newIP string, existing *Record) {
	if cache == nil {
		return
	}

	if _, exists := cache.Get(zoneID); !exists {
		debugLog("CACHE", fqdn, phrases().IonosCacheZoneNotFound)
		return
	}

	var create cachedRecordCreateFunc
	if existing == nil {
		create = func(records []Record) *Record {
			return &Record{
				ID:      syntheticCachedRecordID(records),
				Name:    recordName,
				Type:    recordType,
				Content: newIP,
			}
		}
	}

	updated := updateCachedZoneRecord(
		cache,
		zoneID,
		func(rec Record) bool {
			return existing != nil && rec.ID == existing.ID
		},
		func(rec *Record) {
			rec.Content = newIP
		},
		create,
	)

	if !updated {
		return
	}

	if existing == nil {
		debugLog("CACHE", fqdn, fmt.Sprintf(phrases().IonosCacheRecordAdded, recordType, newIP))
		return
	}

	debugLog("CACHE", fqdn, fmt.Sprintf(phrases().IonosCacheUpdated, recordType, newIP))
}

// ============================================================================
// CLEANUP - IONOS
// ============================================================================
func cleanupIONOSRecords(ctx context.Context, zones []Zone, recordCache *ZoneRecordCache) {
	ionosDC := findIONOSConfigForCleanup()
	if ionosDC == nil {
		return
	}

	debugLog("MAINTENANCE", "", phrases().CleanupStartIonos)
	configDomains := buildIONOSConfigDomains()

	for _, zone := range zones {
		cleanupIONOSZoneRecords(ctx, ionosDC, zone, recordCache, configDomains)
	}
}

func findIONOSConfigForCleanup() *DomainConfig {
	return findProviderConfigForCleanup(ProviderIONOS)
}

func buildIONOSConfigDomains() map[string]struct{} {
	return buildProviderConfigDomains(ProviderIONOS)
}

func cleanupIONOSZoneRecords(
	ctx context.Context,
	ionosDC *DomainConfig,
	zone Zone,
	recordCache *ZoneRecordCache,
	configDomains map[string]struct{},
) {
	records, exists := recordCache.Get(zone.ID)
	if !exists {
		return
	}

	zoneName := strings.ToLower(strings.TrimSuffix(zone.Name, "."))

	for _, rec := range records {
		cleanupSingleIONOSRecord(ctx, ionosDC, zone, zoneName, rec, configDomains)
	}
}

func cleanupSingleIONOSRecord(
	ctx context.Context,
	ionosDC *DomainConfig,
	zone Zone,
	zoneName string,
	rec Record,
	configDomains map[string]struct{},
) {
	fqdn, shouldDelete := shouldCleanupIONOSRecord(zoneName, rec, configDomains)
	if !shouldDelete {
		return
	}

	debugLog("MAINTENANCE", fqdn, fmt.Sprintf(phrases().CleanupOrphanedIonos, rec.Type, rec.ID))

	if cfg.DryRun {
		log(LogContext{
			Level:   LogInfo,
			Action:  ActionCleanup,
			Domain:  fqdn,
			Message: phrases().CleanupDryRun,
		})
		return
	}

	url := fmt.Sprintf("%s/%s/records/%s", ionosBaseURL, zone.ID, rec.ID)
	if _, err := ionosAPI(ctx, ionosDC, MethodDELETE, url, nil); err != nil {
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

func shouldCleanupIONOSRecord(
	zoneName string,
	rec Record,
	configDomains map[string]struct{},
) (string, bool) {
	if !isAddressRecord(rec.Type) {
		return "", false
	}

	fqdn := ionosRecordFQDN(zoneName, rec.Name)
	if _, ok := configDomains[fqdn]; ok {
		return "", false
	}

	return fqdn, true
}

func ionosRecordFQDN(zoneName, recordName string) string {
	var fqdn string

	switch {
	case recordName == "@":
		fqdn = zoneName
	case recordName == zoneName:
		fqdn = zoneName
	case strings.HasSuffix(recordName, "."+zoneName):
		fqdn = recordName
	default:
		fqdn = recordName + "." + zoneName
	}

	return strings.ToLower(strings.TrimSuffix(fqdn, "."))
}
