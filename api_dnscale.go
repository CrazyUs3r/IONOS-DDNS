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
	neturl "net/url"
	"strings"
	"time"
)

// ============================================================================
// CACHE - DNSCALE
// ============================================================================

func saveDNScaleCacheToFile(zones []Zone, recordCache *ZoneRecordCache) error {
	return saveProviderCacheToFile("DNScale", "dnscale_cache.json", zones, recordCache)
}

func loadDNScaleCacheFromFile() ([]Zone, *ZoneRecordCache, error) {
	return loadProviderCacheFromFile("DNScale", "dnscale_cache.json")
}

// ============================================================================
// API - DNSCALE
// ============================================================================

func dnscaleAPI(ctx context.Context, dc *DomainConfig, method, url string, body any) ([]byte, error) {
	allowRetry := method != MethodPOST

	return apiWithRetry(ctx, "DNScale", phrases().DNScaleAPIFailed, func(attempt, maxRetries int) ([]byte, bool, error) {
		return dnscaleAPIAttempt(ctx, dc, method, url, body, attempt, maxRetries, allowRetry)
	})
}

func dnscaleAPIAttempt(
	ctx context.Context,
	dc *DomainConfig,
	method, url string,
	body any,
	attempt, maxRetries int,
	allowRetry bool,
) ([]byte, bool, error) {
	debugLog("HTTP", "", fmt.Sprintf(phrases().DNScaleAttempt, phrases().Attempt, attempt+1, maxRetries, method, url))

	bodyBytes, err := marshalDNScaleBody(body)
	if err != nil {
		return nil, false, err
	}

	req, err := buildDNScaleRequest(ctx, dc, method, url, body, bodyBytes)
	if err != nil {
		return nil, false, err
	}

	start := time.Now()
	res, err := getHTTPClient().Do(req)
	duration := time.Since(start)

	if err != nil {
		if !allowRetry {
			debugLog("HTTP", "", fmt.Sprintf(phrases().DNScaleNetworkErrorNoRetry, err, duration))
			apiMetrics.RecordError(method, 0, err, duration)

			return nil, false, fmt.Errorf("%s: %w", phrases().ErrNetworkError, err)
		}

		retry, handledErr := handleProviderNetworkError(ctx, "DNScale", method, err, duration, attempt, maxRetries, false)

		return nil, retry, handledErr
	}

	defer func() {
		if err := res.Body.Close(); err != nil {
			debugLog("HTTP", "", fmt.Sprintf(phrases().ErrBodyClose+": %v", err))
		}
	}()

	debugLog("HTTP", "", fmt.Sprintf(phrases().HTTPStatusLatency, res.StatusCode, phrases().AvgLatency, duration))

	responseAttempt := attempt
	if !allowRetry {
		responseAttempt = maxRetries - 1
	}

	return handleDNScaleResponse(ctx, res, method, url, duration, responseAttempt, maxRetries)
}

func marshalDNScaleBody(body any) ([]byte, error) {
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

func buildDNScaleRequest(
	ctx context.Context,
	dc *DomainConfig,
	method, url string,
	body any,
	bodyBytes []byte,
) (*http.Request, error) {
	var bodyReader io.Reader
	if len(bodyBytes) > 0 {
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", phrases().ErrRequestCreate, err)
	}

	if body != nil {
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(bodyBytes)), nil
		}
	}

	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(dc.APIKey))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", ManagedComment)

	return req, nil
}

func handleDNScaleResponse(
	ctx context.Context,
	res *http.Response,
	method, url string,
	duration time.Duration,
	attempt, maxAttempts int,
) ([]byte, bool, error) {
	return handleProviderHTTPResponse(ctx, "DNScale", phrases().DNScaleMaxAttempts, res, method, url, duration, attempt, maxAttempts)
}

// ============================================================================
// ZONE HELPERS - DNSCALE
// ============================================================================

type dnscaleZonesResponse struct {
	Status string `json:"status"`
	Data   struct {
		Items []Zone `json:"items"`
		Total int    `json:"total"`
	} `json:"data"`
}

type dnscaleRecordsResponse struct {
	Status string `json:"status"`
	Data   struct {
		Records    []Record `json:"records"`
		Pagination struct {
			Total   int  `json:"total"`
			Offset  int  `json:"offset"`
			Limit   int  `json:"limit"`
			Count   int  `json:"count"`
			HasMore bool `json:"has_more"`
		} `json:"pagination"`
	} `json:"data"`
}

type dnscaleRecordResponse struct {
	Status string `json:"status"`
	Data   struct {
		Message string `json:"message"`
		Record  Record `json:"record"`
	} `json:"data"`
}

func loadDNScaleZones(ctx context.Context, dc *DomainConfig) ([]Zone, error) {
	domainConfigs := snapshotDomainConfigs()

	var allZones []Zone
	offset := 0
	const pageSize = 100

	for {
		url := fmt.Sprintf("%s?limit=%d&offset=%d", dnscaleBaseURL, pageSize, offset)
		data, err := dnscaleAPI(ctx, dc, MethodGET, url, nil)
		if err != nil {
			return nil, fmt.Errorf(phrases().DNScaleZonesLoadFailed, err)
		}
		if len(data) == 0 {
			return nil, errors.New(phrases().DNScaleEmptyAPIResponse)
		}

		var resp dnscaleZonesResponse
		if err := json.Unmarshal(data, &resp); err != nil {
			return nil, fmt.Errorf(phrases().DNScaleZonesParseFailed, err)
		}

		allZones = append(allZones, resp.Data.Items...)
		if len(allZones) >= resp.Data.Total || len(resp.Data.Items) == 0 {
			break
		}
		offset += pageSize
	}

	needed := make(map[string]struct{})
	for _, dc := range domainConfigs {
		if dc.Provider != ProviderDNScale {
			continue
		}
		dn := strings.TrimSuffix(strings.ToLower(dc.FQDN), ".")
		needed[dn] = struct{}{}
	}

	filtered := allZones[:0]
	for _, z := range allZones {
		zn := strings.TrimSuffix(strings.ToLower(z.Name), ".")
		for dn := range needed {
			if dn == zn || strings.HasSuffix(dn, "."+zn) {
				filtered = append(filtered, z)

				break
			}
		}
	}

	if len(filtered) < len(allZones) {
		debugLog("ZONE", "", fmt.Sprintf(phrases().DNScaleZonesFiltered, len(filtered), len(allZones)))
	}

	return filtered, nil
}

func loadDNScaleInfrastructureRecords(ctx context.Context, dc *DomainConfig, zoneID string) ([]Record, error) {
	var allRecords []Record
	offset := 0
	const pageSize = 100

	for {
		url := fmt.Sprintf("%s/%s/records?limit=%d&offset=%d", dnscaleBaseURL, zoneID, pageSize, offset)
		data, err := dnscaleAPI(ctx, dc, MethodGET, url, nil)
		if err != nil {
			return nil, fmt.Errorf(phrases().DNScaleRecordsLoadFailed, zoneID, err)
		}

		var resp dnscaleRecordsResponse
		if err := json.Unmarshal(data, &resp); err != nil {
			return nil, fmt.Errorf(phrases().DNScaleRecordsParseFailed, zoneID, err)
		}

		allRecords = append(allRecords, resp.Data.Records...)
		if !resp.Data.Pagination.HasMore || len(resp.Data.Records) == 0 {
			break
		}
		offset += len(resp.Data.Records)
	}

	return allRecords, nil
}

// ============================================================================
// DNS LOGIC - DNSCALE
// ============================================================================

func updateDNScaleDNS(
	ctx context.Context,
	dc *DomainConfig,
	fqdn, recordType, newIP string,
	records []Record,
	zoneID string,
	zoneName string,
	cache *ZoneRecordCache,
) (bool, error) {
	recordName := recordNameFromFQDN(fqdn, zoneName)
	existing := findDNScaleExistingRecord(records, fqdn, recordName, recordType)

	if shouldSkipDNScaleUpdate(fqdn, recordType, newIP, existing) {
		return false, nil
	}

	if zoneName == "" {
		return false, fmt.Errorf(phrases().ErrZoneNameEmpty, fqdn)
	}

	if dryRunEnabled() {
		log(LogContext{
			Level:   LogWarn,
			Action:  ActionDryRun,
			Domain:  fqdn,
			Message: fmt.Sprintf("⚠️ %s %s %s", phrases().WouldSet, recordType, newIP),
		})

		return true, nil
	}

	actionType, updatedRecord, err := executeDNScaleDNSUpdate(
		ctx, dc, fqdn, recordName, recordType, newIP, zoneID, existing,
	)
	if err != nil {
		return false, err
	}

	log(LogContext{
		Level:   LogInfo,
		Action:  actionType,
		Domain:  fqdn,
		Message: fmt.Sprintf("🔄 %s -> %s %s", recordType, newIP, phrases().Update),
	})

	updateDNScaleCache(cache, zoneID, recordName, fqdn, recordType, newIP, existing, updatedRecord)

	return true, nil
}

func findDNScaleExistingRecord(records []Record, fqdn, recordName, recordType string) *Record {
	wantedFQDN := normalizeProviderFQDN(fqdn)
	wantedRecordName := normalizeProviderFQDN(recordName)
	wantedType := strings.ToUpper(strings.TrimSpace(recordType))

	for i := range records {
		actualName := normalizeProviderFQDN(records[i].Name)
		actualType := strings.ToUpper(strings.TrimSpace(records[i].Type))

		if (actualName == wantedFQDN || actualName == wantedRecordName) && actualType == wantedType {
			existing := &records[i]
			debugLog("DNS-LOGIC", fqdn, fmt.Sprintf("📌 %s: %s (ID: %s)", phrases().RecordFound, existing.Content, existing.ID))

			return existing
		}
	}

	return nil
}

func shouldSkipDNScaleUpdate(fqdn, recordType, newIP string, existing *Record) bool {
	if existing != nil && dnsRecordContentEqual(recordType, existing.Content, newIP) {
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

func effectiveDNScaleTTL(dc *DomainConfig) int {
	ttl := effectiveTTL(dc)

	if ttl < 300 {
		return 300
	}

	if ttl > 86400 {
		return 86400
	}

	return ttl
}

func executeDNScaleDNSUpdate(
	ctx context.Context,
	dc *DomainConfig,
	fqdn, recordName, recordType, newIP, zoneID string,
	existing *Record,
) (string, *Record, error) {
	ttl := effectiveDNScaleTTL(dc)

	if existing != nil {
		requestURL := fmt.Sprintf(
			"%s/%s/records/by-name/%s/%s",
			dnscaleBaseURL,
			zoneID,
			dnscalePathName(recordName, fqdn, zoneID),
			recordType,
		)

		if isAddressRecord(recordType) {
			requestURL += "?content=" + neturl.QueryEscape(existing.Content)
		}

		debugLog(
			"DNS-LOGIC",
			fqdn,
			fmt.Sprintf("📡 %s: %s %s", phrases().APICall, MethodPUT, requestURL),
		)

		payload := map[string]any{
			"content": newIP,
			"ttl":     ttl,
		}

		data, err := dnscaleAPI(ctx, dc, MethodPUT, requestURL, payload)
		if err != nil {
			return "", nil, handleDNScaleDNSAPIError(
				fqdn,
				recordType,
				newIP,
				err,
			)
		}

		record := parseDNScaleRecordResponse(data, fqdn)
		debugLog(
			"DNS-LOGIC",
			fqdn,
			fmt.Sprintf(
				phrases().DNScaleRecordArrow,
				phrases().Success,
				recordType,
				newIP,
			),
		)

		return ActionUpdate, record, nil
	}

	url := fmt.Sprintf("%s/%s/records", dnscaleBaseURL, zoneID)
	debugLog("DNS-LOGIC", fqdn, fmt.Sprintf("📡 %s: %s %s", phrases().APICall, MethodPOST, url))

	payload := map[string]any{
		"name":    dnscaleRecordName(recordName, fqdn),
		"type":    recordType,
		"content": newIP,
		"ttl":     ttl,
	}

	data, err := dnscaleAPI(ctx, dc, MethodPOST, url, payload)
	if err != nil {
		return "", nil, handleDNScaleDNSAPIError(fqdn, recordType, newIP, err)
	}

	record := parseDNScaleRecordResponse(data, fqdn)
	debugLog("DNS-LOGIC", fqdn, fmt.Sprintf(phrases().DNScaleRecordArrow, phrases().Success, recordType, newIP))

	return ActionCreate, record, nil
}

func dnscaleRecordName(recordName, fqdn string) string {
	name := strings.TrimSpace(recordName)
	if name == "" {
		name = strings.TrimSpace(fqdn)
	}

	return name
}

func dnscalePathName(recordName, fqdn, zoneID string) string {
	_ = zoneID

	return neturl.PathEscape(dnscaleRecordName(recordName, fqdn))
}

func parseDNScaleRecordResponse(data []byte, fqdn string) *Record {
	if len(data) == 0 {
		return nil
	}

	var resp dnscaleRecordResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		debugLog("DNS-LOGIC", fqdn, fmt.Sprintf(phrases().DNScaleSuccessResponseParseFailed, err))

		return nil
	}

	if strings.TrimSpace(resp.Data.Record.ID) != "" {
		return &resp.Data.Record
	}

	return nil
}

func handleDNScaleDNSAPIError(fqdn, recordType, newIP string, err error) error {
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr == nil {
		debugLog("DNS-LOGIC", fqdn, fmt.Sprintf(phrases().UpdateFailedWithError, err))

		return err
	}

	message := fmt.Sprintf(phrases().DNScaleAPIError, recordType, apiErr.StatusCode, apiErr.Message)
	level := LogError
	action := ActionError

	switch apiErr.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		log(LogContext{Level: level, Action: action, Domain: fqdn, Message: message})

		return fmt.Errorf("%s: %w", phrases().ErrAuthFailed, err)
	case http.StatusNotFound:
		action = ActionZone
		log(LogContext{Level: level, Action: action, Domain: fqdn, Message: message})

		return fmt.Errorf("%s: %w", phrases().ErrResourceNotFound, err)
	case http.StatusTooManyRequests:
		level = LogWarn
		action = ActionRetry
		log(LogContext{Level: level, Action: action, Domain: fqdn, Message: message})

		return err
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		message = fmt.Sprintf(phrases().DNScaleAPIErrorWithIP, recordType, apiErr.Message, newIP)
		log(LogContext{Level: level, Action: action, Domain: fqdn, Message: message})

		return fmt.Errorf("%s: %w", phrases().ErrValidationFailed, err)
	default:
		log(LogContext{Level: level, Action: action, Domain: fqdn, Message: message})

		return err
	}
}

// ============================================================================
// CACHE UPDATE - DNSCALE
// ============================================================================

func updateDNScaleCache(
	cache *ZoneRecordCache,
	zoneID, recordName, fqdn, recordType, newIP string,
	existing, updatedRecord *Record,
) {
	if !dnscaleCacheZoneExists(cache, zoneID, fqdn) {
		return
	}

	match := func(rec Record) bool {
		return matchesDNScaleCachedRecord(rec, existing, updatedRecord)
	}
	mutate := func(rec *Record) {
		applyDNScaleCachedRecordUpdate(rec, newIP, updatedRecord)
	}
	create := dnscaleCachedRecordCreateFunc(
		existing,
		updatedRecord,
		recordName,
		recordType,
		newIP,
	)

	if !updateCachedZoneRecord(cache, zoneID, match, mutate, create) {
		return
	}

	logDNScaleCacheUpdate(fqdn, recordType, newIP, existing == nil)
}

func dnscaleCacheZoneExists(cache *ZoneRecordCache, zoneID, fqdn string) bool {
	if cache == nil {
		return false
	}
	if _, exists := cache.Get(zoneID); exists {
		return true
	}

	debugLog("CACHE", fqdn, phrases().DNScaleCacheZoneNotFound)

	return false
}

func matchesDNScaleCachedRecord(
	rec Record,
	existing, updatedRecord *Record,
) bool {
	if existing == nil {
		return updatedRecord != nil && rec.ID == updatedRecord.ID
	}

	return normalizeProviderFQDN(rec.Name) == normalizeProviderFQDN(existing.Name) &&
		strings.EqualFold(rec.Type, existing.Type) &&
		rec.Content == existing.Content
}

func applyDNScaleCachedRecordUpdate(
	rec *Record,
	newIP string,
	updatedRecord *Record,
) {
	rec.Content = newIP
	if updatedRecord == nil {
		return
	}

	if strings.TrimSpace(updatedRecord.ID) != "" {
		rec.ID = updatedRecord.ID
	}
	if strings.TrimSpace(updatedRecord.Name) != "" {
		rec.Name = updatedRecord.Name
	}
}

func dnscaleCachedRecordCreateFunc(
	existing, updatedRecord *Record,
	recordName, recordType, newIP string,
) cachedRecordCreateFunc {
	if existing != nil {
		return nil
	}

	return func(_ []Record) *Record {
		return newDNScaleCachedRecord(updatedRecord, recordName, recordType, newIP)
	}
}

func newDNScaleCachedRecord(
	updatedRecord *Record,
	recordName, recordType, newIP string,
) *Record {
	var record Record
	if updatedRecord != nil {
		record = *updatedRecord
	}
	if strings.TrimSpace(record.Name) == "" {
		record.Name = recordName
	}
	if strings.TrimSpace(record.Type) == "" {
		record.Type = recordType
	}
	record.Content = newIP

	return &record
}

func logDNScaleCacheUpdate(
	fqdn, recordType, newIP string,
	created bool,
) {
	message := phrases().DNScaleCacheUpdated
	if created {
		message = phrases().DNScaleCacheRecordAdded
	}
	debugLog("CACHE", fqdn, fmt.Sprintf(message, recordType, newIP))
}

// ============================================================================
// CLEANUP - DNSCALE
// ============================================================================

func cleanupDNScaleRecords(ctx context.Context, zones []Zone, recordCache *ZoneRecordCache) {
	dnscaleDC := findDNScaleConfigForCleanup()
	if dnscaleDC == nil {
		return
	}

	debugLog("MAINTENANCE", "", phrases().CleanupStartDNScale)
	configRecords := buildDNScaleConfigRecords()
	managedDomains := buildDNScaleManagedDomains()

	for _, zone := range zones {
		cleanupDNScaleZoneRecords(ctx, dnscaleDC, zone, recordCache, configRecords, managedDomains)
	}
}

func buildDNScaleManagedDomains() map[string]struct{} {
	return buildProviderManagedDomains(ProviderDNScale)
}

func findDNScaleConfigForCleanup() *DomainConfig {
	return findProviderConfigForCleanup(ProviderDNScale)
}

func buildDNScaleConfigRecords() map[string]struct{} {
	return buildProviderConfigRecords(ProviderDNScale)
}

func cleanupDNScaleZoneRecords(
	ctx context.Context,
	dc *DomainConfig,
	zone Zone,
	recordCache *ZoneRecordCache,
	configRecords map[string]struct{},
	managedDomains map[string]struct{},
) {
	records, exists := recordCache.Get(zone.ID)
	if !exists {
		return
	}

	zoneName := strings.ToLower(strings.TrimSuffix(zone.Name, "."))

	for _, rec := range records {
		cleanupSingleDNScaleRecord(ctx, dc, zone, zoneName, rec, configRecords, managedDomains)
	}
}

func cleanupSingleDNScaleRecord(
	ctx context.Context,
	dc *DomainConfig,
	zone Zone,
	zoneName string,
	rec Record,
	configRecords map[string]struct{},
	managedDomains map[string]struct{},
) {
	fqdn, shouldDelete := shouldCleanupDNScaleRecord(zoneName, rec, configRecords, managedDomains)
	if !shouldDelete {
		return
	}

	debugLog("MAINTENANCE", fqdn, fmt.Sprintf(phrases().CleanupOrphanedDNScale, rec.Type, rec.ID))

	if dryRunEnabled() {
		log(LogContext{
			Level:   LogInfo,
			Action:  ActionCleanup,
			Domain:  fqdn,
			Message: phrases().CleanupDryRun,
		})

		return
	}

	var url string
	if strings.TrimSpace(rec.ID) != "" {
		url = fmt.Sprintf("%s/%s/records/%s", dnscaleBaseURL, zone.ID, rec.ID)
	} else {
		recName := dnscalePathName(rec.Name, fqdn, zone.ID)
		url = fmt.Sprintf("%s/%s/records/by-name/%s/%s", dnscaleBaseURL, zone.ID, recName, rec.Type)
		if isAddressRecord(rec.Type) && strings.TrimSpace(rec.Content) != "" {
			url += "?content=" + neturl.QueryEscape(rec.Content)
		}
	}

	if _, err := dnscaleAPI(ctx, dc, MethodDELETE, url, nil); err != nil {
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

func shouldCleanupDNScaleRecord(
	zoneName string,
	rec Record,
	configRecords map[string]struct{},
	managedDomains map[string]struct{},
) (string, bool) {
	if !isCleanupEligibleRecordType(rec.Type) {
		return "", false
	}

	fqdn := dnscaleRecordFQDN(zoneName, rec.Name)
	if _, ok := configRecords[managedRecordKey(fqdn, rec.Type)]; ok {
		return "", false
	}
	if _, owned := managedDomains[fqdn]; !owned {
		return "", false
	}

	return fqdn, true
}

func dnscaleRecordFQDN(zoneName, recordName string) string {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(recordName), "."))
	zone := strings.ToLower(strings.TrimSuffix(zoneName, "."))

	var fqdn string
	switch {
	case name == "@":
		fqdn = zone
	case name == zone:
		fqdn = zone
	case strings.HasSuffix(name, "."+zone):
		fqdn = name
	case name == "":
		fqdn = zone
	default:
		fqdn = name + "." + zone
	}

	return strings.ToLower(strings.TrimSuffix(fqdn, "."))
}
