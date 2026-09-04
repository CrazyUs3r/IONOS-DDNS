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
	allowRetry := method != MethodPOST

	return apiWithRetry(ctx, "IONOS", phrases().IonosAPIFailed, func(attempt, maxRetries int) ([]byte, bool, error) {
		return ionosAPIAttempt(ctx, dc, method, url, body, attempt, maxRetries, allowRetry)
	})
}

func ionosAPIAttempt(
	ctx context.Context,
	dc *DomainConfig,
	method, url string,
	body any,
	attempt, maxRetries int,
	allowRetry bool,
) ([]byte, bool, error) {
	debugLog("HTTP", "", fmt.Sprintf(phrases().IonosAttempt, phrases().Attempt, attempt+1, maxRetries, method, url))

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
		if !allowRetry {
			debugLog("HTTP", "", fmt.Sprintf(phrases().IonosNetworkErrorNoRetry, err, duration))
			apiMetrics.RecordError(method, 0, err, duration)

			return nil, false, fmt.Errorf("%s: %w", phrases().ErrNetworkError, err)
		}

		retry, handledErr := handleProviderNetworkError(ctx, "IONOS", method, err, duration, attempt, maxRetries, false)

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

	return handleIonosResponse(ctx, res, method, url, duration, responseAttempt, maxRetries)
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
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", ManagedComment)

	return req, nil
}

func handleIonosResponse(
	ctx context.Context,
	res *http.Response,
	method, url string,
	duration time.Duration,
	attempt, maxAttempts int,
) ([]byte, bool, error) {
	return handleProviderHTTPResponse(ctx, "IONOS", phrases().IonosMaxAttempts, res, method, url, duration, attempt, maxAttempts)
}

func loadIonosInfrastructureRecords(ctx context.Context, dc *DomainConfig, zoneID string) ([]Record, error) {
	data, err := ionosAPI(ctx, dc, MethodGET, ionosBaseURL+"/"+zoneID, nil)
	if err != nil {
		return nil, fmt.Errorf(phrases().IonosRecordsLoadFailed, zoneID, err)
	}

	var detail struct {
		Records []Record `json:"records"`
	}
	if err := json.Unmarshal(data, &detail); err != nil {
		return nil, fmt.Errorf(phrases().IonosRecordsParseFailed, zoneID, err)
	}

	return detail.Records, nil
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
	if strings.TrimSpace(zoneName) == "" {
		return false, fmt.Errorf(phrases().ErrZoneNameEmpty, fqdn)
	}

	recordName := recordNameFromFQDN(fqdn, zoneName)

	conflictsRemoved, err := removeConflictingIonosRecords(
		ctx,
		dc,
		fqdn,
		recordName,
		recordType,
		zoneID,
		records,
	)
	if err != nil {
		return false, err
	}

	if conflictsRemoved && dryRunEnabled() {
		return true, nil
	}

	if conflictsRemoved {
		liveRecords, err := loadIonosInfrastructureRecords(ctx, dc, zoneID)
		if err != nil {
			return false, fmt.Errorf(
				"%s: %w",
				phrases().IonosReloadAfterTypeChangeFailed,
				err,
			)
		}

		records = liveRecords

		if cache != nil {
			cache.Set(zoneID, liveRecords)
		}
	}

	existing := findIonosExistingRecord(
		records,
		fqdn,
		recordName,
		recordType,
	)

	if existing != nil && isInvalidIonosRecordID(existing.ID) {
		debugLog(
			"CACHE",
			fqdn,
			fmt.Sprintf(
				phrases().IonosInvalidCachedRecordID,
				existing.ID,
			),
		)

		liveRecords, err := loadIonosInfrastructureRecords(
			ctx,
			dc,
			zoneID,
		)
		if err != nil {
			return false, fmt.Errorf(
				phrases().IonosRefreshInvalidCachedRecordFailed,
				err,
			)
		}

		records = liveRecords

		if cache != nil {
			cache.Set(zoneID, liveRecords)
		}

		existing = findIonosExistingRecord(
			records,
			fqdn,
			recordName,
			recordType,
		)
	}

	if shouldSkipIonosUpdate(
		dc,
		fqdn,
		recordType,
		newIP,
		existing,
	) {
		return conflictsRemoved, nil
	}

	if dryRunEnabled() {
		log(LogContext{
			Level:  LogWarn,
			Action: ActionDryRun,
			Domain: fqdn,
			Message: fmt.Sprintf(
				"⚠️ %s %s %s",
				phrases().WouldSet,
				recordType,
				newIP,
			),
		})

		return true, nil
	}

	method, url, actionType, payload := buildIonosUpdateRequest(
		dc,
		fqdn,
		recordType,
		newIP,
		zoneID,
		existing,
	)

	debugIonosUpdateRequest(
		fqdn,
		method,
		url,
		zoneName,
		recordType,
	)

	updatedRecord, err := executeIonosDNSUpdate(
		ctx,
		dc,
		fqdn,
		recordName,
		recordType,
		newIP,
		zoneID,
		method,
		url,
		payload,
		existing,
	)
	if err != nil {
		return false, err
	}

	log(LogContext{
		Level:  LogInfo,
		Action: actionType,
		Domain: fqdn,
		Message: fmt.Sprintf(
			"🔄 %s -> %s %s",
			recordType,
			newIP,
			phrases().Update,
		),
	})

	updateIONOSCache(
		cache,
		zoneID,
		recordName,
		fqdn,
		recordType,
		newIP,
		existing,
		updatedRecord,
	)

	return true, nil
}

func removeConflictingIonosRecords(
	ctx context.Context,
	dc *DomainConfig,
	fqdn, recordName, wantedRecordType, zoneID string,
	records []Record,
) (bool, error) {
	wantedType := strings.ToUpper(strings.TrimSpace(wantedRecordType))
	removed := false

	for i := range records {
		record := records[i]

		if !isConflictingIonosRecord(
			record,
			fqdn,
			recordName,
			wantedType,
		) {
			continue
		}

		removed = true

		if dryRunEnabled() {
			log(LogContext{
				Level:  LogWarn,
				Action: ActionDryRun,
				Domain: fqdn,
				Message: fmt.Sprintf(
					phrases().IonosConflictWouldRemoveFormat,
					record.Type,
					wantedType,
				),
			})

			continue
		}

		if isInvalidIonosRecordID(record.ID) {
			return false, fmt.Errorf(
				"IONOS-%s-Record %s hat keine gültige Record-ID",
				record.Type,
				fqdn,
			)
		}

		url := fmt.Sprintf(
			"%s/%s/records/%s",
			ionosBaseURL,
			zoneID,
			record.ID,
		)

		if _, err := ionosAPI(
			ctx,
			dc,
			MethodDELETE,
			url,
			nil,
		); err != nil {
			return false, fmt.Errorf(
				"inkompatibler IONOS-%s-Record für %s konnte nicht entfernt werden: %w",
				record.Type,
				fqdn,
				err,
			)
		}

		log(LogContext{
			Level:  LogInfo,
			Action: ActionUpdate,
			Domain: fqdn,
			Message: fmt.Sprintf(
				phrases().IonosConflictRemovedFormat,
				record.Type,
				wantedType,
			),
		})
	}

	return removed, nil
}

func isConflictingIonosRecord(
	record Record,
	fqdn, recordName, wantedRecordType string,
) bool {
	actualName := normalizeProviderFQDN(record.Name)
	wantedFQDN := normalizeProviderFQDN(fqdn)
	wantedName := normalizeProviderFQDN(recordName)

	if actualName != wantedFQDN && actualName != wantedName {
		return false
	}

	actualType := strings.ToUpper(strings.TrimSpace(record.Type))

	switch wantedRecordType {
	case "CNAME":
		return actualType == "A" || actualType == "AAAA"

	case "A", "AAAA":
		return actualType == "CNAME"

	default:
		return false
	}
}

func isInvalidIonosRecordID(id string) bool {
	id = strings.ToLower(strings.TrimSpace(id))

	return id == "" || strings.HasPrefix(id, "new-")
}

func findIonosExistingRecord(records []Record, fqdn, recordName, recordType string) *Record {
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

func shouldSkipIonosUpdate(dc *DomainConfig, fqdn, recordType, newIP string, existing *Record) bool {
	if existing != nil {
		contentCurrent := dnsRecordContentEqual(
			recordType,
			existing.Content,
			newIP,
		)

		ttlCurrent := existing.TTL == effectiveIonosTTL(dc)

		if contentCurrent && ttlCurrent {
			debugLog("DNS-LOGIC", fqdn, fmt.Sprintf("✅ %s: %s = %s, TTL = %d", phrases().RecordCurrent, recordType, newIP, existing.TTL))
			log(LogContext{
				Level:   LogInfo,
				Action:  ActionCurrent,
				Domain:  fqdn,
				Message: fmt.Sprintf("%-4s %s TTL=%d %s", recordType, newIP, existing.TTL, phrases().Current),
			})

			return true
		}
	}

	if existing == nil {
		debugLog("DNS-LOGIC", fqdn, fmt.Sprintf("🆕 %s: %s", phrases().NoRecordFound, recordType))
	} else {
		debugLog("DNS-LOGIC", fqdn, fmt.Sprintf("🔄 %s: %s TTL=%d -> %s TTL=%d", phrases().RecordUpdateNeeded, existing.Content, existing.TTL, newIP, effectiveIonosTTL(dc)))
	}

	return false
}

func effectiveIonosTTL(dc *DomainConfig) int {
	ttl := effectiveTTL(dc)
	if ttl < 60 {
		return 60
	}

	return ttl
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
				"ttl":     effectiveIonosTTL(dc),
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
				TTL:     effectiveIonosTTL(dc),
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
	fqdn, recordName, recordType, newIP, zoneID, method, url string,
	payload any,
	existing *Record,
) (*Record, error) {
	data, err := ionosAPI(ctx, dc, method, url, payload)
	if err != nil {
		return handleIonosUpdateError(
			ctx,
			dc,
			fqdn,
			recordName,
			recordType,
			newIP,
			zoneID,
			method,
			err,
		)
	}

	updatedRecord, parseErr := parseIonosUpdatedRecord(
		data,
		fqdn,
		recordName,
		recordType,
		newIP,
	)
	if parseErr != nil {
		debugLog("DNS-LOGIC", fqdn, fmt.Sprintf(phrases().IonosSuccessResponseParseFailed, parseErr))
	}

	updatedRecord, err = ensureIonosCreatedRecord(
		ctx,
		dc,
		fqdn,
		recordName,
		recordType,
		newIP,
		zoneID,
		method,
		updatedRecord,
	)
	if err != nil {
		return nil, err
	}

	updatedRecord = fallbackIonosPutRecord(
		method,
		updatedRecord,
		existing,
		fqdn,
		recordType,
		newIP,
	)

	debugLog("DNS-LOGIC", fqdn, fmt.Sprintf(phrases().IonosRecordArrow, phrases().Success, recordType, newIP))

	return updatedRecord, nil
}

func handleIonosUpdateError(
	ctx context.Context,
	dc *DomainConfig,
	fqdn, recordName, recordType, newIP, zoneID, method string,
	updateErr error,
) (*Record, error) {
	if method == MethodPOST && shouldReconcileIonosCreateError(updateErr) {
		record, reconcileErr := reconcileIonosCreatedRecord(
			ctx,
			dc,
			zoneID,
			fqdn,
			recordName,
			recordType,
			newIP,
		)

		if reconcileErr == nil && hasUsableIonosRecordID(record) {
			debugLog("DNS-LOGIC", fqdn, phrases().IonosCreateReconciled)

			return record, nil
		}

		if reconcileErr != nil {
			debugLog("DNS-LOGIC", fqdn, fmt.Sprintf(phrases().IonosCreateReconciliationFailed, reconcileErr))
		}
	}

	var apiErr *APIError
	if errors.As(updateErr, &apiErr) && apiErr != nil {
		return nil, handleIonosDNSAPIError(
			fqdn,
			recordType,
			newIP,
			apiErr,
			updateErr,
		)
	}

	debugLog("DNS-LOGIC", fqdn, fmt.Sprintf(phrases().UpdateFailedWithError, updateErr))

	return nil, updateErr
}

func ensureIonosCreatedRecord(
	ctx context.Context,
	dc *DomainConfig,
	fqdn, recordName, recordType, newIP, zoneID, method string,
	record *Record,
) (*Record, error) {
	if method != MethodPOST || hasUsableIonosRecordID(record) {
		return record, nil
	}

	record, err := reconcileIonosCreatedRecord(
		ctx,
		dc,
		zoneID,
		fqdn,
		recordName,
		recordType,
		newIP,
	)
	if err != nil {
		return nil, fmt.Errorf(
			phrases().IonosCreatedRecordIDLoadFailed,
			err,
		)
	}

	if !hasUsableIonosRecordID(record) {
		return nil, errors.New(
			phrases().IonosCreatedRecordIDMissing,
		)
	}

	return record, nil
}

func fallbackIonosPutRecord(
	method string,
	updatedRecord, existing *Record,
	fqdn, recordType, newIP string,
) *Record {
	if method != MethodPUT || updatedRecord != nil || existing == nil {
		return updatedRecord
	}

	record := *existing
	record.Name = fqdn
	record.Type = recordType
	record.Content = newIP

	return &record
}

func hasUsableIonosRecordID(record *Record) bool {
	return record != nil && strings.TrimSpace(record.ID) != ""
}

func parseIonosUpdatedRecord(
	data []byte,
	fqdn, recordName, recordType, newIP string,
) (*Record, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var records []Record
	if err := json.Unmarshal(data, &records); err == nil {
		if record := findMatchingIonosRecord(records, fqdn, recordName, recordType, newIP); record != nil {
			return record, nil
		}
		if len(records) == 1 && strings.TrimSpace(records[0].ID) != "" {
			return &records[0], nil
		}
	}

	var response struct {
		Records []Record `json:"records"`
	}
	if err := json.Unmarshal(data, &response); err == nil {
		if record := findMatchingIonosRecord(response.Records, fqdn, recordName, recordType, newIP); record != nil {
			return record, nil
		}
		if len(response.Records) == 1 && strings.TrimSpace(response.Records[0].ID) != "" {
			return &response.Records[0], nil
		}
	}

	var record Record
	if err := json.Unmarshal(data, &record); err == nil && strings.TrimSpace(record.ID) != "" {
		return &record, nil
	}

	return nil, fmt.Errorf(phrases().IonosUnexpectedResponseBody, strings.TrimSpace(string(data)))
}

func shouldReconcileIonosCreateError(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr != nil {
		return apiErr.IsRetryable() || apiErr.StatusCode == http.StatusConflict
	}

	return true
}

func reconcileIonosCreatedRecord(
	ctx context.Context,
	dc *DomainConfig,
	zoneID, fqdn, recordName, recordType, newIP string,
) (*Record, error) {
	records, err := loadIonosInfrastructureRecords(ctx, dc, zoneID)
	if err != nil {
		return nil, err
	}

	return findMatchingIonosRecord(records, fqdn, recordName, recordType, newIP), nil
}

func findMatchingIonosRecord(
	records []Record,
	fqdn, recordName, recordType, content string,
) *Record {
	wantedFQDN := normalizeProviderFQDN(fqdn)
	wantedRecordName := normalizeProviderFQDN(recordName)
	wantedType := strings.ToUpper(strings.TrimSpace(recordType))

	for i := range records {
		actualName := normalizeProviderFQDN(records[i].Name)
		actualType := strings.ToUpper(strings.TrimSpace(records[i].Type))

		if (actualName == wantedFQDN || actualName == wantedRecordName) &&
			actualType == wantedType &&
			dnsRecordContentEqual(recordType, records[i].Content, content) {
			return &records[i]
		}
	}

	return nil
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
	message := fmt.Sprintf(phrases().IonosAPIError, recordType, apiErr.StatusCode, apiErr.Message)

	switch apiErr.StatusCode {
	case http.StatusNotFound:
		action = ActionZone
	case http.StatusTooManyRequests:
		level = LogWarn
		action = ActionRetry
	case http.StatusUnprocessableEntity:
		message = fmt.Sprintf(phrases().IonosAPIErrorWithIP, recordType, apiErr.Message, newIP)
	}

	log(LogContext{
		Level:   level,
		Action:  action,
		Domain:  fqdn,
		Message: message,
	})
}

func loadIONOSZones(ctx context.Context, dc *DomainConfig) ([]Zone, error) {
	domainConfigs := snapshotDomainConfigs()

	data, err := ionosAPI(ctx, dc, MethodGET, ionosBaseURL, nil)
	if err != nil {
		return nil, fmt.Errorf(phrases().IonosZonesLoadFailed, err)
	}
	if len(data) == 0 {
		return nil, errors.New(phrases().IonosEmptyAPIResponse)
	}

	var zones []Zone
	if err := json.Unmarshal(data, &zones); err != nil {
		return nil, fmt.Errorf(phrases().IonosZonesParseFailed, err)
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
		debugLog("ZONE", "", fmt.Sprintf(phrases().IonosZonesFiltered, len(filtered), len(zones)))
	}

	return filtered, nil
}

// ============================================================================
// CACHE UPDATE - IONOS
// ============================================================================

func updateIONOSCache(
	cache *ZoneRecordCache,
	zoneID, recordName, fqdn, recordType, newIP string,
	existing, updatedRecord *Record,
) {
	if cache == nil {
		return
	}

	if _, exists := cache.Get(zoneID); !exists {
		debugLog("CACHE", fqdn, phrases().IonosCacheZoneNotFound)

		return
	}

	var create cachedRecordCreateFunc
	if existing == nil {
		if updatedRecord == nil || strings.TrimSpace(updatedRecord.ID) == "" {
			debugLog("CACHE", fqdn, phrases().IonosCacheMissingRealRecordID)

			return
		}

		create = func(_ []Record) *Record {
			record := *updatedRecord
			if strings.TrimSpace(record.Name) == "" {
				record.Name = recordName
			}
			if strings.TrimSpace(record.Type) == "" {
				record.Type = recordType
			}
			record.Content = newIP

			return &record
		}
	}

	updated := updateCachedZoneRecord(
		cache,
		zoneID,
		func(rec Record) bool {
			if existing != nil {
				return rec.ID == existing.ID
			}

			return updatedRecord != nil && rec.ID == updatedRecord.ID
		},
		func(rec *Record) {
			rec.Content = newIP
			if updatedRecord != nil {
				if strings.TrimSpace(updatedRecord.Name) != "" {
					rec.Name = updatedRecord.Name
				}
				if strings.TrimSpace(updatedRecord.Type) != "" {
					rec.Type = updatedRecord.Type
				}
			}
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
	configRecords := buildIONOSConfigRecords()
	managedDomains := buildProviderManagedDomains(ProviderIONOS)

	for _, zone := range zones {
		cleanupIONOSZoneRecords(ctx, ionosDC, zone, recordCache, configRecords, managedDomains)
	}
}

func findIONOSConfigForCleanup() *DomainConfig {
	return findProviderConfigForCleanup(ProviderIONOS)
}

func buildIONOSConfigRecords() map[string]struct{} {
	return buildProviderConfigRecords(ProviderIONOS)
}

func cleanupIONOSZoneRecords(
	ctx context.Context,
	ionosDC *DomainConfig,
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
		cleanupSingleIONOSRecord(ctx, ionosDC, zone, zoneName, rec, configRecords, managedDomains)
	}
}

func cleanupSingleIONOSRecord(
	ctx context.Context,
	ionosDC *DomainConfig,
	zone Zone,
	zoneName string,
	rec Record,
	configRecords map[string]struct{},
	managedDomains map[string]struct{},
) {
	fqdn, shouldDelete := shouldCleanupIONOSRecord(zoneName, rec, configRecords, managedDomains)
	if !shouldDelete {
		return
	}

	if isInvalidIonosRecordID(rec.ID) {
		debugLog("MAINTENANCE", fqdn, fmt.Sprintf(phrases().IonosCleanupInvalidCachedRecordID, rec.ID))

		return
	}

	debugLog("MAINTENANCE", fqdn, fmt.Sprintf(phrases().CleanupOrphanedIonos, rec.Type, rec.ID))

	if dryRunEnabled() {
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
	configRecords map[string]struct{},
	managedDomains map[string]struct{},
) (string, bool) {
	if !isCleanupEligibleRecordType(rec.Type) {
		return "", false
	}

	fqdn := ionosRecordFQDN(zoneName, rec.Name)
	if _, ok := configRecords[managedRecordKey(fqdn, rec.Type)]; ok {
		return "", false
	}

	if _, owned := managedDomains[fqdn]; !owned {
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
