// Package main
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const febasResponseBodyLimit = 64 << 10

func loadFebasZones(ctx context.Context) ([]Zone, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	domainConfigs := snapshotDomainConfigs()
	zones := make([]Zone, 0, len(domainConfigs))
	seen := make(map[string]struct{}, len(domainConfigs))

	for _, dc := range domainConfigs {
		if dc.Provider != ProviderFebas {
			continue
		}

		fqdn := normalizeProviderFQDN(dc.FQDN)
		if fqdn == "" {
			continue
		}
		if _, exists := seen[fqdn]; exists {
			continue
		}

		seen[fqdn] = struct{}{}
		zones = append(zones, Zone{
			ID:   febasZoneID(fqdn),
			Name: fqdn,
		})
	}

	sort.Slice(zones, func(i, j int) bool {
		return len(zones[i].Name) > len(zones[j].Name)
	})

	return zones, nil
}

func febasZoneID(fqdn string) string {
	return "febas:" + normalizeProviderFQDN(fqdn)
}

func loadFebasZoneRecords(ctx context.Context, zone Zone) ([]Record, error) {
	fqdn := normalizeProviderFQDN(zone.Name)
	if fqdn == "" {
		return nil, fmt.Errorf("Febas zone name is empty")
	}

	cfgMu.RLock()
	dnsServers := append([]string(nil), cfg.DNSServers...)
	cfgMu.RUnlock()

	resolverCache := newDNSCacheWithServers(dnsServers, time.Minute)
	addrs, err := resolverCache.getIPAddrs(ctx, fqdn)
	if err != nil {
		debugLog("FEBAS", fqdn, fmt.Sprintf("current DNS lookup failed; update will still be attempted: %v", err))
		return []Record{}, nil
	}

	records := make([]Record, 0, len(addrs))
	seen := make(map[string]struct{}, len(addrs))

	for _, addr := range addrs {
		ip := addr.IP
		if ip == nil {
			continue
		}

		recordType := RecordTypeAAAA
		value := ip.String()
		if v4 := ip.To4(); v4 != nil {
			recordType = RecordTypeA
			value = v4.String()
		}

		key := recordType + "\x00" + value
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}

		records = append(records, Record{
			ID:      "febas-" + strings.ToLower(recordType) + "-" + value,
			Name:    fqdn,
			Type:    recordType,
			Content: value,
		})
	}

	return records, nil
}

func processFebasDomainUpdate(
	ctx context.Context,
	dc *DomainConfig,
	job domainUpdateJob,
	result domainUpdateResult,
	ipMode string,
	cache *ZoneRecordCache,
) domainUpdateResult {
	ipv4 := ""
	ipv6 := ""

	if ipMode != IPModeV6 {
		ipv4 = job.IPv4
	}
	if ipMode != IPModeV4 {
		ipv6 = job.IPv6
	}

	changed, err := updateFebasDNS(
		ctx,
		dc,
		job.Domain,
		ipv4,
		ipv6,
		job.Records,
		job.ZoneID,
		cache,
	)
	if err != nil {
		result.Error = err
		return result
	}

	result.Changed = changed
	return result
}

func updateFebasDNS(
	ctx context.Context,
	dc *DomainConfig,
	fqdn, ipv4, ipv6 string,
	records []Record,
	zoneID string,
	cache *ZoneRecordCache,
) (bool, error) {
	if dc == nil {
		return false, fmt.Errorf("Febas domain configuration is nil")
	}

	needV4 := ipv4 != "" && !febasRecordContains(records, RecordTypeA, ipv4)
	needV6 := ipv6 != "" && !febasRecordContains(records, RecordTypeAAAA, ipv6)
	if !needV4 && !needV6 {
		debugLog("FEBAS", fqdn, "published DNS records are already current")
		return false, nil
	}

	cfgMu.RLock()
	dryRun := cfg.DryRun
	cfgMu.RUnlock()

	if dryRun {
		log(LogContext{
			Level:   LogWarn,
			Action:  ActionDryRun,
			Domain:  fqdn,
			Message: fmt.Sprintf("⚠️ Would call Febas DynDNS (IPv4=%s, IPv6=%s)", ipv4, ipv6),
		})
		return true, nil
	}

	requestURL, err := renderFebasUpdateURL(dc.FebasUpdateURL, fqdn, ipv4, ipv6)
	if err != nil {
		return false, err
	}

	respBody, err := febasAPI(ctx, requestURL)
	if err != nil {
		return false, err
	}

	changed := febasResponseChanged(respBody)

	updateFebasCache(cache, zoneID, fqdn, ipv4, ipv6)

	log(LogContext{
		Level:   LogInfo,
		Action:  ActionUpdate,
		Domain:  fqdn,
		Message: fmt.Sprintf("🔄 Febas DynDNS update requested (IPv4=%s, IPv6=%s)", ipv4, ipv6),
	})

	return changed, nil
}

func febasRecordContains(records []Record, recordType, wantedIP string) bool {
	wanted := net.ParseIP(strings.TrimSpace(wantedIP))
	if wanted == nil {
		return false
	}

	for _, record := range records {
		if !strings.EqualFold(record.Type, recordType) {
			continue
		}

		actual := net.ParseIP(strings.TrimSpace(record.Content))
		if actual != nil && actual.Equal(wanted) {
			return true
		}
	}

	return false
}

func updateFebasCache(
	cache *ZoneRecordCache,
	zoneID, fqdn, ipv4, ipv6 string,
) {
	if cache == nil || zoneID == "" {
		return
	}

	records, _ := cache.Get(zoneID)
	records = setFebasCachedAddress(records, fqdn, RecordTypeA, ipv4)
	records = setFebasCachedAddress(records, fqdn, RecordTypeAAAA, ipv6)
	cache.Set(zoneID, records)
}

func setFebasCachedAddress(
	records []Record,
	fqdn, recordType, value string,
) []Record {
	if strings.TrimSpace(value) == "" {
		return records
	}

	for i := range records {
		if strings.EqualFold(records[i].Type, recordType) &&
			normalizeProviderFQDN(records[i].Name) == normalizeProviderFQDN(fqdn) {
			records[i].Content = value
			return records
		}
	}

	return append(records, Record{
		ID:      "febas-" + strings.ToLower(recordType),
		Name:    normalizeProviderFQDN(fqdn),
		Type:    recordType,
		Content: value,
	})
}

func febasAPI(ctx context.Context, requestURL string) ([]byte, error) {
	return apiWithRetry(ctx, "FEBAS", "Febas API failed after %d attempts", func(attempt, maxRetries int) ([]byte, bool, error) {
		return febasAPIAttempt(ctx, requestURL, attempt, maxRetries)
	})
}

func febasAPIAttempt(
	ctx context.Context,
	requestURL string,
	attempt, maxRetries int,
) ([]byte, bool, error) {
	redactedURL := redactFebasURL(requestURL)
	debugLog("HTTP", "", fmt.Sprintf("Febas attempt %d/%d GET %s", attempt+1, maxRetries, redactedURL))

	req, err := http.NewRequestWithContext(ctx, MethodGET, requestURL, nil)
	if err != nil {
		return nil, false, fmt.Errorf("create Febas request: %w", err)
	}
	req.Header.Set("Accept", "text/plain, application/json;q=0.9, */*;q=0.8")
	req.Header.Set("User-Agent", ManagedComment)

	start := time.Now()
	res, err := febasHTTPClient().Do(req)
	duration := time.Since(start)
	if err != nil {
		retry, handledErr := handleProviderNetworkError(ctx, "FEBAS", MethodNIC, err, duration, attempt, false)
		return nil, retry, handledErr
	}
	defer func() {
		if closeErr := res.Body.Close(); closeErr != nil {
			debugLog("HTTP", "", fmt.Sprintf("Febas response close failed: %v", closeErr))
		}
	}()

	respBody, readErr := io.ReadAll(io.LimitReader(res.Body, febasResponseBodyLimit))
	if readErr != nil {
		retry, handledErr := handleProviderReadError(ctx, "FEBAS", MethodNIC, res.StatusCode, readErr, duration, attempt)
		return nil, retry, handledErr
	}

	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		apiErr := classifyAPIErrorWithHeaders(
			res.StatusCode,
			MethodNIC,
			redactedURL,
			sanitizeFebasText(string(respBody)),
			res.Header,
		)
		retry, handledErr := handleProviderAPIError(
			ctx,
			"FEBAS",
			"Febas maximum attempts reached",
			apiErr,
			MethodNIC,
			res.StatusCode,
			duration,
			attempt,
		)
		return nil, retry, handledErr
	}

	if retryable, responseErr := febasResponseError(respBody); responseErr != nil {
		apiMetrics.RecordError(MethodNIC, res.StatusCode, responseErr, duration)
		lastErrorMsg.Set(sanitizeError(responseErr))

		if retryable && attempt < maxRetries-1 {
			wait := calculateRetryDelay(attempt, true)
			debugLog("HTTP", "", fmt.Sprintf("Febas temporary response; retrying in %v", wait))
			if !sleepOrCancel(ctx, wait) {
				return nil, false, fmt.Errorf("%s: %w", phrases().ErrContextCancelled, ctx.Err())
			}
			return nil, true, responseErr
		}

		return nil, false, responseErr
	}

	apiMetrics.RecordSuccess(MethodNIC, duration)
	lastErrorMsg.Set("")
	debugLog("HTTP", "", fmt.Sprintf("✅ Febas success: %s", sanitizeFebasText(strings.TrimSpace(string(respBody)))))
	return respBody, false, nil
}

func febasHTTPClient() *http.Client {
	base := getHTTPClient()
	client := *base
	baseRedirect := base.CheckRedirect

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		host := strings.ToLower(req.URL.Hostname())
		if host != "febas.de" && host != "www.febas.de" {
			return fmt.Errorf("Febas redirect to untrusted host %q blocked", host)
		}
		if len(via) >= 5 {
			return fmt.Errorf("too many Febas redirects")
		}
		if baseRedirect != nil {
			return baseRedirect(req, via)
		}
		return nil
	}

	return &client
}

func febasResponseError(body []byte) (bool, error) {
	response := strings.ToLower(strings.TrimSpace(string(body)))
	if response == "" {
		return false, nil
	}

	temporaryMarkers := []string{
		"911",
		"dnserr",
		"temporary",
		"temporär",
		"try again",
		"später erneut",
	}
	for _, marker := range temporaryMarkers {
		if strings.Contains(response, marker) {
			return true, fmt.Errorf("Febas temporary error: %s", sanitizeFebasText(strings.TrimSpace(string(body))))
		}
	}

	permanentMarkers := []string{
		"badauth",
		"nohost",
		"notfqdn",
		"abuse",
		"unauthorized",
		"forbidden",
		"invalid token",
		"ungültig",
		"fehler",
		"error",
		"failed",
	}
	for _, marker := range permanentMarkers {
		if strings.Contains(response, marker) {
			return false, fmt.Errorf("Febas rejected update: %s", sanitizeFebasText(strings.TrimSpace(string(body))))
		}
	}

	return false, nil
}

func febasResponseChanged(body []byte) bool {
	response := strings.ToLower(strings.TrimSpace(string(body)))
	if response == "" {
		return true
	}

	noChangeMarkers := []string{
		"nochg",
		"no change",
		"unchanged",
		"unverändert",
		"keine änderung",
	}
	for _, marker := range noChangeMarkers {
		if strings.Contains(response, marker) {
			return false
		}
	}

	return true
}

func renderFebasUpdateURL(rawURL, fqdn, ipv4, ipv6 string) (string, error) {
	rawURL = strings.TrimSpace(rawURL)
	if err := validateFebasUpdateURL(rawURL); err != nil {
		return "", err
	}

	values := map[string]string{
		"domain":   fqdn,
		"hostname": fqdn,
		"ipaddr":   ipv4,
		"ipv4":     ipv4,
		"ip6addr":  ipv6,
		"ipv6":     ipv6,
	}

	rendered := rawURL
	for name, value := range values {
		escaped := url.QueryEscape(value)
		placeholders := []string{
			"<" + name + ">",
			"{" + name + "}",
			"%3C" + name + "%3E",
			"%7B" + name + "%7D",
		}
		for _, placeholder := range placeholders {
			rendered = strings.ReplaceAll(rendered, placeholder, escaped)
		}
	}

	if _, err := url.ParseRequestURI(rendered); err != nil {
		return "", fmt.Errorf("invalid rendered Febas update URL: %w", err)
	}

	return rendered, nil
}

func validateFebasUpdateURL(rawURL string) error {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return fmt.Errorf("Febas update URL is required")
	}

	u, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return fmt.Errorf("invalid Febas update URL: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("Febas update URL must use HTTPS")
	}

	host := strings.ToLower(u.Hostname())
	if host != "febas.de" && host != "www.febas.de" {
		return fmt.Errorf("Febas update URL must point to febas.de")
	}
	if !strings.EqualFold(strings.TrimRight(u.Path, "/"), "/api/dyndns.php") {
		return fmt.Errorf("Febas update URL must use /api/dyndns.php")
	}

	query := u.Query()
	if strings.TrimSpace(query.Get("kundenid")) == "" {
		return fmt.Errorf("Febas update URL is missing kundenid")
	}
	if strings.TrimSpace(query.Get("token")) == "" {
		return fmt.Errorf("Febas update URL is missing token")
	}

	return nil
}

func redactFebasURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "https://www.febas.de/api/dyndns.php?***"
	}

	query := u.Query()
	for key := range query {
		lowerKey := strings.ToLower(key)
		if lowerKey == "kundenid" || strings.Contains(lowerKey, "token") || strings.Contains(lowerKey, "pass") {
			query.Set(key, "***")
		}
	}
	u.RawQuery = query.Encode()
	return u.String()
}

func sanitizeFebasText(value string) string {
	if replacer := getSecretReplacer(); replacer != nil {
		return replacer.Replace(value)
	}
	return value
}
