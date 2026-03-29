// Package main
package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"unicode"
)

//go:embed lang/*.json
var embeddedLang embed.FS

// ============================================================================
// LANGUAGE
// ============================================================================
func loadLanguage(lang string) error {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("[ERROR] %s: %v\n", T.PanicLoadingLanguage, r)
		}
	}()

	langFile := filepath.Join(langDir, lang+".json")
	fmt.Printf("[INFO] %s %s\n", T.TryingLoadLanguage, langFile)

	data, err := os.ReadFile(langFile)
	if err != nil {
		embedName := "lang/" + lang + ".json"
		if embedded, embedErr := embeddedLang.ReadFile(embedName); embedErr == nil {
			fmt.Printf("[INFO] %s (embedded)\n", T.TryingLoadLanguage)
			data = embedded
		} else {
			fmt.Printf("[WARN] %s %v\n", T.LanguageFileNotFound, err)
			if lang != "en" {
				fmt.Printf("[INFO] %s\n", T.TryingFallbackEn)
				return loadLanguage("en")
			}
			fmt.Printf("[WARN] %s\n", T.UsingBuiltinDefaults)
			setDefaultPhrases()
			return nil
		}
	}

	var translations map[string]string
	if err := json.Unmarshal(data, &translations); err != nil {
		fmt.Printf("[ERROR] %s: %v\n", T.JSONParseError, err)

		if lang != "en" {
			return loadLanguage("en")
		}
		setDefaultPhrases()
		return nil
	}

	fmt.Printf("[INFO] ✓ "+T.LanguageLoaded+"\n", lang, len(translations))

	requiredKeys := []string{"startup", "shutdown", "no_zones", "update", "requests", "success_rate", "avg_latency"}
	for _, key := range requiredKeys {
		if _, ok := translations[key]; !ok {
			fmt.Printf("[WARN] %s: %s\n", T.MissingTranslationKey, key)
		}
	}

	v := reflect.ValueOf(&T).Elem()
	typ := v.Type()

	for i := 0; i < v.NumField(); i++ {
		field := typ.Field(i)
		jsonKey := toSnakeCase(field.Name)

		if val, ok := translations[jsonKey]; ok {
			v.Field(i).SetString(val)
		}
	}

	return nil
}

var knownAcronyms = []string{
	"IPv4", "IPv6", "HTTP", "JSON", "API", "DNS", "IP", "CF"}

var snakeCaseOverrides = map[string]string{
	"HealthCheckOK":      "health_check_ok",
	"LanguageFileNotFound": "language_file_not_found",
	"BasedOnLast60Min":   "based_on_last_60_min",
	"CleanupStartIonos":  "cleanup_start_ionos",
	"CleanupStartCF":     "cleanup_start_c_f",
	"CleanupStartIPv64":  "cleanup_start_i_pv64",
	"IPv64APIError":      "ipv64_a_p_i_error",
	"IPv64HTTPError":     "ipv64_h_t_t_p_error",
	"IPv64CacheAPIError": "ipv64_cache_a_p_i_error",
	"IonosRetryable":     "ionos_retryable",
	"IonosErrDetail":     "ionos_err_detail",
}

func toSnakeCase(s string) string {
	if key, ok := snakeCaseOverrides[s]; ok {
		return key
	}

	for _, acr := range knownAcronyms {
		replacement := string(unicode.ToUpper([]rune(acr)[0])) +
			strings.ToLower(acr[1:])
		s = strings.ReplaceAll(s, acr, replacement)
	}

	var result []rune
	for i, r := range s {
		if i > 0 && unicode.IsUpper(r) {
			result = append(result, '_')
		}
		result = append(result, unicode.ToLower(r))
	}
	return string(result)
}

func setDefaultPhrases() {
	T = Phrases{
		Startup:                  "Starting DynDNS Service",
		Shutdown:                 "Shutting down",
		NoZones:                  "No zones found",
		Update:                   "Updated",
		Created:                  "Created",
		Current:                  "Current",
		DryRunWarn:               "DRY RUN MODE - No changes will be made",
		ConfigError:              "Configuration error",
		DashTitle:                "DynDNS Dashboard",
		StatusOk:                 "System Healthy",
		StatusErr:                "System Error",
		LastUpdate:               "Last Update",
		InfraHeading:             "Infrastructure Overview",
		ZoneLabel:                "Zone",
		ServiceStarted:           "Service Started",
		ServiceStopped:           "Service Stopped",
		DashboardStarted:         "Dashboard started on Port %v",
		ServerError:              "Server error",
		HealthCheckOK:            "Health check OK",
		HealthCheckFailed:        "Health check failed",
		SystemEvents:             "System Events",
		History:                  "History",
		EventLog:                 "Event Log",
		DomainStatus:             "Domain Status",
		Provider:                 "Provider",
		LastChanged:              "Last Changed",
		IPv4Label:                "IPv4",
		IPv6Label:                "IPv6",
		Requests:                 "Requests",
		SuccessRate:              "Success Rate",
		LastSuccess:              "Last Success",
		AvgLatency:               "Avg Latency",
		Errors:                   "Errors",
		HourlyLimit:              "Hourly Limit",
		RequestHistory:           "Request History (Last 24h)",
		LatencyHistory:           "Latency History (Last 24h)",
		APIPerformance:           "API Performance",
		BasedOnLast60Min:         "Based on last 60 minutes",
		UnhealthyStatus:          "Unhealthy",
		DetailedStats:            "Detailed Statistics",
		TotalRequests:            "Total Requests",
		ClientErrors:             "Client Errors",
		ServerErrors:             "Server Errors",
		NoDomains:                "No domains configured",
		InvalidDomain:            "Invalid domain",
		NoZoneFound:              "No zone found",
		NoValidDomains:           "No valid domains",
		RootDomain:               "Root Domain",
		CouldNotExtractDomain:    "Could not extract domain",
		LogRotated:               "Log file rotated",
		LogRotationError:         "Log rotation error",
		RecordFound:              "Record found",
		RecordCurrent:            "Record current",
		NoRecordFound:            "No record found",
		RecordUpdateNeeded:       "Record update needed",
		WouldSet:                 "Would set",
		APICall:                  "API call",
		PayloadSent:              "Payload sent",
		ReceivedIP:               "Received IP",
		CheckingInterface:        "Checking interface",
		InterfaceNotFound:        "Interface not found",
		AddressesNotReadable:     "Addresses not readable",
		NoIPv6OnInterface:        "No IPv6 on interface",
		FallbackToExternal:       "Fallback to external",
		Attempt:                  "Attempt",
		NetworkError:             "Network error",
		RetryIn:                  "Retry in",
		Success:                  "Success",
		BodyReadError:            "Body read error",
		NonRetryableError:        "Non-retryable error",
		MaxAttemptsReached:       "Max attempts reached",
		RetryScheduled:           "Retry scheduled",
		ContextCancelled:         "Context cancelled",
		WorkerSlotAcquired:       "Worker slot acquired",
		WorkerProcessingComplete: "Worker processing complete",
		WorkerSlotReleased:       "Worker slot released",
		ContextExpired:           "Context expired",
		NoZoneFoundForDomain:     "No zone found for domain",
		NoRecordsInCache:         "No records in cache",
		CheckingIPv4:             "Checking IPv4",
		CheckingIPv6:             "Checking IPv6",
		UpdateFailed:             "Update failed",
		CriticalError:            "Critical error",
		ChangesDetected:          "Changes detected",
		WritingStatusFile:        "Writing status file",
		NoChangesNeeded:          "No changes needed",
		SchedulerStarted:         "Scheduler started (firstRun=%v)",
		SchedulerCompleted:       "Scheduler completed (%d updates)",
		ConfigHeading:            "Configuration",
		ConfigAPIPrefix:          "API Prefix",
		ConfigDomains:            "Domains",
		ConfigInterval:           "Interval",
		ConfigIPMode:             "IP Mode",
		ConfigInterface:          "Interface",
		ConfigHealthPort:         "Health Port",
		ConfigDryRun:             "Dry Run",
		ConfigLogDir:             "Log Directory",
		ConfigLanguage:           "Language",
		BadRequest:               "Bad Request",
		Unauthorized:             "Unauthorized",
		Forbidden:                "Forbidden",
		NotFound:                 "Not Found",
		UnprocessableEntity:      "Unprocessable Entity",
		RateLimitExceeded:        "Rate Limit Exceeded",
		InternalServerError:      "Internal Server Error",
		BadGateway:               "Bad Gateway",
		ServiceUnavailable:       "Service Unavailable",
		GatewayTimeout:           "Gateway Timeout",
		MaintenanceStarting:      "Starting maintenance",
		HTTPConnectionsClosed:    "HTTP connections closed",
		ServerShuttingDown:       "Server shutting down",
		ServerShutdownComplete:   "Server shutdown complete",
		ShutdownError:            "Shutdown error",
		Mode:                     "Mode",
		NoDNSServer:              "No DNS server",
		DNSFailover:              "DNS failover",
		HTTPClientInitialized:    "HTTP client initialized with %d DNS servers",
		InvalidPort:              "Invalid port: %s",
		UsingDefaultPort:         "Using default port",
		IntervalTooSmall:         "Interval too small",
		ShortIntervalWarning:     "Short interval warning with many domains",
		InvalidIPMode:            "Invalid IP mode: %s",
		UsingDefaultMode:         "Using default mode",
		CriticalAPIError:         "CRITICAL API ERROR",
		PanicLoadingLanguage:     "Panic while loading language: %v",
		TryingLoadLanguage:       "Trying to load language file:",
		LanguageFileNotFound:     "Language file not found:",
		TryingFallbackEn:         "Trying fallback to EN...",
		UsingBuiltinDefaults:     "Using built-in default translations",
		JSONParseError:           "Error parsing JSON: %v",
		LanguageLoaded:           "Language file loaded: %s (%d translations)",
		MissingTranslationKey:    "Missing translation key: %s",
		HTTPPool:                 "HTTP Pool expanded:",
		HourlyLimitEst:           "HOURLY LIMIT (EST.)",
		RequestsLabel:            "Requests",
		UsageLast60Min:           "Based on requests from the last 60 minutes",
		MaxLogLines:              "Log Max Lines",
		MaxAPIRetries:            "API Max Retries",
		MaxConcurrent:            "Max Concurrent",
		Interval:                 "Interval",
		DeleteDomainCheck:        "Really remove from status? The domain is no longer in the configuration.",
		DeleteButton:             "🗑️ Remove",
		DeleteSuccess:            "removed",
		DeleteError:              "Error while deleting",
		ConnectionError:          "Connection error",
		DomainSearchPlaceholder:  "🔍 Search domain...",
		NoMoreEntries:            "No more entries",
		NotConfigured:            "no longer configured",
		RecentlyChanged:          "🔄 just changed",
		LastUpdateShort:          "Last:",
		LatencyPercentile:        "Latency Percentile",
		IPCheckLatency:           "IP-Check Latency",
		ChecksLabel:              "Checks",
		LastLabel:                "Last:",
		TimeLabel:                "Time",
		IPAddresses:              "IP Addresses",
		MetricsResetConfirm:      "Really delete all metrics (statistics)?",
		MetricsResetSuccess:      "Metrics reset",
		MetricsResetFailed:       "Reset failed",
		UpdateStarting:           "Starting update...",
		RateLimitGlobal:          "Rate limit reached - please wait",
		RateLimitIP:              "Too many requests - please wait",
		UpdateInProgress:         "Update already in progress",
		InvalidToken:             "Invalid or missing token",
		UpdateStarted:            "Update started",
		RemainingLabel:           "Remaining",
		NoIPToCopy:               "No IP to copy",
		Copied:                   "Copied",
		CopyFailed:               "Copy failed",
		ExportStarted:            "Export started",
		ExportFailed:             "Export failed",
		EntriesLabel:             "entries",
		DotNoUpdate:              "No update seen yet",
		DotJustChanged:           "Just changed: ",
		DotLastChanged:           "Last changed: ",
		DotActive:                "Active · Last changed: ",
		DotOtherUpdated:          "· Another domain has been updated since",
		BadgeChanged:             "🔄 just changed",
		MetricsBroadcast:         "📊 Metrics have been reset",
		FilterAll:                "All",
		FilterErrors:             "Errors",
		FilterWarnings:           "Warnings",
		FilterUpdates:            "Updates",
		FilterStarts:             "Starts",
		FilterStop:               "Stop",
		FilterCreated:            "Created",
		FilterCleanup:            "Cleanup",
		FilterSkip:               "Skip",
		DailyLabel:               "Daily",
		AvgFromLabel:             "Ø from",
		LastCheckLabel:           "Last:",
		NoDomainsConfigured:      "No domains configured.",
		DomainContext:            "Domain %d (%s): %s",
		IonosAPIRequired:         "Domain %s (IONOS): API_PREFIX and API_SECRET required.",
		Ipv64TokenRequired:       "Domain %s (IPv64): IPv64Token required.",
		CloudflareAuthRequired:   "Domain %s (Cloudflare): CFToken or CFEmail+CFSecret required.",
		UnknownProvider:          "Domain %s: Unknown provider %s",
		ConfigErrorPrefix:        "Config error: %s",
		DomainIsEmpty:            "Domain is empty.",
		DomainTooLong:            "Domain is too long: %d characters (max 253).",
		InvalidDomainFormat:      "Invalid domain format: %s",
		LabelTooLong:             "Label '%s' is too long: %d characters (max 63).",
		InvalidLabel:             "Invalid label: %s",

		// Cache & persistence
		ErrRecordCacheNil:  "record cache is nil",
		ErrCacheDirCreate:  "failed to create cache directory",
		ErrCacheMarshal:    "failed to marshal cache",
		ErrCacheWrite:      "failed to write cache",
		ErrCacheRename:     "failed to rename cache",
		CacheSavedZones:    "💾 %s cache saved (%d zones, %d records)",
		CacheSavedDomains:  "💾 %s cache saved (%d domains)",
		CacheFileNotFound:  "ℹ️ No %s cache file found (first start)",
		CacheLoadedZones:   "📂 %s cache loaded from disk (%d zones, age: %v)",
		CacheLoadedDomains: "📂 %s cache loaded from disk (%d domains)",

		// Generic API errors
		ErrContextError:     "context error",
		ErrJSONMarshal:      "json marshal failed",
		ErrRequestCreate:    "request creation failed",
		ErrNetworkError:     "network error",
		ErrBodyClose:        "failed to close response body",
		ErrBodyRead:         "failed to read response",
		ErrRateLimit:        "rate limit exceeded (429)",
		ErrAuthFailed:       "authorization failed",
		ErrResourceNotFound: "resource not found",
		ErrValidationFailed: "validation failed",
		ErrZoneNotInCache:   "zone not found in cache",
		ErrZoneNameEmpty:    "zone name is empty for domain %s",
		ErrAPIGeneric:       "API error %d",
		ErrContextCancelled: "context cancelled: %w",

		// Maintenance / Cleanup
		CleanupStartIonos:    "🧹 starting cleanup of orphaned DNS records...",
		CleanupStartCF:       "🧹 starting cleanup of orphaned Cloudflare DNS records...",
		CleanupStartIPv64:    "🧹 starting cleanup of orphaned IPv64 records...",
		CleanupDryRun:        "⚠️ Dry-Run: record would have been deleted",
		CleanupDeleteError:   "❌ error while deleting: %v",
		CleanupRecordRemoved: "✅ %s record removed (no longer configured)",

		// IONOS specific
		IonosAPIFailed:         "API failed after %d attempts",
		IonosMaxAttempts:       "maximum attempts reached",
		IonosCacheZoneNotFound: "⚠️ zone not found in cache",
		IonosCacheUpdated:      "✅ cache updated: %s -> %s",
		IonosCacheRecordAdded:  "✅ cache: new %s record added: %s",

		// Cloudflare specific
		CFNoCredentials:     "no Cloudflare credentials configured",
		CFTokenEmpty:        "CFToken is set but empty after sanitizing",
		CFHTMLResponse:      "Cloudflare API returned HTML (status %d): %s",
		CFInvalidJSON:       "invalid JSON response from Cloudflare API",
		CFApiFailed:         "Cloudflare API failed after %d attempts",
		CFZoneLoadError:     "failed to load Cloudflare zones",
		CFZoneParseError:    "failed to parse Cloudflare zones",
		CFRecordsParseError: "failed to parse DNS records",

		// IPv64 specific
		IPv64BaseDomainNotFound: "IPv64 base domain not found: %s",
		IPv64CDNIgnoredV4:       "ℹ️ CDN records ignored for A comparison: %v",
		IPv64CDNIgnoredV6:       "ℹ️ CDN records ignored for AAAA comparison: %v",
		IPv64UpdateURL:          "📡 IPv64 update: %s",
		IPv64HTMLResponse:       "IPv64 API returned HTML instead of JSON: %s",
		IPv64ParseError:         "failed to parse IPv64 response",
		IPv64APIError:           "IPv64 API error: %s",
		IPv64ApiFailed:          "IPv64 API failed after %d attempts",
		IPv64HTTPError:          "IPv64 HTTP %d: %s",
		IPv64UpdateFailed:       "IPv64 update failed: %s",
		IPv64RateLimitHeader:    "⌛ rate limit: waiting %ds (Retry-After header)",
		IPv64RateLimitBackoff:   "⌛ rate limit: waiting %s (exponential backoff)",
		IPv64RetriableWait:      "⏳ retriable error, waiting %s...",
		IPv64CacheBuilt:         "✅ IPv64 zones built from provider cache (%d domains, no API call)",
		IPv64CacheUsed:          "✅ using IPv64 cache (age: %s)",
		IPv64CacheLoadDisk:      "⚠️ no IPv64 cache in RAM - trying to load from disk",
		IPv64CacheLoadedDisk:    "✅ IPv64 cache loaded from disk (no API call needed)",
		IPv64CacheAPIError:      "⚠️ IPv64 API error, keeping old cache: %v",
		IPv64CacheDiskError:     "⚠️ could not load cache from disk either: %v",
		IPv64CacheFallback:      "✅ fallback to persisted cache successful",
		IPv64ParseHTMLCache:     "⚠️ IPv64 parse error (likely HTML instead of JSON), keeping old cache: %v",
		IPv64CacheSaveError:     "⚠️ could not save cache: %v",

		// Health
		HealthStarting:         "waiting for first scheduler run",
		HealthLastRunFailed:    "last scheduler run failed (IP fetch, zone load or record update error)",
		IPv64CachedDomain:      "✅ cached IPv64 domain (%d records, hash %s***)",
		CleanupSkipForeignBase: "⏭️ not our base domain - skipped",
		CleanupSkipCDN:         "⏭️ CDN/Failover record skipped (ID: %d, TTL: %d, policy: %s)",
		CleanupSkipDeactivated: "⏭️ deactivated record skipped (ID: %d)",
		CleanupSkipOrphaned:    "🗑️ removing orphaned %s record (ID: %d) - no longer configured",
		CleanupDryRunID:        "⚠️ Dry-Run: %s record ID %d would have been deleted",
	}
}

func copyEmbeddedLangFiles(dir string) {
	entries, err := embeddedLang.ReadDir("lang")
	if err != nil {
		fmt.Println("[ERROR] cannot read embedded lang dir:", err)
		return
	}

	for _, e := range entries {
		name := e.Name()
		dst := filepath.Join(dir, name)

		if _, err := os.Stat(dst); err == nil {
			continue
		}

		data, err := embeddedLang.ReadFile("lang/" + name)
		if err != nil {
			fmt.Printf("[WARN] Embedded file unreadable: %s: %v\n", name, err)
			continue
		}

		if err := os.WriteFile(dst, data, 0644); err != nil {
			fmt.Printf("[WARN] write failed: %s: %v\n", dst, err)
		} else {
			fmt.Printf("[INFO] copied: %s\n", dst)
		}
	}
}