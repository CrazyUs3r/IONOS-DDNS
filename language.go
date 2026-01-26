package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"unicode"
)

// ============================================================================
// LANGUAGE
// ============================================================================

func loadLanguage(lang string) error {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("[ERROR] Panic beim Laden der Sprache: %v\n", r)
		}
	}()

	langFile := filepath.Join(langDir, lang+".json")
	fmt.Printf("[INFO] Versuche Sprachdatei zu laden: %s\n", langFile)

	data, err := os.ReadFile(langFile)
	if err != nil {
		fmt.Printf("[WARN] Sprachdatei nicht gefunden: %v\n", err)

		if lang != "en" {
			fmt.Printf("[INFO] Versuche Fallback zu EN...\n")
			return loadLanguage("en")
		}

		fmt.Printf("[WARN] Nutze eingebaute Default-Übersetzungen\n")
		setDefaultPhrases()
		return nil
	}

	var translations map[string]string
	if err := json.Unmarshal(data, &translations); err != nil {
		fmt.Printf("[ERROR] Fehler beim Parsen der JSON: %v\n", err)

		if lang != "en" {
			return loadLanguage("en")
		}
		setDefaultPhrases()
		return nil
	}

	fmt.Printf("[INFO] ✓ Sprachdatei geladen: %s (%d Übersetzungen)\n",
		lang, len(translations))

	requiredKeys := []string{"startup", "shutdown", "no_zones", "update"}
	for _, key := range requiredKeys {
		if _, ok := translations[key]; !ok {
			fmt.Printf("[WARN] Fehlender Übersetzungsschlüssel: %s\n", key)
		}
	}

	v := reflect.ValueOf(&T).Elem()
	t := v.Type()

	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		jsonKey := toSnakeCase(field.Name)

		if val, ok := translations[jsonKey]; ok {
			v.Field(i).SetString(val)
		}
	}

	return nil
}

func toSnakeCase(s string) string {
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
		DashboardStarted:         "Dashboard started on port",
		ServerError:              "Server error",
		HealthCheckOK:            "Health check OK",
		HealthCheckFailed:        "Health check failed",
		SystemEvents:             "System Events",
		History:                  "History",
		EventLog:                 "Event Log",
		DomainStatus:             "Domain Status",
		Provider:                 "Provider",
		LastChanged:              "Last Changed",
		Ipv4Label:                "IPv4",
		Ipv6Label:                "IPv6",
		Requests:                 "Requests",
		SuccessRate:              "Success Rate",
		LastSuccess:              "Last Success",
		AvgLatency:               "Avg Latency",
		Errors:                   "Errors",
		HourlyLimit:              "Hourly Limit",
		RequestHistory:           "Request History (Last 24h)",
		LatencyHistory:           "Latency History (Last 24h)",
		ApiPerformance:           "API Performance",
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
		ReceivedIp:               "Received IP",
		CheckingInterface:        "Checking interface",
		InterfaceNotFound:        "Interface not found",
		AddressesNotReadable:     "Addresses not readable",
		NoIpv6OnInterface:        "No IPv6 on interface",
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
		CheckingIpv4:             "Checking IPv4",
		CheckingIpv6:             "Checking IPv6",
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
		ConfigIpMode:             "IP Mode",
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
		HttpClientInitialized:    "HTTP client initialized with %d DNS servers",
		InvalidPort:              "Invalid port: %s",
		UsingDefaultPort:         "Using default port",
		IntervalTooSmall:         "Interval too small",
		ShortIntervalWarning:     "Short interval warning with many domains",
		InvalidIPMode:            "Invalid IP mode: %s",
		UsingDefaultMode:         "Using default mode",
	}
}
