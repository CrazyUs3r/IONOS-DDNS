// Package main
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ============================================================================
// MAIN
// ============================================================================
func initTimezone() {
	tz := os.Getenv("TZ")
	if tz == "" {
		return
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		fmt.Printf(
			"[WARN] Could not load timezone %q: %v – using UTC\n",
			tz,
			err,
		)
		time.Local = time.UTC
		return
	}
	time.Local = loc
}

func main() {
	initTimezone()
	startTime = time.Now()

	exitCode := run()
	os.Exit(exitCode)
}

func run() (exitCode int) {
	defer handleRunPanic(&exitCode)

	paths := initRuntimePaths()

	if err := prepareRuntimeDirectories(paths); err != nil {
		return 1
	}

	fmt.Printf("\n🌐 Go-DynDNS v%s (built: %s, ref: %s)\n\n", Version, BuildDate, VCSRef)

	logRuntimePaths(paths)

	loadPersistedMetrics(paths.metricsPersistPath)

	envCfg := readEnvConfig()

	initDefaultConfig(paths.logsDir)

	configLoaded := loadConfigFromFile()
	if !configLoaded {
		applyEnvOverrides(
			paths.logsDir,
			envCfg.interval,
			envCfg.dnsList,
			envCfg.maxAPIRetries,
			envCfg.maxLogLines,
			envCfg.hourlyLimit,
			envCfg.maxConcurrent,
		)
	}

	applyDebugOverrides()
	if err := configureLanguage(paths.langDir); err != nil {
		return 1
	}

	initShutdownContext()
	defer shutdownCancel()

	if err := initAuth(paths.logsDir); err != nil {
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: "Dashboard authentication initialization failed",
			Error:   err,
		})
		return 1
	}

	workerLimiter = NewDynamicWorkerLimiter(cfg.MaxConcurrent)

	if err := initializeProvidersAndNotifiers(); err != nil {
		return 1
	}

	logDebugConfiguration()

	logHTTPClientStats()
	metricsBroadcasterLoop()

	if err := ensureRuntimeDirs(paths); err != nil {
		return 1
	}

	setRuntimeFilePaths(paths.logsDir)

	startBackgroundWorkers()

	if err := validateRuntimeConfig(); err != nil {
		return 1
	}

	if hasDomainConfig() {
		logStartupProviders()
	} else {
		logSetupMode()
	}

	initializeRateLimiters()

	if hasDomainConfig() {
		refreshCaches()
	}

	startMaintenanceWorkers()

	servers, err := newDashboardServers()
	if err != nil {
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: fmt.Sprintf("Dashboard server configuration failed: %v", err),
		})
		return 1
	}

	startDashboardServers(servers)
	startWebSocketHub()

	if hasDomainConfig() {
		runUpdate(true)
	}

	return runMainLoop(servers)
}

type runtimePaths struct {
	configDir          string
	langDir            string
	logsDir            string
	metricsPersistPath string
}

type envConfig struct {
	dnsList       []string
	interval      int
	maxAPIRetries int
	maxLogLines   int
	hourlyLimit   int
	maxConcurrent int
}

func handleRunPanic(exitCode *int) {
	if r := recover(); r != nil {
		*exitCode = 1

		fmt.Printf("[FATAL] Main-Panic: %v\n", r)

		if metricsPersistPath != "" {
			_ = apiMetrics.SaveToFile(metricsPersistPath)
		}

		stopLogWriterAndWait()
	}
}

func initRuntimePaths() runtimePaths {
	configDir = os.Getenv("CONFIG_DIR")
	if configDir == "" {
		configDir = "/config"
	}

	langDir = filepath.Join(configDir, "lang")
	logsDir := filepath.Join(configDir, "logs")
	metricsPersistPath = filepath.Join(logsDir, "metrics.json")

	if configPath == "" {
		configPath = filepath.Join(configDir, "config.json")
	}

	return runtimePaths{
		configDir:          configDir,
		langDir:            langDir,
		logsDir:            logsDir,
		metricsPersistPath: metricsPersistPath,
	}
}

func prepareRuntimeDirectories(paths runtimePaths) error {
	if err := os.MkdirAll(paths.langDir, 0o755); err != nil {
		log(LogContext{
			Level:    LogError,
			Category: "CONFIG",
			Message:  fmt.Sprintf(t(phrases().LanguageDirCreateFailed, "Failed to create language directory: %v"), err),
		})
		return err
	}

	if err := copyEmbeddedLangFiles(paths.langDir); err != nil {
		return fmt.Errorf("copy embedded lang files: %w", err)
	}

	return nil
}

func logRuntimePaths(paths runtimePaths) {
	log(LogContext{
		Level:    LogInfo,
		Category: "CONFIG",
		Message:  fmt.Sprintf(t(phrases().ConfigDir, "Config directory: %s"), paths.configDir),
	})

	log(LogContext{
		Level:    LogInfo,
		Category: "CONFIG",
		Message:  fmt.Sprintf(t(phrases().ConfigLanguageDir, "Languages: %s"), paths.langDir),
	})

	log(LogContext{
		Level:    LogInfo,
		Category: "CONFIG",
		Message:  fmt.Sprintf(t(phrases().ConfigLogsDir, "Logs: %s"), paths.logsDir),
	})
}

func loadPersistedMetrics(path string) {
	if err := apiMetrics.LoadFromFile(path); err != nil {
		log(LogContext{
			Level:    LogWarn,
			Category: "CONFIG",
			Action:   ActionConfig,
			Message:  fmt.Sprintf(t(phrases().MetricsLoadFailed, "Failed to load metrics: %v"), err),
		})
	}
}

func readEnvConfig() envConfig {
	return envConfig{
		interval:      readIntervalFromEnv(),
		dnsList:       readDNSServersFromEnv(),
		maxAPIRetries: readMaxAPIRetriesFromEnv(),
		maxLogLines:   readMaxLogLinesFromEnv(),
		hourlyLimit:   readHourlyRateLimitFromEnv(),
		maxConcurrent: readMaxConcurrentFromEnv(),
	}
}

func readIntervalFromEnv() int {
	tempInterval := DefaultInterval

	if s := strings.TrimSpace(os.Getenv("INTERVAL")); s != "" {
		if i, err := strconv.Atoi(s); err == nil && i >= 30 {
			tempInterval = i
		} else {
			log(LogContext{
				Level:    LogWarn,
				Category: "CONFIG",
				Action:   ActionConfig,
				Message:  fmt.Sprintf(t(phrases().InvalidInterval, "Invalid INTERVAL value '%s', using default 300"), s),
			})
		}
	}

	return tempInterval
}

func readDNSServersFromEnv() []string {
	dnsEnv := os.Getenv("DNS_SERVERS")
	if dnsEnv == "" {
		return nil
	}

	var dnsList []string
	parts := strings.SplitSeq(dnsEnv, ",")
	for p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			dnsList = append(dnsList, trimmed)
		}
	}

	return dnsList
}

func readMaxAPIRetriesFromEnv() int {
	value := DefaultMaxAPIRetries

	if s := strings.TrimSpace(os.Getenv("MAX_API_RETRIES")); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v >= 0 && v <= 20 {
			value = v
		} else {
			log(LogContext{
				Level:   LogWarn,
				Action:  ActionConfig,
				Message: fmt.Sprintf(t(phrases().MaxAPIRetriesInvalid, "Invalid MAX_API_RETRIES value '%s', using default %d"), s, DefaultMaxAPIRetries),
			})
		}
	}

	return value
}

func readMaxLogLinesFromEnv() int {
	value := DefaultMaxLogLines

	if s := strings.TrimSpace(os.Getenv("LOG_MAX_LINES")); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			value = v
		} else {
			log(LogContext{
				Level:   LogWarn,
				Action:  ActionConfig,
				Message: fmt.Sprintf(t(phrases().LogMaxLinesInvalid, "Invalid LOG_MAX_LINES value '%s', using default %d"), s, DefaultMaxLogLines),
			})
		}
	}

	return value
}

func readHourlyRateLimitFromEnv() int {
	value := DefaultHourlyRateLimit

	if envLimit := os.Getenv("HOURLY_RATE_LIMIT"); envLimit != "" {
		if parsed, err := strconv.Atoi(envLimit); err == nil && parsed > 0 {
			value = parsed
		}
	}

	return value
}

func readMaxConcurrentFromEnv() int {
	value := DefaultMaxConcurrent

	if envMax := os.Getenv("MAX_CONCURRENT"); envMax != "" {
		if parsed, err := strconv.Atoi(envMax); err == nil && parsed > 0 && parsed <= 20 {
			value = parsed
		}
	}

	return value
}

func initDefaultConfig(logsDir string) {
	cfgMu.Lock()
	cfg = Config{
		Interval:        DefaultInterval,
		IPMode:          "BOTH",
		HealthPort:      "8080",
		LogDir:          logsDir,
		HourlyRateLimit: DefaultHourlyRateLimit,
		MaxConcurrent:   DefaultMaxConcurrent,
		MaxLogLines:     DefaultMaxLogLines,
		MaxAPIRetries:   DefaultMaxAPIRetries,
	}
	cfgMu.Unlock()
}

func loadConfigFromFile() bool {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return false
	}

	loaded, err := parseConfig(data)
	if err != nil {
		log(LogContext{
			Level:   LogWarn,
			Action:  ActionConfig,
			Message: fmt.Sprintf(t(phrases().ConfigJSONReadFailed, "config.json could not be read, using defaults: %v"), err),
		})
		return false
	}

	applyLegacyNotificationDefault(data, &loaded)
	applyConfigDefaults(&loaded)
	normalizeLoadedConfig(&loaded)
	storeLoadedConfig(loaded)

	return true
}

func parseConfig(data []byte) (Config, error) {
	var loaded Config
	err := json.Unmarshal(data, &loaded)
	return loaded, err
}

func applyLegacyNotificationDefault(data []byte, loaded *Config) {
	if configFieldPresent(data, "notifications", "enabled") {
		return
	}
	if notificationCredentialsConfigured(*loaded) {
		loaded.Notifications.Enabled = true
	}
}

func applyConfigDefaults(loaded *Config) {
	if loaded.Interval <= 0 {
		loaded.Interval = DefaultInterval
	}
	if loaded.HealthPort == "" {
		loaded.HealthPort = "8080"
	}
	if loaded.IPMode == "" {
		loaded.IPMode = "BOTH"
	}
	if loaded.LogDir == "" {
		loaded.LogDir = configuredLogDir()
	}
	if loaded.MaxConcurrent <= 0 || loaded.MaxConcurrent > 20 {
		loaded.MaxConcurrent = DefaultMaxConcurrent
	}
	if loaded.MaxLogLines <= 0 {
		loaded.MaxLogLines = DefaultMaxLogLines
	}
	if loaded.MaxAPIRetries < 0 || loaded.MaxAPIRetries > 20 {
		loaded.MaxAPIRetries = DefaultMaxAPIRetries
	}
	if loaded.HourlyRateLimit <= 0 {
		loaded.HourlyRateLimit = DefaultHourlyRateLimit
	}
}

func configuredLogDir() string {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	return cfg.LogDir
}

func normalizeLoadedConfig(loaded *Config) {
	loaded.IPMode = strings.ToUpper(strings.TrimSpace(loaded.IPMode))
	for i := range loaded.DomainConfigs {
		normalizeDomainConfig(&loaded.DomainConfigs[i])
	}
}

func normalizeDomainConfig(domainConfig *DomainConfig) {
	domainConfig.FQDN = normalizeDomain(domainConfig.FQDN)
	domainConfig.Provider = normalizeProviderName(string(domainConfig.Provider))
	domainConfig.IPMode = strings.ToUpper(strings.TrimSpace(domainConfig.IPMode))
}

func storeLoadedConfig(loaded Config) {
	cfgMu.Lock()
	cfg = loaded
	cfgMu.Unlock()
	invalidateSecretReplacer()
}

func configFieldPresent(data []byte, objectKey, fieldKey string) bool {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return false
	}
	rawObject, ok := root[objectKey]
	if !ok {
		return false
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(rawObject, &object); err != nil {
		return false
	}
	_, ok = object[fieldKey]
	return ok
}

func applyDebugOverrides() {
	if v := os.Getenv("DEBUG"); v != "" {
		cfg.DebugEnabled = v == constTrue
	}
	if v := os.Getenv("DEBUG_HTTP_RAW"); v != "" {
		cfg.DebugHTTPRaw = v == constTrue
	}
	setAtomicDebugFlags(cfg.DebugEnabled, cfg.DebugHTTPRaw)
}

func configureLanguage(langDir string) error {
	var lang string

	if strings.TrimSpace(cfg.Lang) != "" {
		lang = normalizeLang(cfg.Lang)
	} else {
		lang = detectLanguage(langDir, os.Getenv("LANG"))
	}

	cfg.Lang = lang

	if err := loadLanguage(cfg.Lang); err != nil {
		log(LogContext{
			Level:    LogError,
			Category: "CONFIG",
			Message:  fmt.Sprintf(t(phrases().LanguageFileLoadFailed, "Failed to load language file: %v"), err),
		})
		return err
	}

	return nil
}

func initShutdownContext() {
	shutdownCtx, shutdownCancel = context.WithCancel(context.Background())
}

func initializeProvidersAndNotifiers() error {
	if err := initProviderConfig(); err != nil {
		log(LogContext{
			Level:   LogError,
			Action:  ActionConfig,
			Message: fmt.Sprintf(t(phrases().ProviderConfigFailed, "Provider-%s failed: %v"), phrases().ConfigHeading, err),
		})
		return err
	}

	invalidateSecretReplacer()
	initNotifiers()
	return nil
}

func logDebugConfiguration() {
	if !cfg.DebugEnabled {
		return
	}

	debugLog("CONFIG", "", fmt.Sprintf(t(phrases().DebugModeActive, "Debug mode active. Interval: %ds, mode: %s"), cfg.Interval, cfg.IPMode))
	debugLog("CONFIG", "", fmt.Sprintf(t(phrases().LoadedDomains, "Loaded domains: %d"), len(cfg.DomainConfigs)))
	debugLog("CONFIG", "", fmt.Sprintf(t(phrases().MaxLogLinesInfo, "Max log lines: %d"), cfg.MaxLogLines))
	debugLog("CONFIG", "", fmt.Sprintf(t(phrases().MaxAPIRetriesInfo, "Max API retries: %d"), cfg.MaxAPIRetries))
	debugLog("CONFIG", "", fmt.Sprintf(t(phrases().MaxConcurrentInfo, "Max concurrent: %d"), cfg.MaxConcurrent))

	for _, dc := range cfg.DomainConfigs {
		debugLog("CONFIG", "", fmt.Sprintf("  - %s (%s)", dc.FQDN, dc.Provider))
	}
}

func ensureRuntimeDirs(paths runtimePaths) error {
	if cfg.HealthPort == "" {
		cfg.HealthPort = "8080"
	}

	if err := os.MkdirAll(paths.logsDir, 0o755); err != nil {
		log(LogContext{
			Level:   LogError,
			Action:  ActionConfig,
			Message: fmt.Sprintf(t(phrases().LogDirCreateFailed, "Failed to create log directory: %v"), err),
		})
		return err
	}

	if err := os.MkdirAll(paths.langDir, 0o755); err != nil {
		log(LogContext{
			Level:   LogError,
			Action:  ActionConfig,
			Message: fmt.Sprintf(t(phrases().LanguageDirCreateFailed, "Failed to create lang directory: %v"), err),
		})
		return err
	}

	return nil
}

func setRuntimeFilePaths(logsDir string) {
	logPath = filepath.Join(logsDir, "dyndns.json")
	updatePath = filepath.Join(logsDir, "update.json")
}

func startBackgroundWorkers() {
	startMetricsAutosave(60 * time.Second)
	startLogWriter()
}

func validateRuntimeConfig() error {
	if !hasDomainConfig() {
		return nil
	}

	if err := validateConfig(); err != nil {
		log(LogContext{
			Level:   LogError,
			Action:  ActionConfig,
			Message: err.Error(),
		})
		return err
	}

	return nil
}

func hasDomainConfig() bool {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	return len(cfg.DomainConfigs) > 0
}

func logSetupMode() {
	log(LogContext{
		Level:   LogWarn,
		Action:  ActionConfig,
		Message: "No domains configured yet. Dashboard setup mode is active; save config.json from the dashboard.",
	})
}

func logStartupProviders() {
	providers := make(map[ProviderType]bool)
	for _, dc := range cfg.DomainConfigs {
		providers[dc.Provider] = true
	}

	providerNames := make([]string, 0, len(providers))
	for p := range providers {
		providerNames = append(providerNames, string(p))
	}
	sort.Strings(providerNames)

	log(LogContext{
		Level:   LogInfo,
		Action:  ActionStart,
		Message: fmt.Sprintf("🚀 %s (%s: %s)", phrases().Startup, t(phrases().Providers, "Providers"), strings.Join(providerNames, ", ")),
	})
}

func initializeRateLimiters() {
	globalTriggerLimiter = NewRateLimiter(10, 1.0/6.0)
	ipTriggerLimiter = NewIPRateLimiter(shutdownCtx, 5, 0.1)
	loginLimiter = NewIPRateLimiter(shutdownCtx, 5, 1.0/60.0)
}

func refreshCaches() {
	if err := updateDomainsCache(); err != nil {
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: fmt.Sprintf(t(phrases().DomainCacheUpdateFailed, "Failed to update domain cache: %v"), err),
		})
	}

	if err := updateMetricsCache(); err != nil {
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: fmt.Sprintf(t(phrases().MetricCacheUpdateFailed, "Failed to update metric cache: %v"), err),
		})
	}
}

func startMaintenanceWorkers() {
	startCacheRefresher()
	startLogRotationWorker()
}

type dashboardServers struct {
	http       *http.Server
	https      *http.Server
	certFile   string
	keyFile    string
	selfSigned bool
}

func newDashboardHandler() http.Handler {
	var handler http.Handler = createMux()

	if authEnabled {
		handler = authMiddleware(handler)
	}

	return securityHeaders(handler)
}

func newDashboardServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
}

func newDashboardServers() (*dashboardServers, error) {
	handler := newDashboardHandler()
	servers := &dashboardServers{
		http: newDashboardServer(":"+cfg.HealthPort, handler),
	}

	certFile, keyFile, selfSigned, err := resolveDashboardTLSFiles()
	if err != nil {
		return nil, err
	}

	httpsPort := strings.TrimSpace(os.Getenv("DASHBOARD_HTTPS_PORT"))
	if httpsPort == "" {
		httpsPort = "8443"
	}
	if httpsPort == cfg.HealthPort {
		return nil, fmt.Errorf("HTTP and HTTPS cannot use the same port %s", httpsPort)
	}

	servers.https = newDashboardServer(":"+httpsPort, handler)
	servers.certFile = certFile
	servers.keyFile = keyFile
	servers.selfSigned = selfSigned
	return servers, nil
}

func startDashboardServers(servers *dashboardServers) {
	startHTTPServer(servers.http)
	if servers.https != nil {
		startHTTPSServer(servers.https, servers.certFile, servers.keyFile, servers.selfSigned)
	}
}

func startHTTPServer(srv *http.Server) {
	ip := getLocalIP()
	go func() {
		debugLog("SYSTEM", "", fmt.Sprintf("%s (http://%s%s)", phrases().DashboardStarted, ip, srv.Addr))
		log(LogContext{
			Level:   LogInfo,
			Action:  ActionServer,
			Message: fmt.Sprintf("%s (http://%s%s)", phrases().DashboardStarted, ip, srv.Addr),
		})

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log(LogContext{
				Level:   LogError,
				Action:  ActionError,
				Message: fmt.Sprintf("%s: %v", phrases().ServerError, err),
			})
		}
	}()
}

func startHTTPSServer(srv *http.Server, certFile, keyFile string, selfSigned bool) {
	ip := getLocalIP()
	go func() {
		message := fmt.Sprintf("%s (https://%s%s)", phrases().DashboardStarted, ip, srv.Addr)
		if selfSigned {
			message += " [self-signed certificate]"
		}
		debugLog("SYSTEM", "", message)
		log(LogContext{
			Level:   LogInfo,
			Action:  ActionServer,
			Message: message,
		})

		if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
			log(LogContext{
				Level:   LogError,
				Action:  ActionError,
				Message: fmt.Sprintf("%s (HTTPS): %v", phrases().ServerError, err),
			})
		}
	}()
}

func startWebSocketHub() {
	go wsHub.run()
	debugLog("SYSTEM", "", t(phrases().WebSocketHubStarted, "WebSocket hub started"))
}

func runMainLoop(servers *dashboardServers) int {
	cfgMu.RLock()
	currentInterval := cfg.Interval
	cfgMu.RUnlock()

	ticker := time.NewTicker(time.Duration(currentInterval) * time.Second)
	defer ticker.Stop()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-shutdownCtx.Done():
			debugLog("SCHEDULER", "", t(phrases().SchedulerShutdownActive, "Shutdown active, stopping scheduler"))
			return handleContextShutdown(ticker, servers)

		case <-ticker.C:
			ticker = handleSchedulerTick(ticker, &currentInterval)

		case sig := <-stop:
			return handleShutdownSignal(sig, ticker, servers)
		}
	}
}

func handleContextShutdown(
	ticker *time.Ticker,
	servers *dashboardServers,
) int {
	ticker.Stop()
	closeNotifiers()

	if httpClient != nil {
		httpClient.CloseIdleConnections()

		debugLog("SYSTEM", "", phrases().HTTPConnectionsClosed)
	}

	shutdownDashboardServers(servers)

	waitForRunningUpdates()

	if err := apiMetrics.SaveToFile(metricsPersistPath); err != nil {
		debugLog("SYSTEM", "", fmt.Sprintf(t(phrases().MetricsSaveFailed, "Metrics could not be saved: %v"), err))
	}

	debugLog("SYSTEM", "", t(phrases().WaitingForLogQueue, "📝 Waiting for log queue..."))

	stopLogWriterAndWait()

	return 0
}

func handleSchedulerTick(ticker *time.Ticker, currentInterval *int) *time.Ticker {
	cfgMu.RLock()
	interval := cfg.Interval
	maxLogLines := cfg.MaxLogLines
	cfgMu.RUnlock()

	if interval != *currentInterval {
		ticker.Stop()
		*currentInterval = interval
		ticker = time.NewTicker(time.Duration(*currentInterval) * time.Second)
		debugLog("SCHEDULER", "", fmt.Sprintf(t(phrases().SchedulerIntervalChanged, "Interval changed → new ticker: %ds"), *currentInterval))
	}

	if !hasDomainConfig() {
		debugLog("SCHEDULER", "", "No domains configured yet; scheduler paused until config.json is saved.")
		return ticker
	}

	debugLog("SCHEDULER", "", t(phrases().SchedulerIntervalReached, "Interval reached, starting runUpdate(false)"))

	if !tryClaimUpdate() {
		debugLog("SCHEDULER", "", t(phrases().SchedulerPreviousUpdateRunning, "⚠️ Previous update is still running. Skipping this cycle..."))

		limit := maxLogLines
		if interval > 500 && limit == DefaultMaxLogLines {
			limit = 1000
		}
		rotateLogFile(logPath, limit)
		return ticker
	}

	go runClaimedUpdate(false)

	limit := maxLogLines
	if interval > 500 && limit == DefaultMaxLogLines {
		limit = 1000
	}

	debugLog("MAINTENANCE", "", phrases().MaintenanceStarting)
	rotateLogFile(logPath, limit)

	return ticker
}

func handleShutdownSignal(sig os.Signal, ticker *time.Ticker, servers *dashboardServers) int {
	debugLog("SYSTEM", "", fmt.Sprintf(t(phrases().ShutdownSignalReceived, "Shutdown signal received: %v"), sig))

	stopCtx := LogContext{
		Level:  LogInfo,
		Action: ActionStop,
		Message: fmt.Sprintf(
			"🛑 %s (Signal: %v)",
			phrases().Shutdown,
			sig,
		),
	}

	notifySync(stopCtx)

	stopCtx.SkipNotify = true
	log(stopCtx)
	closeNotifiers()

	ticker.Stop()

	shutdownCancel()

	if httpClient != nil {
		httpClient.CloseIdleConnections()

		debugLog("SYSTEM", "", phrases().HTTPConnectionsClosed)
	}

	shutdownDashboardServers(servers)

	waitForRunningUpdates()

	if err := apiMetrics.SaveToFile(metricsPersistPath); err != nil {
		debugLog("SYSTEM", "", fmt.Sprintf(t(phrases().MetricsSaveFailed, "Metrics could not be saved: %v"), err))
	}

	debugLog("SYSTEM", "", t(phrases().WaitingForLogQueue, "📝 Waiting for log queue..."))

	stopLogWriterAndWait()

	return 0
}

func stopLogWriterAndWait() {
	if !logWriterStarted.Load() {
		return
	}

	stopLogWriterOnce.Do(func() {
		close(logWriterStop)
	})

	timer := time.NewTimer(logFlushTimeout)
	defer timer.Stop()

	select {
	case <-logWriterDone:

	case <-timer.C:
		fmt.Fprintf(
			os.Stderr,
			"log writer shutdown timed out; %d entries may remain\n",
			len(logWriteQueue),
		)
	}
}

func waitForRunningUpdates() {
	debugLog("SYSTEM", "", t(phrases().WaitingForRunningUpdates, "⏳ Waiting for running updates..."))

	waitCtx, waitCancel := context.WithTimeout(
		context.Background(),
		ShutdownWaitTimeout,
	)
	defer waitCancel()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		if activeUpdates.Load() == 0 && !updateInProgress.Load() {
			debugLog("SYSTEM", "", t(phrases().AllUpdatesFinished, "✅ All updates finished"))

			return
		}

		select {
		case <-ticker.C:

		case <-waitCtx.Done():
			debugLog("SYSTEM", "", t(phrases().WaitForUpdatesTimeout, "⚠️ Timeout while waiting for updates - force shutdown"))

			return
		}
	}
}

func shutdownDashboardServers(servers *dashboardServers) {
	ctx, cancel := context.WithTimeout(context.Background(), ShutdownGraceTimeout)
	defer cancel()

	debugLog("SYSTEM", "", phrases().ServerShuttingDown)
	for _, srv := range []*http.Server{servers.http, servers.https} {
		if srv == nil {
			continue
		}
		if err := srv.Shutdown(ctx); err != nil {
			log(LogContext{
				Level:   LogWarn,
				Action:  ActionError,
				Message: fmt.Sprintf("%s (%s): %v", phrases().ShutdownError, srv.Addr, err),
			})
		}
	}
	debugLog("SYSTEM", "", phrases().ServerShutdownComplete)
}

func applyEnvOverrides(
	logsDir string,
	tempInterval int,
	dnsList []string,
	maxAPIRetries, maxLogLines, hourlyLimit, maxConcurrent int,
) {
	cfgMu.Lock()
	defer cfgMu.Unlock()

	applyCoreEnvOverrides(logsDir, tempInterval, dnsList)
	applyLimitEnvOverrides(maxAPIRetries, maxLogLines, hourlyLimit, maxConcurrent)
}

func applyCoreEnvOverrides(logsDir string, tempInterval int, dnsList []string) {
	if v := strings.ToUpper(os.Getenv("IP_MODE")); v != "" {
		cfg.IPMode = v
	}
	if v := os.Getenv("INTERFACE"); v != "" {
		cfg.IfaceName = v
	}
	if v := os.Getenv("HEALTH_PORT"); v != "" {
		cfg.HealthPort = v
	}
	if v := os.Getenv("DRY_RUN"); v != "" {
		cfg.DryRun = v == constTrue
	}

	cfg.LogDir = logsDir

	if v := strings.TrimSpace(os.Getenv("LANG")); v != "" {
		cfg.Lang = normalizeLang(v)
	}
	if os.Getenv("INTERVAL") != "" {
		cfg.Interval = tempInterval
	}
	if os.Getenv("DNS_SERVERS") != "" {
		cfg.DNSServers = dnsList
	}
}

func applyLimitEnvOverrides(maxAPIRetries, maxLogLines, hourlyLimit, maxConcurrent int) {
	if os.Getenv("MAX_API_RETRIES") != "" {
		cfg.MaxAPIRetries = maxAPIRetries
	}
	if os.Getenv("LOG_MAX_LINES") != "" {
		cfg.MaxLogLines = maxLogLines
	}
	if os.Getenv("HOURLY_RATE_LIMIT") != "" {
		cfg.HourlyRateLimit = hourlyLimit
	}
	if os.Getenv("MAX_CONCURRENT") != "" {
		cfg.MaxConcurrent = maxConcurrent
	}
}
