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
		fmt.Printf("[WARN] Could not load timezone %q: %v – using UTC\n", tz, err)
		return
	}
	time.Local = loc
}

func main() {
	initTimezone()
	exitCode := run()
	os.Exit(exitCode)
}

func run() int {
	defer handleRunPanic()

	paths := initRuntimePaths()

	if err := prepareRuntimeDirectories(paths); err != nil {
		return 1
	}

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

	initAuth(paths.logsDir)

	workerSemaphore = make(chan struct{}, cfg.MaxConcurrent)

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

	logStartupProviders()

	initializeRateLimiters()

	refreshCaches()

	startMaintenanceWorkers()

	srv := newHTTPServer()
	startHTTPServer(srv)
	startWebSocketHub()

	runUpdate(true)

	return runMainLoop(srv)
}

type runtimePaths struct {
	configDir          string
	langDir            string
	logsDir            string
	metricsPersistPath string
}

type envConfig struct {
	interval      int
	dnsList       []string
	maxAPIRetries int
	maxLogLines   int
	hourlyLimit   int
	maxConcurrent int
}

func handleRunPanic() {
	if r := recover(); r != nil {
		fmt.Printf("[FATAL] Main-Panic: %v\n", r)

		flushLogQueue()

		if metricsPersistPath != "" {
			_ = apiMetrics.SaveToFile(metricsPersistPath)
		}

		flushLogQueue()
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
			Message:  fmt.Sprintf(t(T.LanguageDirCreateFailed, "Failed to create language directory: %v"), err),
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
		Message:  fmt.Sprintf(t(T.ConfigDir, "Config directory: %s"), paths.configDir),
	})

	log(LogContext{
		Level:    LogInfo,
		Category: "CONFIG",
		Message:  fmt.Sprintf(t(T.ConfigLanguageDir, "Languages: %s"), paths.langDir),
	})

	log(LogContext{
		Level:    LogInfo,
		Category: "CONFIG",
		Message:  fmt.Sprintf(t(T.ConfigLogsDir, "Logs: %s"), paths.logsDir),
	})
}

func loadPersistedMetrics(path string) {
	if err := apiMetrics.LoadFromFile(path); err != nil {
		log(LogContext{
			Level:    LogWarn,
			Category: "CONFIG",
			Action:   ActionConfig,
			Message:  fmt.Sprintf(t(T.MetricsLoadFailed, "Failed to load metrics: %v"), err),
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
				Message:  fmt.Sprintf(t(T.InvalidInterval, "Invalid INTERVAL value '%s', using default 300"), s),
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
				Message: fmt.Sprintf(t(T.MaxAPIRetriesInvalid, "Invalid MAX_API_RETRIES value '%s', using default %d"), s, DefaultMaxAPIRetries),
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
				Message: fmt.Sprintf(t(T.LogMaxLinesInvalid, "Invalid LOG_MAX_LINES value '%s', using default %d"), s, DefaultMaxLogLines),
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
	var loaded Config

	if err := json.Unmarshal(data, &loaded); err != nil {
		log(LogContext{
			Level:   LogWarn,
			Action:  ActionConfig,
			Message: fmt.Sprintf(t(T.ConfigJSONReadFailed, "config.json could not be read, using defaults: %v"), err),
		})
		return false
	}

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
		loaded.LogDir = cfg.LogDir
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

	cfgMu.Lock()
	cfg = loaded
	cfgMu.Unlock()

	return len(cfg.DomainConfigs) > 0
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
			Message:  fmt.Sprintf(t(T.LanguageFileLoadFailed, "Failed to load language file: %v"), err),
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
			Message: fmt.Sprintf(t(T.ProviderConfigFailed, "Provider-%s failed: %v"), T.ConfigHeading, err),
		})
		return err
	}

	initNotifiers()
	return nil
}

func logDebugConfiguration() {
	if !cfg.DebugEnabled {
		return
	}

	debugLog("CONFIG", "", fmt.Sprintf(t(T.DebugModeActive, "Debug mode active. Interval: %ds, mode: %s"), cfg.Interval, cfg.IPMode))
	debugLog("CONFIG", "", fmt.Sprintf(t(T.LoadedDomains, "Loaded domains: %d"), len(cfg.DomainConfigs)))
	debugLog("CONFIG", "", fmt.Sprintf(t(T.MaxLogLinesInfo, "Max log lines: %d"), cfg.MaxLogLines))
	debugLog("CONFIG", "", fmt.Sprintf(t(T.MaxAPIRetriesInfo, "Max API retries: %d"), cfg.MaxAPIRetries))
	debugLog("CONFIG", "", fmt.Sprintf(t(T.MaxConcurrentInfo, "Max concurrent: %d"), cfg.MaxConcurrent))

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
			Message: fmt.Sprintf(t(T.LogDirCreateFailed, "Failed to create log directory: %v"), err),
		})
		return err
	}

	if err := os.MkdirAll(paths.langDir, 0o755); err != nil {
		log(LogContext{
			Level:   LogError,
			Action:  ActionConfig,
			Message: fmt.Sprintf(t(T.LanguageDirCreateFailed, "Failed to create lang directory: %v"), err),
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
	if err := validateConfig(); err != nil {
		log(LogContext{
			Level:   LogError,
			Action:  ActionConfig,
			Message: fmt.Sprintf("%v", err),
		})
		return err
	}

	return nil
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
		Message: fmt.Sprintf("🚀 %s (%s: %s)", T.Startup, t(T.Providers, "Providers"), strings.Join(providerNames, ", ")),
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
			Message: fmt.Sprintf(t(T.DomainCacheUpdateFailed, "Failed to update domain cache: %v"), err),
		})
	}

	if err := updateMetricsCache(); err != nil {
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: fmt.Sprintf(t(T.MetricCacheUpdateFailed, "Failed to update metric cache: %v"), err),
		})
	}
}

func startMaintenanceWorkers() {
	startCacheRefresher()
	startLogRotationWorker()
}

func newHTTPServer() *http.Server {
	mux := createMux()

	var handler http.Handler = mux
	if authEnabled {
		handler = authMiddleware(mux)
	}

	handler = cspMiddleware(handler)

	return &http.Server{
		Addr:              ":" + cfg.HealthPort,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
}

func cspMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		isHTML := path == "/" ||
			path == "/login" ||
			path == "/setup" ||
			path == "/logout"

		if isHTML {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			w.Header().Set("Content-Security-Policy",
				"default-src 'self'; "+
					"script-src 'self' 'unsafe-inline'; "+
					"style-src 'self' 'unsafe-inline'; "+
					"img-src 'self' data:; "+
					"connect-src 'self' ws: wss:; "+
					"frame-ancestors 'none';",
			)
		}
		next.ServeHTTP(w, r)
	})
}

func startHTTPServer(srv *http.Server) {
	ip := getLocalIP()
	go func() {
		debugLog("SYSTEM", "", fmt.Sprintf("%s (http://%s:%s)", T.DashboardStarted, ip, cfg.HealthPort))
		log(LogContext{
			Level:   LogInfo,
			Action:  ActionServer,
			Message: fmt.Sprintf("%s (http://%s:%s)", T.DashboardStarted, ip, cfg.HealthPort),
		})

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log(LogContext{
				Level:   LogError,
				Action:  ActionError,
				Message: fmt.Sprintf("%s: %v", T.ServerError, err),
			})
		}
	}()
}

func startWebSocketHub() {
	go wsHub.run()
	debugLog("SYSTEM", "", t(T.WebSocketHubStarted, "WebSocket hub started"))
}

func runMainLoop(srv *http.Server) int {
	currentInterval := cfg.Interval
	ticker := time.NewTicker(time.Duration(currentInterval) * time.Second)
	defer ticker.Stop()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-shutdownCtx.Done():
			debugLog("SCHEDULER", "", t(T.SchedulerShutdownActive, "Shutdown active, stopping scheduler"))
			return handleContextShutdown(ticker, srv)

		case <-ticker.C:
			ticker = handleSchedulerTick(ticker, &currentInterval)

		case sig := <-stop:
			return handleShutdownSignal(sig, ticker, srv)
		}
	}
}

func handleContextShutdown(ticker *time.Ticker, srv *http.Server) int {
	ticker.Stop()

	if httpClient != nil {
		httpClient.CloseIdleConnections()
		debugLog("SYSTEM", "", T.HTTPConnectionsClosed)
	}

	waitForRunningUpdates()

	debugLog("SYSTEM", "", t(T.WaitingForLogQueue, "📝 Waiting for log queue..."))
	flushLogQueue()

	if err := apiMetrics.SaveToFile(metricsPersistPath); err != nil {
		debugLog("SYSTEM", "", fmt.Sprintf(t(T.MetricsSaveFailed, "Metrics could not be saved: %v"), err))
	}

	safeCloseLogWriteQueue()
	shutdownHTTPServer(srv)

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
		debugLog("SCHEDULER", "", fmt.Sprintf(t(T.SchedulerIntervalChanged, "Interval changed → new ticker: %ds"), *currentInterval))
	}

	debugLog("SCHEDULER", "", t(T.SchedulerIntervalReached, "Interval reached, starting runUpdate(false)"))

	if activeUpdates.Load() > 0 {
		debugLog("SCHEDULER", "", t(T.SchedulerPreviousUpdateRunning, "⚠️ Previous update is still running. Skipping this cycle..."))

		limit := maxLogLines
		if interval > 500 && limit == DefaultMaxLogLines {
			limit = 1000
		}
		rotateLogFile(logPath, limit)
		return ticker
	}

	go runUpdate(false)

	limit := maxLogLines
	if interval > 500 && limit == DefaultMaxLogLines {
		limit = 1000
	}

	debugLog("MAINTENANCE", "", T.MaintenanceStarting)
	rotateLogFile(logPath, limit)

	return ticker
}

func handleShutdownSignal(sig os.Signal, ticker *time.Ticker, srv *http.Server) int {
	debugLog("SYSTEM", "", fmt.Sprintf(t(T.ShutdownSignalReceived, "Shutdown signal received: %v"), sig))

	stopCtx := LogContext{
		Level:   LogInfo,
		Action:  ActionStop,
		Message: fmt.Sprintf("🛑 %s (Signal: %v)", T.Shutdown, sig),
	}
	notifySync(stopCtx)
	stopCtx.SkipNotify = true
	log(stopCtx)

	ticker.Stop()
	shutdownCancel()

	if httpClient != nil {
		httpClient.CloseIdleConnections()
		debugLog("SYSTEM", "", T.HTTPConnectionsClosed)
	}

	waitForRunningUpdates()

	debugLog("SYSTEM", "", t(T.WaitingForLogQueue, "📝 Waiting for log queue..."))
	flushLogQueue()

	if err := apiMetrics.SaveToFile(metricsPersistPath); err != nil {
		debugLog("SYSTEM", "", fmt.Sprintf(t(T.MetricsSaveFailed, "Metrics could not be saved: %v"), err))
	}

	safeCloseLogWriteQueue()
	shutdownHTTPServer(srv)

	return 0
}

func safeCloseLogWriteQueue() {
	closeLogWriterOnce.Do(func() {
		close(logWriteQueue)
	})
}

func waitForRunningUpdates() {
	debugLog("SYSTEM", "", t(T.WaitingForRunningUpdates, "⏳ Waiting for running updates..."))

	waitCtx, waitCancel := context.WithTimeout(context.Background(), ShutdownWaitTimeout)
	defer waitCancel()

	done := make(chan bool, 1)
	go func() {
		defer close(done)
		for {
			if activeUpdates.Load() == 0 {
				done <- true
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()

	select {
	case <-done:
		debugLog("SYSTEM", "", t(T.AllUpdatesFinished, "✅ All updates finished"))
	case <-waitCtx.Done():
		debugLog("SYSTEM", "", t(T.WaitForUpdatesTimeout, "⚠️ Timeout while waiting for updates - force shutdown"))
	}
}

func shutdownHTTPServer(srv *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), ShutdownGraceTimeout)
	defer cancel()

	debugLog("SYSTEM", "", T.ServerShuttingDown)
	if err := srv.Shutdown(ctx); err != nil {
		log(LogContext{
			Level:   LogWarn,
			Action:  ActionError,
			Message: fmt.Sprintf("%s: %v", T.ShutdownError, err),
		})
	} else {
		debugLog("SYSTEM", "", T.ServerShutdownComplete)
	}
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
