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
func main() {
	exitCode := run()
	os.Exit(exitCode)
}

func run() int {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("[FATAL] Main-Panic: %v\n", r)

			flushLogQueue(2 * time.Second)

			if metricsPersistPath != "" {
				_ = apiMetrics.SaveToFile(metricsPersistPath)
			}

			select {
			case _, ok := <-logWriteQueue:
				if ok {
					close(logWriteQueue)
				}
			default:
			}
		}
	}()

	configDir = os.Getenv("CONFIG_DIR")
	if configDir == "" {
		configDir = "/config"
	}

	langDir = filepath.Join(configDir, "lang")
	logsDir := filepath.Join(configDir, "logs")
	metricsPersistPath = filepath.Join(logsDir, "metrics.json")
	if configPath == "" {
		configPath = filepath.Join(logsDir, "config.json")
	}

	copyEmbeddedLangFiles(langDir)

	if err := os.MkdirAll(langDir, 0755); err != nil {
		log(LogContext{
			Level:    LogError,
			Category: "CONFIG",
			Message:  fmt.Sprintf(t(T.LanguageDirCreateFailed, "Failed to create language directory: %v"), err),
		})
		return 1
	}

	log(LogContext{
		Level:    LogInfo,
		Category: "CONFIG",
		Message:  fmt.Sprintf(t(T.ConfigDir, "Config directory: %s"), configDir),
	})

	log(LogContext{
		Level:    LogInfo,
		Category: "CONFIG",
		Message:  fmt.Sprintf(t(T.ConfigLanguageDir, "Languages: %s"), langDir),
	})

	log(LogContext{
		Level:    LogInfo,
		Category: "CONFIG",
		Message:  fmt.Sprintf(t(T.ConfigLogsDir, "Logs: %s"), logsDir),
	})

	if err := apiMetrics.LoadFromFile(metricsPersistPath); err != nil {
		log(LogContext{
			Level:    LogWarn,
			Category: "CONFIG",
			Action:   ActionConfig,
			Message:  fmt.Sprintf(t(T.MetricsLoadFailed, "Failed to load metrics: %v"), err),
		})
	}

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

	dnsEnv := os.Getenv("DNS_SERVERS")
	var dnsList []string
	if dnsEnv != "" {
		parts := strings.Split(dnsEnv, ",")
		for _, p := range parts {
			trimmed := strings.TrimSpace(p)
			if trimmed != "" {
				dnsList = append(dnsList, trimmed)
			}
		}
	}

	tempmaxAPIRetries := DefaultMaxAPIRetries
	if s := strings.TrimSpace(os.Getenv("MAX_API_RETRIES")); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v >= 0 && v <= 20 {
			tempmaxAPIRetries = v
		} else {
			log(LogContext{
				Level:   LogWarn,
				Action:  ActionConfig,
				Message: fmt.Sprintf(t(T.MaxAPIRetriesInvalid, "Invalid MAX_API_RETRIES value '%s', using default %d"), s, DefaultMaxAPIRetries),
			})
		}
	}

	tempmaxLogLines := DefaultMaxLogLines
	if s := strings.TrimSpace(os.Getenv("LOG_MAX_LINES")); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			tempmaxLogLines = v
		} else {
			log(LogContext{
				Level:   LogWarn,
				Action:  ActionConfig,
				Message: fmt.Sprintf(t(T.LogMaxLinesInvalid, "Invalid LOG_MAX_LINES value '%s', using default %d"), s, DefaultMaxLogLines),
			})
		}
	}

	hourlyLimit := DefaultHourlyRateLimit
	if envLimit := os.Getenv("HOURLY_RATE_LIMIT"); envLimit != "" {
		if parsed, err := strconv.Atoi(envLimit); err == nil && parsed > 0 {
			hourlyLimit = parsed
		}
	}

	maxConcurrent := DefaultMaxConcurrent
	if envMax := os.Getenv("MAX_CONCURRENT"); envMax != "" {
		if parsed, err := strconv.Atoi(envMax); err == nil && parsed > 0 && parsed <= 20 {
			maxConcurrent = parsed
		}
	}

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

	configLoaded := false

	if data, err := os.ReadFile(configPath); err == nil {
		if err := json.Unmarshal(data, &cfg); err != nil {
			log(LogContext{
				Level:   LogWarn,
				Action:  ActionConfig,
				Message: fmt.Sprintf(t(T.ConfigJSONReadFailed, "config.json could not be read, using defaults: %v"), err),
			})
		} else if len(cfg.DomainConfigs) > 0 {
			configLoaded = true
		}
	}

	if !configLoaded {
		applyEnvOverrides(
			logsDir, tempInterval, dnsList,
			tempmaxAPIRetries, tempmaxLogLines,
			hourlyLimit, maxConcurrent,
		)
	}
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
		return 1
	}

	shutdownCtx, shutdownCancel = context.WithCancel(context.Background())
	defer shutdownCancel()

	workerSemaphore = make(chan struct{}, cfg.MaxConcurrent)

	if err := initProviderConfig(); err != nil {
		log(LogContext{
			Level:   LogError,
			Action:  ActionConfig,
			Message: fmt.Sprintf(t(T.ProviderConfigFailed, "Provider-%s failed: %v"), T.ConfigHeading, err),
		})
		return 1
	}

	initNotifiers()

	if cfg.DebugEnabled {
		debugLog("CONFIG", "", fmt.Sprintf(t(T.DebugModeActive, "Debug mode active. Interval: %ds, mode: %s"), cfg.Interval, cfg.IPMode))
		debugLog("CONFIG", "", fmt.Sprintf(t(T.LoadedDomains, "Loaded domains: %d"), len(cfg.DomainConfigs)))
		debugLog("CONFIG", "", fmt.Sprintf(t(T.MaxLogLinesInfo, "Max log lines: %d"), cfg.MaxLogLines))
		debugLog("CONFIG", "", fmt.Sprintf(t(T.MaxAPIRetriesInfo, "Max API retries: %d"), cfg.MaxAPIRetries))
		debugLog("CONFIG", "", fmt.Sprintf(t(T.MaxConcurrentInfo, "Max concurrent: %d"), cfg.MaxConcurrent))
		for _, dc := range cfg.DomainConfigs {
			debugLog("CONFIG", "", fmt.Sprintf("  - %s (%s)", dc.FQDN, dc.Provider))
		}
	}

	logHTTPClientStats()
	metricsBroadcasterLoop()

	if cfg.HealthPort == "" {
		cfg.HealthPort = "8080"
	}

	if err := os.MkdirAll(logsDir, 0755); err != nil {
		log(LogContext{
			Level:   LogError,
			Action:  ActionConfig,
			Message: fmt.Sprintf(t(T.LogDirCreateFailed, "Failed to create log directory: %v"), err),
		})
		return 1
	}

	if err := os.MkdirAll(langDir, 0755); err != nil {
		log(LogContext{
			Level:   LogError,
			Action:  ActionConfig,
			Message: fmt.Sprintf(t(T.LanguageDirCreateFailed, "Failed to create lang directory: %v"), err),
		})
		return 1
	}

	logPath = filepath.Join(logsDir, "dyndns.json")
	updatePath = filepath.Join(logsDir, "update.json")
	logCachePath = filepath.Join(logsDir, "log_cache.json")

	startMetricsAutosave(60 * time.Second)
	startLogWriter()

	if err := validateConfig(); err != nil {
		log(LogContext{
			Level:   LogError,
			Action:  ActionConfig,
			Message: fmt.Sprintf("%v", err),
		})
		return 1
	}

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

	globalTriggerLimiter = NewRateLimiter(10, 1.0/6.0)
	ipTriggerLimiter = NewIPRateLimiter(shutdownCtx, 5, 0.1)

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

	startCacheRefresher()
	startLogRotationWorker()

	srv := &http.Server{Addr: ":" + cfg.HealthPort, Handler: createMux()}

	go func() {
		debugLog("SYSTEM", "", fmt.Sprintf(T.DashboardStarted, cfg.HealthPort))
		log(LogContext{
			Level:   LogInfo,
			Action:  ActionServer,
			Message: fmt.Sprintf(T.DashboardStarted, cfg.HealthPort),
		})
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log(LogContext{
				Level:   LogError,
				Action:  ActionError,
				Message: fmt.Sprintf("%s: %v", T.ServerError, err),
			})
		}
	}()

	go wsHub.run()
	debugLog("SYSTEM", "", t(T.WebSocketHubStarted, "WebSocket hub started"))

	runUpdate(true)
	ticker := time.NewTicker(time.Duration(cfg.Interval) * time.Second)
	defer ticker.Stop()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-shutdownCtx.Done():
			debugLog("SCHEDULER", "", t(T.SchedulerShutdownActive, "Shutdown active, stopping scheduler"))
			return 0

		case <-ticker.C:
			debugLog("SCHEDULER", "", t(T.SchedulerIntervalReached, "Interval reached, starting runUpdate(false)"))
			if activeUpdates.Load() > 0 {
				debugLog("SCHEDULER", "", t(T.SchedulerPreviousUpdateRunning, "⚠️ Previous update is still running. Skipping this cycle..."))

				limit := cfg.MaxLogLines
				if cfg.Interval > 500 && limit == DefaultMaxLogLines {
					limit = 1000
				}
				rotateLogFile(logPath, limit)
				continue
			}

			go runUpdate(false)

			limit := cfg.MaxLogLines
			if cfg.Interval > 500 && limit == DefaultMaxLogLines {
				limit = 1000
			}

			debugLog("MAINTENANCE", "", T.MaintenanceStarting)
			rotateLogFile(logPath, limit)

		case sig := <-stop:
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

			debugLog("SYSTEM", "", t(T.WaitingForRunningUpdates, "⏳ Waiting for running updates..."))

			waitCtx, waitCancel := context.WithTimeout(context.Background(), ShutdownWaitTimeout)

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
			waitCancel()

			debugLog("SYSTEM", "", t(T.WaitingForLogQueue, "📝 Waiting for log queue..."))
			flushLogQueue(2 * time.Second)
			if err := apiMetrics.SaveToFile(metricsPersistPath); err != nil {
				debugLog("SYSTEM", "", fmt.Sprintf(t(T.MetricsSaveFailed, "Metrics could not be saved: %v"), err))
			}
			close(logWriteQueue)

			ctx, cancel := context.WithTimeout(context.Background(), ShutdownGraceTimeout)

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
			cancel()

			return 0
		}
	}
}

func applyEnvOverrides(
	logsDir string,
	tempInterval int,
	dnsList []string,
	maxAPIRetries, maxLogLines, hourlyLimit, maxConcurrent int,
) {
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
		cfg.DryRun = v == "true"
	}
	if v := os.Getenv("DEBUG"); v != "" {
		cfg.DebugEnabled = v == "true"
	}
	if v := os.Getenv("DEBUG_HTTP_RAW"); v != "" {
		cfg.DebugHTTPRaw = v == "true"
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
	if v := os.Getenv("TELEGRAM_BOT_TOKEN"); v != "" {
		cfg.Notifications.Telegram.Token = strings.TrimSpace(v)
	}
	if v := os.Getenv("TELEGRAM_CHAT_ID"); v != "" {
		cfg.Notifications.Telegram.ChatID = strings.TrimSpace(v)
	}
	if v := os.Getenv("GOTIFY_URL"); v != "" {
		cfg.Notifications.Gotify.URL = strings.TrimSpace(v)
	}
	if v := os.Getenv("GOTIFY_TOKEN"); v != "" {
		cfg.Notifications.Gotify.Token = strings.TrimSpace(v)
	}
	if v := os.Getenv("NOTIFY_ON"); v != "" {
		cfg.Notifications.Events = strings.Split(v, ",")
	}
	if !cfg.Notifications.Enabled {
		cfg.Notifications.Enabled =
			cfg.Notifications.Telegram.Token != "" ||
				cfg.Notifications.Gotify.URL != ""
	}
}
