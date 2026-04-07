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

	fmt.Printf("[INFO] Config-Verzeichnis: %s\n", configDir)
	fmt.Printf("[INFO] → Sprachen: %s\n", langDir)
	fmt.Printf("[INFO] → Logs: %s\n", logsDir)

	lang := detectLanguage(langDir)

	if err := os.MkdirAll(langDir, 0755); err != nil {
		fmt.Printf("[FATAL] Lang-Verzeichnis konnte nicht erstellt werden: %v\n", err)
		return 1
	}

	copyEmbeddedLangFiles(langDir)

	if err := loadLanguage(lang); err != nil {
		fmt.Printf("[FATAL] Sprachdatei konnte nicht geladen werden: %v\n", err)
		return 1
	}

	if err := apiMetrics.LoadFromFile(metricsPersistPath); err != nil {
		log(LogContext{
			Level:   LogWarn,
			Action:  ActionConfig,
			Message: fmt.Sprintf("Metrics konnten nicht geladen werden: %v", err),
		})
	}

	tempInterval := DefaultInterval
	if s := strings.TrimSpace(os.Getenv("INTERVAL")); s != "" {
		if i, err := strconv.Atoi(s); err == nil && i >= 30 {
			tempInterval = i
		} else {
			log(LogContext{
				Level:   LogWarn,
				Action:  ActionConfig,
				Message: fmt.Sprintf("Ungültiger INTERVAL Wert '%s', benutze Default 300", s),
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
				Message: fmt.Sprintf("Ungültiger MAX_API_RETRIES Wert '%s', benutze Default %d", s, DefaultMaxAPIRetries),
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
				Message: fmt.Sprintf("Ungültiger LOG_MAX_LINES Wert '%s', benutze Default %d", s, DefaultMaxLogLines),
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
		Lang:            lang,
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
				Message: fmt.Sprintf("config.json konnte nicht gelesen werden, nutze Defaults: %v", err),
			})
		} else if len(cfg.DomainConfigs) > 0 {
			configLoaded = true
		}
	}

	if !configLoaded {
		applyEnvOverrides(
			logsDir, lang, tempInterval, dnsList,
			tempmaxAPIRetries, tempmaxLogLines,
			hourlyLimit, maxConcurrent,
		)
	}

	workerSemaphore = make(chan struct{}, cfg.MaxConcurrent)

	if err := initProviderConfig(); err != nil {
		log(LogContext{
			Level:   LogError,
			Action:  ActionConfig,
			Message: fmt.Sprintf("Provider-%s fehlgeschlagen: %v", T.ConfigHeading, err),
		})
		return 1
	}

	initNotifiers()

	if cfg.DebugEnabled {
		debugLog("CONFIG", "", fmt.Sprintf("Debug-Modus aktiv. Intervall: %ds, Mode: %s", cfg.Interval, cfg.IPMode))
		debugLog("CONFIG", "", fmt.Sprintf("Geladene Domains: %d", len(cfg.DomainConfigs)))
		debugLog("CONFIG", "", fmt.Sprintf("Max Log Lines: %d", cfg.MaxLogLines))
		debugLog("CONFIG", "", fmt.Sprintf("Max API Retries: %d", cfg.MaxAPIRetries))
		debugLog("CONFIG", "", fmt.Sprintf("Max Concurrent: %d", cfg.MaxConcurrent))
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
			Message: fmt.Sprintf("Log-Verzeichnis konnte nicht erstellt werden: %v", err),
		})
		return 1
	}

	if err := os.MkdirAll(langDir, 0755); err != nil {
		log(LogContext{
			Level:   LogError,
			Action:  ActionConfig,
			Message: fmt.Sprintf("Lang-Verzeichnis konnte nicht erstellt werden: %v", err),
		})
		return 1
	}

	logPath = filepath.Join(logsDir, "dyndns.json")
	updatePath = filepath.Join(logsDir, "update.json")
	logCachePath = filepath.Join(logsDir, "log_cache.json")

	shutdownCtx, shutdownCancel = context.WithCancel(context.Background())
	defer shutdownCancel()

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
		Message: fmt.Sprintf("🚀 %s (Providers: %s)", T.Startup, strings.Join(providerNames, ", ")),
	})

	globalTriggerLimiter = NewRateLimiter(10, 1.0/6.0)
	ipTriggerLimiter = NewIPRateLimiter(5, 0.1, shutdownCtx)

	if err := updateDomainsCache(); err != nil {
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: fmt.Sprintf("Failed to update domain cache: %v", err),
		})
	}

	if err := updateMetricsCache(); err != nil {
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: fmt.Sprintf("Failed to update metric cache: %v", err),
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
	debugLog("SYSTEM", "", "WebSocket Hub gestartet")

	runUpdate(true)
	ticker := time.NewTicker(time.Duration(cfg.Interval) * time.Second)
	defer ticker.Stop()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-shutdownCtx.Done():
			debugLog("SCHEDULER", "", "Shutdown aktiv, beende Scheduler")
			return 0

		case <-ticker.C:
			debugLog("SCHEDULER", "", "Intervall erreicht, starte runUpdate(false)")
			if activeUpdates.Load() > 0 {
				debugLog("SCHEDULER", "", "⚠️ Vorheriges Update läuft noch. Überspringe diesen Durchlauf...")

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
			debugLog("SYSTEM", "", fmt.Sprintf("Shutdown Signal empfangen: %v", sig))
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

			debugLog("SYSTEM", "", "⏳ Warte auf laufende Updates...")

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
				debugLog("SYSTEM", "", "✅ Alle Updates abgeschlossen")
			case <-waitCtx.Done():
				debugLog("SYSTEM", "", "⚠️ Timeout beim Warten auf Updates - Force Shutdown")
			}
			waitCancel()

			debugLog("SYSTEM", "", "📝 Warte auf Log-Queue...")
			flushLogQueue(2 * time.Second)
			if err := apiMetrics.SaveToFile(metricsPersistPath); err != nil {
				debugLog("SYSTEM", "", fmt.Sprintf("Metrics konnten nicht gespeichert werden: %v", err))
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
	logsDir, lang string,
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
	if os.Getenv("LANG") != "" {
		cfg.Lang = lang
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
