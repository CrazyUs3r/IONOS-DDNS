package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"

	"github.com/gorilla/websocket"
)

// ============================================================================
// KONSTANTEN
// ============================================================================

const (
	// Actions
	ActionStart   = "START"
	ActionStop    = "STOP"
	ActionUpdate  = "UPDATE"
	ActionCreate  = "CREATE"
	ActionCurrent = "CURRENT"
	ActionRetry   = "RETRY"
	ActionError   = "ERROR"
	ActionConfig  = "CONFIG"
	ActionZone    = "ZONE"
	ActionDryRun  = "DRY-RUN"
	ActionCleanup = "CLEANUP"

	// Defaults
	DefaultMaxLogLines     = 500
	DefaultHourlyRateLimit = 1200
	DefaultMaxConcurrent   = 5
	MaxAPIRetries          = 3

	// Timeouts
	APITimeout           = 25 * time.Second
	BaseUpdateTimeout    = 50 * time.Second
	PerDomainTimeout     = 10 * time.Second
	UpdateBufferTimeout  = 30 * time.Second
	MinUpdateTimeout     = 50 * time.Second
	MaxUpdateTimeout     = 10 * time.Minute
	IPCheckTimeout       = 10 * time.Second
	DNSDialTimeout       = 3 * time.Second
	DNSResolverTimeout   = 10 * time.Second
	DNSKeepalive         = 30 * time.Second
	ShutdownGraceTimeout = 5 * time.Second
	ShutdownWaitTimeout  = 10 * time.Second

	// HTTP Transport
	HTTPMaxIdleConns     = 10
	HTTPMaxIdleConnsHost = 3
	HTTPMaxConnsHost     = 5
	HTTPIdleConnTimeout  = 60 * time.Second
	HTTPTLSTimeout       = 10 * time.Second
	HTTPResponseTimeout  = 10 * time.Second
	HTTPExpectTimeout    = 1 * time.Second

	// WebSocket
	WSWriteTimeout = 10 * time.Second
	WSPongTimeout  = 60 * time.Second
	WSPingInterval = 30 * time.Second

	// Retry
	RetryBaseDelay        = 1 * time.Second
	RetryMaxDelay         = 60 * time.Second
	RetryJitterMaxMs      = 1000
	RetryExponentBase     = 2.0
	RateLimitRetryDelay   = 60 * time.Second
	ServerErrorRetryDelay = 30 * time.Second

	// Misc
	IPCheckBodyMaxBytes   = 1024
	MaxStatusHistoryItems = 20
	TriggerTokenHeader    = "X-Trigger-Token"
)

type ProviderType string

const (
	ProviderIONOS      ProviderType = "IONOS"
	ProviderCloudflare ProviderType = "CLOUDFLARE"
	ProviderIPv64      ProviderType = "IPV64"
)

var actionClass = map[string]string{
	ActionStart:   "act-start",
	ActionStop:    "act-stop",
	ActionUpdate:  "act-update",
	ActionCreate:  "act-create",
	ActionRetry:   "act-retry",
	ActionError:   "act-error",
	ActionZone:    "act-error",
	ActionConfig:  "act-error",
	ActionDryRun:  "act-dryrun",
	ActionCleanup: "act-cleanup",
}

var persistentActions = map[string]bool{
	"START":   true,
	"STOP":    true,
	"UPDATE":  true,
	"CREATE":  true,
	"ERROR":   true,
	"RETRY":   true,
	"CONFIG":  true,
	"ZONE":    true,
	"CLEANUP": true,
}

// ============================================================================
// STRUKTUREN
// ============================================================================

type Phrases struct {
	// Basis & Dashboard
	Startup, Shutdown, NoZones, Update, Created, Current, DryRunWarn, ConfigError string
	DashTitle, StatusOk, StatusErr, LastUpdate, InfraHeading, ZoneLabel           string
	ServiceStarted, ServiceStopped, DashboardStarted, ServerError                 string
	HealthCheckOK, HealthCheckFailed, SystemEvents, History, EventLog             string
	DomainStatus, Provider, LastChanged, Ipv4Label, Ipv6Label                     string

	// Statistiken & Metriken
	Requests, SuccessRate, LastSuccess, AvgLatency, Errors, HourlyLimit       string
	RequestHistory, LatencyHistory, ApiPerformance, BasedOnLast60Min          string
	UnhealthyStatus, DetailedStats, TotalRequests, ClientErrors, ServerErrors string

	// Validierung & Log
	NoDomains, InvalidDomain, NoZoneFound, NoValidDomains, RootDomain string
	CouldNotExtractDomain, LogRotated, LogRotationError               string

	// DNS & Netzwerk Logik
	RecordFound, RecordCurrent, NoRecordFound, RecordUpdateNeeded, WouldSet   string
	APICall, PayloadSent, ReceivedIp, CheckingInterface, InterfaceNotFound    string
	AddressesNotReadable, NoIpv6OnInterface, FallbackToExternal               string
	Attempt, NetworkError, RetryIn, Success, BodyReadError, NonRetryableError string
	MaxAttemptsReached, RetryScheduled, ContextCancelled, ContextExpired      string

	// Worker & Status
	WorkerSlotAcquired, WorkerProcessingComplete, WorkerSlotReleased   string
	NoZoneFoundForDomain, NoRecordsInCache, CheckingIpv4, CheckingIpv6 string
	UpdateFailed, CriticalError, ChangesDetected, WritingStatusFile    string
	NoChangesNeeded, SchedulerStarted, SchedulerCompleted              string

	// Konfiguration
	ConfigHeading, ConfigAPIPrefix, ConfigDomains, ConfigInterval string
	ConfigIpMode, ConfigInterface, ConfigHealthPort, ConfigDryRun string
	ConfigLogDir, ConfigLanguage                                  string

	// API Fehler & System
	BadRequest, Unauthorized, Forbidden, NotFound, UnprocessableEntity     string
	RateLimitExceeded, InternalServerError, BadGateway, ServiceUnavailable string
	GatewayTimeout, MaintenanceStarting, HTTPConnectionsClosed             string
	ServerShuttingDown, ServerShutdownComplete, ShutdownError              string

	// Sonstiges
	Mode, NoDNSServer, DNSFailover, HttpClientInitialized                 string
	InvalidPort, UsingDefaultPort, IntervalTooSmall, ShortIntervalWarning string
	InvalidIPMode, UsingDefaultMode                                       string
}

type LogLevel int

const (
	LogDebug LogLevel = iota
	LogInfo
	LogWarn
	LogError
)

type LogContext struct {
	Level    LogLevel
	Action   string
	Domain   string
	Category string
	Message  string
	Error    error
}

type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Action    string `json:"action"`
	Domain    string `json:"domain"`
	Message   string `json:"message"`
}

type IPEntry struct {
	Time string `json:"time"`
	IPv4 string `json:"ipv4,omitempty"`
	IPv6 string `json:"ipv6,omitempty"`
}

type DomainHistory struct {
	IPs         []IPEntry `json:"ips"`
	Provider    string    `json:"provider"`
	LastChanged string    `json:"last_changed"`
}

type Config struct {
	// Provider
	Provider         ProviderType
	CloudflareToken  string
	CloudflareEmail  string
	CloudflareZoneID string
	IPv64Token       string

	// IONOS (existing)
	APIPrefix string
	APISecret string

	// Common
	IPMode          string
	IfaceName       string
	HealthPort      string
	LogDir          string
	Lang            string
	Domains         []string
	DNSServers      []string
	Interval        int
	DryRun          bool
	DebugEnabled    bool
	DebugHTTPRaw    bool
	HourlyRateLimit int
	MaxConcurrent   int
}

type Zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Record struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
}

type DNSRecord struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
}

type CloudflareZone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

type CloudflareRecord struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

type CloudflareResponse struct {
	Success  bool              `json:"success"`
	Errors   []CloudflareError `json:"errors"`
	Messages []string          `json:"messages"`
	Result   interface{}       `json:"result"`
}

type CloudflareError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type IPv64Domain struct {
	Domain string `json:"domain"`
	Type   string `json:"type"`
	IPv4   string `json:"ipv4"`
	IPv6   string `json:"ipv6"`
}

type IPv64Response struct {
	Info    string                 `json:"info"`
	Domains map[string]IPv64Domain `json:"domains,omitempty"`
}

type ZoneRecordCache struct {
	sync.RWMutex
	data map[string][]Record
}

type APIError struct {
	StatusCode int
	Method     string
	URL        string
	Message    string
	Retryable  bool
	RetryAfter time.Duration
}

type APIMetrics struct {
	sync.Mutex
	TotalRequests        int64
	SuccessRequests      int64
	FailedRequests       int64
	RateLimitHits        int64
	ServerErrors         int64
	ClientErrors         int64
	AverageLatency       time.Duration
	LastError            string
	LastErrorTimestamp   time.Time
	LastSuccessTimestamp time.Time
	RequestTimestamps    []time.Time
	HourlyStats          [24]int
	lastHour             int64
	HourlyLatency        [24]time.Duration
}

type SafeErrorMsg struct {
	sync.RWMutex
	msg string
}

type WSMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

type WSHub struct {
	clients    map[*websocket.Conn]bool
	broadcast  chan WSMessage
	register   chan *websocket.Conn
	unregister chan *websocket.Conn
	mu         sync.RWMutex
}

type CachedResponse struct {
	Data         []byte
	ETag         string
	LastModified time.Time
	mu           sync.RWMutex
}

type RateLimiter struct {
	tokens     float64
	maxTokens  float64
	refillRate float64
	lastRefill time.Time
	mu         sync.Mutex
}

type IPRateLimiter struct {
	limiters    map[string]*RateLimiter
	mu          sync.RWMutex
	cleanup     time.Duration
	tokensPerIP float64
	refillRate  float64
}

type loggingTransport struct {
	base http.RoundTripper
}

type domainUpdateJob struct {
	Domain   string
	ZoneID   string
	ZoneName string
	Records  []Record
	IPv4     string
	IPv6     string
}

type domainUpdateResult struct {
	Domain  string
	Changed bool
	Error   error
}

// ============================================================================
// GLOBALE VARIABLEN
// ============================================================================

var (
	cfg               Config
	T                 Phrases
	configDir         string
	langDir           string
	logPath           string
	updatePath        string
	apiBaseURL        = "https://api.hosting.ionos.com/dns/v1/zones"
	cloudflareAPIBase = "https://api.cloudflare.com/client/v4"
	ipv64APIBase      = "https://ipv64.net/api"

	lastOk       atomic.Bool
	logMutex     sync.Mutex
	statusMutex  sync.Mutex
	lastErrorMsg = &SafeErrorMsg{}

	httpClient *http.Client
	clientOnce sync.Once
	apiMetrics = &APIMetrics{}

	domainRegex = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`)
	labelRegex  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

	secretReplacer     *strings.Replacer
	secretReplacerOnce sync.Once

	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc

	globalTriggerLimiter *RateLimiter
	ipTriggerLimiter     *IPRateLimiter
	updateInProgress     atomic.Bool

	domainsCache = &CachedResponse{}
	metricsCache = &CachedResponse{}

	rotationQueue = make(chan struct{}, 1)

	wsHub = &WSHub{
		clients:    make(map[*websocket.Conn]bool),
		broadcast:  make(chan WSMessage, 256),
		register:   make(chan *websocket.Conn),
		unregister: make(chan *websocket.Conn),
	}
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			return origin == "" || strings.Contains(origin, r.Host)
		},
	}
)

// ============================================================================
// PROVIDER INITIALIZATION
// ============================================================================

func initProviderConfig() error {
	providerEnv := strings.ToUpper(os.Getenv("PROVIDER"))

	switch providerEnv {
	case "CLOUDFLARE":
		cfg.Provider = ProviderCloudflare
		cfg.CloudflareToken = os.Getenv("CLOUDFLARE_TOKEN")
		cfg.CloudflareEmail = os.Getenv("CLOUDFLARE_EMAIL")
		cfg.CloudflareZoneID = os.Getenv("CLOUDFLARE_ZONE_ID")

		if cfg.CloudflareToken == "" && (cfg.CloudflareEmail == "" || cfg.APISecret == "") {
			return fmt.Errorf("cloudflare requires CLOUDFLARE_TOKEN or CLOUDFLARE_EMAIL + API_SECRET")
		}

		debugLog("CONFIG", "", "Provider: Cloudflare (API Token Auth)")

	case "IPV64":
		cfg.Provider = ProviderIPv64
		cfg.IPv64Token = os.Getenv("IPV64_TOKEN")

		if cfg.IPv64Token == "" {
			return fmt.Errorf("ipv64 requires IPV64_TOKEN")
		}

		debugLog("CONFIG", "", "Provider: IPv64")

	case "IONOS", "":
		cfg.Provider = ProviderIONOS
		debugLog("CONFIG", "", "Provider: IONOS")

	default:
		return fmt.Errorf("unknown provider: %s (supported: IONOS, CLOUDFLARE, IPV64)", providerEnv)
	}

	return nil
}

// ============================================================================
// RATE LIMITER
// ============================================================================

func NewRateLimiter(maxTokens float64, refillPerSecond float64) *RateLimiter {
	return &RateLimiter{
		tokens:     maxTokens,
		maxTokens:  maxTokens,
		refillRate: refillPerSecond,
		lastRefill: time.Now(),
	}
}

func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastRefill).Seconds()
	rl.tokens = math.Min(rl.maxTokens, rl.tokens+elapsed*rl.refillRate)
	rl.lastRefill = now

	if rl.tokens >= 1.0 {
		rl.tokens -= 1.0
		return true
	}

	return false
}

func (rl *RateLimiter) Remaining() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastRefill).Seconds()
	tokens := math.Min(rl.maxTokens, rl.tokens+elapsed*rl.refillRate)

	return int(tokens)
}

func NewIPRateLimiter(tokensPerIP, refillRate float64) *IPRateLimiter {
	limiter := &IPRateLimiter{
		limiters:    make(map[string]*RateLimiter),
		cleanup:     5 * time.Minute,
		tokensPerIP: tokensPerIP,
		refillRate:  refillRate,
	}
	go limiter.cleanupRoutine()
	return limiter
}

func (ipl *IPRateLimiter) GetLimiter(ip string) *RateLimiter {
	ipl.mu.RLock()
	limiter, exists := ipl.limiters[ip]
	ipl.mu.RUnlock()

	if exists {
		return limiter
	}

	ipl.mu.Lock()
	defer ipl.mu.Unlock()

	if limiter, exists := ipl.limiters[ip]; exists {
		return limiter
	}

	limiter = NewRateLimiter(ipl.tokensPerIP, ipl.refillRate)
	ipl.limiters[ip] = limiter

	return limiter
}

func (ipl *IPRateLimiter) cleanupRoutine() {
	ticker := time.NewTicker(ipl.cleanup)
	defer ticker.Stop()

	for range ticker.C {
		ipl.mu.Lock()

		for ip, limiter := range ipl.limiters {
			limiter.mu.Lock()
			inactive := time.Since(limiter.lastRefill) > ipl.cleanup
			limiter.mu.Unlock()

			if inactive {
				delete(ipl.limiters, ip)
			}
		}

		ipl.mu.Unlock()
	}
}

// ============================================================================
// LOGGING
// ============================================================================

func log(ctx LogContext) {
	if ctx.Level == LogDebug && !cfg.DebugEnabled {
		return
	}

	var levelStr, icon string
	switch ctx.Level {
	case LogDebug:
		levelStr, icon = "DBG", "🐞"
	case LogInfo:
		levelStr, icon = "INFO", "ℹ️"
	case LogWarn:
		levelStr, icon = "WARN", "⚠️"
	case LogError:
		levelStr, icon = "ERR", "❌"
	}

	if ctx.Level == LogInfo && ctx.Action == ActionCurrent {
		icon = "✅"
	}

	ts := time.Now().Local().Format("02.01.2006 15:04:05")

	var msg string
	if ctx.Error != nil {
		msg = fmt.Sprintf("%s: %v", ctx.Message, ctx.Error)
	} else {
		msg = ctx.Message
	}

	if ctx.Category != "" {
		icon = getCategoryIcon(ctx.Category)
	}

	if ctx.Domain != "" {
		if ctx.Category != "" {
			fmt.Printf("[%s] [%-4s] %s %-12s | %-35s: %s\n",
				ts, levelStr, icon, ctx.Category, ctx.Domain, msg)
		} else {
			fmt.Printf("[%s] [%-4s] %s %-35s: %s\n",
				ts, levelStr, icon, ctx.Domain, msg)
		}
	} else if ctx.Category != "" {
		fmt.Printf("[%s] [%-4s] %s %-12s: %s\n",
			ts, levelStr, icon, ctx.Category, msg)
	} else {
		fmt.Printf("[%s] [%-4s] %s %s\n",
			ts, levelStr, icon, msg)
	}

	if shouldPersistLevel(ctx.Level, ctx.Action) {
		persistLog(ctx)
	}
}

func getCategoryIcon(category string) string {
	icons := map[string]string{
		"SYSTEM":       "⚙️",
		"CONFIG":       "⚙️",
		"DNS":          "🌐",
		"ZONE":         "🌐",
		"API":          "🌐",
		"NETWORK":      "📡",
		"IP":           "📡",
		"IP-CHECK":     "📡",
		"SCHEDULER":    "⏱️",
		"MAINTENANCE":  "🧹",
		"SERVER":       "📊",
		"HTTP":         "📊",
		"HTTP-RAW":     "📝",
		"WS":           "🔌",
		"WORKER":       "👷",
		"DNS-LOGIC":    "🔧",
		"CACHE":        "💾",
		"DNS-FAILOVER": "🔀",
		"STATUS":       "📄",
	}

	if icon, ok := icons[category]; ok {
		return icon
	}
	return "🐞"
}

func shouldPersistLevel(level LogLevel, action string) bool {
	if level == LogError || level == LogWarn {
		return persistentActions[action]
	}

	switch action {
	case ActionStart, ActionStop, ActionUpdate, ActionCreate, ActionCleanup:
		return true
	}
	return false
}

func persistLog(ctx LogContext) {
	logMutex.Lock()
	defer logMutex.Unlock()

	sanitizedMsg := ctx.Message
	if replacer := getSecretReplacer(); replacer != nil {
		sanitizedMsg = replacer.Replace(sanitizedMsg)
	}

	entry := LogEntry{
		Timestamp: time.Now().Format("2006-01-02T15:04:05"),
		Level:     levelToString(ctx.Level),
		Action:    ctx.Action,
		Domain:    ctx.Domain,
		Message:   sanitizedMsg,
	}

	if js, err := json.Marshal(entry); err == nil {
		if f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
			defer f.Close()
			_, _ = f.Write(append(js, '\n'))
		}
	}
}

func levelToString(level LogLevel) string {
	switch level {
	case LogDebug:
		return "DBG"
	case LogInfo:
		return "INFO"
	case LogWarn:
		return "WARN"
	case LogError:
		return "ERR"
	default:
		return "INFO"
	}
}

func writeLog(level, action, domain, msg string) {
	var logLevel LogLevel
	switch level {
	case "DBG":
		logLevel = LogDebug
	case "WARN":
		logLevel = LogWarn
	case "ERR":
		logLevel = LogError
	case "CURRENT":
		logLevel = LogInfo
	default:
		logLevel = LogInfo
	}

	log(LogContext{
		Level:   logLevel,
		Action:  action,
		Domain:  domain,
		Message: msg,
	})
}

func debugLog(category, domain, msg string) {
	log(LogContext{
		Level:    LogDebug,
		Category: category,
		Domain:   domain,
		Message:  msg,
	})
}

// ============================================================================
// LOG ROTATION
// ============================================================================

func rotateLogFile(path string, maxLines int) {
	select {
	case rotationQueue <- struct{}{}:
	default:
		debugLog("MAINTENANCE", "", "Log-Rotation bereits aktiv, überspringe")
	}
}

func rotationWorker(path string, maxLogLines int) {
	for range rotationQueue {
		func() {
			logMutex.Lock()
			defer logMutex.Unlock()

			data, err := os.ReadFile(path)
			if err != nil {
				if !os.IsNotExist(err) {
					fmt.Printf("[WARN] %s: %v\n", T.LogRotationError, err)
				}
				return
			}

			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			if len(lines) <= maxLogLines {
				return
			}

			newLines := lines[len(lines)-maxLogLines:]
			output := strings.Join(newLines, "\n") + "\n"

			tmpPath := path + ".tmp." + strconv.FormatInt(time.Now().UnixNano(), 10)
			if err := os.WriteFile(tmpPath, []byte(output), 0644); err != nil {
				fmt.Printf("[WARN] %s: %v\n", T.LogRotationError, err)
				return
			}

			if err := os.Rename(tmpPath, path); err != nil {
				fmt.Printf("[WARN] %s: %v\n", T.LogRotationError, err)
				_ = os.Remove(tmpPath)
				return
			}

			debugLog("MAINTENANCE", "", fmt.Sprintf("✅ %s: %d → %d", T.LogRotated, len(lines), len(newLines)))
		}()
	}
}

// ============================================================================
// HTTP CLIENT & TRANSPORT
// ============================================================================

func (t *loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if cfg.DebugHTTPRaw {
		logReq := req.Clone(req.Context())
		if req.GetBody != nil {
			if rc, err := req.GetBody(); err == nil {
				logReq.Body = rc
			}
		}

		if apiKey := logReq.Header.Get("X-API-Key"); apiKey != "" {
			parts := strings.Split(apiKey, ".")
			if len(parts) == 2 {
				logReq.Header.Set("X-API-Key", parts[0][:5]+"***."+"***"+parts[1][len(parts[1])-5:])
			} else {
				logReq.Header.Set("X-API-Key", "***MASKED***")
			}
		}

		if auth := logReq.Header.Get("Authorization"); auth != "" {
			if strings.HasPrefix(auth, "Bearer ") {
				logReq.Header.Set("Authorization", "Bearer ***MASKED***")
			}
		}

		requestDump, _ := httputil.DumpRequestOut(logReq, true)
		debugLog("HTTP-RAW", "", "\n>>> REQUEST >>>\n"+string(requestDump))
	}

	start := time.Now()
	resp, err := t.base.RoundTrip(req)
	duration := time.Since(start)

	if err != nil {
		return nil, err
	}

	if cfg.DebugHTTPRaw && resp != nil {
		var bodyBytes []byte
		if resp.Body != nil {
			bodyBytes, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
			resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		bodyStr := string(bodyBytes)
		if replacer := getSecretReplacer(); replacer != nil {
			bodyStr = replacer.Replace(bodyStr)
		}

		var prettyJSON bytes.Buffer
		if err := json.Indent(&prettyJSON, []byte(bodyStr), "", "  "); err == nil {
			bodyStr = prettyJSON.String()
		}

		maxDebugLen := 5000
		if len(bodyStr) > maxDebugLen {
			totalLen := len(bodyStr)
			bodyStr = bodyStr[:maxDebugLen] + fmt.Sprintf("\n... (%d bytes truncated for debug log)", totalLen-maxDebugLen)
		}

		debugLog("HTTP-RAW", "", fmt.Sprintf("\n<<< RESPONSE (%.2fs) <<<\nStatus: %s\nBody:\n%s\n",
			duration.Seconds(),
			resp.Status,
			bodyStr))
	}
	return resp, nil
}

func getHTTPClient() *http.Client {
	clientOnce.Do(func() {
		dnsList := cfg.DNSServers
		if len(dnsList) == 0 {
			dnsList = []string{"1.1.1.1:53", "8.8.8.8:53"}
		}

		dialer := &net.Dialer{
			Timeout:   DNSResolverTimeout,
			KeepAlive: DNSKeepalive,
			Resolver: &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					var lastErr error

					for i, dnsAddr := range dnsList {
						targetAddr := dnsAddr
						if !strings.Contains(targetAddr, ":") {
							targetAddr += ":53"
						}

						d := net.Dialer{
							Timeout: DNSDialTimeout,
						}

						conn, err := d.DialContext(ctx, "udp", targetAddr)
						if err == nil {
							return conn, nil
						}

						lastErr = err
						if i == len(dnsList)-1 {
							debugLog("DNS-FAILOVER", "", fmt.Sprintf("⚠️ %s %s: %v", T.NoDNSServer, targetAddr, err))
						}
					}

					return nil, fmt.Errorf("alle konfigurierten DNS-Server fehlgeschlagen: %w", lastErr)
				},
			},
		}

		baseTransport := &http.Transport{
			DialContext:           dialer.DialContext,
			MaxIdleConns:          HTTPMaxIdleConns,
			MaxIdleConnsPerHost:   HTTPMaxIdleConnsHost,
			MaxConnsPerHost:       HTTPMaxConnsHost,
			IdleConnTimeout:       HTTPIdleConnTimeout,
			TLSHandshakeTimeout:   HTTPTLSTimeout,
			ResponseHeaderTimeout: HTTPResponseTimeout,
			ExpectContinueTimeout: HTTPExpectTimeout,
			DisableKeepAlives:     false,
			ForceAttemptHTTP2:     true,
		}

		httpClient = &http.Client{
			Timeout: 0,
			Transport: &loggingTransport{
				base: baseTransport,
			},
		}

		debugLog("SYSTEM", "", fmt.Sprintf(T.HttpClientInitialized, len(dnsList)))
	})

	return httpClient
}

// ============================================================================
// SANITIZATION
// ============================================================================

func getSecretReplacer() *strings.Replacer {
	secretReplacerOnce.Do(func() {
		replacements := []string{}

		if cfg.APIPrefix != "" && cfg.APISecret != "" {
			fullKey := cfg.APIPrefix + "." + cfg.APISecret
			replacements = append(replacements, fullKey, "***API-KEY***")
		}

		if cfg.APISecret != "" {
			replacements = append(replacements, cfg.APISecret, "***SECRET***")
		}

		if cfg.APIPrefix != "" {
			replacements = append(replacements, cfg.APIPrefix, "***PREFIX***")
		}

		if cfg.CloudflareToken != "" {
			replacements = append(replacements, cfg.CloudflareToken, "***CF-TOKEN***")
		}

		if cfg.IPv64Token != "" {
			replacements = append(replacements, cfg.IPv64Token, "***IPV64-TOKEN***")
		}

		if len(replacements) > 0 {
			secretReplacer = strings.NewReplacer(replacements...)
		}
	})

	return secretReplacer
}

func sanitizeError(err error) string {
	if err == nil {
		return ""
	}

	msg := err.Error()

	if replacer := getSecretReplacer(); replacer != nil {
		msg = replacer.Replace(msg)
	}

	return msg
}

// ============================================================================
// VALIDATION
// ============================================================================

func validateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("domain is empty")
	}

	if len(domain) > 253 {
		return fmt.Errorf("domain too long: %d chars (max 253)", len(domain))
	}

	if !domainRegex.MatchString(domain) {
		return fmt.Errorf("invalid domain format: %s", domain)
	}

	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if len(label) > 63 {
			return fmt.Errorf("label '%s' too long: %d chars (max 63)", label, len(label))
		}
		if !labelRegex.MatchString(label) {
			return fmt.Errorf("invalid label: %s", label)
		}
	}

	return nil
}

func validateConfig() error {
	var errs []string

	switch cfg.Provider {
	case ProviderIONOS:
		if cfg.APIPrefix == "" {
			errs = append(errs, "API_PREFIX fehlt")
		}
		if cfg.APISecret == "" {
			errs = append(errs, "API_SECRET fehlt")
		}
	case ProviderCloudflare:
		if cfg.CloudflareToken == "" && (cfg.CloudflareEmail == "" || cfg.APISecret == "") {
			errs = append(errs, "CLOUDFLARE_TOKEN oder CLOUDFLARE_EMAIL + API_SECRET fehlt")
		}
	case ProviderIPv64:
		if cfg.IPv64Token == "" {
			errs = append(errs, "IPV64_TOKEN fehlt")
		}
	}

	if len(cfg.Domains) == 0 {
		errs = append(errs, T.NoDomains)
	}

	port, err := strconv.Atoi(cfg.HealthPort)
	if err != nil || port < 1 || port > 65535 {
		log(LogContext{
			Level:   LogWarn,
			Action:  ActionConfig,
			Message: fmt.Sprintf(T.InvalidPort, cfg.HealthPort),
		})
		cfg.HealthPort = "8080"
	}

	if cfg.Interval < 60 {
		if cfg.Interval < 30 {
			log(LogContext{
				Level:   LogWarn,
				Action:  ActionConfig,
				Message: T.IntervalTooSmall,
			})
			cfg.Interval = 60
		} else if len(cfg.Domains) > 10 {
			log(LogContext{
				Level:   LogWarn,
				Action:  ActionConfig,
				Message: "⚠️ " + T.ShortIntervalWarning,
			})
		}
	}

	validModes := map[string]bool{"IPV4": true, "IPV6": true, "BOTH": true}
	if !validModes[cfg.IPMode] {
		log(LogContext{
			Level:   LogWarn,
			Action:  ActionConfig,
			Message: fmt.Sprintf(T.InvalidIPMode, cfg.IPMode),
		})
		cfg.IPMode = "BOTH"
	}

	if len(errs) > 0 {
		return fmt.Errorf("Config-Fehler: %s", strings.Join(errs, ", "))
	}

	return nil
}

// ============================================================================
// API - IONOS
// ============================================================================

func calculateRetryDelay(attempt int, isServerError bool) time.Duration {
	baseWait := time.Duration(math.Pow(RetryExponentBase, float64(attempt+1))) * RetryBaseDelay
	if baseWait < RetryBaseDelay {
		baseWait = RetryBaseDelay
	}
	if baseWait > RetryMaxDelay {
		baseWait = RetryMaxDelay
	}

	jitter := time.Duration(rand.Intn(RetryJitterMaxMs)) * time.Millisecond
	wait := baseWait + jitter

	if isServerError {
		wait = wait * 2
		if wait > RetryMaxDelay {
			wait = RetryMaxDelay
		}
	}

	return wait
}

func ionosAPI(ctx context.Context, method, url string, body interface{}) ([]byte, error) {
	var lastErr error

	for attempt := 0; attempt < MaxAPIRetries; attempt++ {
		start := time.Now()
		debugLog("HTTP", "", fmt.Sprintf(
			"🔄 %s %d/%d: %s %s",
			T.Attempt, attempt+1, MaxAPIRetries, method, url,
		))

		var bodyBytes []byte
		var err error

		if body != nil {
			bodyBytes, err = json.Marshal(body)
			if err != nil {
				return nil, fmt.Errorf("json marshal failed: %w", err)
			}
			debugLog("HTTP", "", fmt.Sprintf("📤 %s: %s", T.PayloadSent, string(bodyBytes)))
		}

		req, err := http.NewRequestWithContext(
			ctx,
			method,
			url,
			bytes.NewReader(bodyBytes),
		)
		if err != nil {
			return nil, fmt.Errorf("request creation failed: %w", err)
		}

		if body != nil {
			req.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(bodyBytes)), nil
			}
		}

		apiKey := strings.TrimSpace(cfg.APIPrefix) + "." + strings.TrimSpace(cfg.APISecret)
		req.Header.Set("X-Api-Key", apiKey)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("User-Agent", "Go-DynDNS/2.0")

		res, err := getHTTPClient().Do(req)
		duration := time.Since(start)

		if err != nil {
			debugLog("HTTP", "", fmt.Sprintf("❌ %s: %v | %s: %v", T.NetworkError, err, T.AvgLatency, duration))
			apiMetrics.RecordError(0, err, duration)
			lastErr = fmt.Errorf("network error: %w", err)

			wait := calculateRetryDelay(attempt, false)
			debugLog("HTTP", "", fmt.Sprintf("⏱️  %s %v", T.RetryIn, wait))

			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
			}
			continue
		}
		defer res.Body.Close()

		debugLog("HTTP", "", fmt.Sprintf("✅ Status: %d | %s: %v", res.StatusCode, T.AvgLatency, duration))

		respBody, err := io.ReadAll(res.Body)

		if err != nil {
			apiMetrics.RecordError(res.StatusCode, err, duration)
			debugLog("HTTP", "", fmt.Sprintf("❌ %s: %v", T.BodyReadError, err))
			lastErr = fmt.Errorf("failed to read response body: %w", err)

			wait := calculateRetryDelay(attempt, false)
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
			}
			continue
		}

		if res.StatusCode >= 200 && res.StatusCode < 300 {
			apiMetrics.RecordSuccess(duration)

			if errVal := lastErrorMsg.Get(); errVal != "" {
				lastErrorMsg.Set("")
			}
			debugLog("HTTP", "", fmt.Sprintf("✅ %s: %d Bytes", T.Success, len(respBody)))
			return respBody, nil
		}

		apiErr := classifyAPIError(res.StatusCode, method, url, string(respBody))
		apiMetrics.RecordError(res.StatusCode, fmt.Errorf("%v", apiErr), duration)

		if res.StatusCode == 401 || res.StatusCode == 403 {
			log(LogContext{
				Level:   LogError,
				Action:  ActionError,
				Message: fmt.Sprintf("🚨 KRITISCHER API-FEHLER: %v", apiErr),
			})
		}

		debugLog("HTTP", "", fmt.Sprintf("⚠️  %s (Retryable: %v)", apiErr.Message, apiErr.Retryable))
		lastErr = apiErr
		lastErrorMsg.Set(sanitizeError(lastErr))

		if !apiErr.IsRetryable() {
			debugLog("HTTP", "", fmt.Sprintf("❌ %s: %s", T.NonRetryableError, apiErr.Message))
			return nil, apiErr
		}

		if attempt >= MaxAPIRetries-1 {
			debugLog("HTTP", "", fmt.Sprintf("❌ %s (%d)", T.MaxAttemptsReached, MaxAPIRetries))
			return nil, fmt.Errorf("maximale Versuche erreicht: %w", apiErr)
		}

		var wait time.Duration
		if apiErr.RetryAfter > 0 {
			wait = apiErr.RetryAfter
		} else {
			wait = calculateRetryDelay(attempt, res.StatusCode >= 500)
		}

		debugLog("HTTP", "", fmt.Sprintf("🔄 %s #%d in %v...", T.RetryScheduled, attempt+2, wait))

		select {
		case <-time.After(wait):
		case <-ctx.Done():
			debugLog("HTTP", "", "❌ "+T.ContextCancelled)
			return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
		}
	}

	return nil, fmt.Errorf("API fehlgeschlagen nach %d Versuchen: %w", MaxAPIRetries, lastErr)
}

// ============================================================================
// API - CLOUDFLARE
// ============================================================================

func cloudflareAPI(ctx context.Context, method, endpoint string, body interface{}) ([]byte, error) {
	url := cloudflareAPIBase + endpoint

	var lastErr error
	for attempt := 0; attempt < MaxAPIRetries; attempt++ {
		start := time.Now()
		debugLog("HTTP", "", fmt.Sprintf("🔄 Cloudflare %s %d/%d: %s %s",
			T.Attempt, attempt+1, MaxAPIRetries, method, url))

		var bodyBytes []byte
		var err error

		if body != nil {
			bodyBytes, err = json.Marshal(body)
			if err != nil {
				return nil, fmt.Errorf("json marshal failed: %w", err)
			}
		}

		req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, fmt.Errorf("request creation failed: %w", err)
		}

		if cfg.CloudflareToken != "" {
			req.Header.Set("Authorization", "Bearer "+cfg.CloudflareToken)
		} else if cfg.CloudflareEmail != "" && cfg.APISecret != "" {
			req.Header.Set("X-Auth-Email", cfg.CloudflareEmail)
			req.Header.Set("X-Auth-Key", cfg.APISecret)
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Go-DynDNS/2.0")

		res, err := getHTTPClient().Do(req)
		duration := time.Since(start)

		if err != nil {
			debugLog("HTTP", "", fmt.Sprintf("❌ %s: %v | %s: %v", T.NetworkError, err, T.AvgLatency, duration))
			apiMetrics.RecordError(0, err, duration)
			lastErr = fmt.Errorf("network error: %w", err)

			wait := calculateRetryDelay(attempt, false)
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
			}
			continue
		}
		defer res.Body.Close()

		respBody, err := io.ReadAll(res.Body)
		if err != nil {
			apiMetrics.RecordError(res.StatusCode, err, duration)
			lastErr = fmt.Errorf("failed to read response: %w", err)
			continue
		}

		var cfResp CloudflareResponse
		if err := json.Unmarshal(respBody, &cfResp); err != nil {
			return nil, fmt.Errorf("failed to parse cloudflare response: %w", err)
		}

		if !cfResp.Success {
			errMsg := "unknown error"
			if len(cfResp.Errors) > 0 {
				errMsg = cfResp.Errors[0].Message
			}

			apiErr := classifyAPIError(res.StatusCode, method, url, errMsg)
			apiMetrics.RecordError(res.StatusCode, fmt.Errorf("%v", apiErr), duration)
			lastErr = apiErr

			if apiErr == nil {
				apiMetrics.RecordSuccess(duration)
				return respBody, nil
			}

			if attempt >= MaxAPIRetries-1 {
				return nil, fmt.Errorf("max attempts reached: %w", apiErr)
			}

			wait := calculateRetryDelay(attempt, res.StatusCode >= 500)
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
			}
			continue
		}

		apiMetrics.RecordSuccess(duration)
		return respBody, nil
	}

	return nil, fmt.Errorf("cloudflare api failed after %d attempts: %w", MaxAPIRetries, lastErr)
}

// ============================================================================
// API - IPV64
// ============================================================================

func ipv64API(ctx context.Context, endpoint string, params map[string]string) ([]byte, error) {
	url := ipv64APIBase + endpoint

	if len(params) > 0 {
		query := make([]string, 0, len(params))
		for k, v := range params {
			query = append(query, k+"="+v)
		}
		url += "?" + strings.Join(query, "&")
	}

	var lastErr error
	for attempt := 0; attempt < MaxAPIRetries; attempt++ {
		start := time.Now()
		debugLog("HTTP", "", fmt.Sprintf("🔄 IPv64 %s %d/%d: GET %s",
			T.Attempt, attempt+1, MaxAPIRetries, endpoint))

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("request creation failed: %w", err)
		}

		res, err := getHTTPClient().Do(req)
		duration := time.Since(start)

		if err != nil {
			debugLog("HTTP", "", fmt.Sprintf("❌ %s: %v", T.NetworkError, err))
			apiMetrics.RecordError(0, err, duration)
			lastErr = fmt.Errorf("network error: %w", err)

			wait := calculateRetryDelay(attempt, false)
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
			}
			continue
		}
		defer res.Body.Close()

		respBody, err := io.ReadAll(res.Body)
		if err != nil {
			apiMetrics.RecordError(res.StatusCode, err, duration)
			lastErr = fmt.Errorf("failed to read response: %w", err)
			continue
		}

		var ipv64Resp IPv64Response
		if err := json.Unmarshal(respBody, &ipv64Resp); err != nil {
			return nil, fmt.Errorf("failed to parse ipv64 response: %w", err)
		}

		if strings.Contains(strings.ToLower(ipv64Resp.Info), "error") ||
			strings.Contains(strings.ToLower(ipv64Resp.Info), "invalid") {

			apiErr := &APIError{
				StatusCode: res.StatusCode,
				Message:    ipv64Resp.Info,
				Retryable:  false,
			}

			apiMetrics.RecordError(res.StatusCode, apiErr, duration)
			return nil, apiErr
		}

		apiMetrics.RecordSuccess(duration)
		return respBody, nil
	}

	return nil, fmt.Errorf("ipv64 api failed after %d attempts: %w", MaxAPIRetries, lastErr)
}

// ============================================================================
// API ERROR HANDLING
// ============================================================================

func (e *APIError) Error() string {
	return fmt.Sprintf("API Error [%s %s]: Status %d - %s", e.Method, e.URL, e.StatusCode, e.Message)
}

func (e *APIError) IsRetryable() bool {
	return e.Retryable
}

func classifyAPIError(statusCode int, method, url, responseBody string) *APIError {
	apiErr := &APIError{
		StatusCode: statusCode,
		Method:     method,
		URL:        url,
		Message:    responseBody,
		Retryable:  false,
		RetryAfter: 0,
	}

	if statusCode >= 200 && statusCode < 300 {
		return apiErr
	}

	switch statusCode {
	case 400:
		apiErr.Message = T.BadRequest
	case 401:
		apiErr.Message = T.Unauthorized
		log(LogContext{Level: LogError, Action: ActionConfig, Message: T.Unauthorized})
	case 403:
		apiErr.Message = T.Forbidden
	case 404:
		apiErr.Message = T.NotFound
	case 422:
		apiErr.Message = T.UnprocessableEntity
	case 429:
		apiErr.Message = T.RateLimitExceeded
		apiErr.Retryable = true
		apiErr.RetryAfter = RateLimitRetryDelay
		log(LogContext{Level: LogWarn, Action: ActionRetry, Message: "⚠️ " + T.RateLimitExceeded})
	case 500:
		apiErr.Message = T.InternalServerError
		apiErr.Retryable = true
	case 502:
		apiErr.Message = T.BadGateway
		apiErr.Retryable = true
	case 503:
		apiErr.Message = T.ServiceUnavailable
		apiErr.Retryable = true
		apiErr.RetryAfter = ServerErrorRetryDelay
	case 504:
		apiErr.Message = T.GatewayTimeout
		apiErr.Retryable = true
	default:
		if statusCode >= 500 {
			apiErr.Message = fmt.Sprintf("Server Error %d", statusCode)
			apiErr.Retryable = true
		} else {
			apiErr.Message = fmt.Sprintf("Client Error %d", statusCode)
			apiErr.Retryable = false
		}
	}

	return apiErr
}

// ============================================================================
// IP DETECTION
// ============================================================================

func getPublicIP(url string) (string, error) {
	debugLog("IP-CHECK", "", "🌐 "+url)

	ctx, cancel := context.WithTimeout(context.Background(), IPCheckTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		debugLog("IP-CHECK", "", fmt.Sprintf("❌ Request-Erstellung: %v", err))
		return "", fmt.Errorf("request error: %w", err)
	}

	resp, err := getHTTPClient().Do(req)
	if err != nil {
		debugLog("IP-CHECK", "", fmt.Sprintf("❌ HTTP: %v", err))
		return "", fmt.Errorf("http error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		debugLog("IP-CHECK", "", fmt.Sprintf("❌ Status Code: %d", resp.StatusCode))
		return "", fmt.Errorf("bad status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, IPCheckBodyMaxBytes))
	if err != nil {
		debugLog("IP-CHECK", "", fmt.Sprintf("❌ %s: %v", T.BodyReadError, err))
		return "", fmt.Errorf("read error: %w", err)
	}

	ip := strings.TrimSpace(string(body))

	if net.ParseIP(ip) == nil {
		debugLog("IP-CHECK", "", fmt.Sprintf("❌ Ungültige IP: '%s'", ip))
		return "", fmt.Errorf("invalid ip: %s", ip)
	}

	debugLog("IP-CHECK", "", fmt.Sprintf("✅ %s: %s", T.ReceivedIp, ip))
	return ip, nil
}

func getIPv6() (string, error) {
	if cfg.IfaceName != "" {
		debugLog("IP-CHECK", "", fmt.Sprintf("🔍 %s: %s", T.CheckingInterface, cfg.IfaceName))

		iface, err := net.InterfaceByName(cfg.IfaceName)
		if err != nil {
			debugLog("IP-CHECK", "", fmt.Sprintf("❌ %s: %v", T.InterfaceNotFound, err))
		} else {
			addrs, err := iface.Addrs()
			if err != nil {
				debugLog("IP-CHECK", "", fmt.Sprintf("❌ %s: %v", T.AddressesNotReadable, err))
			} else {
				for _, a := range addrs {
					ipnet, ok := a.(*net.IPNet)

					isV6 := ok && ipnet.IP.To4() == nil
					isULA := isV6 && len(ipnet.IP) >= 1 && ipnet.IP[0] == 0xfd

					if isV6 && !ipnet.IP.IsLoopback() &&
						ipnet.IP.IsGlobalUnicast() && !ipnet.IP.IsLinkLocalUnicast() && !isULA {

						debugLog("IP-CHECK", "", fmt.Sprintf("✅ IPv6 via Interface %s: %s", cfg.IfaceName, ipnet.IP.String()))
						return ipnet.IP.String(), nil
					}
				}
				debugLog("IP-CHECK", "", "⚠️  "+T.NoIpv6OnInterface)
			}
		}
	}
	return getPublicIP("https://6.ident.me/")
}

func fetchCurrentIPs(ctx context.Context) (ipv4, ipv6 string, err error) {
	var errV4, errV6 error

	if cfg.IPMode != "IPV6" {
		ipv4, errV4 = getPublicIP("https://4.ident.me/")
		if errV4 != nil {
			log(LogContext{
				Level:   LogError,
				Action:  ActionError,
				Message: "IPv4 check failed",
				Error:   errV4,
			})
		}
	}

	if cfg.IPMode != "IPV4" {
		ipv6, errV6 = getIPv6()
		if errV6 != nil {
			log(LogContext{
				Level:   LogError,
				Action:  ActionError,
				Message: "IPv6 check failed",
				Error:   errV6,
			})
		}
	}

	switch cfg.IPMode {
	case "IPV4":
		if errV4 != nil {
			return "", "", fmt.Errorf("IPv4 required but failed: %w", errV4)
		}
	case "IPV6":
		if errV6 != nil {
			return "", "", fmt.Errorf("IPv6 required but failed: %w", errV6)
		}
	case "BOTH":
		if errV4 != nil && errV6 != nil {
			return "", "", fmt.Errorf("both IP versions failed: v4=%v, v6=%v", errV4, errV6)
		}
	}

	return ipv4, ipv6, nil
}

// ============================================================================
// DNS LOGIC - IONOS
// ============================================================================

func updateDNS(
	ctx context.Context,
	fqdn, recordType, newIP string,
	records []Record,
	zoneID string,
	zoneName string,
) (bool, error) {

	var existing *Record
	for i := range records {
		recordName := recordNameFromFQDN(fqdn, zoneName)
		if (records[i].Name == fqdn || records[i].Name == recordName) && records[i].Type == recordType {
			existing = &records[i]
			debugLog("DNS-LOGIC", fqdn,
				fmt.Sprintf("📌 %s: %s (ID: %s)",
					T.RecordFound, existing.Content, existing.ID))
			break
		}
	}

	if existing != nil && existing.Content == newIP {
		debugLog("DNS-LOGIC", fqdn,
			fmt.Sprintf("✅ %s: %s = %s",
				T.RecordCurrent, recordType, newIP))
		writeLog("CURRENT", ActionCurrent, fqdn,
			fmt.Sprintf("%-4s %s %s", recordType, newIP, T.Current))
		return false, nil
	}

	if existing == nil {
		debugLog("DNS-LOGIC", fqdn,
			fmt.Sprintf("🆕 %s: %s", T.NoRecordFound, recordType))
	} else {
		debugLog("DNS-LOGIC", fqdn,
			fmt.Sprintf("🔄 %s: %s -> %s",
				T.RecordUpdateNeeded, existing.Content, newIP))
	}

	if cfg.DryRun {
		log(LogContext{
			Level:  LogWarn,
			Action: ActionDryRun,
			Domain: fqdn,
			Message: fmt.Sprintf("⚠️ %s %s %s",
				T.WouldSet, recordType, newIP),
		})
		return true, nil
	}

	var (
		method     string
		url        string
		actionType string
		payload    interface{}
	)

	ttl := 60

	recordName := recordNameFromFQDN(fqdn, zoneName)

	if existing != nil {
		method = "PUT"
		url = fmt.Sprintf("%s/%s/records/%s", apiBaseURL, zoneID, existing.ID)
		actionType = ActionUpdate

		payload = map[string]interface{}{
			"name":    fqdn,
			"type":    recordType,
			"content": newIP,
			"ttl":     ttl,
		}
	} else {
		method = "POST"
		url = fmt.Sprintf("%s/%s/records", apiBaseURL, zoneID)
		actionType = ActionCreate

		payload = []DNSRecord{
			{
				Name:    fqdn,
				Type:    recordType,
				Content: newIP,
				TTL:     ttl,
			},
		}
	}

	debugLog("DNS-LOGIC", fqdn,
		fmt.Sprintf("📡 %s: %s %s", T.APICall, method, url))

	debugLog("DNS-LOGIC", fqdn,
		fmt.Sprintf("📦 Payload: zone=%s name=%s type=%s",
			zoneName, recordName, recordType))

	_, err := ionosAPI(ctx, method, url, payload)
	if err != nil {
		if apiErr, ok := err.(*APIError); ok {
			switch apiErr.StatusCode {
			case 401, 403:
				log(LogContext{
					Level:   LogError,
					Action:  ActionError,
					Domain:  fqdn,
					Message: fmt.Sprintf("%s: %s!", recordType, T.Forbidden),
				})
				return false, fmt.Errorf("authorization failed: %w", err)

			case 404:
				log(LogContext{
					Level:   LogError,
					Action:  ActionZone,
					Domain:  fqdn,
					Message: fmt.Sprintf("%s: %s!", recordType, T.NotFound),
				})
				return false, fmt.Errorf("resource not found: %w", err)

			case 422:
				log(LogContext{
					Level:  LogError,
					Action: ActionError,
					Domain: fqdn,
					Message: fmt.Sprintf("%s: %s (IP: %s)",
						recordType, T.UnprocessableEntity, newIP),
				})
				return false, fmt.Errorf("validation failed: %w", err)

			case 429:
				log(LogContext{
					Level:  LogWarn,
					Action: ActionRetry,
					Domain: fqdn,
					Message: fmt.Sprintf("⏳ %s: %s...",
						recordType, T.RateLimitExceeded),
				})
				return false, err

			default:
				log(LogContext{
					Level:  LogError,
					Action: ActionError,
					Domain: fqdn,
					Message: fmt.Sprintf("%s: API-Fehler %d",
						recordType, apiErr.StatusCode),
				})
				return false, err
			}
		}

		debugLog("DNS-LOGIC", fqdn,
			fmt.Sprintf("❌ %s: %v", T.UpdateFailed, err))
		return false, err
	}

	debugLog("DNS-LOGIC", fqdn,
		fmt.Sprintf("🔄 %s: %s -> %s",
			T.Success, recordType, newIP))

	log(LogContext{
		Level:  LogInfo,
		Action: actionType,
		Domain: fqdn,
		Message: fmt.Sprintf("🔄 %s -> %s %s",
			recordType, newIP, T.Update),
	})

	if zoneName == "" {
		return false, fmt.Errorf("zoneName is empty for fqdn %s", fqdn)
	}

	return true, nil
}

// ============================================================================
// DNS LOGIC - CLOUDFLARE
// ============================================================================

func updateCloudflareDNS(ctx context.Context, fqdn, recordType, newIP string,
	records []Record, zoneID string) (bool, error) {

	var existing *Record
	for i := range records {
		if records[i].Name == fqdn && records[i].Type == recordType {
			existing = &records[i]
			break
		}
	}

	if existing != nil && existing.Content == newIP {
		debugLog("DNS-LOGIC", fqdn, fmt.Sprintf("✅ %s: %s = %s",
			T.RecordCurrent, recordType, newIP))
		writeLog("CURRENT", ActionCurrent, fqdn,
			fmt.Sprintf("%-4s %s %s", recordType, newIP, T.Current))
		return false, nil
	}

	if cfg.DryRun {
		log(LogContext{
			Level:   LogWarn,
			Action:  ActionDryRun,
			Domain:  fqdn,
			Message: fmt.Sprintf("⚠️ %s %s %s", T.WouldSet, recordType, newIP),
		})
		return true, nil
	}

	payload := map[string]interface{}{
		"type":    recordType,
		"name":    fqdn,
		"content": newIP,
		"ttl":     60,
		"proxied": false,
	}

	var endpoint string
	var method string
	var actionType string

	if existing != nil {
		method = "PUT"
		endpoint = fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, existing.ID)
		actionType = ActionUpdate
	} else {
		method = "POST"
		endpoint = fmt.Sprintf("/zones/%s/dns_records", zoneID)
		actionType = ActionCreate
	}

	_, err := cloudflareAPI(ctx, method, endpoint, payload)
	if err != nil {
		return false, err
	}

	log(LogContext{
		Level:   LogInfo,
		Action:  actionType,
		Domain:  fqdn,
		Message: fmt.Sprintf("🔄 %s -> %s %s", recordType, newIP, T.Update),
	})

	return true, nil
}

// ============================================================================
// DNS LOGIC - IPV64
// ============================================================================

func updateIPv64DNS(ctx context.Context, fqdn, recordType, newIP string) (bool, error) {
	params := map[string]string{
		"get_domains": cfg.IPv64Token,
	}

	data, err := ipv64API(ctx, "", params)
	if err != nil {
		return false, err
	}

	var resp IPv64Response
	if err := json.Unmarshal(data, &resp); err != nil {
		return false, fmt.Errorf("failed to parse response: %w", err)
	}

	domain, exists := resp.Domains[fqdn]
	if !exists {
		return false, fmt.Errorf("domain %s not found in ipv64 account", fqdn)
	}

	needsUpdate := false
	if recordType == "A" && domain.IPv4 != newIP {
		needsUpdate = true
	} else if recordType == "AAAA" && domain.IPv6 != newIP {
		needsUpdate = true
	}

	if !needsUpdate {
		debugLog("DNS-LOGIC", fqdn, fmt.Sprintf("✅ %s: %s = %s",
			T.RecordCurrent, recordType, newIP))
		writeLog("CURRENT", ActionCurrent, fqdn,
			fmt.Sprintf("%-4s %s %s", recordType, newIP, T.Current))
		return false, nil
	}

	if cfg.DryRun {
		log(LogContext{
			Level:   LogWarn,
			Action:  ActionDryRun,
			Domain:  fqdn,
			Message: fmt.Sprintf("⚠️ %s %s %s", T.WouldSet, recordType, newIP),
		})
		return true, nil
	}

	updateParams := map[string]string{
		"update_domain": cfg.IPv64Token,
		"domain":        fqdn,
	}

	if recordType == "A" {
		updateParams["ipv4"] = newIP
	} else if recordType == "AAAA" {
		updateParams["ipv6"] = newIP
	}

	_, err = ipv64API(ctx, "", updateParams)
	if err != nil {
		return false, err
	}

	log(LogContext{
		Level:   LogInfo,
		Action:  ActionUpdate,
		Domain:  fqdn,
		Message: fmt.Sprintf("🔄 %s -> %s %s", recordType, newIP, T.Update),
	})

	return true, nil
}

// ============================================================================
// DNS HELPERS
// ============================================================================

func recordNameFromFQDN(fqdn, zone string) string {
	if fqdn == zone {
		return "@"
	}

	suffix := "." + zone
	if strings.HasSuffix(fqdn, suffix) {
		return strings.TrimSuffix(fqdn, suffix)
	}

	return fqdn
}

func isNonRecoverableError(err error) bool {
	if apiErr, ok := err.(*APIError); ok {
		switch apiErr.StatusCode {
		case 401, 403, 404:
			return true
		}
	}
	return false
}

func processDomainUpdate(ctx context.Context, job domainUpdateJob) domainUpdateResult {
	result := domainUpdateResult{Domain: job.Domain}

	v4Changed, v6Changed := false, false

	if cfg.IPMode != "IPV6" && job.IPv4 != "" {
		debugLog("DNS-LOGIC", job.Domain, T.CheckingIpv4)

		var changed bool
		var err error

		switch cfg.Provider {
		case ProviderCloudflare:
			changed, err = updateCloudflareDNS(ctx, job.Domain, "A", job.IPv4, job.Records, job.ZoneID)
		case ProviderIPv64:
			changed, err = updateIPv64DNS(ctx, job.Domain, "A", job.IPv4)
		default:
			changed, err = updateDNS(ctx, job.Domain, "A", job.IPv4, job.Records, job.ZoneID, job.ZoneName)
		}

		if err != nil {
			if isNonRecoverableError(err) {
				result.Error = fmt.Errorf("non-recoverable IPv4 error: %w", err)
				return result
			}
			debugLog("DNS-LOGIC", job.Domain, fmt.Sprintf("%s IPv4: %v", T.UpdateFailed, err))
		}
		v4Changed = changed
	}

	if cfg.IPMode != "IPV4" && job.IPv6 != "" {
		debugLog("DNS-LOGIC", job.Domain, T.CheckingIpv6)

		var changed bool
		var err error

		switch cfg.Provider {
		case ProviderCloudflare:
			changed, err = updateCloudflareDNS(ctx, job.Domain, "AAAA", job.IPv6, job.Records, job.ZoneID)
		case ProviderIPv64:
			changed, err = updateIPv64DNS(ctx, job.Domain, "AAAA", job.IPv6)
		default:
			changed, err = updateDNS(ctx, job.Domain, "AAAA", job.IPv6, job.Records, job.ZoneID, job.ZoneName)
		}

		if err != nil {
			if isNonRecoverableError(err) {
				result.Error = fmt.Errorf("non-recoverable IPv6 error: %w", err)
				return result
			}
			debugLog("DNS-LOGIC", job.Domain, fmt.Sprintf("%s IPv6: %v", T.UpdateFailed, err))
		}
		v6Changed = changed
	}

	result.Changed = v4Changed || v6Changed
	return result
}

func cleanupOldRecords(ctx context.Context, zones []Zone, recordCache *ZoneRecordCache) {
	if cfg.Provider != ProviderIONOS {
		return
	}

	debugLog("MAINTENANCE", "", "🧹 Starte Bereinigung verwaister DNS-Records...")

	configDomains := make(map[string]struct{})
	for _, d := range cfg.Domains {
		configDomains[strings.ToLower(strings.TrimSuffix(d, "."))] = struct{}{}
	}

	for _, zone := range zones {
		records, exists := recordCache.Get(zone.ID)
		if !exists {
			continue
		}

		zoneName := strings.ToLower(strings.TrimSuffix(zone.Name, "."))

		for _, rec := range records {
			if rec.Type != "A" && rec.Type != "AAAA" {
				continue
			}

			var fqdn string

			switch {
			case rec.Name == "@":
				fqdn = zoneName

			case rec.Name == zoneName:
				fqdn = zoneName

			case strings.HasSuffix(rec.Name, "."+zoneName):
				fqdn = rec.Name

			default:
				fqdn = rec.Name + "." + zoneName
			}

			fqdn = strings.ToLower(strings.TrimSuffix(fqdn, "."))

			if _, ok := configDomains[fqdn]; ok {
				continue
			}

			debugLog(
				"MAINTENANCE",
				fqdn,
				fmt.Sprintf("🗑️ Entferne verwaisten %s Record (ID: %s)", rec.Type, rec.ID),
			)

			if cfg.DryRun {
				log(LogContext{
					Level:   LogInfo,
					Action:  ActionCleanup,
					Domain:  fqdn,
					Message: "⚠️ Dry-Run: Record wäre gelöscht worden",
				})
				continue
			}

			url := fmt.Sprintf("%s/%s/records/%s", apiBaseURL, zone.ID, rec.ID)
			if _, err := ionosAPI(ctx, "DELETE", url, nil); err != nil {
				debugLog("MAINTENANCE", fqdn, fmt.Sprintf("❌ Fehler beim Löschen: %v", err))
			} else {
				log(LogContext{
					Level:   LogInfo,
					Action:  ActionCleanup,
					Domain:  fqdn,
					Message: fmt.Sprintf("✅ %s Record entfernt (nicht mehr konfiguriert)", rec.Type),
				})
			}
		}
	}
}

// ============================================================================
// ZONE & CACHE
// ============================================================================

func NewZoneRecordCache() *ZoneRecordCache {
	return &ZoneRecordCache{
		data: make(map[string][]Record),
	}
}

func (c *ZoneRecordCache) Set(zoneID string, records []Record) {
	c.Lock()
	defer c.Unlock()
	c.data[zoneID] = records
}

func (c *ZoneRecordCache) Get(zoneID string) ([]Record, bool) {
	c.RLock()
	defer c.RUnlock()
	records, exists := c.data[zoneID]
	return records, exists
}

func loadZones(ctx context.Context) ([]Zone, error) {
	data, err := ionosAPI(ctx, "GET", apiBaseURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load zones: %w", err)
	}

	var zones []Zone
	if err := json.Unmarshal(data, &zones); err != nil {
		return nil, fmt.Errorf("failed to parse zones: %w", err)
	}

	return zones, nil
}

func loadCloudflareZones(ctx context.Context) ([]Zone, error) {
	data, err := cloudflareAPI(ctx, "GET", "/zones", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load cloudflare zones: %w", err)
	}

	var resp struct {
		Result []CloudflareZone `json:"result"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse zones: %w", err)
	}

	zones := make([]Zone, len(resp.Result))
	for i, z := range resp.Result {
		zones[i] = Zone{ID: z.ID, Name: z.Name}
	}

	return zones, nil
}

func loadIPv64Domains(ctx context.Context) ([]Zone, error) {
	params := map[string]string{
		"get_domains": cfg.IPv64Token,
	}

	data, err := ipv64API(ctx, "", params)
	if err != nil {
		return nil, fmt.Errorf("failed to load ipv64 domains: %w", err)
	}

	var resp IPv64Response
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse domains: %w", err)
	}

	zones := make([]Zone, 0, len(resp.Domains))
	for domain := range resp.Domains {
		zones = append(zones, Zone{
			ID:   domain,
			Name: domain,
		})
	}

	return zones, nil
}

func loadZonesForProvider(ctx context.Context) ([]Zone, error) {
	switch cfg.Provider {
	case ProviderCloudflare:
		return loadCloudflareZones(ctx)
	case ProviderIPv64:
		return loadIPv64Domains(ctx)
	case ProviderIONOS:
		return loadZones(ctx)
	default:
		return nil, fmt.Errorf("unknown provider: %s", cfg.Provider)
	}
}

func loadCloudflareRecords(ctx context.Context, zoneID string) ([]Record, error) {
	endpoint := fmt.Sprintf("/zones/%s/dns_records", zoneID)
	data, err := cloudflareAPI(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load records: %w", err)
	}

	var resp struct {
		Result []CloudflareRecord `json:"result"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse records: %w", err)
	}

	records := make([]Record, len(resp.Result))
	for i, r := range resp.Result {
		records[i] = Record{
			ID:      r.ID,
			Name:    r.Name,
			Type:    r.Type,
			Content: r.Content,
		}
	}

	return records, nil
}

func loadZoneCache(ctx context.Context, zones []Zone) (*ZoneRecordCache, error) {
	cache := NewZoneRecordCache()

	if cfg.Provider == ProviderIPv64 {
		return cache, nil
	}

	var cacheWg sync.WaitGroup
	var cacheErrors []string
	var cacheErrorsMu sync.Mutex

	for _, z := range zones {
		needed := false
		for _, d := range cfg.Domains {
			dn := strings.TrimSuffix(strings.ToLower(d), ".")
			zn := strings.TrimSuffix(strings.ToLower(z.Name), ".")
			if dn == zn || strings.HasSuffix(dn, "."+zn) {
				needed = true
				break
			}
		}

		if !needed {
			continue
		}

		cacheWg.Add(1)
		go func(zone Zone) {
			defer cacheWg.Done()

			var records []Record
			var err error

			if cfg.Provider == ProviderCloudflare {
				records, err = loadCloudflareRecords(ctx, zone.ID)
			} else {
				var detailData []byte
				detailData, err = ionosAPI(ctx, "GET", apiBaseURL+"/"+zone.ID, nil)
				if err == nil {
					var detail struct{ Records []Record }
					err = json.Unmarshal(detailData, &detail)
					if err == nil {
						records = detail.Records
					}
				}
			}

			if err != nil {
				errMsg := fmt.Sprintf("Zone %s (%s): %v", zone.Name, zone.ID, err)
				cacheErrorsMu.Lock()
				cacheErrors = append(cacheErrors, errMsg)
				cacheErrorsMu.Unlock()
				debugLog("CACHE", zone.Name, fmt.Sprintf("❌ Fehler beim Laden: %v", err))
				return
			}

			cache.Set(zone.ID, records)
			debugLog("CACHE", zone.Name, fmt.Sprintf("✅ %d Records geladen", len(records)))
		}(z)
	}

	cacheWg.Wait()

	if len(cacheErrors) > 0 {
		log(LogContext{
			Level:   LogWarn,
			Action:  ActionError,
			Message: fmt.Sprintf("Cache-Fehler bei %d Zone(n): %s", len(cacheErrors), strings.Join(cacheErrors, "; ")),
		})
	}

	return cache, nil
}

func sortZonesBySpecificity(zones []Zone) {
	sort.Slice(zones, func(i, j int) bool {
		return len(zones[i].Name) > len(zones[j].Name)
	})
}

func processDomains(
	ctx context.Context,
	zones []Zone,
	cache *ZoneRecordCache,
	ipv4, ipv6 string,
) int {

	var wg sync.WaitGroup
	sem := make(chan struct{}, cfg.MaxConcurrent)
	results := make(chan domainUpdateResult, len(cfg.Domains))

domainLoop:
	for _, fqdn := range cfg.Domains {
		select {
		case <-ctx.Done():
			debugLog("SCHEDULER", "", "Domain-Loop abgebrochen: Context cancelled")
			break domainLoop
		default:
		}

		wg.Add(1)
		go func(domain string) {
			defer wg.Done()

			defer func() {
				if r := recover(); r != nil {
					log(LogContext{
						Level:   LogError,
						Action:  ActionError,
						Domain:  domain,
						Message: fmt.Sprintf("Panic: %v", r),
					})
				}
			}()

			select {
			case sem <- struct{}{}:
				debugLog("WORKER", domain, T.WorkerSlotAcquired)
			case <-ctx.Done():
				debugLog("WORKER", domain, "Abgebrochen: Context cancelled")
				return
			}

			defer func() {
				debugLog("WORKER", domain, T.WorkerSlotReleased)
				<-sem
			}()

			if ctx.Err() != nil {
				debugLog("WORKER", domain, T.ContextExpired)
				return
			}

			var matchedZone *Zone
			dn := strings.TrimSuffix(strings.ToLower(domain), ".")
			for i := range zones {
				zn := strings.TrimSuffix(strings.ToLower(zones[i].Name), ".")
				if dn == zn || strings.HasSuffix(dn, "."+zn) {
					matchedZone = &zones[i]
					break
				}
			}

			if matchedZone == nil {
				debugLog("DNS-LOGIC", domain, T.NoZoneFoundForDomain)
				results <- domainUpdateResult{
					Domain: domain,
					Error:  fmt.Errorf("no zone found"),
				}
				return
			}

			zoneID := matchedZone.ID
			if zoneID == "" {
				results <- domainUpdateResult{
					Domain: domain,
					Error:  fmt.Errorf("matched zone has empty ID"),
				}
				return
			}

			records, exists := cache.Get(zoneID)
			if !exists && cfg.Provider != ProviderIPv64 {
				debugLog("DNS-LOGIC", domain, T.NoRecordsInCache)
				results <- domainUpdateResult{
					Domain: domain,
					Error:  fmt.Errorf("no records in cache"),
				}
				return
			}

			job := domainUpdateJob{
				Domain:   domain,
				ZoneID:   zoneID,
				ZoneName: matchedZone.Name,
				Records:  records,
				IPv4:     ipv4,
				IPv6:     ipv6,
			}

			result := processDomainUpdate(ctx, job)
			results <- result

			providerName := string(cfg.Provider)

			if result.Changed && !cfg.DryRun {
				debugLog("STATUS", domain, T.ChangesDetected)
				updateStatusFile(domain, ipv4, ipv6, providerName)
			} else if result.Error == nil {
				debugLog("STATUS", domain, T.NoChangesNeeded)
			}
		}(fqdn)
	}

	wg.Wait()
	close(results)

	successCount := 0
	hasErrors := false

	for result := range results {
		if result.Error != nil {
			hasErrors = true
		} else if result.Changed {
			successCount++
		}
	}

	lastOk.Store(!hasErrors)
	return successCount
}

// ============================================================================
// UPDATE ORCHESTRATION
// ============================================================================

func runUpdate(firstRun bool) {
	debugLog("SCHEDULER", "", fmt.Sprintf(T.SchedulerStarted, firstRun))

	baseTimeout := BaseUpdateTimeout
	perDomainTimeout := time.Duration(len(cfg.Domains)) * PerDomainTimeout
	buffer := UpdateBufferTimeout
	totalTimeout := baseTimeout + perDomainTimeout + buffer

	if totalTimeout < MinUpdateTimeout {
		totalTimeout = MinUpdateTimeout
	}
	if totalTimeout > MaxUpdateTimeout {
		totalTimeout = MaxUpdateTimeout
	}

	debugLog("SCHEDULER", "", fmt.Sprintf("Context Timeout: %v (für %d Domains)", totalTimeout, len(cfg.Domains)))

	ctx, cancel := context.WithTimeout(context.Background(), totalTimeout)
	defer cancel()

	currentIPv4, currentIPv6, err := fetchCurrentIPs(ctx)
	if err != nil {
		lastOk.Store(false)
		return
	}

	zones, err := loadZonesForProvider(ctx)
	if err != nil {
		lastOk.Store(false)
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: T.NoZones,
			Error:   err,
		})
		return
	}
	sortZonesBySpecificity(zones)

	if firstRun {
		printGroupedDomains()
		printInfrastructure(ctx, zones)
	}

	cache, err := loadZoneCache(ctx, zones)
	if err != nil {
		lastOk.Store(false)
		return
	}

	cleanupOldRecords(ctx, zones, cache)

	successCount := processDomains(ctx, zones, cache, currentIPv4, currentIPv6)

	debugLog("SCHEDULER", "", fmt.Sprintf(T.SchedulerCompleted, successCount))
}

// ============================================================================
// STATUS FILE
// ============================================================================

func updateStatusFile(fqdn, ipv4, ipv6, provider string) {
	statusMutex.Lock()
	defer statusMutex.Unlock()

	domains := make(map[string]DomainHistory)
	if b, err := os.ReadFile(updatePath); err == nil {
		json.Unmarshal(b, &domains)
	}

	h := domains[fqdn]
	h.Provider = provider
	h.LastChanged = time.Now().Local().Format("02.01.2006 15:04:05")
	newEntry := IPEntry{
		Time: time.Now().Local().Format("02.01.2006 15:04:05"),
		IPv4: ipv4,
		IPv6: ipv6,
	}
	h.IPs = append(h.IPs, newEntry)

	if len(h.IPs) > MaxStatusHistoryItems {
		h.IPs = h.IPs[len(h.IPs)-MaxStatusHistoryItems:]
	}
	domains[fqdn] = h

	js, err := json.MarshalIndent(domains, "", "  ")
	if err != nil {
		return
	}

	tmp := updatePath + ".tmp"
	os.WriteFile(tmp, js, 0644)
	os.Rename(tmp, updatePath)

	go updateDomainsCache()

	broadcastUpdate("domain_update", map[string]interface{}{
		"domain": fqdn,
		"ipv4":   ipv4,
		"ipv6":   ipv6,
		"time":   newEntry.Time,
	})
}

// ============================================================================
// CACHING
// ============================================================================

func updateDomainsCache() error {
	statusMutex.Lock()
	defer statusMutex.Unlock()

	domains := make(map[string]DomainHistory)
	if b, err := os.ReadFile(updatePath); err == nil {
		if err := json.Unmarshal(b, &domains); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	data, err := json.Marshal(domains)
	if err != nil {
		return err
	}

	etag := fmt.Sprintf(`"%x"`, md5.Sum(data))

	domainsCache.mu.Lock()
	domainsCache.Data = data
	domainsCache.ETag = etag
	domainsCache.LastModified = time.Now()
	domainsCache.mu.Unlock()

	return nil
}

func updateMetricsCache() {
	stats := apiMetrics.GetStats()

	data, err := json.Marshal(stats)
	if err != nil {
		debugLog("CACHE", "", fmt.Sprintf("Metrics cache marshal error: %v", err))
		return
	}

	etag := fmt.Sprintf(`"%x"`, md5.Sum(data))

	metricsCache.mu.Lock()
	metricsCache.Data = data
	metricsCache.ETag = etag
	metricsCache.LastModified = time.Now()
	metricsCache.mu.Unlock()
}

func serveCachedJSON(w http.ResponseWriter, r *http.Request, cache *CachedResponse) {
	cache.mu.RLock()
	data := cache.Data
	etag := cache.ETag
	lastMod := cache.LastModified
	cache.mu.RUnlock()

	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	if ifModSince := r.Header.Get("If-Modified-Since"); ifModSince != "" {
		if t, err := http.ParseTime(ifModSince); err == nil {
			if !lastMod.After(t) {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", etag)
	w.Header().Set("Last-Modified", lastMod.UTC().Format(http.TimeFormat))
	w.Header().Set("Cache-Control", "public, max-age=5")

	w.Write(data)
}

func startCacheRefresher() {
	ticker := time.NewTicker(5 * time.Second)

	go func() {
		for range ticker.C {
			if err := updateDomainsCache(); err != nil {
				debugLog("CACHE", "", fmt.Sprintf("Domain cache refresh failed: %v", err))
			}

			updateMetricsCache()
		}
	}()
}

// ============================================================================
// METRICS
// ============================================================================

func (m *APIMetrics) RecordSuccess(duration time.Duration) {
	m.Lock()

	m.trackHistory()

	now := time.Now()
	m.TotalRequests++
	m.SuccessRequests++
	m.LastSuccessTimestamp = now

	m.cleanupOldTimestamps(now)
	m.RequestTimestamps = append(m.RequestTimestamps, now)

	m.HourlyStats[23]++
	m.updateLatency(duration)

	statsCopy := m.getStatsUnsafe()

	m.Unlock()

	go broadcastUpdate("metrics", statsCopy)
}

func (m *APIMetrics) RecordError(statusCode int, err error, duration time.Duration) {
	m.Lock()

	m.trackHistory()

	now := time.Now()
	m.TotalRequests++
	m.FailedRequests++
	m.LastError = err.Error()
	m.LastErrorTimestamp = now

	m.cleanupOldTimestamps(now)
	m.RequestTimestamps = append(m.RequestTimestamps, now)

	m.HourlyStats[23]++
	m.updateLatency(duration)

	switch {
	case statusCode == 429:
		m.RateLimitHits++
	case statusCode >= 500:
		m.ServerErrors++
	case statusCode >= 400:
		m.ClientErrors++
	}

	statsCopy := m.getStatsUnsafe()

	m.Unlock()

	go broadcastUpdate("metrics", statsCopy)
}

func (m *APIMetrics) updateLatency(duration time.Duration) {
	if m.AverageLatency == 0 {
		m.AverageLatency = duration
	} else {
		m.AverageLatency = (m.AverageLatency + duration) / 2
	}
	m.AverageLatency = m.AverageLatency.Round(time.Millisecond)

	if m.HourlyLatency[23] == 0 {
		m.HourlyLatency[23] = duration
	} else {
		m.HourlyLatency[23] = (m.HourlyLatency[23] + duration) / 2
	}
}

func (m *APIMetrics) cleanupOldTimestamps(now time.Time) {
	threshold := now.Add(-1 * time.Hour)

	firstValid := len(m.RequestTimestamps)
	for i, t := range m.RequestTimestamps {
		if t.After(threshold) {
			firstValid = i
			break
		}
	}

	if firstValid >= len(m.RequestTimestamps) {
		m.RequestTimestamps = m.RequestTimestamps[:0]
		return
	}

	if firstValid > 0 {
		m.RequestTimestamps = m.RequestTimestamps[firstValid:]
	}
}

func (m *APIMetrics) GetStats() map[string]interface{} {
	m.Lock()
	defer m.Unlock()
	return m.getStatsUnsafe()
}

func (m *APIMetrics) getUsageColor(p float64) string {
	if p > 90 {
		return "#f87171"
	}
	if p > 70 {
		return "#facc15"
	}
	return "#4ade80"
}

func (m *APIMetrics) trackHistory() {
	now := time.Now()
	currentHourUnix := now.Unix() / 3600

	if m.lastHour == 0 {
		m.lastHour = currentHourUnix
		return
	}

	if currentHourUnix != m.lastHour {
		diff := int(currentHourUnix - m.lastHour)
		if diff > 0 {
			if diff >= 24 {
				m.HourlyStats = [24]int{}
				m.HourlyLatency = [24]time.Duration{}
			} else {
				for i := 0; i < 24-diff; i++ {
					m.HourlyStats[i] = m.HourlyStats[i+diff]
					m.HourlyLatency[i] = m.HourlyLatency[i+diff]
				}
				for i := 24 - diff; i < 24; i++ {
					m.HourlyStats[i] = 0
					m.HourlyLatency[i] = 0
				}
			}
			m.lastHour = currentHourUnix
		}
	}
}

func (m *APIMetrics) getStatsUnsafe() map[string]interface{} {
	currentCount := len(m.RequestTimestamps)

	limit := float64(cfg.HourlyRateLimit)
	percent := (float64(currentCount) / limit) * 100
	if percent > 100 {
		percent = 100
	}

	successRate := 0.0
	if m.TotalRequests > 0 {
		successRate = float64(m.SuccessRequests) / float64(m.TotalRequests) * 100
	}

	return map[string]interface{}{
		"total_requests":    m.TotalRequests,
		"success_rate":      fmt.Sprintf("%.2f%%", successRate),
		"avg_latency":       m.AverageLatency.String(),
		"server_errors":     m.ServerErrors,
		"client_errors":     m.ClientErrors,
		"last_success_time": m.LastSuccessTimestamp.Format("15:04:05"),
		"usage_count":       currentCount,
		"usage_percent":     fmt.Sprintf("%.1f", percent),
		"usage_color":       m.getUsageColor(percent),
		"hourly_stats":      m.HourlyStats,
		"hourly_latency":    m.HourlyLatency,
		"hourly_limit":      cfg.HourlyRateLimit,
	}
}

// ============================================================================
// WEBSOCKET
// ============================================================================

func (h *WSHub) run() {
	for {
		select {
		case conn := <-h.register:
			h.mu.Lock()
			h.clients[conn] = true
			h.mu.Unlock()

			go h.keepAlive(conn)

			debugLog("WS", "", fmt.Sprintf("Client connected (total: %d)", len(h.clients)))

		case conn := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[conn]; ok {
				delete(h.clients, conn)
				conn.Close()
			}
			h.mu.Unlock()
			debugLog("WS", "", fmt.Sprintf("Client disconnected (total: %d)", len(h.clients)))

		case message := <-h.broadcast:
			h.mu.RLock()
			clients := make([]*websocket.Conn, 0, len(h.clients))
			for conn := range h.clients {
				clients = append(clients, conn)
			}
			h.mu.RUnlock()

			for _, conn := range clients {
				go func(c *websocket.Conn) {
					c.SetWriteDeadline(time.Now().Add(WSWriteTimeout))

					if err := c.WriteJSON(message); err != nil {
						debugLog("WS", "", fmt.Sprintf("Write failed: %v", err))
						h.unregister <- c
					}
				}(conn)
			}
		}
	}
}

func (h *WSHub) keepAlive(conn *websocket.Conn) {
	ticker := time.NewTicker(WSPingInterval)
	defer ticker.Stop()

	conn.SetReadDeadline(time.Now().Add(WSPongTimeout))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(WSPongTimeout))
		return nil
	})

	for {
		select {
		case <-ticker.C:
			conn.SetWriteDeadline(time.Now().Add(WSWriteTimeout))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				debugLog("WS", "", "Ping failed, closing connection")
				h.unregister <- conn
				return
			}
		}
	}
}

func broadcastUpdate(updateType string, data interface{}) {
	msg := WSMessage{Type: updateType, Data: data}
	select {
	case wsHub.broadcast <- msg:
	default:
		debugLog("WS", "", "broadcast queue full - dropping message")
	}
}

// ============================================================================
// HELPERS
// ============================================================================

func (s *SafeErrorMsg) Set(msg string) {
	s.Lock()
	defer s.Unlock()
	s.msg = msg
}

func (s *SafeErrorMsg) Get() string {
	s.RLock()
	defer s.RUnlock()
	return s.msg
}

func actionCSS(a string) string {
	if c, ok := actionClass[a]; ok {
		return c
	}
	return "act-default"
}

func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return ip
}

func validateTriggerToken(r *http.Request) bool {
	token := r.Header.Get(TriggerTokenHeader)

	expectedToken := os.Getenv("TRIGGER_TOKEN")
	if expectedToken == "" {
		return true
	}

	return token == expectedToken
}

// ============================================================================
// PRINTING
// ============================================================================

func printGroupedDomains() {
	fmt.Printf("\n🚀  %s [%s] (%s: %s) [Provider: %s]:\n",
		T.ServiceStarted, cfg.Lang, T.Mode, cfg.IPMode, cfg.Provider)

	if len(cfg.Domains) == 0 {
		fmt.Println("\n⚠️  " + T.NoDomains)
		return
	}

	groups := make(map[string][]string)
	for _, d := range cfg.Domains {
		if d == "" {
			continue
		}

		if err := validateDomain(d); err != nil {
			fmt.Printf("\n⚠️  %s: %s (%v)\n", T.InvalidDomain, d, err)
			continue
		}

		parts := strings.Split(d, ".")
		if len(parts) < 2 {
			fmt.Printf("\n⚠️  %s: %s\n", T.InvalidDomain, d)
			continue
		}

		main := strings.Join(parts[len(parts)-2:], ".")

		if main == "" {
			fmt.Printf("\n⚠️  %s: %s\n", T.CouldNotExtractDomain, d)
			continue
		}

		if d != main {
			prefix := strings.TrimSuffix(d, "."+main)
			groups[main] = append(groups[main], prefix)
		} else if _, ok := groups[main]; !ok {
			groups[main] = []string{}
		}
	}

	if len(groups) == 0 {
		fmt.Println("\n⚠️  " + T.NoValidDomains)
		return
	}

	var mainDomains []string
	for m := range groups {
		mainDomains = append(mainDomains, m)
	}
	sort.Strings(mainDomains)

	for _, main := range mainDomains {
		fmt.Printf("\n📦 %s\n", strings.ToUpper(main))
		subs := groups[main]
		sort.Strings(subs)
		if len(subs) == 0 {
			fmt.Printf("   ╚━━ 🏠   %s\n", T.RootDomain)
		} else {
			for i, sub := range subs {
				char := "┣"
				if i == len(subs)-1 {
					char = "╚"
				}
				fmt.Printf("   %s━━ 🌐 %s\n", char, sub)
			}
		}
	}
	fmt.Println("\n" + strings.Repeat("-", 40))
}

func printInfrastructure(ctx context.Context, zones []Zone) {
	fmt.Println("\n" + T.InfraHeading)

	for _, z := range zones {
		fmt.Printf("\n🌐 %s: %s\n", T.ZoneLabel, z.Name)

		if cfg.Provider == ProviderIPv64 {
			fmt.Println("   ┣━ IPv64 Domain (dynamische IP-Updates)")
			continue
		}

		var records []Record
		if cfg.Provider == ProviderCloudflare {
			records, _ = loadCloudflareRecords(ctx, z.ID)
		} else {
			data, _ := ionosAPI(ctx, "GET", apiBaseURL+"/"+z.ID, nil)
			var detail struct{ Records []Record }
			_ = json.Unmarshal(data, &detail)
			records = detail.Records
		}

		var relevant []Record
		for _, r := range records {
			if r.Type == "A" || r.Type == "AAAA" || r.Type == "CNAME" {
				relevant = append(relevant, r)
			}
		}
		sort.Slice(relevant, func(i, j int) bool { return relevant[i].Name < relevant[j].Name })
		for _, r := range relevant {
			fmt.Printf("   ┣━ %-35s [%-5s] -> %s\n", r.Name, r.Type, r.Content)
		}
	}
	fmt.Println("\n" + strings.Repeat("-", 40))
}

func logHTTPClientStats() {
	if !cfg.DebugEnabled {
		return
	}

	prefix := cfg.APIPrefix
	if len(prefix) > 5 {
		prefix = prefix[:5] + "***"
	}

	debugLog("CONFIG", "", "========== "+T.ConfigHeading+" ==========")
	debugLog("CONFIG", "", fmt.Sprintf("Provider: %s", cfg.Provider))
	debugLog("CONFIG", "", fmt.Sprintf("%s: %s", T.ConfigAPIPrefix, prefix))
	debugLog("CONFIG", "", fmt.Sprintf("%s: %v", T.ConfigDomains, cfg.Domains))
	debugLog("CONFIG", "", fmt.Sprintf("%s: %ds", T.ConfigInterval, cfg.Interval))
	debugLog("CONFIG", "", fmt.Sprintf("%s: %s", T.ConfigIpMode, cfg.IPMode))
	debugLog("CONFIG", "", fmt.Sprintf("%s: %s", T.ConfigInterface, cfg.IfaceName))
	debugLog("CONFIG", "", fmt.Sprintf("%s: %s", T.ConfigHealthPort, cfg.HealthPort))
	debugLog("CONFIG", "", fmt.Sprintf("%s: %v", T.ConfigDryRun, cfg.DryRun))
	debugLog("CONFIG", "", fmt.Sprintf("%s: %s", T.ConfigLogDir, cfg.LogDir))
	debugLog("CONFIG", "", fmt.Sprintf("%s: %s", T.ConfigLanguage, cfg.Lang))
	debugLog("CONFIG", "", "===================================")
}

// ============================================================================
// SVG CHARTS
// ============================================================================

func generateSVGChart(data [24]int) string {
	maxVal := 0
	for _, v := range data {
		if v > maxVal {
			maxVal = v
		}
	}
	renderMax := float64(maxVal) * 1.2
	if renderMax < 10 {
		renderMax = 10
	}

	width, height := 300.0, 60.0
	var points [][2]float64
	for i, val := range data {
		x := float64(i) * (width / 23.0)
		y := height - (float64(val) * height / renderMax)
		points = append(points, [2]float64{x, y})
	}

	pathData := fmt.Sprintf("M %.1f,%.1f", points[0][0], points[0][1])
	for i := 0; i < len(points)-1; i++ {
		p0, p1 := points[i], points[i+1]
		cp1x := p0[0] + (p1[0]-p0[0])/2
		pathData += fmt.Sprintf(" C %.1f,%.1f %.1f,%.1f %.1f,%.1f", cp1x, p0[1], cp1x, p1[1], p1[0], p1[1])
	}

	now := time.Now()
	timeLabels := ""
	for i := 0; i < 5; i++ {
		h := now.Add(time.Duration(-24+(i*6)) * time.Hour).Hour()
		timeLabels += fmt.Sprintf("<span>%02dh</span>", h)
	}

	return fmt.Sprintf(`
<details class="card">
	<summary>📈 %s</summary>
	<div class="card-content" style="position:relative; padding-left:40px; margin-top:15px; padding-right:10px;">
		<div style="position:absolute; left:0; top:0; height:60px; font-size:0.6rem; color:gray; text-align:right; width:35px; pointer-events:none;">
			<div style="position:absolute; top:0; right:5px; transform: translateY(-50%%);">%.0f</div>
			<div style="position:absolute; top:30px; right:5px; transform: translateY(-50%%);">%.0f</div>
			<div style="position:absolute; top:60px; right:5px; transform: translateY(-50%%);">0</div>
		</div>
		
		<svg viewBox="0 0 300 60" preserveAspectRatio="none" style="width:100%%; height:60px; display:block; border-bottom: 1px solid rgba(255,255,255,0.1);">
			<path d="%s L 300,60 L 0,60 Z" fill="rgba(56,189,248,0.1)"/>
			<path d="%s" fill="none" stroke="#38bdf8" stroke-width="2" stroke-linecap="round"/>
		</svg>

		<div style="display:flex; justify-content:space-between; font-size:0.6rem; margin-top:8px; color:gray;">
			%s
		</div>
	</div>
</details>`, T.RequestHistory, renderMax, renderMax/2, pathData, pathData, timeLabels)
}

func generateLatencyChart(data [24]time.Duration) string {
	var maxMs float64
	pointsData := make([]float64, 24)
	for i, v := range data {
		ms := float64(v.Milliseconds())
		pointsData[i] = ms
		if ms > maxMs {
			maxMs = ms
		}
	}
	renderMax := maxMs * 1.2
	if renderMax < 50 {
		renderMax = 50
	}

	width, height := 300.0, 60.0
	var points [][2]float64
	for i, val := range pointsData {
		x := float64(i) * (width / 23.0)
		y := height - (val * height / renderMax)
		points = append(points, [2]float64{x, y})
	}

	pathData := fmt.Sprintf("M %.1f,%.1f", points[0][0], points[0][1])
	for i := 0; i < len(points)-1; i++ {
		p0, p1 := points[i], points[i+1]
		cp1x := p0[0] + (p1[0]-p0[0])/2
		pathData += fmt.Sprintf(" C %.1f,%.1f %.1f,%.1f %.1f,%.1f", cp1x, p0[1], cp1x, p1[1], p1[0], p1[1])
	}

	now := time.Now()
	timeLabels := ""
	for i := 0; i < 5; i++ {
		h := now.Add(time.Duration(-24+(i*6)) * time.Hour).Hour()
		timeLabels += fmt.Sprintf("<span>%02dh</span>", h)
	}

	return fmt.Sprintf(`
<details class="card">
	<summary>⚡ %s</summary>
	<div class="card-content" style="position:relative; padding-left:40px; margin-top:15px; padding-right:5px;">
		<div style="position:absolute; left:0; top:0; height:60px; font-size:0.55rem; color:gray; text-align:right; width:35px; pointer-events:none; font-family:monospace;">
			<div style="position:absolute; top:0; right:5px; transform:translateY(-50%%);">%.0fms</div>
			<div style="position:absolute; top:30px; right:5px; transform:translateY(-50%%);">%.0fms</div>
			<div style="position:absolute; top:60px; right:5px; transform:translateY(-50%%);">0</div>
		</div>
		
		<svg viewBox="0 0 300 60" preserveAspectRatio="none" style="width:100%%; height:60px; display:block; border-bottom: 1px solid rgba(255,255,255,0.1); overflow:visible;">
			<path d="%s L 300,60 L 0,60 Z" fill="rgba(139,92,246,0.15)"/>
			<path d="%s" fill="none" stroke="#a78bfa" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
		</svg>

		<div style="display:flex; justify-content:space-between; font-size:0.6rem; margin-top:8px; color:gray;">
			%s
		</div>
	</div>
</details>`, T.LatencyHistory, renderMax, renderMax/2, pathData, pathData, timeLabels)
}

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

// ============================================================================
// DASHBOARD HTTP HANDLER
// ============================================================================

func createMux() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			debugLog("WS", "", fmt.Sprintf("Upgrade failed: %v", err))
			return
		}

		conn.SetReadDeadline(time.Now().Add(WSPongTimeout))
		conn.SetPongHandler(func(string) error {
			conn.SetReadDeadline(time.Now().Add(WSPongTimeout))
			return nil
		})

		wsHub.register <- conn

		stats := apiMetrics.GetStats()
		conn.SetWriteDeadline(time.Now().Add(WSWriteTimeout))
		conn.WriteJSON(WSMessage{Type: "initial", Data: stats})

		go func() {
			defer func() { wsHub.unregister <- conn }()
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					break
				}
			}
		}()
	})

	mux.HandleFunc("/api/domains", func(w http.ResponseWriter, r *http.Request) {
		serveCachedJSON(w, r, domainsCache)
	})

	mux.HandleFunc("/api/trigger", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		clientIP := getClientIP(r)

		if !validateTriggerToken(r) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "invalid or missing trigger token",
			})

			debugLog("API", clientIP, "Trigger blocked: Invalid token")
			return
		}

		if !globalTriggerLimiter.Allow() {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "10")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":               "global rate limit exceeded",
				"retry_after_seconds": 10,
			})

			debugLog("API", clientIP, "Trigger blocked: Global rate limit")
			return
		}

		ipLimiter := ipTriggerLimiter.GetLimiter(clientIP)
		if !ipLimiter.Allow() {
			remaining := ipLimiter.Remaining()

			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "10")
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":               "IP rate limit exceeded",
				"retry_after_seconds": 10,
				"remaining":           remaining,
			})

			debugLog("API", clientIP, "Trigger blocked: IP rate limit")
			return
		}

		if !updateInProgress.CompareAndSwap(false, true) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":  "update already in progress",
				"status": "busy",
			})

			debugLog("API", clientIP, "Trigger blocked: Update already running")
			return
		}

		go func() {
			defer updateInProgress.Store(false)

			debugLog("API", clientIP, "Manual update triggered")
			runUpdate(false)
		}()

		remaining := ipLimiter.Remaining()

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":               "triggered",
			"message":              "update started",
			"rate_limit_remaining": remaining,
		})
	})

	mux.HandleFunc("/api/trigger/status", func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)
		ipLimiter := ipTriggerLimiter.GetLimiter(clientIP)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ip":                 clientIP,
			"remaining_requests": ipLimiter.Remaining(),
			"update_in_progress": updateInProgress.Load(),
			"global_limit":       globalTriggerLimiter.Remaining(),
		})
	})

	mux.HandleFunc("/api/export", func(w http.ResponseWriter, r *http.Request) {
		statusMutex.Lock()
		defer statusMutex.Unlock()

		exportData := map[string]interface{}{
			"timestamp": time.Now().Format(time.RFC3339),
			"metrics":   apiMetrics.GetStats(),
		}

		if b, err := os.ReadFile(updatePath); err == nil {
			var domains map[string]DomainHistory
			json.Unmarshal(b, &domains)
			exportData["domains"] = domains
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=dyndns-export.json")

		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.Encode(exportData)
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if !lastOk.Load() {
			stats := apiMetrics.GetStats()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":      "unhealthy",
				"api_metrics": stats,
			})
			return
		}

		if r.URL.Query().Get("detailed") == "true" {
			stats := apiMetrics.GetStats()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":      "healthy",
				"api_metrics": stats,
			})
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		serveCachedJSON(w, r, metricsCache)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		statusMutex.Lock()
		data := make(map[string]interface{})
		if fileData, err := os.ReadFile(updatePath); err == nil {
			_ = json.Unmarshal(fileData, &data)
		}
		statusMutex.Unlock()

		statusClass, statusText := "status-ok", T.StatusOk
		if !lastOk.Load() {
			statusClass, statusText = "status-error", T.StatusErr
		}

		var logs []LogEntry
		if b, err := os.ReadFile(logPath); err == nil {
			lines := strings.Split(string(b), "\n")
			for i := len(lines) - 1; i >= 0 && len(logs) < 500; i-- {
				if strings.TrimSpace(lines[i]) == "" {
					continue
				}
				var e LogEntry
				if json.Unmarshal([]byte(lines[i]), &e) == nil {
					logs = append(logs, e)
				}
			}
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!DOCTYPE html><html><head>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<title>`+html.EscapeString(T.DashTitle)+`</title>
		<style>
		* {box-sizing: border-box; margin: 0; padding: 0;}

		:root {
			--bg: #0f172a; --card: #1e293b; --text: #f8fafc; --border: #334155;
			--success: #4ade80; --error: #f87171; --warning: #facc15;
		}
		[data-theme="light"] {
			--bg: #f8fafc; --card: #ffffff; --text: #0f172a; --border: #e2e8f0;
		}
		
		body {
			font-family: system-ui, -apple-system, sans-serif;
			background: var(--bg);
			color: var(--text);
			padding: 10px;
			transition: background 0.3s, color 0.3s;
		}
		
		.container {max-width: 1200px; margin: 0 auto;}

		.header {
			display: flex;
			justify-content: space-between;
			align-items: center;
			margin-bottom: 20px;
			padding: 15px;
			background: var(--card);
			border-radius: 12px;
			border: 1px solid var(--border);
		}
		
		.theme-toggle {
			background: var(--border);
			border: none;
			padding: 8px 16px;
			border-radius: 8px;
			cursor: pointer;
			color: var(--text);
			font-size: 1.2rem;
		}

		.status-banner {
			display: flex;
			justify-content: space-between;
			align-items: center;
			padding: 15px 20px;
			border-radius: 12px;
			margin-bottom: 20px;
			font-weight: 600;
			border: 1px solid rgba(255,255,255,0.1);
		}
		.status-ok {background: rgba(34,197,94,0.15); color: var(--success);}
		.status-error {background: rgba(239,68,68,0.15); color: var(--error);}

		.card {
			background: var(--card);
			padding: 0;
			margin-bottom: 15px;
			border-radius: 12px;
			border: 1px solid var(--border);
			overflow: hidden;
		}
		
		details.card {
			padding: 0;
		}
		
		details.card > summary {
			cursor: pointer;
			padding: 15px 20px;
			font-weight: 600;
			list-style: none;
			display: flex;
			justify-content: space-between;
			align-items: center;
			user-select: none;
		}
		
		details.card > summary::-webkit-details-marker {display: none;}
		
		details.card > summary::after {
			content: '▼';
			transition: transform 0.2s;
			font-size: 0.8em;
			opacity: 0.5;
		}
		
		details.card[open] > summary::after {
			transform: rotate(-180deg);
		}
		
		.card-content {
			padding: 0 20px 20px 20px;
		}

		.search-box {
			width: 100%;
			padding: 12px 16px;
			background: var(--card);
			border: 1px solid var(--border);
			border-radius: 8px;
			color: var(--text);
			font-size: 1rem;
			margin-bottom: 15px;
		}

		.log-filters {
			display: flex;
			gap: 8px;
			margin-bottom: 15px;
			flex-wrap: wrap;
		}
		
		.filter-btn {
			padding: 6px 12px;
			background: var(--border);
			border: 1px solid transparent;
			border-radius: 6px;
			cursor: pointer;
			color: var(--text);
			font-size: 0.85rem;
			transition: all 0.2s;
		}
		
		.filter-btn:hover {
			border-color: var(--success);
		}
		
		.filter-btn.active {
			background: var(--success);
			color: white;
		}

		.copy-btn {
			background: transparent;
			border: 1px solid var(--border);
			padding: 4px 8px;
			border-radius: 4px;
			cursor: pointer;
			font-size: 0.9rem;
			transition:  all 0.2s;
			color: var(--text); 
		}
		
		.copy-btn:hover {
			background: var(--success);
			border-color: var(--success);
			color: white;  
		}

		.toast {
			position: fixed;
			top: 20px;
			right: 20px;
			background: var(--card);
			border: 1px solid var(--border);
			padding: 15px 20px;
			border-radius: 8px;
			box-shadow: 0 4px 12px rgba(0,0,0,0.3);
			transform: translateX(400px);
			transition: transform 0.3s;
			z-index: 1000;
			max-width: 300px;
		}
		
		.toast.show {
			transform: translateX(0);
		}

		.badge {
			padding: 3px 8px;
			border-radius: 4px;
			font-size: 0.7rem;
			color: #fff;
			font-weight: bold;
			display: inline-block;
			margin-right: 6px;
		}
		.v4 {background: #0ea5e9;}
		.v6 {background: #8b5cf6;}

		.log-entry {
			padding: 10px;
			margin-bottom: 6px;
			border-radius: 6px;
			font-size: 0.85rem;
			background: rgba(255,255,255,0.03);
		}
		
		.log-entry.hidden {display: none;}

		.action-btn {
			background: var(--success);
			color: white;
			border: none;
			padding: 10px 20px;
			border-radius: 8px;
			cursor: pointer;
			font-weight: 600;
			transition: all 0.2s;
		}
		
		.action-btn:hover {
			transform: translateY(-2px);
			box-shadow: 0 4px 12px rgba(74, 222, 128, 0.3);
		}

		@media (max-width: 768px) {
			.header {flex-direction: column; gap: 10px;}
			.status-banner {flex-direction: column; text-align: center;}
		}

		.domain-card {
			display: flex;
			justify-content: space-between;
			align-items: center;
			padding: 15px;
			background: rgba(255,255,255,0.02);
			border-radius: 8px;
			margin-bottom: 10px;
		}
		
		.ip-display {
			display: flex;
			align-items: center;
			gap: 8px;
			font-family: 'Courier New', monospace;
		}
		</style>
	</head>
	<body>
	<div class="container">
		<div class="header">
			<h1>🌐 `+html.EscapeString(T.DashTitle)+`</h1>
			<div style="display: flex; gap: 10px; align-items: center;">
				<button class="action-btn" onclick="triggerUpdate()">🔄 Update</button>
				<button class="action-btn" onclick="exportData()">📥 Export</button>
				<button class="theme-toggle" onclick="toggleTheme()">🌓</button>
			</div>
		</div>
		
		<div class="status-banner `+statusClass+`">
			<span>`+statusText+`</span>
			<span>`+T.LastUpdate+`: <span id="lastUpdate">`+time.Now().Format("15:04:05")+`</span></span>
		</div>
		
		<div id="toast" class="toast"></div>
		
		<input type="text" class="search-box" id="domainSearch" placeholder="🔍 Domain suchen..." oninput="filterDomains(this.value)">
	`)

		stats := apiMetrics.GetStats()
		chartSVG := generateSVGChart(stats["hourly_stats"].([24]int))
		latencySVG := generateLatencyChart(stats["hourly_latency"].([24]time.Duration))

		fmt.Fprintf(w, `
		<details class="card" open id="metrics-card">
			<summary>📊 `+T.ApiPerformance+`</summary>
			<div class="card-content">
				<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-top: 10px;">
					<div><strong>`+T.TotalRequests+`:</strong> %v</div>
					<div><strong>`+T.SuccessRate+`:</strong> <span style="color:var(--success)">%v</span></div>
					<div><strong>`+T.AvgLatency+`:</strong> %v</div>
					<div><strong>`+T.Errors+`:</strong> %v / %v</div>
				</div>
                <div style="margin-top: 20px;">
                    <div style="display: flex; justify-content: space-between; font-size: 0.7rem; color: #94a3b8; margin-bottom: 4px;">
                        <span>STÜNDLICHES LIMIT (EST.)</span>
                        <span>%v / %v Requests</span> </div>
                    <div style="width: 100%%; background: #334155; height: 8px; border-radius: 4px; overflow: hidden;">
                        <div style="width: %s%%; height: 100%%; background: %s; transition: width 0.5s ease;"></div>
                    </div>
                    <div style="font-size: 0.65rem; color: #64748b; margin-top: 4px;">Basierend auf Requests der letzten 60 Minuten</div>
                </div>
            </div>
		</details>
		
		%s
		
		%s
	`,
			stats["total_requests"],
			stats["success_rate"],
			stats["avg_latency"],
			stats["client_errors"],
			stats["server_errors"],
			stats["usage_count"],
			stats["hourly_limit"],
			stats["usage_percent"],
			stats["usage_color"],
			chartSVG,
			latencySVG)

		if len(logs) > 0 {
			fmt.Fprintf(w, `
	<details class="card" id="logs-card">
	    <summary>🧾 %s</summary>
	    <div class="card-content">
	        <div class="log-filters">
				<button class="filter-btn active" data-filter="all" onclick="filterLogs('all')">All</button>
				<button class="filter-btn" data-filter="ERR" onclick="filterLogs('ERR')">Errors</button>
				<button class="filter-btn" data-filter="WARN" onclick="filterLogs('WARN')">Warnings</button>
				<button class="filter-btn" data-filter="UPDATE" onclick="filterLogs('UPDATE')">Updates</button>
				<button class="filter-btn" data-filter="START" onclick="filterLogs('START')">Starts</button>
				<button class="filter-btn" data-filter="CREATE" onclick="filterLogs('CREATE')">Created</button>
				<button class="filter-btn" data-filter="CLEANUP" onclick="filterLogs('CLEANUP')">Cleanup</button>
			</div>
		<div id="logContainer" style="max-height: 300px; overflow-y: auto; font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 13px; padding-right: 5px;">
	    `, T.SystemEvents)

			for _, e := range logs {
				displayTime := e.Timestamp
				if len(displayTime) >= 16 {
					datePart := displayTime[8:10] + "." + displayTime[5:7] + "." + displayTime[0:4]
					timePart := displayTime[11:16]
					displayTime = datePart + " " + timePart
				}

				actionUpper := strings.ToUpper(e.Action)

				icon := "🔹"
				switch actionUpper {
				case "ERROR", "FAIL", "CLEANUP":
					icon = "⚠️"
				case "SUCCESS", "ADDED":
					icon = "✅"
				case "UPDATE":
					icon = "🔄"
				case "CREATE":
					icon = "🆕"
				}

				fmt.Fprintf(w, `
	        <div class="log-entry"
	             data-action="%s"
	             data-level="%s"
	             style="display: flex; align-items: flex-start; padding: 6px 8px;
	                    border-radius: 4px; margin-bottom: 4px; gap: 10px;
	                    background: rgba(255,255,255,0.03);">
	            <span style="flex-shrink: 0; width: 20px; text-align: center;">%s</span>
	            <span style="color: #888; white-space: nowrap; font-size: 0.85em;">%s</span>
	            <div style="flex: 1; word-break: break-word;">
	                %s
	                <span style="opacity: 0.9;">%s</span>
	            </div>
	        </div>
	        `,
					actionUpper,
					e.Level,
					icon,
					displayTime,
					func() string {
						if e.Domain == "" {
							return ""
						}
						return `<span style="font-weight: 600; color: #64b5f6; margin-right: 5px;">` +
							html.EscapeString(e.Domain) + `</span>`
					}(),
					html.EscapeString(e.Message),
				)
			}

			fmt.Fprint(w, `
	        </div>
	    </div>
	</details>
	    `)
		}

		var keys []string
		for k := range data {
			if !strings.HasPrefix(k, "_") {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)

		fmt.Fprint(w, `<div id="domainContainer">`)
		for _, k := range keys {
			var h DomainHistory
			b, _ := json.Marshal(data[k])
			_ = json.Unmarshal(b, &h)

			latest := IPEntry{}
			if len(h.IPs) > 0 {
				latest = h.IPs[len(h.IPs)-1]
			}

			safeID := strings.ReplaceAll(k, ".", "-")

			fmt.Fprintf(w, `
		<details class="card domain-item" data-domain="%s">
			<summary>🌐 %s <span style="opacity:0.6; font-size:0.9em;">(%s)</span></summary>
			<div class="card-content">
				<div class="domain-card" style="border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 15px; margin-bottom: 10px;">
					<div>
						<div class="ip-display">
							<span class="badge v4">IPv4</span>
							<span id="ip4-%s">%s</span>
							<button class="copy-btn" onclick="copyIP('%s', 'ip4-%s')" title="Copy">📋</button>
						</div>
						<div class="ip-display" style="margin-top: 8px;">
							<span class="badge v6">IPv6</span>
							<span id="ip6-%s">%s</span>
							<button class="copy-btn" onclick="copyIP('%s', 'ip6-%s')" title="Copy">📋</button>
						</div>
					</div>
					<div style="text-align: right; opacity: 0.7;">
						<small>Zuletzt: %s</small>
					</div>
				</div>

				<div style="max-height: 200px; overflow-y: auto;">
					<table style="width: 100%%; font-size: 0.85em; border-collapse: collapse;">
						<thead style="text-align: left; opacity: 0.5; font-size: 0.7rem;">
							<tr>
								<th style="padding-bottom: 5px;">Zeitpunkt</th>
								<th style="padding-bottom: 5px;">IP Adressen</th>
							</tr>
						</thead>
						<tbody>`,
				html.EscapeString(k), html.EscapeString(k), html.EscapeString(h.Provider),
				safeID, html.EscapeString(latest.IPv4), html.EscapeString(latest.IPv4), safeID,
				safeID, html.EscapeString(latest.IPv6), html.EscapeString(latest.IPv6), safeID,
				html.EscapeString(latest.Time))

			for i := len(h.IPs) - 2; i >= 0; i-- {
				e := h.IPs[i]
				fmt.Fprintf(w, `
			<tr style="border-top: 1px solid rgba(255,255,255,0.05);">
				<td style="padding: 8px 0; vertical-align: top; opacity: 0.7; font-family: monospace;">%s</td>
				<td style="padding: 8px 0;">
					<div style="display:flex; align-items:center; gap:5px;">
						<span class="badge v4" style="font-size:0.6rem; padding: 1px 4px;">v4</span> 
						<span style="opacity:0.9;">%s</span>
					</div>
					<div style="display:flex; align-items:center; gap:5px; margin-top:4px;">
						<span class="badge v6" style="font-size:0.6rem; padding: 1px 4px;">v6</span> 
						<span style="opacity:0.9;">%s</span>
					</div>
				</td>
			</tr>`,
					html.EscapeString(e.Time),
					html.EscapeString(e.IPv4),
					html.EscapeString(e.IPv6),
				)
			}

			if len(h.IPs) < 2 {
				fmt.Fprint(w, `<tr><td colspan="2" style="text-align:center; opacity:0.5; padding: 10px;">Keine weiteren Einträge</td></tr>`)
			}

			fmt.Fprint(w, `
						</tbody>
					</table>
				</div>
			</div>
		</details>`)
		}
		fmt.Fprint(w, `</div>`)

		fmt.Fprint(w, `
	<script>
	function toggleTheme() {
		const html = document.documentElement;
		const current = html.getAttribute('data-theme') || 'dark';
		const next = current === 'dark' ? 'light' : 'dark';
		html.setAttribute('data-theme', next);
		localStorage.setItem('theme', next);
		showToast('Theme: ' + next);
	}

	const savedTheme = localStorage.getItem('theme') || 'dark';
	document.documentElement.setAttribute('data-theme', savedTheme);

	let ws = new WebSocket('ws://' + location.host + '/ws');
	ws.onmessage = (e) => {
		const data = JSON.parse(e.data);
		if (data.type === 'metrics') {
				updateMetrics(data.data);
		} else if (data.type === 'domain_update') {
    		updateDomainDisplay(data.data);
	 }
	};

	ws.onerror = (err) => {
		console.error('WebSocket error:', err);
		showToast('WebSocket connection lost', 'error');
	};

	
	ws.onclose = () => {
		console.log('WebSocket closed, reconnecting in 5s...');
		setTimeout(() => {
 		   location.reload();
		}, 5000);
	};

	function updateDomainDisplay(data) {
		const safeID = data.domain.replace(/\./g, '-');
		const ip4El = document.getElementById('ip4-' + safeID);
	 const ip6El = document.getElementById('ip6-' + safeID);

	 if (ip4El && data.ipv4) ip4El.textContent = data.ipv4;
	  if (ip6El && data.ipv6) ip6El.textContent = data.ipv6;

		showToast('✓ ' + data.domain + ' updated');
	}
	
	function updateMetrics(data) {
		document.getElementById('lastUpdate').textContent = new Date().toLocaleTimeString();
	}

	function filterLogs(filter) {
		document.querySelectorAll('.filter-btn').forEach(btn => {
        if (btn.dataset.filter === filter) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
    });

    document.querySelectorAll('.log-entry').forEach(entry => {
        const action = (entry.dataset.action || '').toUpperCase();
        const level = (entry.dataset.level || '').toUpperCase();
        const filterUpper = filter.toUpperCase();

        if (filter === 'all') {
            entry.style.display = '';
            return;
        }

        let shouldShow = false;
        
        if (filterUpper === 'ERR' && level === 'ERR') {
            shouldShow = true;
        } else if (filterUpper === 'WARN' && level === 'WARN') {
            shouldShow = true;
        } else if (action === filterUpper) {
            shouldShow = true;
        }

        entry.style.display = shouldShow ? '' : 'none';
    });
}

	function copyIP(ip, elementId) {
		navigator.clipboard.writeText(ip).then(() => {
			showToast('✓ Copied: ' + ip);
		}).catch(() => {
			showToast('Copy failed', 'error');
		});
	}

	function showToast(message, type = 'success') {
		const toast = document.getElementById('toast');
		toast.textContent = message;
		toast.style.borderLeft = type === 'error' ? '4px solid var(--error)' : '4px solid var(--success)';
		toast.classList.add('show');
		setTimeout(() => toast.classList.remove('show'), 3000);
	}

	function filterDomains(query) {
		const domains = document.querySelectorAll('.domain-item');
		query = query.toLowerCase();
		domains.forEach(domain => {
			const name = domain.getAttribute('data-domain').toLowerCase();
			domain.style.display = name.includes(query) ? 'block' : 'none';
		});
	}

	function exportData() {
		fetch('/api/export')
			.then(r => r.blob())
			.then(blob => {
				const url = URL.createObjectURL(blob);
				const a = document.createElement('a');
				a.href = url;
				a.download = 'dyndns-export-' + new Date().toISOString().split('T')[0] + '.json';
				a.click();
				showToast('✓ Export started');
			})
			.catch(() => showToast('Export failed', 'error'));
	}

	function triggerUpdate() {
		fetch('/api/trigger', {method: 'POST'})
			.then(r => r.json())
			.then(() => showToast('✓ Update triggered'))
			.catch(() => showToast('Trigger failed', 'error'));
	}

	document.querySelectorAll('details.card').forEach(details => {
	  const id = details.id;
	  const saved = id ? localStorage.getItem('collapse-' + id) : null;

	  if (saved === 'open') {
		details.setAttribute('open', '');
	  } else if (saved === 'closed') {
		details.removeAttribute('open');
	  } else {
		if (id === 'metrics-card') details.setAttribute('open', '');
		else details.removeAttribute('open');
	  }

	  if (id) {
		details.addEventListener('toggle', () => {
		  localStorage.setItem('collapse-' + id, details.open ? 'open' : 'closed');
		});
	  }
	});
	</script>
	</div>
	</body>
	</html>
	`)
	})

	return mux
}

// ============================================================================
// MAIN
// ============================================================================

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("[FATAL] Main-Panic: %v\n", r)
			os.Exit(1)
		}
	}()
	
	rand.Seed(time.Now().UnixNano())

	configDir = os.Getenv("CONFIG_DIR")
	if configDir == "" {
		configDir = "/config"
	}

	langDir = filepath.Join(configDir, "lang")
	logsDir := filepath.Join(configDir, "logs")

	fmt.Printf("[INFO] Config-Verzeichnis: %s\n", configDir)
	fmt.Printf("[INFO] → Sprachen: %s\n", langDir)
	fmt.Printf("[INFO] → Logs: %s\n", logsDir)

	lang := "de"
	envLang := strings.ToLower(os.Getenv("LANG"))
	if envLang != "" {
		if strings.HasPrefix(envLang, "en") {
			lang = "en"
		} else if strings.HasPrefix(envLang, "fr") {
			lang = "fr"
		}
	}

	if err := loadLanguage(lang); err != nil {
		fmt.Printf("[FATAL] Sprachdatei konnte nicht geladen werden: %v\n", err)
		os.Exit(1)
	}

	var d []string
	for _, s := range strings.Split(os.Getenv("DOMAINS"), ",") {
		trimmed := strings.TrimSpace(strings.ToLower(s))
		if trimmed == "" {
			continue
		}

		if err := validateDomain(trimmed); err != nil {
			log(LogContext{
				Level:   LogWarn,
				Action:  ActionConfig,
				Message: fmt.Sprintf("⚠️ Ungültige Domain übersprungen: %s (%v)", s, err),
			})
			continue
		}

		d = append(d, trimmed)
	}

	if len(d) == 0 {
		log(LogContext{
			Level:   LogError,
			Action:  ActionConfig,
			Message: "Keine gültigen Domains konfiguriert!",
		})
		os.Exit(1)
	}

	iv := 300
	if i, err := strconv.Atoi(os.Getenv("INTERVAL")); err == nil && i >= 30 {
		iv = i
	}

	maxLogLines := DefaultMaxLogLines
	if s := strings.TrimSpace(os.Getenv("LOG_MAX_LINES")); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			maxLogLines = v
		} else {
			log(LogContext{
				Level:   LogWarn,
				Action:  ActionConfig,
				Message: fmt.Sprintf("Ungültiger LOG_MAX_LINES Wert '%s', benutze Default %d", s, DefaultMaxLogLines),
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
		APIPrefix:       os.Getenv("API_PREFIX"),
		APISecret:       os.Getenv("API_SECRET"),
		Domains:         d,
		Interval:        iv,
		IPMode:          strings.ToUpper(os.Getenv("IP_MODE")),
		IfaceName:       os.Getenv("INTERFACE"),
		HealthPort:      os.Getenv("HEALTH_PORT"),
		DryRun:          os.Getenv("DRY_RUN") == "true",
		LogDir:          logsDir,
		Lang:            lang,
		DNSServers:      dnsList,
		DebugEnabled:    os.Getenv("DEBUG") == "true",
		DebugHTTPRaw:    os.Getenv("DEBUG_HTTP_RAW") == "true",
		HourlyRateLimit: hourlyLimit,
		MaxConcurrent:   maxConcurrent,
	}

	if cfg.IPMode == "" {
		cfg.IPMode = "BOTH"
	}

	if err := initProviderConfig(); err != nil {
		log(LogContext{
			Level:   LogError,
			Action:  ActionConfig,
			Message: fmt.Sprintf("Provider-Konfiguration fehlgeschlagen: %v", err),
		})
		os.Exit(1)
	}

	if cfg.DebugEnabled {
		debugLog("CONFIG", "", fmt.Sprintf("Debug-Modus aktiv. Intervall: %ds, Mode: %s", cfg.Interval, cfg.IPMode))
		debugLog("CONFIG", "", fmt.Sprintf("Geladene Domains: %v", cfg.Domains))
	}

	logHTTPClientStats()

	if cfg.HealthPort == "" {
		cfg.HealthPort = "8080"
	}

	_ = os.MkdirAll(logsDir, 0755)
	_ = os.MkdirAll(langDir, 0755)

	logPath = filepath.Join(logsDir, "dyndns.json")
	updatePath = filepath.Join(logsDir, "update.json")

	if err := validateConfig(); err != nil {
		log(LogContext{
			Level:   LogError,
			Action:  ActionConfig,
			Message: fmt.Sprintf("%v", err),
		})
		os.Exit(1)
	}

	log(LogContext{
		Level:   LogInfo,
		Action:  ActionStart,
		Message: fmt.Sprintf("🚀 %s (Provider: %s)", T.Startup, cfg.Provider),
	})

	shutdownCtx, shutdownCancel = context.WithCancel(context.Background())
	defer shutdownCancel()

	globalTriggerLimiter = NewRateLimiter(10, 1.0/6.0)
	ipTriggerLimiter = NewIPRateLimiter(5, 0.1)

	go rotationWorker(logPath, maxLogLines)

	updateDomainsCache()
	updateMetricsCache()

	startCacheRefresher()

	srv := &http.Server{Addr: ":" + cfg.HealthPort, Handler: createMux()}

	go func() {
		debugLog("SYSTEM", "", fmt.Sprintf(T.DashboardStarted, cfg.HealthPort))
		log(LogContext{
			Level:   LogInfo,
			Action:  "SERVER",
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
		case <-ticker.C:
			select {
			case <-shutdownCtx.Done():
				debugLog("SCHEDULER", "", "Shutdown aktiv, überspringe Update")
				return
			default:
				debugLog("SCHEDULER", "", "Intervall erreicht, starte runUpdate(false)")
				runUpdate(false)
				limit := maxLogLines
				if cfg.Interval > 300 {
					limit = 1000
				}
				debugLog("MAINTENANCE", "", T.MaintenanceStarting)
				rotateLogFile(logPath, limit)
			}

		case sig := <-stop:
			debugLog("SYSTEM", "", fmt.Sprintf("Shutdown Signal empfangen: %v", sig))
			log(LogContext{
				Level:   LogInfo,
				Action:  ActionStop,
				Message: fmt.Sprintf("🛑 %s (Signal: %v)", T.Shutdown, sig),
			})

			shutdownCancel()

			ticker.Stop()

			if httpClient != nil {
				httpClient.CloseIdleConnections()
				debugLog("SYSTEM", "", T.HTTPConnectionsClosed)
			}

			updateDone := make(chan struct{})
			go func() {
				time.Sleep(2 * time.Second)
				close(updateDone)
			}()

			select {
			case <-updateDone:
				debugLog("SYSTEM", "", "Alle Updates abgeschlossen")
			case <-time.After(ShutdownWaitTimeout):
				debugLog("SYSTEM", "", "⚠️ Timeout beim Warten auf Updates")
			}

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
			return
		}
	}
}
