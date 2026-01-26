package main

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

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
	ionosBaseURL      = "https://api.hosting.ionos.com/dns/v1/zones"
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

	secretReplacer      *strings.Replacer
	secretReplacerMutex sync.RWMutex
	secretReplacerOnce  sync.Once

	lastConfigHash string

	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc

	globalTriggerLimiter *RateLimiter
	ipTriggerLimiter     *IPRateLimiter
	updateInProgress     atomic.Bool

	domainsCache = &CachedResponse{}
	metricsCache = &CachedResponse{}

	rotationQueue      = make(chan rotationJob, 1)
	rotationInProgress atomic.Bool
	logWriteQueue      = make(chan LogEntry, 100)

	activeUpdates atomic.Int32

	lastSuccessfulDNS int32 = 0

	providerCache = &ProviderDataCache{
		ionosRecords: make(map[string][]Record),
		ipv64Records: make(map[string]IPv64Domain),
	}
	workerSemaphore chan struct{}

	lastIPv64Update time.Time
	ipv64Mutex      sync.Mutex

	wsHub = &WSHub{
		clients:    make(map[*websocket.Conn]bool),
		broadcast:  make(chan WSMessage, 256),
		register:   make(chan *websocket.Conn),
		unregister: make(chan *websocket.Conn),
	}
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			if origin == "" {
				return true
			}
			u, err := url.Parse(origin)
			if err != nil {
				return false
			}
			return strings.EqualFold(u.Host, r.Host)
		},
	}
)

// ============================================================================
// ACTIONS
// ============================================================================

const (
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
	ActionStart:   true,
	ActionStop:    true,
	ActionUpdate:  true,
	ActionCreate:  true,
	ActionError:   true,
	ActionRetry:   true,
	ActionConfig:  true,
	ActionZone:    true,
	ActionCleanup: true,
}

// ============================================================================
// DEFAULTS
// ============================================================================

const (
	DefaultMaxLogLines     = 500
	DefaultHourlyRateLimit = 1200
	DefaultMaxConcurrent   = 5
	MaxAPIRetries          = 3
)

// ============================================================================
// TIMEOUTS
// ============================================================================

const (
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
)

// ============================================================================
// HTTP TRANSPORT
// ============================================================================

const (
	HTTPMaxIdleConns     = 100
	HTTPMaxIdleConnsHost = 10
	HTTPMaxConnsHost     = 20
	HTTPIdleConnTimeout  = 60 * time.Second
	HTTPTLSTimeout       = 10 * time.Second
	HTTPResponseTimeout  = 10 * time.Second
	HTTPExpectTimeout    = 1 * time.Second
)

// ============================================================================
// WEBSOCKET
// ============================================================================

const (
	WSWriteTimeout = 10 * time.Second
	WSPongTimeout  = 60 * time.Second
	WSPingInterval = 30 * time.Second
)

// ============================================================================
// RETRY
// ============================================================================

const (
	RetryBaseDelay        = 1 * time.Second
	RetryMaxDelay         = 60 * time.Second
	RetryJitterMaxMs      = 1000
	RetryExponentBase     = 2.0
	RateLimitRetryDelay   = 60 * time.Second
	ServerErrorRetryDelay = 30 * time.Second
)

// ============================================================================
// MISC
// ============================================================================

const (
	IPCheckBodyMaxBytes   = 1024
	MaxStatusHistoryItems = 20
	TriggerTokenHeader    = "X-Trigger-Token"
)

// ============================================================================
// PROVIDER TYPES
// ============================================================================

type ProviderType string

const (
	ProviderIONOS      ProviderType = "IONOS"
	ProviderCloudflare ProviderType = "CLOUDFLARE"
	ProviderIPv64      ProviderType = "IPV64"
)

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

type DomainConfig struct {
	FQDN     string       `json:"domain"`
	Provider ProviderType `json:"provider"`

	APIPrefix string `json:"api_prefix,omitempty"`
	APISecret string `json:"api_secret,omitempty"`

	CFToken  string `json:"cf_token,omitempty"`
	CFEmail  string `json:"cf_email,omitempty"`
	CFSecret string `json:"cf_secret,omitempty"`
	CFZoneID string `json:"cf_zone_id,omitempty"`

	IPv64Token string `json:"ipv64_token,omitempty"`
}

type Config struct {
	DomainConfigs   []DomainConfig
	IPMode          string
	IfaceName       string
	HealthPort      string
	LogDir          string
	Lang            string
	DNSServers      []string
	Interval        int
	DryRun          bool
	DebugEnabled    bool
	DebugHTTPRaw    bool
	HourlyRateLimit int
	MaxConcurrent   int
}

type Zone struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Records []Record `json:"records"`
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

type IPv64Response struct {
	Subdomains map[string]IPv64Subdomain `json:"subdomains"`
	Info       string                    `json:"info"`
	Status     string                    `json:"status"`
}

type IPv64Subdomain struct {
	Updates          int           `json:"updates"`
	Wildcard         int           `json:"wildcard"`
	DomainUpdateHash string        `json:"domain_update_hash"`
	IPv6Prefix       string        `json:"ipv6prefix"`
	Dualstack        string        `json:"dualstack"`
	Deactivated      int           `json:"deactivated"`
	Records          []IPv64Record `json:"records"`
}

type IPv64Record struct {
	RecordID       int    `json:"record_id"`
	Content        string `json:"content"`
	TTL            int    `json:"ttl"`
	Type           string `json:"type"`
	Praefix        string `json:"praefix"`
	LastUpdate     string `json:"last_update"`
	RecordKey      string `json:"record_key"`
	Deactivated    int    `json:"deactivated"`
	FailoverPolicy string `json:"failover_policy"`
}

type IPv64Domain struct {
	Domain           string `json:"domain"`
	IPv4             string `json:"ipv4"`
	IPv6             string `json:"ipv6"`
	DomainUpdateHash string `json:"domain_update_hash"`
	Updates          int    `json:"updates"`
	Wildcard         int    `json:"wildcard"`
	Deactivated      int    `json:"deactivated"`
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

type ProviderDataCache struct {
	sync.RWMutex
	ionosRecords map[string][]Record
	ipv64Records map[string]IPv64Domain
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

type rotationJob struct {
	path     string
	maxLines int
}
