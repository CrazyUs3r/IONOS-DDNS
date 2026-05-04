// Package main
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/sync/singleflight"
)

// ============================================================================
// GLOBALE VARIABLEN
// ============================================================================
var (
	cfg               Config
	T                 Phrases
	startTime         = time.Now()
	configDir         string
	langDir           string
	logPath           string
	configPath        string
	updatePath        string
	logCachePath      string
	ionosBaseURL      = "https://api.hosting.ionos.com/dns/v1/zones"
	cloudflareAPIBase = "https://api.cloudflare.com/client/v4"
	ipv64APIBase      = "https://ipv64.net/api.php"

	lastOk             atomic.Bool
	schedulerRanOnce   atomic.Bool
	cfgMu              sync.RWMutex
	phraseMu           sync.RWMutex
	logMutex           sync.Mutex
	logFile            *os.File
	logWriter          *bufio.Writer
	closeLogWriterOnce sync.Once
	statusMutex        sync.Mutex
	lastErrorMsg       = &SafeErrorMsg{}

	httpClient   *http.Client
	clientMu     sync.RWMutex
	clientDNSKey string

	notifyCfg   notifyConfig
	notifyCfgMu sync.RWMutex

	apiMetrics      = &APIMetrics{}
	latestMetricsMu sync.RWMutex
	latestMetrics   map[string]interface{}
	logCacheWriteMu sync.Mutex

	metricsSignal = make(chan struct{}, 1)

	domainRegex = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`)
	labelRegex  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

	secretReplacer   *strings.Replacer
	secretReplacerMu sync.Mutex

	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc

	globalTriggerLimiter *RateLimiter
	ipTriggerLimiter     *IPRateLimiter
	updateInProgress     atomic.Bool
	forceNextUpdate      atomic.Bool

	lastZoneLoad          time.Time
	lastRecordLoad        time.Time
	cachedZones           map[string][]Zone
	cachedRecords         *ZoneRecordCache
	lastCleanupNano       atomic.Int64
	zoneCacheMutex        sync.RWMutex
	lastDiskPersistZone   time.Time
	lastDiskPersistRecord time.Time
	diskPersistMutex      sync.Mutex

	ipLoadGroup      singleflight.Group
	zonesLoadGroup   singleflight.Group
	recordsLoadGroup singleflight.Group

	cacheWriteMutex sync.Mutex

	domainsCache = &CachedResponse{}
	metricsCache = &CachedResponse{}

	metricsPersistPath = ""

	rotationQueue   = make(chan rotationJob, 4)
	logWriteQueue   = make(chan LogEntry, 500)
	logFlushTimeout = 2 * time.Second

	activeUpdates atomic.Int32

	lastSuccessfulDNS atomic.Int64

	providerCache = &ProviderDataCache{
		ionosRecords: make(map[string][]Record),
		ipv64Records: make(map[string]IPv64Domain),
	}
	workerSemaphore chan struct{}

	lastIPv64Update          time.Time
	ipv64Mutex               sync.Mutex
	lastIPv64DomainsLoadNano atomic.Int64

	wsHub = &WSHub{
		clients:    make(map[*WSClient]bool),
		broadcast:  make(chan WSMessage, 256),
		register:   make(chan *WSClient, 64),
		unregister: make(chan *WSClient, 64),
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

	DefaultIPv4Endpoints = []string{
		"https://4.ident.me/",
		"https://4.tnedi.me/",
		"https://api.ipify.org/",
		"https://checkip.amazonaws.com/",
		"https://ifconfig.me/ip",
		"https://ipinfo.io/ip",
	}

	DefaultIPv6Endpoints = []string{
		"https://6.ident.me/",
		"https://6.tnedi.me/",
		"https://api6.ipify.org/",
		"https://ipv6.myip.wtf/text",
		"https://botwhatismyipaddress.com/",
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
	ActionSkip    = "SKIP"
	ActionAPI     = "API"
	ActionServer  = "SERVER"
)

var persistOnWarnError = map[string]struct{}{
	ActionStart:   {},
	ActionStop:    {},
	ActionUpdate:  {},
	ActionCreate:  {},
	ActionError:   {},
	ActionRetry:   {},
	ActionConfig:  {},
	ActionZone:    {},
	ActionCleanup: {},
	ActionSkip:    {},
	ActionAPI:     {},
	ActionServer:  {},
}

var persistOnOtherLevels = map[string]struct{}{
	ActionStart:   {},
	ActionStop:    {},
	ActionUpdate:  {},
	ActionCreate:  {},
	ActionCleanup: {},
	ActionSkip:    {},
	ActionAPI:     {},
	ActionRetry:   {},
	ActionConfig:  {},
	ActionZone:    {},
	ActionServer:  {},
}

// ============================================================================
// Dashboard
// ============================================================================
const (
	IconDefault = "🔹"
	IconStart   = "🚀"
	IconStop    = "🛑"
	IconUpdate  = "🔄"
	IconCreate  = "🆕"
	IconCurrent = "✓"
	IconRetry   = "🔁"
	IconError   = "❌"
	IconConfig  = "⚙️"
	IconZone    = "🌐"
	IconDryRun  = "🔍"
	IconCleanup = "🧹"
	IconSkip    = "⏭️"
	IconAPI     = "🔌"
	IconServer  = "🖥️"
	IconSuccess = "✅"
	HTMLChecked = " checked"
)

var actionIcons = map[string]string{
	"START":   IconStart,
	"STOP":    IconStop,
	"UPDATE":  IconUpdate,
	"CREATE":  IconCreate,
	"CURRENT": IconCurrent,
	"RETRY":   IconRetry,
	"ERROR":   IconError,
	"FAIL":    IconError,
	"CONFIG":  IconConfig,
	"ZONE":    IconZone,
	"DRY-RUN": IconDryRun,
	"CLEANUP": IconCleanup,
	"SKIP":    IconSkip,
	"API":     IconAPI,
	"SERVER":  IconServer,
	"SUCCESS": IconSuccess,
	"ADDED":   IconSuccess,
}

// ============================================================================
// DEFAULTS
// ============================================================================
const (
	DefaultMaxLogLines     = 500
	DefaultHourlyRateLimit = 1200
	DefaultMaxConcurrent   = 5
	DefaultMaxAPIRetries   = 3
	DefaultInterval        = 300
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

const (
	IPAny IPVersion = 0
	IPV4  IPVersion = 4
	IPV6  IPVersion = 6
)

const (
	RecordTypeA    = "A"
	RecordTypeAAAA = "AAAA"
	IPModeBoth     = "BOTH"
	IPModeV4       = "IPV4"
	IPModeV6       = "IPV6"
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
	ZoneCacheTTL          = 60 * time.Minute
	RecordCacheTTL        = 60 * time.Minute
	ipv64DomainsCacheTTL  = 60 * time.Minute
	CleanupInterval       = 1 * time.Hour
)

// ============================================================================
// METHOD
// ============================================================================
const (
	MethodPUT    = "PUT"
	MethodPOST   = "POST"
	MethodDELETE = "DELETE"
	MethodGET    = "GET"
	MethodNIC    = "NIC"
)

// ============================================================================
// MISC
// ============================================================================
const (
	IPCheckBodyMaxBytes   = 1024
	MaxStatusHistoryItems = 20
	TriggerTokenHeader    = "X-Trigger-Token"
	ManagedComment        = "Go-DynDNS/2.0"
)

const (
	gotifyQueueSize   = 64
	gotifyQueueMaxAge = 5 * time.Minute
	gotifySendDelay   = 200 * time.Millisecond
)

const (
	tgQueueSize    = 64
	tgQueueMaxAge  = 5 * time.Minute
	tgSendInterval = 500 * time.Millisecond
)

const (
	constTrue  = "TRUE"
	constFalse = "FALSE"
)

// ============================================================================
// PROVIDER TYPES
// ============================================================================
const (
	ProviderIONOS      ProviderType = "IONOS"
	ProviderCloudflare ProviderType = "CLOUDFLARE"
	ProviderIPv64      ProviderType = "IPV64"
)

type ProviderType string

// ============================================================================
// STRUKTUREN
// ============================================================================
type Phrases struct {
	// Basis & Dashboard
	Startup, Shutdown, NoZones, Update, Current, LoginSubtitle, Username                  string
	DashboardTitle, StatusOk, StatusErr, LastUpdate, InfraHeading                         string
	ServiceStarted, DashboardStarted, ServerError, SystemEvents, CriticalAPIError         string
	PanicLoadingLanguage, TryingLoadLanguage, LanguageFileNotFound                        string
	TryingFallbackEn, JSONParseError, LanguageLoaded, MissingTranslationKey               string
	HTTPPool, HourlyLimitEst, RequestsLabel, UsageLast60Min                               string
	MaxLogLines, MaxAPIRetries, MaxConcurrent, Interval, EmptyTranslationValue            string
	IPEndpointStatusTitle, IPEndpointStatusWaiting, Password, LoginButton                 string
	DebugLogTitle, DebugLogLive, DebugFilterPlaceholder, LoginHint, LoginTitle            string
	DebugClearBtn, DebugAutoscroll, DebugWaitingMsg, SetupHeading, SetupSubtitle          string
	SettingsCFProxyLabel, SetupToken, PasswordMinHint, PasswordConfirm, SetupButton       string
	NotifierActive, NotifierDisconnected, SetupHint, SetupTitle                           string
	TooltipLastCheck, TooltipClock, TooltipUptime, FirstAdminCreatedLog                   string
	LoadingSavingJS, LoadingSlowJS, NoLogEntries, AuthDisabled, SetupRequired             string
	SetupTokenLabel, SetupOpenURL, LoginSuccessLog, LoginFailedLog                        string
	ErrInvalidLogin, ErrInvalidSetupToken, ErrUsernameTooShort                            string
	ErrPasswordTooShort, ErrPasswordsMismatch, ErrAccountCreate, ErrAccountSave           string
	ErrInvalidJSON, ErrUsernamePasswordMin, ErrHash, ErrSave, UserCreatedLog              string
	StatusCreated, ErrInvalidRole, ErrUsernameTaken, ErrMissingID                         string
	ErrUserNotFound, StatusUpdated, ErrForbidden, ErrOwnAccountDelete, StatusDeleted      string
	UserLoadFailedJS, NoUsersFoundJS, UserCreatedJS, RoleChangedJS, UserDeletedJS         string
	GenericErrorJS, RoleAdminJS, RoleEditorJS, RoleViewerJS, AuthUserMinJS, AuthPassMinJS string

	// Statistiken & Metriken
	SuccessRate, AvgLatency, Errors, RequestHistory, LatencyHistory, APIPerformance            string
	TotalRequests, ClientErrors, ServerErrors, MetricLatencyPercentile, MetricHTTPMethods      string
	MetricIPLatency, MetricLastCheck, MetricAvgFrom, MetricsResetBtn, MetricsResetNotification string

	// Validierung & allgemeine Fehler
	NoDomains, InvalidPort, IntervalTooSmall, ShortIntervalWarning                           string
	InvalidIPMode, InvalidToken, ConfigErrorPrefix                                           string
	DomainIsEmpty, DomainTooLong, InvalidDomainFormat                                        string
	LabelTooLong, InvalidLabel                                                               string
	APIErrorBadRequest, APIErrorUnauthorized, APIErrorForbidden                              string
	APIErrorNotFound, APIErrorUnprocessableEntity, APIErrorRateLimitExceeded                 string
	APIErrorInternalServerError, APIErrorBadGateway, APIErrorServiceUnavailable              string
	APIErrorGatewayTimeout, APIErrorMethodNotAllowed, APIErrorRequestTimeout                 string
	APIErrorConflict, APIErrorGone, APIErrorPreconditionFailed                               string
	APIErrorPayloadTooLarge, APIErrorUnsupportedMediaType, APIErrorTooEarly                  string
	APIErrorPreconditionRequired, APIErrorRequestHeaderFieldsTooLarge                        string
	APIErrorUnavailableForLegalReasons, APIErrorNotImplemented                               string
	APIErrorInsufficientStorage, APIErrorLoopDetected, APIErrorNetworkAuthenticationRequired string
	APIErrorServerErrorGeneric, APIErrorClientErrorGeneric                                   string

	// Logging
	LogRotated, LogRotationError                                    string
	LogQueueFull, LogWriterPanic, LogCannotOpenFile, LogWriteFailed string
	RotationWorkerPanic, LogFlushQueueNotEmptyWithN                 string
	LogFileCloseFailed, RotationQueued, RotationQueueFull           string
	RotationScannerError, NoLanguageDataLoaded                      string

	// DNS & Netzwerk
	RecordFound, RecordCurrent, NoRecordFound, RecordUpdateNeeded, WouldSet     string
	APICall, PayloadSent, ReceivedIP, CheckingInterface, InterfaceNotFound      string
	AddressesNotReadable, NoIPv6OnInterface                                     string
	Attempt, NetworkError, RetryIn, Success, BodyReadError, NonRetryableError   string
	MaxAttemptsReached, RetryScheduled, ContextCancelled, ContextExpired        string
	RequestCreationFailed, HTTPError, FailedCloseResponseBody                   string
	BadStatusCode, InvalidIPDetected, ExpectedIPv4ButGot, ExpectedIPv6ButGot    string
	FallbackFailed, NoIPEndpointsConfigured, AllIPEndpointsFailed               string
	IPv6PublicFallback, IPv6FallbackEndpoints, IPv4CheckFailed, IPv6CheckFailed string
	IPv4RequiredButFailed, IPv6RequiredButFailed, BothIPVersionsFailed          string
	PublicIPDetectedVia, IPv6ViaInterface, IPv4Current, IPv6Current             string
	DomainLoopCancelled, PanicOccurred, WorkerCancelledContext                  string
	NoZonesFoundForProvider, NoZoneFound, MatchedZoneEmptyID                    string
	NonRecoverableIPv64Error, NonRecoverableIPv4Error, NonRecoverableIPv6Error  string

	// Worker & Status
	WorkerSlotAcquired, WorkerSlotReleased                                     string
	NoZoneFoundForDomain, NoRecordsInCache, CheckingIPv4, CheckingIPv6         string
	UpdateFailed, ChangesDetected, NoChangesNeeded                             string
	SchedulerStarted, SchedulerCompleted                                       string
	UpdateAlreadyInProgressAPI, TriggerStatusBusy, TriggerBlockedUpdateRunning string
	UpdateAlreadyRunningNotification, ManualUpdateTriggeredLog                 string
	ManualUpdateStartedNotification, UpdateStartedMessage                      string
	WaitingForFirstSchedulerRun, HealthCriticalSuccessRate                     string
	HealthDegradedSuccessRate, HealthLastSchedulerFailed                       string

	// Configuration
	ConfigHeading, ConfigInterval, ConfigIPMode, ConfigInterface                        string
	ConfigHealthPort, ConfigDryRun                                                      string
	ConfigLogDir, ConfigLanguage, ConfigDir, ConfigLanguageDir, ConfigLogsDir           string
	LanguageDirCreateFailed, LanguageFileLoadFailed, MetricsLoadFailed, InvalidInterval string

	// System
	MaintenanceStarting, HTTPConnectionsClosed                            string
	ServerShuttingDown, ServerShutdownComplete, ShutdownError             string
	Mode, HTTPClientInitialized                                           string
	WSUpgradeFailed, CouldNotLoadLanguages                                string
	SaveFailed, LanguageParamMissing, UnsupportedLanguage                 string
	LanguageLoadFailed, ConfigSaveWarnAfterLanguageChange                 string
	LanguageChangedLog, LanguageChangedNotification                       string
	RemovedUnusedKey, UpdateDetected, NewFileDetected                     string
	WriteFailed, FileSaved, EmbeddedFileUnreadable, CannotReadEmbeddedDir string

	// Dashboard UI
	DomainSearchPlaceholder, NoMoreEntries, ChecksLabel, EntriesLabel     string
	BadgeChanged, FilterAll, FilterErrors, FilterWarnings                 string
	FilterUpdates, FilterStarts, FilterStop, FilterCreated, FilterCleanup string
	FilterSkip, FilterConfig, NoDomainsConfigured, DomainContext          string
	ThemeLabelJS, NoIPToCopyJS, CopiedJS, CopyFailedJS                    string
	UpdateStartingJS, UpdateStartedJS, ConnectionErrorJS                  string
	ExportStartedJS, ExportFailedJS, FQDNMissingJS                        string
	SaveConfigConfirmJS, SavedReloadJS, ErrorPrefixJS                     string
	ResetMetricsConfirmJS, MetricsResetOKJS, MetricsResetFailedJS         string
	DeleteDomainConfirmJS, DomainRemovedJS, DeleteFailedJS                string
	TokenSavedJS, TokenDeletedJS, TokenSavedMaskedJS, TokenEnterJS        string
	DomainUpdatedJS, ClearedJS                                            string

	// Provider-Hinweise / Config
	IonosAPIRequired, Ipv64TokenRequired, CloudflareAuthRequired, UnknownProvider  string
	DomainParamMissing, DomainStillActiveInConfig, NicIPv64Updates                 string
	NoStatusFileFound, DomainNotFoundInStatus                                      string
	DomainDeletedFromStatusLog, DomainRemovedFromStatus                            string
	FailedToCreateConfigDirectoryFormat, CreateConfigDirectoryFormat               string
	FailedToMarshalConfigFormat, MarshalConfigFormat                               string
	FailedToWriteTempConfigFileFormat, WriteTempConfigFileFormat                   string
	FailedToReplaceConfigFileFormat, ReplaceConfigFileFormat                       string
	ConfigJSONMissingMigratingFromDomainsConfig, InvalidDomainsConfigJSONFormat    string
	CouldNotCreateConfigJSONFormat, ConfigJSONSuccessfullyCreatedFromEnv           string
	NoConfigJSONAndNoDomainsConfigFoundUsingLegacyMode                             string
	IonosRequiresAPIPrefixAndAPISecret, CloudflareRequiresTokenOrEmailAndAPISecret string
	Ipv64RequiresToken, UnknownProviderFormat                                      string

	// Trigger / Rate Limit
	InvalidOrMissingTriggerToken, TriggerBlockedInvalidToken                  string
	GlobalRateLimitExceeded, TriggerBlockedGlobalRateLimit                    string
	TooManyUpdateRequestsWait, IPRateLimitExceeded, TriggerBlockedIPRateLimit string
	RateLimitGlobal                                                           string

	// Notify event labels & descriptions
	NotifyEventUpdateLabel, NotifyEventUpdateDesc                              string
	NotifyEventCreateLabel, NotifyEventCreateDesc                              string
	NotifyEventErrorLabel, NotifyEventErrorDesc                                string
	NotifyEventStartLabel, NotifyEventStartDesc                                string
	NotifyEventStopLabel, NotifyEventStopDesc                                  string
	NotifyEventCleanupLabel, NotifyEventCleanupDesc                            string
	NotifyTelegramActive, NotifyGotifyActive, NotifyWebhookActive              string
	TgCmdStart, TgCmdStatus, TgCmdMetrics, TgCmdDomains                        string
	TgCmdUpdate, TgCmdHealth, TgCmdHelp, TgMenuPrompt                          string
	TgUpdateAlreadyRunning, TgUpdateStarting, TgUpdateDone                     string
	TgUnknownCommand, NotifyTelegramManualUpdate, NotifyFailed                 string
	TgStatusOnline, TgStatusError, TgStatusStarting, TgStatusHeading           string
	TgStatusLabelStatus, TgStatusLabelIPMode, TgStatusLabelDomains             string
	TgStatusLabelInterval, TgStatusLabelDryRun, TgStatusLabelRequests          string
	TgStatusLabelSuccessRate, TgStatusLabelLatency, TgStatusLabelLastOk        string
	TgMetricsHeading, TgMetricsRequests, TgMetricsTotal, TgMetricsSuccessRate  string
	TgMetricsClientErr, TgMetricsServerErr, TgMetricsLatency, TgMetricsIPCheck string
	TgMetricsChecks, TgMetricsLast, TgMetricsHourlyLimit, TgMetricsUsed        string
	TgMetricsLoad, TgMetricsTodayHTTP, TgDomainsHeading, TgDomainsCurrentIPs   string
	TgHealthHeading, TgHealthStarting, TgHealthWaitingDetail                   string
	TgHealthHealthy, TgHealthUnhealthy, TgHealthErrorLabel                     string
	TgBtnMenu, TgBtnClose, TgBtnStatus, TgBtnMetrics, TgBtnDomains             string
	TgBtnHealth, TgBtnUpdate, TgUnauthAccess, TgBotCmdsReg                     string
	TgSetCmdsFailed, TgGetUpdatesFailed, TgPollingStopped, TgPollingStarted    string
	TgMaxRetries, TgGetUpdatesNotOk, TgSendError, TgHTTPError                  string
	TgRateLimit, TgSendFailed, TgMsgDiscarded, TgQueueFull, TgQueuePushFailed  string
	TgWebhookDeleteRequestError, TgWebhookDeleteFailed, TgWebhookUnregistered  string
	GotifyQueueFull, GotifyMsgDiscarded, GotifySendFailed, GotifyRetry         string

	// Cache & persistence
	ErrRecordCacheNil, ErrCacheDirCreate, ErrCacheMarshal               string
	ErrCacheWrite, ErrCacheRename, FileCloseError, ScannerError         string
	CacheSavedZones, CacheSavedDomains, ZoneCacheHitSkipAPI             string
	CacheFileNotFound, CacheLoadedZones, CacheLoadedDomains             string
	IPv64CacheNoData, CacheLoadError, CacheRecordsLoaded                string
	IPv64CacheRecordsLoaded, IPv64CacheLoadDiskFailed                   string
	ErrParseStatusFile, ErrMarshalStatusFile, ErrWriteTempStatusFile    string
	ErrReplaceStatusFile, ErrUpdateDomainsCache, ErrMetricsCacheMarshal string
	ErrResponseWrite, ErrPanicRecovered, CacheRefresherStopped          string
	ErrPanicRefreshCycle, ErrDomainCacheRefresh, ErrMetricsCacheRefresh string

	// Generic API errors
	ErrContextError, ErrJSONMarshal, ErrRequestCreate, ErrNetworkError string
	ErrBodyClose, ErrBodyRead, ErrRateLimit, ErrContextCancelled       string
	ErrAuthFailed, ErrResourceNotFound, ErrValidationFailed            string
	ErrZoneNameEmpty, ErrAPIGeneric, ErrRecordNotFound                 string

	// Cleanup
	CleanupStartIonos, CleanupStartCF, CleanupStartIPv64           string
	CleanupDryRun, CleanupDeleteError, CleanupRecordRemoved        string
	CleanupSkipForeignBase, CleanupSkipCDN, CleanupSkipDeactivated string
	CleanupSkipOrphaned, CleanupOrphanedCF, CleanupOrphanedIonos   string

	// Ionos
	IonosAPIFailed, IonosMaxAttempts                                 string
	IonosCacheZoneNotFound, IonosCacheUpdated, IonosCacheRecordAdded string
	IonosPayload, IonosRecordArrow, IonosRetryable, IonosErrDetail   string

	// Cloudflare
	CFNoCredentials, CFTokenEmpty, CFHTMLResponse string
	CFInvalidJSON, CFAPIFailed, CFZoneLoadError   string
	CFZoneParseError, CFRecordsParseError         string
	CFUnmanagedRecord                             string

	// IPv64
	IPv64BaseDomainNotFound, IPv64CDNIgnoredV4, IPv64CDNIgnoredV6    string
	IPv64UpdateURL, IPv64HTMLResponse, IPv64ParseError               string
	IPv64APIError, IPv64APIFailed, IPv64HTTPError, IPv64UpdateFailed string
	IPv64RateLimitHeader, IPv64RateLimitBackoff, IPv64RetriableWait  string
	IPv64CacheBuilt, IPv64CacheUsed, IPv64CacheLoadDisk              string
	IPv64CacheLoadedDisk, IPv64CacheAPIError, IPv64CacheDiskError    string
	IPv64CacheFallback, IPv64ParseHTMLCache, IPv64CacheSaveError     string
	IPv64CachedDomain, IPv64RecordUpdated, IPv64RecordUpdatedV6      string
	IPv64CacheUpdated, IPv64DeleteResponse                           string

	// Retry attempts
	CFAttempt, IPv64Attempt, IonosAttempt string

	// Settings Modal
	SettingsTitle, SettingsSecurity, SettingsTriggerToken                    string
	SettingsTokenPlaceholder, SettingsTokenSave                              string
	SettingsSystem, SettingsIPMode, SettingsInterval                         string
	SettingsHealthPort, SettingsIface, SettingsIfaceHint                     string
	SettingsDNS, SettingsMaxLog, SettingsMaxRetries                          string
	SettingsMaxConcurrent, SettingsHourlyLimit                               string
	SettingsLanguage, SettingsDryRun, SettingsDryRunHint                     string
	SettingsCheckboxActive, SettingsCheckboxDeactive, SettingsAddDomain      string
	SettingsDomains, SettingsAddBtn, SettingsCancelBtn, SettingsCFOr         string
	SettingsNotify, SettingsNotifyEnabled, SettingsNotifyOn                  string
	SettingsNotifyEvents, SettingsTGToken, SettingsTGChatID                  string
	SettingsTokenUnchanged, SettingsDNSHint                                  string
	SettingsSaveBtn, SettingsSaveHint, SettingsRestartHint                   string
	SettingsDebugVerboseHint, SettingsDebugHTTPHint                          string
	SettingsIfacePlaceholder, SettingsAPIPrefix, SettingsAPISecret           string
	SettingsCFEmail, SettingsCFGlobalKey, NotifyMqttActive                   string
	SettingsIPv64Token, SettingsTelegramHeading, SettingsMqttHeading         string
	SettingsGotifyHeading, SettingsDomainPlaceholder, SettingsWebhookHeading string
	SettingsCFTokenHint, SettingsGotifyURL, SettingsGotifyToken              string
	SettingsIPv4Endpoints, SettingsIPv6Endpoints                             string
	SettingsAddBtnJS                                                         string
	EditDomainTitleJS, EditDomainSavedJS, EditDomainCancelledJS              string

	// Domain display
	DotTitleNoUpdate, DotTitleChanged, DotTitleLast string
	DotTitleOther, DotTitleActive                   string
	TableTime, TableIPs, LastShort                  string
	NotConfiguredLabel, RemoveBtn                   string

	// Scheduler / Cache / Cleanup
	ContextTimeoutForDomains, IPFetchFailed, ZoneLoadingFailed, ProviderReturnedNoZonesCheckAPIKey string
	CacheLoadFailed, IPv64CacheError, RecordCacheError, RecordCacheCouldNotBeLoaded                string
	UsingZoneCacheAge, ForcedRefreshLoadZones, NoZoneCacheInitialLoad, ZoneCacheTooOldReload       string
	ZonesLoadedFromDiskNoAPICall, ZoneAPILoadFailed, TryingDiskCacheFallback, ZonesLoadedFromDisk  string
	ZonesLoadedFromAPI, UsingRecordCacheAge, ForcedRefreshLoadRecords, NoRecordCacheInitialLoad    string
	RecordCacheTooOldReload, RecordCacheLoadedFromDiskNoAPICall, TryingLoadRecordCacheFromDisk     string
	RecordCacheLoadedFromDisk, RecordsLoadedSuccessfully, RecordCacheErrorZone                     string
	DiskCachePersistSkipped, CloudflareCacheSaveFailed, IonosCacheSaveFailed                       string
	CleanupSkippedLastRun, CleanupStartingLastRun, CheckingIPv64OrphanedRecords                    string
	IPv64ZonesLoadedFromDisk, CloudflareZonesLoadedFromDisk, IonosZonesLoadedFromDisk              string
	NoProviderCacheOnDiskFound, NoRecordCachesFound, APIAndDiskCacheFailed                         string

	// Main
	MaxAPIRetriesInvalid, LogMaxLinesInvalid, ConfigJSONReadFailed, ProviderConfigFailed                   string
	DebugModeActive, LoadedDomains, MaxLogLinesInfo, MaxAPIRetriesInfo, MaxConcurrentInfo                  string
	LogDirCreateFailed, DomainCacheUpdateFailed, MetricCacheUpdateFailed, SchedulerIntervalChanged         string
	WebSocketHubStarted, SchedulerShutdownActive, SchedulerIntervalReached, SchedulerPreviousUpdateRunning string
	ShutdownSignalReceived, WaitingForRunningUpdates, AllUpdatesFinished, WaitForUpdatesTimeout            string
	WaitingForLogQueue, MetricsSaveFailed, Providers                                                       string

	// Misc
	ExportBtn string
}

type LogLevel int

const (
	LogDebug LogLevel = iota
	LogInfo
	LogWarn
	LogError
)

type LogContext struct {
	Level      LogLevel
	Action     string
	Domain     string
	Category   string
	Message    string
	Error      error
	SkipNotify bool
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
	FQDN       string       `json:"fqdn"`
	Provider   ProviderType `json:"provider"`
	APIPrefix  string       `json:"api_prefix,omitempty"`
	APISecret  string       `json:"api_secret,omitempty"`
	CFToken    string       `json:"cf_token,omitempty"`
	CFEmail    string       `json:"cf_email,omitempty"`
	CFSecret   string       `json:"cf_secret,omitempty"`
	CFZoneID   string       `json:"cf_zone_id,omitempty"`
	IPv64Token string       `json:"ipv64_token,omitempty"`
	TTL        int          `json:"ttl,omitempty"`
	CFProxied  bool         `json:"cf_proxied,omitempty"`
	IPMode     string       `json:"ip_mode,omitempty"`
}

type rawEntry struct {
	FQDN     string `json:"fqdn"`
	Provider string `json:"provider"`

	// IONOS – canonical lowercase and env-var uppercase
	APIPrefix  string `json:"api_prefix"`
	APISecret  string `json:"api_secret"`
	APIPrefix2 string `json:"API_PREFIX"`
	APISecret2 string `json:"API_SECRET"`

	// Cloudflare
	CFToken   string `json:"cf_token"`
	CFEmail   string `json:"cf_email"`
	CFSecret  string `json:"cf_secret"`
	CFZoneID  string `json:"cf_zone_id"`
	CFToken2  string `json:"CLOUDFLARE_TOKEN"`
	CFEmail2  string `json:"CLOUDFLARE_EMAIL"`
	CFSecret2 string `json:"CLOUDFLARE_API_SECRET"`

	// IPv64
	IPv64Token  string `json:"ipv64_token"`
	IPv64Token2 string `json:"IPV64_TOKEN"`

	TTL       int  `json:"ttl"`
	CFProxied bool `json:"cf_proxied"`
}

type Config struct {
	DomainConfigs   []DomainConfig `json:"DomainConfigs"`
	IPMode          string         `json:"ip_mode"`
	IfaceName       string         `json:"iface_name"`
	HealthPort      string         `json:"health_port"`
	LogDir          string         `json:"log_dir"`
	Lang            string         `json:"lang"`
	DNSServers      []string       `json:"dns_servers"`
	Interval        int            `json:"interval"`
	DryRun          bool           `json:"dry_run"`
	DebugEnabled    bool           `json:"debug_enabled"`
	DebugHTTPRaw    bool           `json:"debug_http_raw"`
	HourlyRateLimit int            `json:"hourly_rate_limit"`
	MaxConcurrent   int            `json:"max_concurrent"`
	MaxLogLines     int            `json:"max_log_lines"`
	MaxAPIRetries   int            `json:"max_api_retries"`
	Notifications   struct {
		Enabled  bool     `json:"enabled"`
		Events   []string `json:"events"`
		Telegram struct {
			Token  string `json:"token"`
			ChatID string `json:"chat_id"`
		} `json:"telegram"`
		Gotify struct {
			URL   string `json:"url"`
			Token string `json:"token"`
		} `json:"gotify"`
		Webhook struct {
			URL    string `json:"url"`
			Secret string `json:"secret"`
		} `json:"webhook"`
		MQTTConfig struct {
			Broker          string `json:"broker"`
			ClientID        string `json:"client_id"`
			Username        string `json:"username"`
			Password        string `json:"password"`
			Topic           string `json:"topic"`
			QoS             byte   `json:"qos"`
			Retain          bool   `json:"retain"`
			CAFile          string `json:"ca_file"`
			Discovery       bool   `json:"discovery"`
			DiscoveryPrefix string `json:"discovery_prefix"`
		} `json:"mqtt"`
	} `json:"notifications"`
	IPv4Endpoints []string        `json:"ipv4_endpoints,omitempty"`
	IPv6Endpoints []string        `json:"ipv6_endpoints,omitempty"`
	Users         []DashboardUser `json:"users,omitempty"`
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
	Comment string `json:"comment"`
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
	Comment string `json:"comment"`
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

type CloudflareCache struct {
	Version    int                 `json:"version"`
	Zones      []Zone              `json:"zones"`
	Records    map[string][]Record `json:"records"`
	LastUpdate time.Time           `json:"last_update"`
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
	Domain           string        `json:"domain"`
	IPv4             string        `json:"ipv4"`
	IPv6             string        `json:"ipv6"`
	DomainUpdateHash string        `json:"domain_update_hash"`
	Updates          int           `json:"updates"`
	Wildcard         int           `json:"wildcard"`
	Deactivated      int           `json:"deactivated"`
	Records          []IPv64Record `json:"records"`
}

type IONOSCache struct {
	Zones      []Zone              `json:"zones"`
	Records    map[string][]Record `json:"records"`
	LastUpdate time.Time           `json:"last_update"`
}

type IPVersion int

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
	LatencySum           time.Duration
	LatencyCount         int64
	AverageLatency       time.Duration
	HourlyLatencySum     [24]time.Duration
	HourlyLatencyCount   [24]int64
	HourlyLatency        [24]time.Duration
	LastError            string
	LastErrorTimestamp   time.Time
	LastSuccessTimestamp time.Time
	RequestTimestamps    []time.Time
	HourlyStats          [24]int
	lastHour             int64
	LatencySamples       [1000]int64
	LatencySampleIdx     int
	LatencySampleCount   int
	DailyGET             int64
	DailyPOST            int64
	DailyPUT             int64
	DailyDELETE          int64
	DailyNIC             int64
	DailyReset           time.Time
	IPLatencySum         time.Duration
	IPLatencyCount       int64
	IPLatencyAvg         time.Duration
	IPLatencySamples     [200]int64
	IPLatencySampleIdx   int
	IPLatencySampleCount int
	LastIPCheckTime      time.Time
}

type SafeErrorMsg struct {
	sync.RWMutex
	msg string
}

type WSMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

type WSClient struct {
	conn      *websocket.Conn
	send      chan WSMessage
	closeOnce sync.Once
}

type WSHub struct {
	clients    map[*WSClient]bool
	register   chan *WSClient
	unregister chan *WSClient
	broadcast  chan WSMessage
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
	ctx         context.Context
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
	IPv4    string
	IPv6    string
}

type rotationJob struct {
	path     string
	maxLines int
}

type apiMetricsSnapshot struct {
	TotalRequests        int64       `json:"total_requests"`
	SuccessRequests      int64       `json:"success_requests"`
	FailedRequests       int64       `json:"failed_requests"`
	RateLimitHits        int64       `json:"rate_limit_hits"`
	ServerErrors         int64       `json:"server_errors"`
	ClientErrors         int64       `json:"client_errors"`
	AverageLatencyMs     int64       `json:"avg_latency_ms"`
	HourlyStats          [24]int     `json:"hourly_stats"`
	HourlyLatencyMs      [24]int64   `json:"hourly_latency_ms"`
	RequestTimestamps    []time.Time `json:"request_timestamps"`
	LastSuccessTime      time.Time   `json:"last_success_at"`
	LastError            string      `json:"last_error"`
	LastErrorTime        time.Time   `json:"last_error_at"`
	SavedAt              time.Time   `json:"saved_at"`
	DailyGET             int64       `json:"daily_get"`
	DailyPOST            int64       `json:"daily_post"`
	DailyPUT             int64       `json:"daily_put"`
	DailyDELETE          int64       `json:"daily_delete"`
	DailyNIC             int64       `json:"daily_nic"`
	DailyReset           time.Time   `json:"daily_reset"`
	LatencySamples       [1000]int64 `json:"latency_samples"`
	LatencySampleIdx     int         `json:"latency_sample_idx"`
	LatencySampleCount   int         `json:"latency_sample_count"`
	IPLatencySum         int64       `json:"ip_latency_sum_ms"`
	IPLatencyCount       int64       `json:"ip_latency_count"`
	IPLatencyAvgMs       int64       `json:"ip_latency_avg_ms"`
	IPLatencySamples     [200]int64  `json:"ip_latency_samples"`
	IPLatencySampleIdx   int         `json:"ip_latency_sample_idx"`
	IPLatencySampleCount int         `json:"ip_latency_sample_count"`
	LastIPCheckTime      time.Time   `json:"last_ip_check_at"`
}

// ============================================================================
// HTTP TRACE / TIMINGS (DNS, CONNECT, TLS, TTFB, REUSE)
// ============================================================================
type httpTimings struct {
	start        time.Time
	end          time.Time
	gotConn      time.Time
	connReused   bool
	connWasIdle  bool
	connIdleTime time.Duration
	dnsStart     time.Time
	dnsDone      time.Time
	dnsErr       error
	connectStart time.Time
	connectDone  time.Time
	connectNet   string
	connectAddr  string
	connectErr   error
	tlsStart     time.Time
	tlsDone      time.Time
	tlsState     *tls.ConnectionState
	tlsErr       error
	wroteRequest time.Time
	firstByte    time.Time
}

// ============================================================================
// NOTIFICATION
// ============================================================================
type NotifyEvent string

const (
	NotifyOnUpdate  NotifyEvent = "UPDATE"
	NotifyOnCreate  NotifyEvent = "CREATE"
	NotifyOnError   NotifyEvent = "ERROR"
	NotifyOnStart   NotifyEvent = "START"
	NotifyOnStop    NotifyEvent = "STOP"
	NotifyOnCleanup NotifyEvent = "CLEANUP"
)

type Notifier interface {
	Name() string
	Send(msg NotifyMessage) error
}

type NotifyMessage struct {
	Action  string
	Domain  string
	Message string
	Level   LogLevel
}

type notifyConfig struct {
	notifiers []Notifier
	events    map[NotifyEvent]struct{}
}

// ============================================================================
// DNS CACHE
// ============================================================================
type dnsCache struct {
	ttl      time.Duration
	mu       sync.Mutex
	entries  map[string]dnsCacheEntry
	inflight map[string]*dnsInFlight
	resolver *net.Resolver
}

type dnsCacheEntry struct {
	ips    []net.IPAddr
	expiry time.Time
}

type dnsInFlight struct {
	done  chan struct{}
	addrs []net.IPAddr
	err   error
}

// ============================================================================
// TELEGRAM TYPES
// ============================================================================
type tgMessage struct {
	MessageID int    `json:"message_id"`
	Text      string `json:"text"`
	Chat      tgChat `json:"chat"`
	From      tgUser `json:"from"`
	Date      int64  `json:"date"`
}

type tgChat struct {
	ID int64 `json:"id"`
}

type tgUser struct {
	ID        int64  `json:"id"`
	FirstName string `json:"first_name"`
	Username  string `json:"username"`
}

type tgInlineKeyboard struct {
	InlineKeyboard [][]tgInlineButton `json:"inline_keyboard"`
}

type tgInlineButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data"`
}

type tgCallbackQuery struct {
	ID      string    `json:"id"`
	From    tgUser    `json:"from"`
	Message tgMessage `json:"message"`
	Data    string    `json:"data"`
}

type tgUpdateFull struct {
	UpdateID      int64            `json:"update_id"`
	Message       *tgMessage       `json:"message,omitempty"`
	CallbackQuery *tgCallbackQuery `json:"callback_query,omitempty"`
}
type telegramNotifier struct {
	token          string
	chatID         string
	instanceTag    string
	pollOnce       sync.Once
	pollClientOnce sync.Once
	pollClient     *http.Client
	lastOffset     atomic.Int64
	sendQueue      chan tgQueuedMsg
	pollCtx        context.Context
	pollCancel     context.CancelFunc
	wg             sync.WaitGroup
}

type tgQueuedMsg struct {
	chatID   string
	text     string
	kb       *tgInlineKeyboard
	enqueued time.Time
}

// ============================================================================
// GOTIFY TYPES
// ============================================================================
type gotifyNotifier struct {
	url       string
	token     string
	sendQueue chan gotifyQueuedMsg
}

type gotifyQueuedMsg struct {
	title    string
	body     string
	priority int
	enqueued time.Time
}
