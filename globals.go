// Package main
package main

import (
	"bufio"
	"context"
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
	cfg        Config
	T          Phrases
	startTime  = time.Now()
	configDir  string
	langDir    string
	logPath    string
	configPath string
	updatePath string

	lastOk             atomic.Bool
	schedulerRanOnce   atomic.Bool
	atomicDebugEnabled atomic.Bool
	atomicDebugHTTPRaw atomic.Bool
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
	latestMetrics   map[string]any

	metricsSignal = make(chan struct{}, 1)

	domainRegex = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`)
	labelRegex  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

	secretReplacer   *strings.Replacer
	secretReplacerMu sync.RWMutex

	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc

	globalTriggerLimiter *RateLimiter
	ipTriggerLimiter     *IPRateLimiter
	loginLimiter         *IPRateLimiter
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

	statusDomains map[string]DomainHistory

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
		broadcast:  make(chan WSMessage, 1024),
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
	IconDefault  = "🔹"
	IconDBG      = "🐞"
	IconInfo     = "ℹ️"
	IconWarn     = "⚠️"
	IconError    = "❌"
	IconStart    = "🚀"
	IconStop     = "🛑"
	IconUpdate   = "🔄"
	IconCreate   = "🆕"
	IconCurrent  = "✓"
	IconRetry    = "🔁"
	IconConfig   = "⚙️"
	IconZone     = "🌐"
	IconNetwork  = "📡"
	IconDryRun   = "🔍"
	IconCleanup  = "🧹"
	IconSkip     = "⏭️"
	IconAPI      = "🔌"
	IconServer   = "🖥️"
	IconSuccess  = "✅"
	HTMLChecked  = " checked"
	HTMLSelected = " selected"
)

var actionIcons = map[string]string{
	ActionStart:   IconStart,
	ActionStop:    IconStop,
	ActionUpdate:  IconUpdate,
	ActionCreate:  IconCreate,
	ActionCurrent: IconCurrent,
	ActionRetry:   IconRetry,
	ActionError:   IconError,
	ActionConfig:  IconConfig,
	ActionZone:    IconZone,
	ActionDryRun:  IconDryRun,
	ActionCleanup: IconCleanup,
	ActionSkip:    IconSkip,
	ActionAPI:     IconAPI,
	ActionServer:  IconServer,
	"FAIL":        IconError,
	"SUCCESS":     IconSuccess,
	"ADDED":       IconSuccess,
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
	RecordTypeA     = "A"
	RecordTypeAAAA  = "AAAA"
	RecordTypeCNAME = "CNAME"
	IPModeBoth      = "BOTH"
	IPModeV4        = "IPV4"
	IPModeV6        = "IPV6"
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
	MethodADD    = "ADD"
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
	constTrue  string = "true"
	constFalse string = "false"
)

// ============================================================================
// PROVIDER TYPES
// ============================================================================
const (
	ProviderIONOS        ProviderType = "IONOS"
	ProviderCloudflare   ProviderType = "CLOUDFLARE"
	ProviderIPv64        ProviderType = "IPV64"
	ProviderHetzner      ProviderType = "HETZNER"
	ProviderHetznerCloud ProviderType = "HETZNERCLOUD"

	ionosBaseURL        = "https://api.hosting.ionos.com/dns/v1/zones"
	cloudflareAPIBase   = "https://api.cloudflare.com/client/v4"
	ipv64APIBase        = "https://ipv64.net/api.php"
	ipv64APINIC         = "https://ipv64.net/nic/update?"
	hetznerDNSBaseURL   = "https://dns.hetzner.com/api/v1"
	hetznerCloudBaseURL = "https://api.hetzner.cloud/v1"
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
	UserLoading, UserNewTitle, UserPlaceholderName, UserPlaceholderPass                   string
	UserRoleViewer, UserRoleEditor, UserRoleAdmin, UserBtnCreate, NotifyTestDesc          string
	NavDashboardJS, NavDomainsJS, NavMetricsJS, NavLogsJS, NavDebugJS                     string
	NavSettingsJS, NavDashboard, NavDomains, IPv64ActionDelete                            string
	IPv64DomainManagement, IPv64DomainFQDN, IPv64DomainPlaceholder, IPv64ActionAdd        string
	ProviderStatusOK, ProviderStatusError, IPv64DomainPlaceholderToken                    string
	IPv64DomainAPITokenOptional                                                           string

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
	HetznerAuthRequired                                                            string
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
	NotifyEventCurrentLabel, NotifyEventCurrentDesc                            string
	NotifyEventRetryLabel, NotifyEventRetryDesc                                string
	NotifyEventConfigLabel, NotifyEventConfigDesc                              string
	NotifyEventZoneLabel, NotifyEventZoneDesc                                  string
	NotifyEventDryRunLabel, NotifyEventDryRunDesc                              string
	NotifyEventSkipLabel, NotifyEventSkipDesc                                  string
	NotifyEventAPILabel, NotifyEventAPIDesc                                    string
	NotifyEventServerLabel, NotifyEventServerDesc                              string
	NotifyTelegramActive, NotifyGotifyActive, NotifyWebhookActive              string
	NotifyTestSuccess, NotifyTestUnauthorized, NotifyTestError                 string
	NotifyTestConnError, NotifyTestBody, NotifyBtnSending                      string
	NotifyBtnTest, NotifyNoNotifier, NotifyStatSuccess                         string
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
	SettingsAddBtnJS, NotifyEmailActive, SettingsEmailHeading                string
	EditDomainTitleJS, EditDomainSavedJS, EditDomainCancelledJS              string
	SettingsUserManagement                                                   string

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
	IPv64CacheSaveFailed, HetznerDNSCacheSaveFailed, HetznerCloudCacheSaveFailed                   string
	CleanupSkippedLastRun, CleanupStartingLastRun, CheckingIPv64OrphanedRecords                    string
	IPv64ZonesLoadedFromDisk, CloudflareZonesLoadedFromDisk, IonosZonesLoadedFromDisk              string
	NoProviderCacheOnDiskFound, NoRecordCachesFound, APIAndDiskCacheFailed                         string
	IPFetchFailedFallback, IPv4Changed, IPv6Changed, HetznerDNSZonesLoadedFromDisk                 string
	HetznerCloudZonesLoadedFromDisk                                                                string

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

	// Hetzner DNS / Hetzner Cloud DNS aliases
	HetznerToken       string `json:"hetzner_token"`
	HetznerToken2      string `json:"HETZNER_TOKEN"`
	HetznerDNSToken    string `json:"hetzner_dns_token"`
	HetznerDNSToken2   string `json:"HETZNER_DNS_TOKEN"`
	HetznerCloudToken  string `json:"hetzner_cloud_token"`
	HetznerCloudToken2 string `json:"HETZNER_CLOUD_TOKEN"`
	HCloudToken        string `json:"hcloud_token"`
	HCloudToken2       string `json:"HCLOUD_TOKEN"`

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
		Email struct {
			Host          string `json:"host"`
			Port          int    `json:"port"`
			Username      string `json:"username"`
			Password      string `json:"password"`
			From          string `json:"from"`
			To            string `json:"to"`
			SubjectPrefix string `json:"subject_prefix"`
			TLSMode       string `json:"tls_mode"`
		} `json:"email"`
	} `json:"notifications"`
	IPv4Endpoints []string `json:"ipv4_endpoints,omitempty"`
	IPv6Endpoints []string `json:"ipv6_endpoints,omitempty"`
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
	Result   any               `json:"result"`
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

type SafeErrorMsg struct {
	sync.RWMutex
	msg string
}

type WSMessage struct {
	Type string `json:"type"`
	Data any    `json:"data"`
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
