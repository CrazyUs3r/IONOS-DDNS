// Package main

package main

// ============================================================================
// GLOBALE TRANSLATE VARIABLEN
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
	LoadingSavingJS, LoadingSlowJS, NoLogEntries, AuthDisabled, AuthDisabledActor         string
	SetupRequired, SetupTokenLabel, SetupOpenURL, LoginSuccessLog, LoginFailedLog         string
	ErrInvalidLogin, ErrInvalidSetupToken, ErrUsernameTooShort, LogoutLog                 string
	ErrPasswordTooShort, ErrPasswordsMismatch, ErrAccountCreate, ErrAccountSave           string
	ErrInvalidJSON, ErrUsernamePasswordMin, ErrHash, ErrSave, UserCreatedLog              string
	StatusCreated, ErrInvalidRole, ErrUsernameTaken, ErrMissingID                         string
	ErrUserNotFound, StatusUpdated, ErrForbidden, ErrOwnAccountDelete, StatusDeleted      string
	UserLoadFailedJS, NoUsersFoundJS, UserCreatedJS, RoleChangedJS, UserDeletedJS         string
	ResetPasswordJS, ResetPasswordPromptJS, PasswordResetJS                               string
	GenericErrorJS, RoleAdminJS, RoleEditorJS, RoleViewerJS, AuthUserMinJS, AuthPassMinJS string
	UserLoading, UserNewTitle, UserPlaceholderName, UserPlaceholderPass                   string
	UserRoleViewer, UserRoleEditor, UserRoleAdmin, UserBtnCreate, NotifyTestDesc          string
	IPv64DomainManagement, IPv64DomainFQDN, IPv64DomainPlaceholder, IPv64ActionAdd        string
	ProviderStatusOK, ProviderStatusError, IPv64DomainPlaceholderToken                    string
	IPv64DomainAPITokenOptional, LogDeleteFailedJS, LogEntryDeletedJS                     string
	NavAuditJS, PageReloadFailedJS, SettingsReloadFailedJS, ProviderInvalidJS             string
	UpdateRunningJS, DNScaleAPIKeyMissingJS, FebasUpdateURLMissingJS                      string
	SettingsCheckboxActiveJS, SettingsCheckboxInactiveJS                                  string
	IPv64DomainAddRunningJS, IPv64DomainDeleteRunningJS                                   string
	IPv64DomainAddSuccessJS, IPv64DomainDeleteSuccessJS, IPv64DomainDeleteConfirmJS       string
	UserLastLoginJS, UserDeleteConfirmJS, KeyboardShortcutsHelpJS, NotifEmptyJS           string
	DiagnoseFlagDryRunJS, DiagnoseFlagDebugJS, DiagnoseFlagHTTPRawJS                      string
	AuditEmptyJS, AuditLoadingJS, AuditLoadFailedJS                                       string
	AuditColTimeJS, AuditColUserJS, AuditColActionJS, AuditColStatusJS, AuditColIPJS      string
	DNSNoExpectedJS, DNSMatchOKJS, DNSMatchMismatchJS                                     string
	DNSExpectedIPv4JS, DNSExpectedIPv6JS                                                  string
	DNSColResolverJS, DNSColIPv4JS, DNSColIPv6JS, DNSColDurationErrorJS                   string
	DNSNoResultsJS, DNSDomainRequiredJS, DNSLoadingJS, DNSCheckFailedJS                   string
	AuditAdminOnly, AuditLogTitle, AuditRefreshBtn                                        string
	DNSPropagationTitle, DNSPropagationHelp, DNSCheckBtn                                  string
	DNSInvalidDomainName, DNSAdminEditorRequired, DNSNoNameserverFound                    string
	DNSSystemResolver, DNSSystemResolverFormat                                            string
	SettingsDebugMode, SettingsDebugHTTPRaw, SettingsTTLPlaceholder                       string
	SettingsIPModeGlobal, SettingsIPModeBoth, SettingsIPModeIPv4Only                      string
	SettingsIPModeIPv6Only, SettingsHetznerDNSToken, SettingsHetznerCloudToken            string
	SettingsWebhookURL, SettingsWebhookSecret, SettingsOptional                           string
	SettingsMQTTBroker, SettingsMQTTClientID, SettingsMQTTUsername                        string
	SettingsMQTTSecret, SettingsMQTTPassword, SettingsMQTTTopic                           string
	SettingsMQTTQoS, SettingsMQTTRetain, SettingsMQTTDiscovery                            string
	SettingsMQTTHomeAssistant, SettingsMQTTDiscoveryPrefix                                string
	SettingsEmailSMTPHost, SettingsEmailPort, SettingsEmailUser                           string
	SettingsEmailPassword, SettingsEmailSender, SettingsEmailRecipient                    string
	SettingsEmailSubject, SettingsEmailTLSMode, SettingsEmailTLSStartTLS                  string
	SettingsEmailTLSDirectTLS, SettingsEmailTLSPlain                                      string
	DebugDisabledNote, LogoutLabel, PageLoading, UnsupportedPage                          string

	// Diagnose / Backup
	NavOverview, NavMonitoring, NavTools, NavConfig, NavDiagnoseJS, NavBackupJS string
	NavDashboardJS, NavDomainsJS, NavMetricsJS, NavLogsJS, NavDebugJS           string
	NavSettingsJS, NavDashboard, NavDomains, IPv64ActionDelete                  string

	DiagnoseTitle, DiagnoseRefreshBtn, DiagnoseLoading, DiagnoseLoadFailed         string
	DiagnoseConnectionFailed                                                       string
	DiagnoseReasonAllGood, DiagnoseReasonSchedulerNotRun                           string
	DiagnoseReasonLastSchedulerFailed, DiagnoseReasonWarningsButRunning            string
	DiagnoseNoDomainsConfigured, DiagnoseDomainWithoutFQDN                         string
	DiagnoseTTLTooLowFormat, DiagnoseIonosCredentialsIncompleteFormat              string
	DiagnoseCloudflareCredentialsIncompleteFormat, DiagnoseIpv64TokenMissingFormat string
	DiagnoseDNScaleAPIKeyMissingFormat, DiagnoseHetznerTokenMissingFormat          string
	DiagnoseUnknownDomain, DiagnoseDryRunActive, DiagnoseDebugActive               string
	DiagnoseHTTPRawDebugActive, DiagnoseIntervalLow, DiagnosePathEmpty             string

	DiagnoseStatusHealthy, DiagnoseStatusDegraded, DiagnoseStatusStarting          string
	DiagnoseStatusUnhealthy                                                        string
	DiagnoseSystemTitle, DiagnoseIPDNSTitle, DiagnoseAPIMetricsTitle               string
	DiagnoseConfigTitle, DiagnoseProviderTitle, DiagnoseNotifierTitle              string
	DiagnoseWarningsTitle, DiagnoseFilesTitle                                      string
	DiagnoseUptime, DiagnoseSchedulerRan, DiagnoseLastRunOK                        string
	DiagnoseUpdateRunning, DiagnoseActiveUpdates                                   string
	DiagnoseLastIPv4, DiagnoseLastIPv6, DiagnoseLastDomainChange                   string
	DiagnoseConfiguredDomains, DiagnoseTotalRequests, DiagnoseSuccessRate          string
	DiagnoseAverageLatency, DiagnoseLogErrors, DiagnoseLogWarnings                 string
	DiagnoseIPMode, DiagnoseInterval, DiagnoseIPv4Endpoints, DiagnoseIPv6Endpoints string
	DiagnoseNoProviders, DiagnoseNoNotifiers, DiagnoseNoConfigWarnings             string
	DiagnoseFileMissing, DiagnoseBytes, DiagnoseYes, DiagnoseNo                    string

	BackupTitle, BackupCreateTitle, BackupCreateDesc, BackupDownloadBtn        string
	BackupSecretsHint, BackupRestoreTitle, BackupRestoreDesc, BackupChooseFile string
	BackupRestoreConfig, BackupRestoreStatus, BackupRestoreUsers               string
	BackupRestoreStartBtn, BackupAdminOnly                                     string
	BackupDownloadSuccess, BackupDownloadFailed, BackupSelectFile              string
	BackupSelectArea, BackupConfirmTitle, BackupConfirmConfig                  string
	BackupConfirmStatus, BackupConfirmUsers, BackupConfirmHint                 string
	BackupRestoreRunning, BackupRestoreSuccessFormat, BackupRestoreFailed      string
	BackupAdminRequired, BackupNothingSelected, BackupFileMissing              string
	BackupInvalidJSONFormat, BackupContainsNoConfig, BackupContainsNoStatus    string
	BackupContainsNoUsers, BackupConfigSaveFailedFormat                        string
	BackupStatusRestoreFailedFormat, BackupUsersRestoreFailedFormat            string
	BackupRestoredLogFormat                                                    string

	// Statistiken & Metriken
	SuccessRate, AvgLatency, Errors, RequestHistory, LatencyHistory, APIPerformance            string
	TotalRequests, ClientErrors, ServerErrors, MetricLatencyPercentile, MetricHTTPMethods      string
	MetricIPLatency, MetricLastCheck, MetricAvgFrom, MetricsResetBtn, MetricsResetNotification string

	// Systemauslastung
	SystemStatsTitle, SystemStatsLoading, SystemStatsCPU, SystemStatsMemory                   string
	SystemStatsNetwork, SystemStatsBlockIO, SystemStatsEnvironment, SystemStatsCPULimit       string
	SystemStatsPIDs, SystemStatsGoProcess, SystemStatsCPUThrottling, SystemStatsPressureAvg10 string
	SystemStatsNetworkTotal, SystemStatsIOTotal, SystemStatsCPUDetecting                      string
	SystemStatsMemoryDetecting, SystemStatsNetworkContainer, SystemStatsIOCgroup              string
	SystemStatsNoCgroupLimit, SystemStatsCPUUsageTotalFormat                                  string
	SystemStatsMemoryWithLimitFormat, SystemStatsMemoryNoLimitFormat                          string
	SystemStatsNetworkNamespace, SystemStatsBlockIOCgroup, SystemStatsUnknown                 string
	SystemStatsLive, SystemStatsUnavailable                                                   string
	SystemStatsEnvKubernetes, SystemStatsEnvContainerd, SystemStatsEnvDocker                  string
	SystemStatsEnvContainer, SystemStatsEnvHostProcess                                        string
	SystemStatsNetworkRateFormat, SystemStatsNetworkTotalFormat                               string
	SystemStatsIORateFormat, SystemStatsIOTotalFormat, SystemStatsProcessFormat               string
	SystemStatsLiveWithTimeFormat                                                             string

	// Validierung & allgemeine Fehler
	NoDomains, InvalidPort, IntervalTooSmall, ShortIntervalWarning                             string
	InvalidIPMode, InvalidToken, ConfigErrorPrefix                                             string
	DomainIsEmpty, DomainTooLong, InvalidDomainFormat                                          string
	LabelTooLong, InvalidLabel                                                                 string
	APIErrorBadRequest, APIErrorUnauthorized, APIErrorPaymentRequired                          string
	APIErrorForbidden, APIErrorNotFound, APIErrorMethodNotAllowed                              string
	APIErrorNotAcceptable, APIErrorProxyAuthenticationRequired, APIErrorRequestTimeout         string
	APIErrorConflict, APIErrorGone, APIErrorLengthRequired                                     string
	APIErrorPreconditionFailed, APIErrorPayloadTooLarge, APIErrorURITooLong                    string
	APIErrorUnsupportedMediaType, APIErrorRangeNotSatisfiable, APIErrorExpectationFailed       string
	APIErrorImATeapot, APIErrorMisdirectedRequest, APIErrorUnprocessableEntity                 string
	APIErrorLocked, APIErrorFailedDependency, APIErrorTooEarly                                 string
	APIErrorUpgradeRequired, APIErrorPreconditionRequired, APIErrorRateLimitExceeded           string
	APIErrorRequestHeaderFieldsTooLarge, APIErrorUnavailableForLegalReasons                    string
	APIErrorInternalServerError, APIErrorNotImplemented, APIErrorBadGateway                    string
	APIErrorServiceUnavailable, APIErrorGatewayTimeout, APIErrorHTTPVersionNotSupported        string
	APIErrorVariantAlsoNegotiates, APIErrorInsufficientStorage, APIErrorLoopDetected           string
	APIErrorBandwidthLimitExceeded, APIErrorNotExtended, APIErrorNetworkAuthenticationRequired string
	APIErrorWebServerUnknownError, APIErrorWebServerDown, APIErrorConnectionTimedOut           string
	APIErrorOriginUnreachable, APIErrorTimeoutOccurred, APIErrorSSLHandshakeFailed             string
	APIErrorInvalidSSLCertificate, APIErrorOriginDNSError                                      string
	APIErrorServerErrorGeneric, APIErrorClientErrorGeneric                                     string

	// Logging
	LogRotated, LogRotationError                                    string
	LogQueueFull, LogWriterPanic, LogCannotOpenFile, LogWriteFailed string
	RotationWorkerPanic, LogFlushQueueNotEmptyWithN                 string
	LogFileCloseFailed, RotationQueued, RotationQueueFull           string
	RotationScannerError, NoLanguageDataLoaded                      string

	// DNS & Netzwerk
	RecordFound, RecordCurrent, NoRecordFound, RecordUpdateNeeded, WouldSet              string
	APICall, PayloadSent, ReceivedIP, CheckingInterface, InterfaceNotFound               string
	AddressesNotReadable, NoIPv6OnInterface                                              string
	Attempt, NetworkError, RetryIn, Success, BodyReadError, NonRetryableError            string
	MaxAttemptsReached, RetryScheduled, ContextCancelled, ContextExpired                 string
	RequestCreationFailed, HTTPError, FailedCloseResponseBody                            string
	BadStatusCode, InvalidIPDetected, ExpectedIPv4ButGot, ExpectedIPv6ButGot             string
	FallbackFailed, NoIPEndpointsConfigured, AllIPEndpointsFailed                        string
	IPv6PublicFallback, IPv6FallbackEndpoints, IPv4CheckFailed, IPv6CheckFailed          string
	IPv4RequiredButFailed, IPv6RequiredButFailed, BothIPVersionsFailed                   string
	PublicIPDetectedVia, IPv6ViaInterface, IPv4Current, IPv6Current                      string
	DomainLoopCancelled, PanicOccurred, WorkerCancelledContext                           string
	NoZonesFoundForProvider, NoZoneFound, MatchedZoneEmptyID                             string
	NonRecoverableIPv64Error, NonRecoverableIPv4Error, NonRecoverableIPv6Error           string
	HTTPTimingFormat, HTTPTimingRoundTrip, HTTPTimingDNS, HTTPTimingConnect              string
	HTTPTimingTLS, HTTPTimingTTFB, HTTPTimingReused, HTTPTimingIdle                      string
	HTTPTimingIdleTime, HTTPTimingDial, HTTPTimingDNSError, HTTPTimingConnectError       string
	HTTPTimingTLSError, HTTPDebugCloseRequestBodyFailed, HTTPDebugCloneRequestBodyFailed string
	HTTPDebugCloseClonedRequestBodyFailed, HTTPDebugReadClonedRequestBodyFailed          string
	HTTPDebugDumpRequestFailed, HTTPDebugRequestBodyTruncated                            string
	HTTPDebugRequestDump, HTTPDebugResponseBodyTruncated, HTTPDebugResponseDump          string
	HTTPDebugPeekResponseBodyFailed, HTTPDebugCloseResponseBodyFailed                    string
	MQTTDebugPublishDump, HTTPDebugBodyTruncated, HTTPPoolConfigured                     string
	DNSErrorNoMatchingIP, HTTPRedirectTooMany, HTTPRedirectCrossHostBlocked              string
	DNSErrorDialNoIPs, HTTPDialAttemptFailed, HTTPDialAllFailed                          string
	DNSErrorEmptyHost, DNSErrorNoResolverConfigured, DNSErrorNilResolverForHost          string
	DNSErrorNoIPsForHost, DNSFailoverLookupFailed, DNSResolverLabel                      string
	DNSErrorAllResolversFailed, DNSErrorAllResolversFailedWithCause                      string

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
	DomainSearchPlaceholder, NoMoreEntries, ChecksLabel, EntriesLabel                  string
	BadgeChanged, FilterAll, FilterErrors, FilterWarnings                              string
	FilterUpdates, FilterStarts, FilterStop, FilterCreated, FilterCleanup              string
	FilterSkip, FilterConfig, FilterInfo, FilterLogin, FilterLogout                    string
	FilterLoginFailed, NoDomainsConfigured                                             string
	DomainContext, ThemeLabelJS, NoIPToCopyJS, CopiedJS, CopyFailedJS                  string
	UpdateStartingJS, UpdateStartedJS, ConnectionErrorJS                               string
	ExportStartedJS, ExportFailedJS, FQDNMissingJS                                     string
	SaveConfigConfirmJS, SavedReloadJS, ErrorPrefixJS                                  string
	ResetMetricsConfirmJS, MetricsResetOKJS, MetricsResetFailedJS                      string
	DeleteDomainConfirmJS, DomainRemovedJS, DeleteFailedJS                             string
	TokenSavedJS, TokenDeletedJS, TokenSavedMaskedJS, TokenEnterJS                     string
	DomainUpdatedJS, ClearedJS, DomainHistorySummary                                   string
	CopyTitle, DeleteEntryTitle, HiddenEntriesFormat, FooterMadeWithByFormat           string
	AuditEntryDeleted, AuditDeleteFailed, CNAMEProviderUnsupported, CNAMETargetMissing string

	// Provider-Hinweise / Config
	IonosAPIRequired, Ipv64TokenRequired, CloudflareAuthRequired, UnknownProvider  string
	HetznerAuthRequired, FebasUpdateURLRequired                                    string
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
	MultiProvider, DomainSingular, DomainPlural, ZoneSingular, ZonePlural          string
	ProviderLabel, ZoneLabel, NoRelevantRecords, ConfigProviderCount               string

	// Ionos
	HTTPStatusLatency, IonosNetworkErrorNoRetry, IonosRecordsLoadFailed                        string
	IonosRecordsParseFailed, IonosInvalidCachedRecordID, IonosRefreshInvalidCachedRecordFailed string
	IonosCreateReconciled, IonosCreateReconcileFailed, IonosSuccessResponseParseFailed         string
	IonosCreatedRecordIDLoadFailed, IonosCreatedRecordIDMissing, IonosUnexpectedResponseBody   string
	IonosAPIError, IonosAPIErrorWithIP, IonosZonesLoadFailed, IonosEmptyAPIResponse            string
	IonosZonesParseFailed, IonosZonesFiltered, IonosCacheMissingRealRecordID                   string
	IonosCleanupInvalidCachedRecordID, IonosCreateReconciliationFailed                         string
	UpdateFailedWithError, IonosConflictWouldRemoveFormat, IonosConflictRemovedFormat          string

	// Febas
	FebasZoneNameEmpty, FebasDomainConfigNil, FebasCreateRequest       string
	FebasRedirectBlocked, FebasTooManyRedirects, FebasTemporaryError   string
	FebasRejectedUpdate, FebasURLRequired, FebasURLInvalid             string
	FebasURLMustUseHTTPS, FebasURLMustPointTo, FebasURLMissingKundenID string
	FebasURLMissingToken, FebasAlreadyCurrent, FebasWouldUpdate        string
	FebasUpdateRequested, FebasAttempt, FebasAPIFailed                 string
	FebasTemporaryRetry, FebasResponseClose, FebasDNSLookupFailed      string

	// DNScale
	DNScaleAPIKeyRequired      string
	DNScaleCacheSaveFailed     string
	DNScaleZonesLoadedFromDisk string
	// DNScale API
	DNScaleAPIFailed           string
	DNScaleAttempt             string
	DNScaleNetworkErrorNoRetry string
	DNScaleMaxAttempts         string

	// DNScale Zones
	DNScaleZonesLoadFailed  string
	DNScaleEmptyAPIResponse string
	DNScaleZonesParseFailed string
	DNScaleZonesFiltered    string

	// DNScale Records
	DNScaleRecordsLoadFailed          string
	DNScaleRecordsParseFailed         string
	DNScaleRecordArrow                string
	DNScaleSuccessResponseParseFailed string

	// DNScale Errors
	DNScaleAPIError       string
	DNScaleAPIErrorWithIP string

	// DNScale Cache
	DNScaleCacheZoneNotFound string
	DNScaleCacheRecordAdded  string
	DNScaleCacheUpdated      string

	// DNScale Cleanup
	CleanupStartDNScale    string
	CleanupOrphanedDNScale string

	// Printing
	IonosInfrastructureLoadFailed, LoadHetznerCloudZoneLoadFailed, LoadHetznerDNSZoneLoadFailed string
	LoadCloudflareLoadFailed, LoadIPv64InfrastructureLoadFailed, MissingDomainConfigForProvider string
	UnsupportedProvider, NoCachedIPv64InfrastructureRecords                                     string
	DomainConfiguredMoreThanOnceFormat, InvalidDomainIPModeFormat, InvalidNegativeTTLFormat     string
	MultipleProviderAccountsNotSupportedFormat, MissingDomainConfigurationFormat                string
	InvalidDomainRecordModeFormat, CNAMETargetRequiredFormat                                    string
	CNAMEUnsupportedProviderFormat, CNAMETargetInvalidFormat                                    string
	UnsupportedInfrastructureProviderFormat, UpdateAlreadyRunning                               string
	ProviderZonesFormat, ZoneFormat, NoRelevantRecordsFound                                     string
	// MQTT
	MqttCAFileReadError, MqttCAFileInvalid, MqttConnected, MqttConnectionLost                     string
	MqttConnecting, MqttInitialConnectionPending, MqttConnectFailed, MqttSubscribeTimeout         string
	MqttSubscribeFailed, MqttDiscoveryError, MqttStatePublishFailed, MqttDomainStatePublishFailed string
	MqttNotConnected, MqttCmdRetainedIgnored, MqttCmdPayloadTooLarge, MqttCmdInvalidUpdatePayload string
	MqttCmdUpdateAlreadyRunning, MqttCmdManualUpdateStarted, MqttManualUpdateTriggered            string
	MqttCmdManualUpdateCompleted, MqttCmdManualUpdateFailed, MqttCmdInvalidRefreshPayload         string
	MqttCmdStateRefreshFailed, MqttCmdStateRepublished, MqttCmdUnknown                            string
	MqttDiscoveryLastEvent, MqttDiscoveryStatus, MqttDiscoveryHealth                              string
	MqttDiscoveryUpdateRunning, MqttDiscoveryDomains, MqttDiscoveryRequests                       string
	MqttDiscoverySuccessRate, MqttDiscoveryAverageLatency, MqttDiscoveryUptime                    string
	MqttDiscoveryLastCommand, MqttDiscoveryUpdateNow, MqttDiscoveryRefreshState                   string
	MqttDiscoveryPublished, MqttDiscoveryIPv4, MqttDiscoveryIPv6                                  string
	MqttPublishTimeout                                                                            string

	// Trigger / Rate Limit
	InvalidOrMissingTriggerToken, TriggerBlockedInvalidToken                     string
	GlobalRateLimitExceeded, TriggerBlockedGlobalRateLimit                       string
	TriggerNoDomainsError, TriggerBlockedNoDomainsLog, UpdateAbortedNoDomainsLog string
	TooManyUpdateRequestsWait, IPRateLimitExceeded, TriggerBlockedIPRateLimit    string
	RateLimitGlobal                                                              string

	// Notify event labels & descriptions
	NotifyEventUpdateLabel, NotifyEventUpdateDesc                                      string
	NotifyEventCreateLabel, NotifyEventCreateDesc                                      string
	NotifyEventErrorLabel, NotifyEventErrorDesc                                        string
	NotifyEventStartLabel, NotifyEventStartDesc                                        string
	NotifyEventStopLabel, NotifyEventStopDesc                                          string
	NotifyEventCleanupLabel, NotifyEventCleanupDesc                                    string
	NotifyEventCurrentLabel, NotifyEventCurrentDesc                                    string
	NotifyEventInfoLabel, NotifyEventInfoDesc                                          string
	NotifyEventRetryLabel, NotifyEventRetryDesc                                        string
	NotifyEventConfigLabel, NotifyEventConfigDesc                                      string
	NotifyEventZoneLabel, NotifyEventZoneDesc                                          string
	NotifyEventDryRunLabel, NotifyEventDryRunDesc                                      string
	NotifyEventSkipLabel, NotifyEventSkipDesc                                          string
	NotifyEventAPILabel, NotifyEventAPIDesc                                            string
	NotifyEventServerLabel, NotifyEventServerDesc                                      string
	NotifyEventLoginLabel, NotifyEventLoginDesc                                        string
	NotifyEventLoginFailedLabel, NotifyEventLoginFailedDesc                            string
	NotifyEventLogoutLabel, NotifyEventLogoutDesc                                      string
	NotifyTelegramActive, NotifyGotifyActive, NotifyWebhookActive                      string
	NotifyNtfyActive                                                                   string
	NotifyTestSuccess, NotifyTestUnauthorized, NotifyTestError                         string
	NotifyTestConnError, NotifyTestBody, NotifyBtnSending                              string
	NotifyBtnTest, NotifyNoNotifier, NotifyStatSuccess                                 string
	TgCmdStart, TgCmdStatus, TgCmdMetrics, TgCmdDomains                                string
	TgCmdUpdate, TgCmdHealth, TgCmdHelp, TgMenuPrompt                                  string
	TgUpdateAlreadyRunning, TgUpdateStarting, TgUpdateDone                             string
	TgUnknownCommand, NotifyTelegramManualUpdate, NotifyFailed                         string
	TgStatusOnline, TgStatusError, TgStatusStarting, TgStatusHeading                   string
	TgStatusLabelStatus, TgStatusLabelIPMode, TgStatusLabelDomains                     string
	TgStatusLabelInterval, TgStatusLabelDryRun, TgStatusLabelRequests                  string
	TgStatusLabelSuccessRate, TgStatusLabelLatency, TgStatusLabelLastOk                string
	TgMetricsHeading, TgMetricsRequests, TgMetricsTotal, TgMetricsSuccessRate          string
	TgMetricsClientErr, TgMetricsServerErr, TgMetricsLatency, TgMetricsIPCheck         string
	TgMetricsChecks, TgMetricsLast, TgMetricsHourlyLimit, TgMetricsUsed                string
	TgMetricsLoad, TgMetricsTodayHTTP, TgDomainsHeading, TgDomainsCurrentIPs           string
	TgHealthHeading, TgHealthStarting, TgHealthWaitingDetail                           string
	TgHealthHealthy, TgHealthUnhealthy, TgHealthErrorLabel                             string
	TgBtnMenu, TgBtnClose, TgBtnStatus, TgBtnMetrics, TgBtnDomains                     string
	TgBtnHealth, TgBtnUpdate, TgUnauthAccess, TgBotCmdsReg                             string
	TgSetCmdsFailed, TgGetUpdatesFailed, TgPollingStopped, TgPollingStarted            string
	TgMaxRetries, TgGetUpdatesNotOk, TgSendError, TgHTTPError                          string
	TgRateLimit, TgSendFailed, TgMsgDiscarded, TgQueueFull, TgQueuePushFailed          string
	TgWebhookDeleteRequestError, TgWebhookDeleteFailed, TgWebhookUnregistered          string
	GotifyQueueFull, GotifyMsgDiscarded, GotifySendFailed, GotifyRetry                 string
	NtfyRetry, NtfyMsgDiscarded, NtfyQueueFull, NtfySendFailed, NtfyMaxAttemptsReached string

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
	IonosReloadAfterTypeChangeFailed                                 string

	// Cloudflare
	CFNoCredentials, CFTokenEmpty, CFHTMLResponse string
	CFInvalidJSON, CFAPIFailed, CFZoneLoadError   string
	CFZoneParseError, CFRecordsParseError         string
	CFUnmanagedRecord                             string

	// IPv64
	IPv64BaseDomainNotFound, IPv64CDNIgnoredV4, IPv64CDNIgnoredV6       string
	IPv64UpdateURL, IPv64HTMLResponse, IPv64ParseError                  string
	IPv64APIError, IPv64APIFailed, IPv64HTTPError, IPv64UpdateFailed    string
	IPv64RateLimitHeader, IPv64RateLimitBackoff, IPv64RetriableWait     string
	IPv64CacheBuilt, IPv64CacheUsed, IPv64CacheLoadDisk                 string
	IPv64CacheLoadedDisk, IPv64CacheAPIError, IPv64CacheDiskError       string
	IPv64CacheFallback, IPv64ParseHTMLCache, IPv64CacheSaveError        string
	IPv64CachedDomain, IPv64RecordUpdated, IPv64RecordUpdatedV6         string
	IPv64CacheUpdated, IPv64DeleteResponse                              string
	IPv64ActionInvalid, IPv64FQDNEmpty, IPv64TokenOwnershipVerifyFailed string
	IPv64TokenDoesNotOwnDomain, IPv64NoTokenOwnsDomain                  string
	IPv64NoMatchingTokenConfigured, IPv64AnyTokenVerifyFailed           string
	IPv64OwnershipCheckFailed, IPv64TokenMissing                        string

	// HETZNER
	HetznerAPIFailed, HetznerTokenMissing string

	// Retry attempts
	CFAttempt, IPv64Attempt, IonosAttempt, HetznerAttempt string

	// Settings Modal
	SettingsTitle, SettingsSecurity, SettingsTriggerToken                      string
	SettingsTokenPlaceholder, SettingsTokenSave                                string
	SettingsSystem, SettingsIPMode, SettingsInterval                           string
	SettingsHealthPort, SettingsIface, SettingsIfaceHint                       string
	SettingsDNS, SettingsMaxLog, SettingsMaxRetries                            string
	SettingsMaxConcurrent, SettingsHourlyLimit                                 string
	SettingsLanguage, SettingsDryRun, SettingsDryRunHint                       string
	SettingsCheckboxActive, SettingsCheckboxDeactive, SettingsAddDomain        string
	SettingsDomains, SettingsAddBtn, SettingsCancelBtn, SettingsCFOr           string
	SettingsNotify, SettingsNotifyEnabled, SettingsNotifyOn                    string
	SettingsNotifyEvents, SettingsTGToken, SettingsTGChatID                    string
	SettingsTokenUnchanged, SettingsDNSHint, SettingsOptionalPlaceholder       string
	SettingsSaveBtn, SettingsSaveHint, SettingsRestartHint                     string
	SettingsThemeHint, SettingsNotifierHint, SettingsUpdateHint                string
	SettingsExportHint, SettingsNotifyHint                                     string
	SettingsDebugVerboseHint, SettingsDebugHTTPHint                            string
	SettingsIfacePlaceholder, SettingsAPIPrefix, SettingsAPISecret             string
	SettingsCFEmail, SettingsCFGlobalKey, NotifyMqttActive                     string
	SettingsIPv64Token, SettingsTelegramHeading, SettingsMqttHeading           string
	SettingsGotifyHeading, SettingsDomainPlaceholder, SettingsWebhookHeading   string
	SettingsFebasUpdateURL, SettingsFebasUpdateURLHint                         string
	SettingsDNScaleAPIKey, SettingsDNScaleAPIKeyHint                           string
	SettingsCFTokenHint, SettingsGotifyURL, SettingsGotifyToken                string
	SettingsNtfyURL, SettingsNtfyToken, SettingsNtfyTopic, SettingsNtfyHeading string
	SettingsIPv4Endpoints, SettingsIPv6Endpoints                               string
	SettingsAddBtnJS, NotifyEmailActive, SettingsEmailHeading                  string
	EditDomainTitleJS, EditDomainSavedJS, EditDomainCancelledJS                string
	SettingsUserManagement                                                     string
	SettingsCNAMETargetPlaceholder                                             string

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

	// TOTP
	TotpSettingsPageTitle, TotpVerificationPageTitle, TotpTitle, TotpAccountMeta                      string
	TotpScanQrInstruction, TotpShowURIManually, TotpCodeFromAppLabel, TotpConfirmActivateButton       string
	TotpGenerateNewSecretButton, TotpActiveTitle, TotpActiveSubtitle, TotpDisableInstruction          string
	TotpCurrentCodeLabel, TotpDisableButton, TotpReplaceSecretButton, TotpInactiveTitle               string
	TotpInactiveSubtitle, TotpSetupButton, TotpBackToDashboard, TotpLoginSubtitle, TotpLoginCodeLabel string
	TotpVerifyButton, TotpBackToLogin, TotpQRAlt, TotpFlashGenerateSecretFailed, TotpFlashScanConfirm string
	TotpFlashSetupExpired, TotpFlashCodeInvalid, TotpFlashSaveFailed, TotpFlashEnabled                string
	TotpFlashDisableInvalid, TotpFlashDisabled, TotpLoginInvalidCode, TotpUserNotFound                string
	NavTotpJS, TotpSettingsLoadFailedJS, TotpActionFailedJS, TotpBadgeActiveJS, TotpBadgeInactiveJS   string

	// Misc
	ExportBtn string
}
