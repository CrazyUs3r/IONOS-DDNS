// Package main
package main

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"math"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"golang.org/x/sync/singleflight"
)

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

// ============================================================================
// HELPERS - DASHBOARD
// ============================================================================
func getAvailableLanguages(dir string) (map[string]bool, error) {
	langs := make(map[string]bool)

	addEntries := func(entries []os.DirEntry) {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			addLanguageFilename(langs, entry.Name())
		}
	}

	var readErr error
	if entries, err := os.ReadDir(dir); err == nil {
		addEntries(entries)
	} else if !errors.Is(err, os.ErrNotExist) {
		readErr = err
	}
	if entries, err := embeddedLang.ReadDir("lang"); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			addLanguageFilename(langs, entry.Name())
		}
	} else if readErr == nil {
		readErr = err
	}

	if len(langs) == 0 && readErr != nil {
		return nil, readErr
	}

	return langs, nil
}

func addLanguageFilename(langs map[string]bool, filename string) {
	ext := filepath.Ext(filename)
	if !strings.EqualFold(ext, ".json") {
		return
	}

	base := strings.TrimSuffix(filename, ext)
	code := normalizeLang(base)

	if code == "" {
		return
	}

	langs[code] = true
}

func normalizeLang(value string) string {
	value = prepareLanguageValue(value)
	if value == "" {
		return ""
	}

	parts := strings.Split(value, "-")
	normalized := make([]string, 0, len(parts))

	for index, part := range parts {
		normalizedPart, ok := normalizeLanguagePart(index, part)
		if !ok {
			return ""
		}

		normalized = append(normalized, normalizedPart)
	}

	return strings.Join(normalized, "-")
}

func prepareLanguageValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	if index := strings.IndexAny(value, ".@"); index >= 0 {
		value = value[:index]
	}

	return strings.ReplaceAll(value, "_", "-")
}

func normalizeLanguagePart(index int, part string) (string, bool) {
	if part == "" || !isASCIIAlphaNumeric(part) {
		return "", false
	}

	if index == 0 {
		return normalizePrimaryLanguage(part)
	}

	return normalizeLanguageSubtag(part), true
}

func normalizePrimaryLanguage(part string) (string, bool) {
	if len(part) < 2 || len(part) > 8 {
		return "", false
	}

	if !isASCIILetters(part) {
		return "", false
	}

	return strings.ToLower(part), true
}

func normalizeLanguageSubtag(part string) string {
	switch {
	case isScriptSubtag(part):
		return strings.ToUpper(part[:1]) +
			strings.ToLower(part[1:])

	case isRegionSubtag(part):
		return strings.ToUpper(part)

	default:
		return strings.ToLower(part)
	}
}

func isScriptSubtag(part string) bool {
	return len(part) == 4 && isASCIILetters(part)
}

func isRegionSubtag(part string) bool {
	if len(part) == 2 {
		return isASCIILetters(part)
	}

	if len(part) == 3 {
		return isASCIIDigits(part)
	}

	return false
}

func isASCIILetters(value string) bool {
	if value == "" {
		return false
	}

	for i := 0; i < len(value); i++ {
		char := value[i]

		if (char < 'a' || char > 'z') &&
			(char < 'A' || char > 'Z') {
			return false
		}
	}

	return true
}

func isASCIIDigits(value string) bool {
	if value == "" {
		return false
	}

	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}

	return true
}

func isASCIIAlphaNumeric(value string) bool {
	if value == "" {
		return false
	}

	for i := 0; i < len(value); i++ {
		char := value[i]

		isLetter := (char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z')

		isDigit := char >= '0' && char <= '9'

		if !isLetter && !isDigit {
			return false
		}
	}

	return true
}

func languageBase(code string) string {
	code = normalizeLang(code)
	if code == "" {
		return ""
	}

	if before, _, ok := strings.Cut(code, "-"); ok {
		return before
	}

	return code
}

func resolveAvailableLanguage(
	preferred string,
	available map[string]bool,
) (string, bool) {
	preferred = normalizeLang(preferred)
	if preferred == "" {
		return "", false
	}

	if available[preferred] {
		return preferred, true
	}

	base := languageBase(preferred)
	defaultLocale := defaultLocaleByBase[base]

	if preferred == base &&
		defaultLocale != "" &&
		available[defaultLocale] {
		return defaultLocale, true
	}

	if preferred != base && available[base] {
		return base, true
	}

	if defaultLocale != "" && available[defaultLocale] {
		return defaultLocale, true
	}

	var family []string

	for code := range available {
		if languageBase(code) == base {
			family = append(family, code)
		}
	}

	sort.Strings(family)

	if len(family) > 0 {
		return family[0], true
	}

	return "", false
}

func detectLanguage(langDir, preferred string) string {
	langs, err := getAvailableLanguages(langDir)
	if err != nil {
		fmt.Printf(
			"[WARN] Konnte Sprachdateien nicht lesen: %v\n",
			err,
		)
		return "en"
	}

	if resolved, ok := resolveAvailableLanguage(preferred, langs); ok {
		return resolved
	}

	if strings.TrimSpace(preferred) != "" {
		fmt.Printf(
			"[WARN] Sprache '%s' nicht gefunden\n",
			preferred,
		)
	}

	if english, ok := resolveAvailableLanguage("en", langs); ok {
		return english
	}

	codes := make([]string, 0, len(langs))

	for code := range langs {
		codes = append(codes, code)
	}

	sort.Strings(codes)

	if len(codes) > 0 {
		return codes[0]
	}

	return "en"
}

func dashboardI18NJSON() string {
	m := map[string]string{
		"theme":                         t(phrases().ThemeLabelJS, "Theme"),
		"no_ip_to_copy":                 t(phrases().NoIPToCopyJS, "❌ No IP to copy"),
		"copied":                        t(phrases().CopiedJS, "✓ Copied: "),
		"copy_failed":                   t(phrases().CopyFailedJS, "❌ Copy failed"),
		"copy_error":                    t(phrases().CopyFailedJS, "❌ Copy failed"),
		"update_starting":               t(phrases().UpdateStartingJS, "⏳ Starting update..."),
		"update_started":                t(phrases().UpdateStartedJS, "✅ Update started"),
		"connection_error":              t(phrases().ConnectionErrorJS, "❌ Connection error"),
		"export_started":                t(phrases().ExportStartedJS, "✓ Export started"),
		"export_failed":                 t(phrases().ExportFailedJS, "Export failed"),
		"fqdn_missing":                  t(phrases().FQDNMissingJS, "FQDN missing"),
		"domain_updated":                t(phrases().DomainUpdatedJS, "✓ {domain} updated"),
		"delete_domain_confirm":         t(phrases().DeleteDomainConfirmJS, `Domain "{domain}" remove from status?`),
		"domain_removed":                t(phrases().DomainRemovedJS, "🗑️ {domain} removed"),
		"delete_failed":                 t(phrases().DeleteFailedJS, "Deletion failed"),
		"remove_btn":                    t(phrases().RemoveBtn, "🗑️ Remove"),
		"save_config_confirm":           t(phrases().SaveConfigConfirmJS, "Save all settings to config.json?"),
		"saved_reload":                  t(phrases().SavedReloadJS, "✅ Saved! Reloading..."),
		"error_prefix":                  t(phrases().ErrorPrefixJS, "❌ Error: "),
		"loading_saving":                t(phrases().LoadingSavingJS, "⏳ Saving configuration..."),
		"loading_slow":                  t(phrases().LoadingSlowJS, "⚠️ Taking longer than expected..."),
		"reset_metrics_confirm":         t(phrases().ResetMetricsConfirmJS, "Clear all metrics?"),
		"metrics_reset_ok":              t(phrases().MetricsResetOKJS, "✅ Metrics reset"),
		"metrics_reset_failed":          t(phrases().MetricsResetFailedJS, "❌ Reset failed"),
		"token_saved":                   t(phrases().TokenSavedJS, "✅ Token saved"),
		"token_deleted":                 t(phrases().TokenDeletedJS, "🗑️ Token deleted"),
		"token_saved_masked":            t(phrases().TokenSavedMaskedJS, "●●●●●● (saved)"),
		"token_enter":                   t(phrases().TokenEnterJS, "Enter token..."),
		"cleared":                       t(phrases().ClearedJS, "Cleared."),
		"no_log_entries":                t(phrases().NoLogEntries, "No log entries visible"),
		"user_load_failed":              t(phrases().UserLoadFailedJS, "Failed to load"),
		"no_users_found":                t(phrases().NoUsersFoundJS, "No users found."),
		"user_created":                  t(phrases().UserCreatedJS, "User created"),
		"user_deleted":                  t(phrases().UserDeletedJS, "User deleted"),
		"role_changed":                  t(phrases().RoleChangedJS, "Role changed"),
		"role_admin":                    t(phrases().RoleAdminJS, "Admin"),
		"role_editor":                   t(phrases().RoleEditorJS, "Editor"),
		"role_viewer":                   t(phrases().RoleViewerJS, "Viewer"),
		"generic_error":                 t(phrases().GenericErrorJS, "Error"),
		"auth_user_min":                 t(phrases().AuthUserMinJS, "Username min. 3 characters"),
		"auth_pass_min":                 t(phrases().AuthPassMinJS, "Password min. 8 characters"),
		"edit_domain_cancelled":         t(phrases().EditDomainCancelledJS, "Edit cancelled"),
		"edit_domain_saved":             t(phrases().EditDomainSavedJS, "Changes saved"),
		"settings_add_btn":              t(phrases().SettingsAddBtnJS, "➕ Add to list"),
		"notify_test_success":           t(phrases().NotifyTestSuccess, "✅ Test message sent successfully!"),
		"notify_test_unauthorized":      t(phrases().NotifyTestUnauthorized, "❌ Unauthorized (check token)"),
		"notify_test_error":             t(phrases().NotifyTestError, "❌ Error while sending"),
		"notify_test_conn_error":        t(phrases().NotifyTestConnError, "❌ Connection error to server"),
		"notify_btn_sending":            t(phrases().NotifyBtnSending, "⏳ Sende..."),
		"notify_btn_test":               t(phrases().NotifyBtnTest, "🧪 Test-Nachricht senden"),
		"notify_no_notifier":            t(phrases().NotifyNoNotifier, "⚠️ Keine aktiven Notifier konfiguriert."),
		"notify_stat_success":           t(phrases().NotifyStatSuccess, "erfolgreich"),
		"nav_dashboard":                 t(phrases().NavDashboardJS, "🌐 Dashboard"),
		"nav_domains":                   t(phrases().NavDomainsJS, "🌐 Domains"),
		"nav_metrics":                   t(phrases().NavMetricsJS, "📊 Metrics"),
		"nav_logs":                      t(phrases().NavLogsJS, "🧾 Logs"),
		"nav_debug":                     t(phrases().NavDebugJS, "🐞 Debug"),
		"nav_settings":                  t(phrases().NavSettingsJS, "⚙️ Settings"),
		"nav_users":                     t(phrases().SettingsUserManagement, "👥 User Management"),
		"nav_diagnose":                  t(phrases().NavDiagnoseJS, "🩺 Diagnose"),
		"nav_backup":                    t(phrases().NavBackupJS, "💾 Backup & Restore"),
		"diagnose_title":                t(phrases().DiagnoseTitle, "Diagnose / Health Center"),
		"diagnose_loading":              t(phrases().DiagnoseLoading, "Loading diagnosis..."),
		"diagnose_load_failed":          t(phrases().DiagnoseLoadFailed, "Diagnosis failed"),
		"diagnose_connection_failed":    t(phrases().DiagnoseConnectionFailed, "Connection failed"),
		"diagnose_status_healthy":       t(phrases().DiagnoseStatusHealthy, "Healthy"),
		"diagnose_status_degraded":      t(phrases().DiagnoseStatusDegraded, "Degraded"),
		"diagnose_status_starting":      t(phrases().DiagnoseStatusStarting, "Starting"),
		"diagnose_status_unhealthy":     t(phrases().DiagnoseStatusUnhealthy, "Unhealthy"),
		"diagnose_system_title":         t(phrases().DiagnoseSystemTitle, "System"),
		"diagnose_ip_dns_title":         t(phrases().DiagnoseIPDNSTitle, "IP / DNS"),
		"diagnose_api_metrics_title":    t(phrases().DiagnoseAPIMetricsTitle, "API metrics"),
		"diagnose_config_title":         t(phrases().DiagnoseConfigTitle, "Config"),
		"diagnose_provider_title":       t(phrases().DiagnoseProviderTitle, "Provider"),
		"diagnose_notifier_title":       t(phrases().DiagnoseNotifierTitle, "Notifier"),
		"diagnose_warnings_title":       t(phrases().DiagnoseWarningsTitle, "Warnings"),
		"diagnose_files_title":          t(phrases().DiagnoseFilesTitle, "Files"),
		"diagnose_uptime":               t(phrases().DiagnoseUptime, "Uptime"),
		"diagnose_scheduler_ran":        t(phrases().DiagnoseSchedulerRan, "Scheduler ran"),
		"diagnose_last_run_ok":          t(phrases().DiagnoseLastRunOK, "Last run OK"),
		"diagnose_update_running":       t(phrases().DiagnoseUpdateRunning, "Update running"),
		"diagnose_active_updates":       t(phrases().DiagnoseActiveUpdates, "Active updates"),
		"diagnose_last_ipv4":            t(phrases().DiagnoseLastIPv4, "Last IPv4"),
		"diagnose_last_ipv6":            t(phrases().DiagnoseLastIPv6, "Last IPv6"),
		"diagnose_last_domain_change":   t(phrases().DiagnoseLastDomainChange, "Last domain change"),
		"diagnose_configured_domains":   t(phrases().DiagnoseConfiguredDomains, "Domains in status"),
		"diagnose_total_requests":       t(phrases().DiagnoseTotalRequests, "Total requests"),
		"diagnose_success_rate":         t(phrases().DiagnoseSuccessRate, "Success rate"),
		"diagnose_average_latency":      t(phrases().DiagnoseAverageLatency, "Average latency"),
		"diagnose_log_errors":           t(phrases().DiagnoseLogErrors, "Log errors"),
		"diagnose_log_warnings":         t(phrases().DiagnoseLogWarnings, "Log warnings"),
		"diagnose_ip_mode":              t(phrases().DiagnoseIPMode, "IP mode"),
		"diagnose_interval":             t(phrases().DiagnoseInterval, "Interval"),
		"diagnose_ipv4_endpoints":       t(phrases().DiagnoseIPv4Endpoints, "IPv4 endpoints"),
		"diagnose_ipv6_endpoints":       t(phrases().DiagnoseIPv6Endpoints, "IPv6 endpoints"),
		"diagnose_no_providers":         t(phrases().DiagnoseNoProviders, "No providers found"),
		"diagnose_no_notifiers":         t(phrases().DiagnoseNoNotifiers, "No notifiers"),
		"diagnose_no_config_warnings":   t(phrases().DiagnoseNoConfigWarnings, "No config warnings"),
		"diagnose_file_missing":         t(phrases().DiagnoseFileMissing, "missing"),
		"diagnose_bytes":                t(phrases().DiagnoseBytes, "bytes"),
		"diagnose_yes":                  t(phrases().DiagnoseYes, "Yes"),
		"diagnose_no":                   t(phrases().DiagnoseNo, "No"),
		"backup_download_success":       t(phrases().BackupDownloadSuccess, "✅ Backup downloaded"),
		"backup_download_failed":        t(phrases().BackupDownloadFailed, "❌ Backup failed"),
		"backup_select_file":            t(phrases().BackupSelectFile, "❌ Please select a backup file"),
		"backup_select_area":            t(phrases().BackupSelectArea, "❌ Please select at least one area"),
		"backup_confirm_title":          t(phrases().BackupConfirmTitle, "Really restore backup?"),
		"backup_confirm_config":         t(phrases().BackupConfirmConfig, "• Config will be overwritten"),
		"backup_confirm_status":         t(phrases().BackupConfirmStatus, "• Domain status will be overwritten"),
		"backup_confirm_users":          t(phrases().BackupConfirmUsers, "• Users will be overwritten"),
		"backup_confirm_hint":           t(phrases().BackupConfirmHint, "This action may replace existing data."),
		"backup_restore_running":        t(phrases().BackupRestoreRunning, "⏳ Restore running..."),
		"backup_restore_success_format": t(phrases().BackupRestoreSuccessFormat, "✅ Restored: {restored}"),
		"backup_restore_failed":         t(phrases().BackupRestoreFailed, "❌ Restore failed"),
		"nav_totp":                      t(phrases().NavTotpJS, "🔐 2FA / Account Security"),
		"totp_settings_load_failed":     t(phrases().TotpSettingsLoadFailedJS, "2FA settings could not be loaded"),
		"totp_action_failed":            t(phrases().TotpActionFailedJS, "2FA action failed"),
		"totp_badge_active":             t(phrases().TotpBadgeActiveJS, "🔐 2FA active"),
		"totp_badge_inactive":           t(phrases().TotpBadgeInactiveJS, "🔓 2FA inactive"),
		"log_delete_failed":             t(phrases().LogDeleteFailedJS, "Löschen fehlgeschlagen"),
		"log_entry_deleted":             t(phrases().LogEntryDeletedJS, "Eintrag gelöscht:"),
	}

	b, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return string(b)
}

var defaultLocaleByBase = map[string]string{
	"bg": "bg-BG",
	"cs": "cs-CZ",
	"da": "da-DK",
	"de": "de-DE",
	"el": "el-GR",
	"en": "en-GB",
	"es": "es-ES",
	"et": "et-EE",
	"fi": "fi-FI",
	"fr": "fr-FR",
	"hr": "hr-HR",
	"hu": "hu-HU",
	"is": "is-IS",
	"it": "it-IT",
	"lt": "lt-LT",
	"lv": "lv-LV",
	"nb": "nb-NO",
	"nl": "nl-NL",
	"pl": "pl-PL",
	"pt": "pt-PT",
	"ro": "ro-RO",
	"ru": "ru-RU",
	"sk": "sk-SK",
	"sl": "sl-SI",
	"sv": "sv-SE",
	"tr": "tr-TR",
	"uk": "uk-UA",
}

var knownLangLabels = map[string]string{
	"bg": "🇧🇬 Български", "bg-BG": "🇧🇬 Български (България)",
	"cs": "🇨🇿 Čeština", "cs-CZ": "🇨🇿 Čeština (Česko)",
	"da": "🇩🇰 Dansk", "da-DK": "🇩🇰 Dansk (Danmark)",
	"de": "🇩🇪 Deutsch", "de-DE": "🇩🇪 Deutsch (Deutschland)", "de-AT": "🇦🇹 Deutsch (Österreich)", "de-CH": "🇨🇭 Deutsch (Schweiz)",
	"el": "🇬🇷 Ελληνικά", "el-GR": "🇬🇷 Ελληνικά (Ελλάδα)",
	"en": "🇬🇧 English", "en-GB": "🇬🇧 English (United Kingdom)", "en-US": "🇺🇸 English (United States)",
	"es": "🇪🇸 Español", "es-ES": "🇪🇸 Español (España)", "es-MX": "🇲🇽 Español (México)",
	"et": "🇪🇪 Eesti", "et-EE": "🇪🇪 Eesti (Eesti)",
	"fi": "🇫🇮 Suomi", "fi-FI": "🇫🇮 Suomi (Suomi)",
	"fr": "🇫🇷 Français", "fr-FR": "🇫🇷 Français (France)", "fr-CA": "🇨🇦 Français (Canada)", "fr-CH": "🇨🇭 Français (Suisse)",
	"hr": "🇭🇷 Hrvatski", "hr-HR": "🇭🇷 Hrvatski (Hrvatska)",
	"hu": "🇭🇺 Magyar", "hu-HU": "🇭🇺 Magyar (Magyarország)",
	"is": "🇮🇸 Íslenska", "is-IS": "🇮🇸 Íslenska (Ísland)",
	"it": "🇮🇹 Italiano", "it-IT": "🇮🇹 Italiano (Italia)",
	"lt": "🇱🇹 Lietuvių", "lt-LT": "🇱🇹 Lietuvių (Lietuva)",
	"lv": "🇱🇻 Latviešu", "lv-LV": "🇱🇻 Latviešu (Latvija)",
	"nb": "🇳🇴 Norsk", "nb-NO": "🇳🇴 Norsk (Norge)",
	"nl": "🇳🇱 Nederlands", "nl-NL": "🇳🇱 Nederlands (Nederland)", "nl-BE": "🇧🇪 Nederlands (België)",
	"pl": "🇵🇱 Polski", "pl-PL": "🇵🇱 Polski (Polska)",
	"pt": "🇵🇹 Português", "pt-PT": "🇵🇹 Português (Portugal)", "pt-BR": "🇧🇷 Português (Brasil)",
	"ro": "🇷🇴 Română", "ro-RO": "🇷🇴 Română (România)",
	"ru": "🇷🇺 Русский", "ru-RU": "🇷🇺 Русский (Россия)",
	"sk": "🇸🇰 Slovenčina", "sk-SK": "🇸🇰 Slovenčina (Slovensko)",
	"sl": "🇸🇮 Slovenščina", "sl-SI": "🇸🇮 Slovenščina (Slovenija)",
	"sv": "🇸🇪 Svenska", "sv-SE": "🇸🇪 Svenska (Sverige)",
	"tr": "🇹🇷 Türkçe", "tr-TR": "🇹🇷 Türkçe (Türkiye)",
	"uk": "🇺🇦 Українська", "uk-UA": "🇺🇦 Українська (Україна)",
}

func getLangLabel(code string) string {
	code = normalizeLang(code)

	if label, ok := knownLangLabels[code]; ok {
		return label
	}

	return code
}

func buildDynamicLangOptions(current string) string {
	langs, err := getAvailableLanguages(langDir)

	if err != nil || len(langs) == 0 {
		current = normalizeLang(current)

		if current == "" {
			current = "en"
		}

		return `<option value="` +
			esc(current) +
			`" selected>` +
			esc(getLangLabel(current)) +
			`</option>`
	}

	if resolved, ok := resolveAvailableLanguage(current, langs); ok {
		current = resolved
	} else {
		current = normalizeLang(current)
	}

	codes := make([]string, 0, len(langs))

	for code := range langs {
		codes = append(codes, code)
	}

	sort.Strings(codes)

	var out strings.Builder

	for _, code := range codes {
		selected := ""

		if code == current {
			selected = ` selected`
		}

		out.WriteString(`<option value="`)
		out.WriteString(esc(code))
		out.WriteString(`"`)
		out.WriteString(selected)
		out.WriteString(`>`)
		out.WriteString(esc(getLangLabel(code)))
		out.WriteString(`</option>`)
	}

	return out.String()
}

func expectedTranslationKeys() []string {
	v := reflect.TypeFor[Phrases]()
	keys := make([]string, 0, v.NumField())
	for field := range v.Fields() {
		keys = append(keys, toSnakeCase(field.Name))
	}
	sort.Strings(keys)
	return keys
}

func expectedTranslationKeySet() map[string]struct{} {
	expected := expectedTranslationKeys()
	keys := make(map[string]struct{}, len(expected))

	for _, key := range expected {
		keys[key] = struct{}{}
	}

	return keys
}

func esc(s string) string {
	return html.EscapeString(s)
}

func jsString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	s = strings.ReplaceAll(s, "<", `\u003c`)
	s = strings.ReplaceAll(s, ">", `\u003e`)
	s = strings.ReplaceAll(s, "&", `\u0026`)
	return s
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func dryRunEnabled() bool {
	cfgMu.RLock()
	enabled := cfg.DryRun
	cfgMu.RUnlock()
	return enabled
}

func writeFileAtomic(path string, data []byte) (err error) {
	dir := filepath.Dir(path)

	tmpFile, err := os.CreateTemp(
		dir,
		"."+filepath.Base(path)+".*.tmp",
	)
	if err != nil {
		return err
	}

	tmpPath := tmpFile.Name()

	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
	}()

	if err := tmpFile.Chmod(0o600); err != nil {
		return err
	}

	if _, err := tmpFile.Write(data); err != nil {
		return err
	}

	if err := tmpFile.Sync(); err != nil {
		return err
	}

	if err := tmpFile.Close(); err != nil {
		return err
	}

	return os.Rename(tmpPath, path)
}

// ============================================================================
// HELPER - DNS
// ============================================================================
func recordNameFromFQDN(fqdn, zone string) string {
	if fqdn == zone {
		return "@"
	}

	suffix := "." + zone
	if before, ok := strings.CutSuffix(fqdn, suffix); ok {
		return before
	}

	return fqdn
}

func isNonRecoverableError(err error) bool {
	if apiErr, ok := errors.AsType[*APIError](err); ok {
		switch apiErr.StatusCode {
		case 401, 403, 404:
			return true
		}
	}
	return false
}

func loadZonesForDomainConfig(ctx context.Context, dc *DomainConfig) ([]Zone, error) {
	switch dc.Provider {
	case ProviderCloudflare:
		return loadCloudflareZones(ctx, dc)
	case ProviderIPv64:
		return loadIPv64Domains(ctx, dc)
	case ProviderIONOS:
		return loadIONOSZones(ctx, dc)
	case ProviderHetzner:
		return loadHetznerDNSZones(ctx, dc)
	case ProviderHetznerCloud:
		return loadHetznerCloudZones(ctx, dc)
	case ProviderFebas:
		return loadFebasZones(ctx)
	case ProviderDNScale:
		return loadDNScaleZones(ctx, dc)
	default:
		return nil, fmt.Errorf("unknown provider: %s", dc.Provider)
	}
}

func loadAllProviderZones(ctx context.Context) (map[string][]Zone, error) {
	zonesByProvider := make(map[string][]Zone)
	providerConfigs := make(map[ProviderType]*DomainConfig)

	cfgMu.RLock()
	domainConfigs := make([]DomainConfig, len(cfg.DomainConfigs))
	copy(domainConfigs, cfg.DomainConfigs)
	cfgMu.RUnlock()

	for i := range domainConfigs {
		dc := &domainConfigs[i]

		if _, exists := providerConfigs[dc.Provider]; !exists {
			providerConfigs[dc.Provider] = dc
		}
	}

	type zoneResult struct {
		provider string
		zones    []Zone
		err      error
	}

	count := len(providerConfigs)
	if count == 0 {
		return zonesByProvider, nil
	}

	results := make(chan zoneResult, count)

	for provider, dc := range providerConfigs {
		go func(p ProviderType, d *DomainConfig) {
			zones, err := loadZonesForDomainConfig(ctx, d)

			results <- zoneResult{
				provider: string(p),
				zones:    zones,
				err:      err,
			}
		}(provider, dc)
	}

	var loadErrors []error

	for range count {
		result := <-results

		if result.err != nil {
			wrappedErr := fmt.Errorf(
				"failed to load zones for %s: %w",
				result.provider,
				result.err,
			)

			loadErrors = append(loadErrors, wrappedErr)

			log(LogContext{
				Level:   LogWarn,
				Action:  ActionZone,
				Message: wrappedErr.Error(),
			})
			continue
		}

		zonesByProvider[result.provider] = result.zones

		debugLog(
			"ZONE",
			"",
			fmt.Sprintf(
				"✅ Loaded %d zones for %s",
				len(result.zones),
				result.provider,
			),
		)
	}

	if len(zonesByProvider) == 0 && len(loadErrors) > 0 {
		return nil, errors.Join(loadErrors...)
	}

	return zonesByProvider, nil
}

func doSingleflight[T any](
	ctx context.Context,
	g *singleflight.Group,
	key string,
	fn func() (T, error),
) (T, error) {
	var zero T

	ch := g.DoChan(key, func() (any, error) {
		v, err := fn()
		if err != nil {
			return nil, err
		}
		return v, nil
	})

	select {
	case <-ctx.Done():
		return zero, ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return zero, res.Err
		}
		return res.Val.(T), nil
	}
}

func calculateRetryDelay(attempt int, isServerError bool) time.Duration {
	baseWait := min(
		max(
			time.Duration(math.Pow(
				RetryExponentBase,
				float64(attempt+1),
			))*RetryBaseDelay,
			RetryBaseDelay,
		),
		RetryMaxDelay,
	)

	var jitter time.Duration

	if RetryJitterMaxMs > 0 {
		randomValue, err := cryptorand.Int(
			cryptorand.Reader,
			big.NewInt(int64(RetryJitterMaxMs)),
		)
		if err == nil {
			jitter = time.Duration(randomValue.Int64()) * time.Millisecond
		}
	}

	wait := baseWait + jitter

	if isServerError {
		wait *= 2
		if wait > RetryMaxDelay {
			wait = RetryMaxDelay
		}
	}

	return wait
}

func sleepOrCancel(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func effectiveTTL(dc *DomainConfig) int {
	if dc == nil {
		return 60
	}
	if dc.TTL <= 0 {
		return 60
	}
	return dc.TTL
}
