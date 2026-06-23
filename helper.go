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

	for range count {
		r := <-results
		if r.err != nil {
			return nil, fmt.Errorf("failed to load zones for %s: %w", r.provider, r.err)
		}

		zonesByProvider[r.provider] = r.zones
		debugLog("ZONE", "", fmt.Sprintf("✅ Loaded %d zones for %s", len(r.zones), r.provider))
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
