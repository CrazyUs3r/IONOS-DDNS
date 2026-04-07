// Package main
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

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
func getAvailableLanguages(langDir string) (map[string]bool, error) {
	files, err := os.ReadDir(langDir)
	if err != nil {
		return nil, err
	}

	langs := make(map[string]bool)

	for _, f := range files {
		if f.IsDir() {
			continue
		}

		name := f.Name()
		ext := filepath.Ext(name)
		base := strings.TrimSuffix(name, ext)

		if ext == ".json" && base != "" {
			base = strings.ToLower(base)
			if i := strings.Index(base, "_"); i != -1 {
				base = base[:i]
			}

			langs[base] = true
		}
	}

	return langs, nil
}

func normalizeLang(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))

	if i := strings.Index(s, "_"); i != -1 {
		s = s[:i]
	}
	if i := strings.Index(s, "."); i != -1 {
		s = s[:i]
	}

	return s
}

func detectLanguage(langDir string) string {
	langs, err := getAvailableLanguages(langDir)
	if err != nil {
		fmt.Printf("[WARN] Konnte Sprachdateien nicht lesen: %v\n", err)
		return "en"
	}

	envLang := normalizeLang(os.Getenv("LANG"))

	if envLang == "" {
		envLang = "en"
	}
	if langs[envLang] {
		return envLang
	}
	if envLang != "" {
		fmt.Printf("[WARN] Sprache '%s' nicht gefunden\n", envLang)
	}
	if langs["en"] {
		return "en"
	}
	for l := range langs {
		return l
	}
	return "en"
}

var knownLangLabels = map[string]string{
	"de": "🇩🇪 Deutsch",
	"en": "🇬🇧 English",
	"fr": "🇫🇷 Français",
	"es": "🇪🇸 Español",
	"it": "🇮🇹 Italiano",
	"nl": "🇳🇱 Nederlands",
	"pl": "🇵🇱 Polski",
	"sv": "🇸🇪 Svenska",
	"da": "🇩🇰 Dansk",
	"pt": "🇵🇹 Português",
	"cs": "🇨🇿 Čeština",
	"hu": "🇭🇺 Magyar",
	"ro": "🇷🇴 Română",
	"tr": "🇹🇷 Türkçe",
	"ja": "🇯🇵 日本語",
	"zh": "🇨🇳 中文",
	"ru": "🇷🇺 Русский",
	"uk": "🇺🇦 Українська",
	"fi": "🇫🇮 Suomi",
	"nb": "🇳🇴 Norsk",
}

func getLangLabel(code string) string {
	if label, ok := knownLangLabels[code]; ok {
		return label
	}
	return strings.ToUpper(code)
}

func buildDynamicLangOptions(current string) string {
	langs, err := getAvailableLanguages(langDir)
	if err != nil || len(langs) == 0 {
		label := getLangLabel(current)
		return `<option value="` + current + `" selected>` + label + `</option>`
	}

	codes := make([]string, 0, len(langs))
	for code := range langs {
		codes = append(codes, code)
	}

	sort.Strings(codes)

	var out strings.Builder
	for _, code := range codes {
		sel := ""
		if code == current {
			sel = ` selected`
		}
		label := getLangLabel(code)
		out.WriteString(`<option value="` + code + `"` + sel + `>` + label + `</option>`)
	}
	return out.String()
}
func expectedTranslationKeys() []string {
	v := reflect.TypeOf(T)
	keys := make([]string, 0, v.NumField())
	for i := 0; i < v.NumField(); i++ {
		keys = append(keys, toSnakeCase(v.Field(i).Name))
	}
	sort.Strings(keys)
	return keys
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
	default:
		return nil, fmt.Errorf("unknown provider: %s", dc.Provider)
	}
}

func loadIONOSZones(ctx context.Context, dc *DomainConfig) ([]Zone, error) {
	data, err := ionosAPI(ctx, dc, "GET", ionosBaseURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load ionos zones: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("empty response from IONOS API")
	}

	var zones []Zone
	if err := json.Unmarshal(data, &zones); err != nil {
		return nil, fmt.Errorf("failed to parse ionos zones: %w", err)
	}

	needed := make(map[string]struct{})
	for _, cfg := range cfg.DomainConfigs {
		if cfg.Provider != ProviderIONOS {
			continue
		}
		dn := strings.TrimSuffix(strings.ToLower(cfg.FQDN), ".")
		needed[dn] = struct{}{}
	}

	filtered := zones[:0]
	for _, z := range zones {
		zn := strings.TrimSuffix(strings.ToLower(z.Name), ".")
		for dn := range needed {
			if dn == zn || strings.HasSuffix(dn, "."+zn) {
				filtered = append(filtered, z)
				break
			}
		}
	}

	if len(filtered) < len(zones) {
		debugLog("ZONE", "", fmt.Sprintf("IONOS: %d von %d Zones relevant (Rest gefiltert)", len(filtered), len(zones)))
	}

	return filtered, nil
}

func loadAllProviderZones(ctx context.Context) (map[string][]Zone, error) {
	zonesByProvider := make(map[string][]Zone)

	providerConfigs := make(map[ProviderType]*DomainConfig)
	for i := range cfg.DomainConfigs {
		dc := &cfg.DomainConfigs[i]
		if _, exists := providerConfigs[dc.Provider]; !exists {
			providerConfigs[dc.Provider] = dc
		}
	}

	for provider, dc := range providerConfigs {
		zones, err := loadZonesForDomainConfig(ctx, dc)
		if err != nil {
			return nil, fmt.Errorf("failed to load zones for %s: %w", provider, err)
		}
		zonesByProvider[string(provider)] = zones

		debugLog("ZONE", "", fmt.Sprintf("✅ Loaded %d zones for %s", len(zones), provider))
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

	ch := g.DoChan(key, func() (interface{}, error) {
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
