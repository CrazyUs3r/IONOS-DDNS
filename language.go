// Package main
package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"unicode"
)

//go:embed lang/*.json
var embeddedLang embed.FS

// ============================================================================
// LANGUAGE
// ============================================================================
func t(val, fallback string) string {
	if strings.TrimSpace(val) == "" {
		return fallback
	}
	return val
}

func loadLanguage(lang string) (err error) {
	requested := normalizeLang(lang)

	defer func() {
		if recovered := recover(); recovered != nil {
			p := phrases()

			log(LogContext{
				Level:    LogError,
				Category: "CONFIG",
				Action:   ActionConfig,
				Message: fmt.Sprintf(
					"%s: %v",
					t(
						p.PanicLoadingLanguage,
						"Panic loading language",
					),
					recovered,
				),
			})

			err = fmt.Errorf(
				"panic loading language: %v",
				recovered,
			)
		}
	}()

	if requested == "" {
		return fmt.Errorf("invalid language code %q", lang)
	}

	available, err := getAvailableLanguages(langDir)
	if err != nil {
		return fmt.Errorf(
			"read available languages: %w",
			err,
		)
	}

	resolved, ok := resolveAvailableLanguage(
		requested,
		available,
	)
	if !ok {
		return fmt.Errorf(
			"language %q is not available",
			requested,
		)
	}

	layers := translationLayers(resolved, available)
	translations := make(map[string]string)

	for _, layerCode := range layers {
		data, err := loadLanguageData(layerCode)
		if err != nil {
			return fmt.Errorf(
				"load language layer %s: %w",
				layerCode,
				err,
			)
		}

		layer, err := parseTranslationData(
			data,
			layerCode,
		)
		if err != nil {
			return err
		}

		translations = mergeTranslations(
			translations,
			layer,
		)
	}

	applyTranslations(translations)

	logLanguageLoaded(resolved, len(translations))
	validateTranslationKeys(translations)

	return nil
}

func translationLayers(
	lang string,
	available map[string]bool,
) []string {
	lang = normalizeLang(lang)
	base := languageBase(lang)

	layers := make([]string, 0, 4)
	seen := make(map[string]struct{})

	add := func(code string) {
		code = normalizeLang(code)

		if code == "" || !available[code] {
			return
		}

		if _, exists := seen[code]; exists {
			return
		}

		seen[code] = struct{}{}
		layers = append(layers, code)
	}

	if base != "en" {
		if english, ok := resolveAvailableLanguage(
			"en",
			available,
		); ok {
			add(english)
		}
	}

	add(base)

	if defaultLocale := defaultLocaleByBase[base]; defaultLocale != "" && defaultLocale != lang {
		add(defaultLocale)
	}

	add(lang)

	return layers
}

func loadLanguageData(lang string) ([]byte, error) {
	lang = normalizeLang(lang)
	if lang == "" {
		return nil, fmt.Errorf("invalid language code")
	}

	filename := lang + ".json"
	diskPath := filepath.Join(langDir, filename)

	p := phrases()

	log(LogContext{
		Level:    LogInfo,
		Category: "CONFIG",
		Action:   ActionConfig,
		Message: fmt.Sprintf(
			t(
				p.TryingLoadLanguage,
				"Trying to load language file: %s",
			),
			diskPath,
		),
	})

	if data, err := os.ReadFile(diskPath); err == nil {
		return data, nil
	}

	embeddedPath := "lang/" + filename

	log(LogContext{
		Level:    LogInfo,
		Category: "CONFIG",
		Action:   ActionConfig,
		Message: fmt.Sprintf(
			t(
				p.TryingLoadLanguage,
				"Trying to load language file: %s",
			),
			embeddedPath,
		),
	})

	data, err := embeddedLang.ReadFile(embeddedPath)
	if err != nil {
		return nil, fmt.Errorf(
			"language file %s not found: %w",
			filename,
			err,
		)
	}

	return data, nil
}

func parseTranslationData(
	data []byte,
	lang string,
) (map[string]string, error) {
	var translations map[string]string

	if err := json.Unmarshal(data, &translations); err != nil {
		p := phrases()

		log(LogContext{
			Level:    LogError,
			Category: "CONFIG",
			Action:   ActionConfig,
			Message: fmt.Sprintf(
				"%s (%s): %v",
				t(
					p.JSONParseError,
					"JSON parse error",
				),
				lang,
				err,
			),
		})

		return nil, fmt.Errorf(
			"parse %s.json: %w",
			lang,
			err,
		)
	}

	if translations == nil {
		translations = make(map[string]string)
	}

	return translations, nil
}

func mergeTranslations(
	base map[string]string,
	overlay map[string]string,
) map[string]string {
	result := make(
		map[string]string,
		len(base)+len(overlay),
	)

	maps.Copy(result, base)

	for key, value := range overlay {
		if strings.TrimSpace(value) == "" {
			continue
		}

		result[key] = value
	}

	return result
}

func applyTranslations(translations map[string]string) {
	newT := &Phrases{}

	v := reflect.ValueOf(newT).Elem()
	typ := v.Type()

	for i := 0; i < v.NumField(); i++ {
		field := typ.Field(i)
		jsonKey := toSnakeCase(field.Name)

		if val, ok := translations[jsonKey]; ok {
			v.Field(i).SetString(val)
		}
	}
	phraseStore.Store(newT)
}

func logLanguageLoaded(lang string, count int) {
	log(LogContext{
		Level:    LogInfo,
		Category: "CONFIG",
		Action:   ActionConfig,
		Message:  fmt.Sprintf(phrases().LanguageLoaded, lang, count),
	})
}

func validateTranslationKeys(translations map[string]string) {
	expectedList := expectedTranslationKeys()
	expectedSet := expectedTranslationKeySet()

	for _, key := range expectedList {
		val, ok := translations[key]
		if !ok {
			log(LogContext{
				Level:    LogWarn,
				Category: "CONFIG",
				Action:   ActionConfig,
				Message:  fmt.Sprintf("%s: %s", phrases().MissingTranslationKey, key),
			})
			continue
		}
		if strings.TrimSpace(val) == "" {
			log(LogContext{
				Level:    LogWarn,
				Category: "CONFIG",
				Action:   ActionConfig,
				Message:  fmt.Sprintf(t(phrases().EmptyTranslationValue, "Empty translation value: %s"), key),
			})
		}
	}

	for key := range translations {
		if _, ok := expectedSet[key]; !ok {
			log(LogContext{
				Level:    LogWarn,
				Category: "CONFIG",
				Action:   ActionConfig,
				Message:  fmt.Sprintf(t(phrases().RemovedUnusedKey, "Removed unused translation key: %s"), key),
			})
			delete(translations, key)
		}
	}
}

var knownAcronyms = []string{
	"DNScale", "IPv4", "IPv6", "HTML", "HTTPS", "HTTP", "JSON", "FQDN", "TTFB", "MQTT",
	"API", "CDN", "DNS", "TTL", "TLS", "URL", "URI", "CF",
	"CA", "OK", "TG", "WS", "ID", "IP", "JS", "QR",
}

var (
	snakeCaseOverrides = map[string]string{
		"HTTPStatusLatency": "http_status_latency",
	}
	snakeCaseCache sync.Map
)

func toSnakeCase(s string) string {
	if key, ok := snakeCaseOverrides[s]; ok {
		return key
	}
	if cached, ok := snakeCaseCache.Load(s); ok {
		return cached.(string)
	}

	result := buildSnakeCase(s)
	snakeCaseCache.Store(s, result)
	return result
}

func phrases() *Phrases {
	if p := phraseStore.Load(); p != nil {
		return p
	}

	return &emptyPhrases
}

func buildSnakeCase(s string) string {
	for _, acr := range knownAcronyms {
		if !strings.Contains(s, acr) {
			continue
		}
		runes := []rune(acr)
		normalized := string(unicode.ToUpper(runes[0])) + strings.ToLower(string(runes[1:]))
		s = strings.ReplaceAll(s, acr, normalized)
	}

	var result []rune
	for i, r := range s {
		if i > 0 && unicode.IsUpper(r) {
			result = append(result, '_')
		}
		result = append(result, unicode.ToLower(r))
	}
	return string(result)
}

func copyEmbeddedLangFiles(dir string) error {
	entries, err := embeddedLang.ReadDir("lang")
	if err != nil {
		log(LogContext{
			Level:    LogError,
			Category: "SYSTEM",
			Action:   ActionConfig,
			Message:  fmt.Sprintf("%s: %v", t(phrases().CannotReadEmbeddedDir, "cannot read embedded lang dir"), err),
		})
		return err
	}

	for _, e := range entries {
		name := e.Name()
		dst := filepath.Join(dir, name)

		newData, err := embeddedLang.ReadFile("lang/" + name)
		if err != nil {
			log(LogContext{
				Level:    LogWarn,
				Category: "SYSTEM",
				Action:   ActionConfig,
				Message:  fmt.Sprintf("%s: %s: %v", t(phrases().EmbeddedFileUnreadable, "Embedded file unreadable"), name, err),
			})
			continue
		}

		if oldData, err := os.ReadFile(dst); err == nil {
			if string(oldData) == string(newData) {
				continue
			}
			log(LogContext{
				Level:    LogInfo,
				Category: "CONFIG",
				Action:   ActionConfig,
				Message:  fmt.Sprintf("%s: %s", t(phrases().UpdateDetected, "Update detected"), name),
			})
		} else {
			log(LogContext{
				Level:    LogInfo,
				Category: "CONFIG",
				Action:   ActionConfig,
				Message:  fmt.Sprintf("%s: %s", t(phrases().NewFileDetected, "New file"), name),
			})
		}

		if err := os.WriteFile(dst, newData, 0o600); err != nil {
			log(LogContext{
				Level:    LogWarn,
				Category: "CONFIG",
				Action:   ActionConfig,
				Message:  fmt.Sprintf("%s: %s: %v", t(phrases().WriteFailed, "write failed"), dst, err),
			})
			continue
		}

		log(LogContext{
			Level:    LogInfo,
			Category: "CONFIG",
			Action:   ActionConfig,
			Message:  fmt.Sprintf("%s: %s", t(phrases().FileSaved, "saved"), dst),
		})
	}

	return nil
}
