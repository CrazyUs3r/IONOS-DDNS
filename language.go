// Package main
package main

import (
	"embed"
	"encoding/json"
	"fmt"
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
	defer func() {
		if r := recover(); r != nil {
			log(LogContext{
				Level:    LogError,
				Category: "CONFIG",
				Action:   ActionConfig,
				Message:  fmt.Sprintf("%s: %v", t(T.PanicLoadingLanguage, "Panic loading language"), r),
			})
			err = fmt.Errorf("panic loading language: %v", r)
		}
	}()

	data, resolvedLang, err := loadLanguageDataWithFallback(lang)
	if err != nil {
		return err
	}

	translations, err := parseTranslationsWithFallback(data, resolvedLang)
	if err != nil {
		return err
	}

	applyTranslations(translations)
	logLanguageLoaded(resolvedLang, len(translations))
	validateTranslationKeys(translations)

	return nil
}

func loadLanguageDataWithFallback(lang string) ([]byte, string, error) {
	data, err := loadLanguageData(lang)
	if err == nil && len(data) > 0 {
		return data, lang, nil
	}

	if err != nil {
		log(LogContext{
			Level:    LogWarn,
			Category: "CONFIG",
			Action:   ActionConfig,
			Message:  fmt.Sprintf("%s %v", t(T.LanguageFileNotFound, "Language file not found:"), err),
		})
	}

	if len(data) == 0 {
		log(LogContext{
			Level:    LogError,
			Category: "CONFIG",
			Action:   ActionConfig,
			Message:  fmt.Sprintf(t(T.NoLanguageDataLoaded, "No language data loaded for: %s"), lang),
		})
	}

	if lang != "en" {
		log(LogContext{
			Level:    LogInfo,
			Category: "CONFIG",
			Action:   ActionConfig,
			Message:  t(T.TryingFallbackEn, "Trying fallback to English..."),
		})
		return loadLanguageDataWithFallback("en")
	}

	return nil, "", fmt.Errorf("no language data available")
}

func loadLanguageData(lang string) ([]byte, error) {
	langFile := filepath.Join(langDir, lang+".json")

	log(LogContext{
		Level:    LogInfo,
		Category: "CONFIG",
		Action:   ActionConfig,
		Message:  fmt.Sprintf(t(T.TryingLoadLanguage, "Trying to load language file: %s"), langFile),
	})

	data, err := os.ReadFile(langFile)
	if err == nil {
		return data, nil
	}

	embedName := "lang/" + lang + ".json"
	embedded, embedErr := embeddedLang.ReadFile(embedName)
	if embedErr == nil {
		log(LogContext{
			Level:    LogInfo,
			Category: "CONFIG",
			Action:   ActionConfig,
			Message:  fmt.Sprintf(t(T.TryingLoadLanguage, "Trying to load language file: %s"), embedName),
		})
		return embedded, nil
	}

	return nil, err
}

func parseTranslationsWithFallback(data []byte, lang string) (map[string]string, error) {
	var translations map[string]string

	err := json.Unmarshal(data, &translations)
	if err == nil {
		return translations, nil
	}

	log(LogContext{
		Level:    LogError,
		Category: "CONFIG",
		Action:   ActionConfig,
		Message:  fmt.Sprintf("%s: %v", t(T.JSONParseError, "JSON parse error"), err),
	})

	if lang != "en" {
		log(LogContext{
			Level:    LogInfo,
			Category: "CONFIG",
			Action:   ActionConfig,
			Message:  t(T.TryingFallbackEn, "Trying fallback to English..."),
		})
		return loadEnglishTranslations()
	}

	return nil, fmt.Errorf("json parse error: %w", err)
}

func loadEnglishTranslations() (map[string]string, error) {
	data, _, err := loadLanguageDataWithFallback("en")
	if err != nil {
		return nil, err
	}

	var translations map[string]string
	if err := json.Unmarshal(data, &translations); err != nil {
		return nil, fmt.Errorf("json parse error: %w", err)
	}
	return translations, nil
}

func applyTranslations(translations map[string]string) {
	var newT Phrases
	v := reflect.ValueOf(&newT).Elem()
	typ := v.Type()

	for i := 0; i < v.NumField(); i++ {
		field := typ.Field(i)
		jsonKey := toSnakeCase(field.Name)
		if val, ok := translations[jsonKey]; ok {
			v.Field(i).SetString(val)
		}
	}
	phraseMu.Lock()
	T = newT
	phraseMu.Unlock()
}

func logLanguageLoaded(lang string, count int) {
	log(LogContext{
		Level:    LogInfo,
		Category: "CONFIG",
		Action:   ActionConfig,
		Message:  fmt.Sprintf(T.LanguageLoaded, lang, count),
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
				Message:  fmt.Sprintf("%s: %s", T.MissingTranslationKey, key),
			})
			continue
		}
		if strings.TrimSpace(val) == "" {
			log(LogContext{
				Level:    LogWarn,
				Category: "CONFIG",
				Action:   ActionConfig,
				Message:  fmt.Sprintf(t(T.EmptyTranslationValue, "Empty translation value: %s"), key),
			})
		}
	}

	for key := range translations {
		if _, ok := expectedSet[key]; !ok {
			log(LogContext{
				Level:    LogWarn,
				Category: "CONFIG",
				Action:   ActionConfig,
				Message:  fmt.Sprintf(t(T.RemovedUnusedKey, "Removed unused translation key: %s"), key),
			})
			delete(translations, key)
		}
	}
}

var knownAcronyms = []string{
	"IPv4", "IPv6", "HTML", "HTTP", "JSON", "FQDN",
	"API", "CDN", "DNS", "URL", "CF",
	"OK", "TG", "WS", "ID", "IP", "JS",
}

var (
	snakeCaseOverrides = map[string]string{}
	snakeCaseCache     sync.Map
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
			Message:  fmt.Sprintf("%s: %v", t(T.CannotReadEmbeddedDir, "cannot read embedded lang dir"), err),
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
				Message:  fmt.Sprintf("%s: %s: %v", t(T.EmbeddedFileUnreadable, "Embedded file unreadable"), name, err),
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
				Message:  fmt.Sprintf("%s: %s", t(T.UpdateDetected, "Update detected"), name),
			})
		} else {
			log(LogContext{
				Level:    LogInfo,
				Category: "CONFIG",
				Action:   ActionConfig,
				Message:  fmt.Sprintf("%s: %s", t(T.NewFileDetected, "New file"), name),
			})
		}

		if err := os.WriteFile(dst, newData, 0o600); err != nil {
			log(LogContext{
				Level:    LogWarn,
				Category: "CONFIG",
				Action:   ActionConfig,
				Message:  fmt.Sprintf("%s: %s: %v", t(T.WriteFailed, "write failed"), dst, err),
			})
			continue
		}

		log(LogContext{
			Level:    LogInfo,
			Category: "CONFIG",
			Action:   ActionConfig,
			Message:  fmt.Sprintf("%s: %s", t(T.FileSaved, "saved"), dst),
		})
	}

	return nil
}
