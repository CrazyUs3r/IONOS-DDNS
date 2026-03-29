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
	"unicode"
)

//go:embed lang/*.json
var embeddedLang embed.FS

// ============================================================================
// LANGUAGE
// ============================================================================
func loadLanguage(lang string) error {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("[ERROR] %s: %v\n", T.PanicLoadingLanguage, r)
		}
	}()

	langFile := filepath.Join(langDir, lang+".json")
	fmt.Printf("[INFO] %s %s\n", T.TryingLoadLanguage, langFile)

	data, err := os.ReadFile(langFile)
	if err != nil {
		embedName := "lang/" + lang + ".json"
		if embedded, embedErr := embeddedLang.ReadFile(embedName); embedErr == nil {
			fmt.Printf("[INFO] %s (embedded)\n", T.TryingLoadLanguage)
			data = embedded
		} else {
			fmt.Printf("[WARN] %s %v\n", T.LanguageFileNotFound, err)
			if lang != "en" {
				fmt.Printf("[INFO] %s\n", T.TryingFallbackEn)
				return loadLanguage("en")
			}
			fmt.Printf("[WARN] %s\n", T.UsingBuiltinDefaults)
			return nil
		}
	}

	if len(data) == 0 {
		fmt.Printf("[WARN] %s\n", T.UsingBuiltinDefaults)
		return nil
	}

	var translations map[string]string
	if err := json.Unmarshal(data, &translations); err != nil {
		fmt.Printf("[ERROR] %s: %v\n", T.JSONParseError, err)

		if lang != "en" {
			return loadLanguage("en")
		}
		return nil
	}

	fmt.Printf("[INFO] ✓ "+T.LanguageLoaded+"\n", lang, len(translations))

	requiredKeys := []string{"startup", "shutdown", "no_zones", "update", "requests", "success_rate", "avg_latency"}
	for _, key := range requiredKeys {
		if _, ok := translations[key]; !ok {
			fmt.Printf("[WARN] %s: %s\n", T.MissingTranslationKey, key)
		}
	}

	v := reflect.ValueOf(&T).Elem()
	typ := v.Type()

	for i := 0; i < v.NumField(); i++ {
		field := typ.Field(i)
		jsonKey := toSnakeCase(field.Name)

		if val, ok := translations[jsonKey]; ok {
			v.Field(i).SetString(val)
		}
	}

	return nil
}

var knownAcronyms = []string{
	"IPv4", "IPv6", "HTTP", "JSON", "API", "DNS", "IP", "CF"}

var snakeCaseOverrides = map[string]string{
	"HealthCheckOK":      "health_check_ok",
	"LanguageFileNotFound": "language_file_not_found",
	"BasedOnLast60Min":   "based_on_last_60_min",
	"CleanupStartIonos":  "cleanup_start_ionos",
	"CleanupStartCF":     "cleanup_start_c_f",
	"CleanupStartIPv64":  "cleanup_start_i_pv64",
	"IPv64APIError":      "ipv64_a_p_i_error",
	"IPv64HTTPError":     "ipv64_h_t_t_p_error",
	"IPv64CacheAPIError": "ipv64_cache_a_p_i_error",
	"IonosRetryable":     "ionos_retryable",
	"IonosErrDetail":     "ionos_err_detail",
}

func toSnakeCase(s string) string {
	if key, ok := snakeCaseOverrides[s]; ok {
		return key
	}

	for _, acr := range knownAcronyms {
		replacement := string(unicode.ToUpper([]rune(acr)[0])) +
			strings.ToLower(acr[1:])
		s = strings.ReplaceAll(s, acr, replacement)
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

func copyEmbeddedLangFiles(dir string) {
	entries, err := embeddedLang.ReadDir("lang")
	if err != nil {
		fmt.Println("[ERROR] cannot read embedded lang dir:", err)
		return
	}

	for _, e := range entries {
		name := e.Name()
		dst := filepath.Join(dir, name)

		if _, err := os.Stat(dst); err == nil {
			continue
		}

		data, err := embeddedLang.ReadFile("lang/" + name)
		if err != nil {
			fmt.Printf("[WARN] Embedded file unreadable: %s: %v\n", name, err)
			continue
		}

		if err := os.WriteFile(dst, data, 0644); err != nil {
			fmt.Printf("[WARN] write failed: %s: %v\n", dst, err)
		} else {
			fmt.Printf("[INFO] copied: %s\n", dst)
		}
	}
}
