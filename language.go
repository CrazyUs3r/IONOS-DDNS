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
	msg := T.TryingLoadLanguage
	if strings.TrimSpace(msg) == "" {
		msg = "Trying to load language file: %s"
	}
	fmt.Println("[INFO]", fmt.Sprintf(msg, langFile))

	data, err := os.ReadFile(langFile)
	if err != nil {
		embedName := "lang/" + lang + ".json"
		if embedded, embedErr := embeddedLang.ReadFile(embedName); embedErr == nil {
			fmt.Println("[INFO]", fmt.Sprintf(T.TryingLoadLanguage, embedName))
			data = embedded
		} else {
			fmt.Printf("[WARN] %s %v\n", T.LanguageFileNotFound, err)
			if lang != "en" {
				fmt.Printf("[INFO] %s\n", T.TryingFallbackEn)
				return loadLanguage("en")
			}
		}
	}

	if len(data) == 0 {
		fmt.Printf("[ERROR] no language data loaded for: %s\n", lang)
		if lang != "en" {
			return loadLanguage("en")
		}
		return fmt.Errorf("no language data available")
	}

	var translations map[string]string
	if err := json.Unmarshal(data, &translations); err != nil {
		fmt.Printf("[ERROR] %s: %v\n", T.JSONParseError, err)
		if lang != "en" {
			return loadLanguage("en")
		}
		return fmt.Errorf("json parse error: %w", err)
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

	fmt.Println("[INFO] ✓", fmt.Sprintf(T.LanguageLoaded, lang, len(translations)))

	expected := expectedTranslationKeys()
	for _, key := range expected {
		val, ok := translations[key]
		if !ok {
			fmt.Printf("[WARN] %s: %s\n", T.MissingTranslationKey, key)
			continue
		}
		if strings.TrimSpace(val) == "" {
			fmt.Printf("[WARN] empty translation value: %s\n", key)
		}
	}

	return nil
}

var knownAcronyms = []string{
	"IPv4", "IPv6", "HTTP", "JSON", "API", "DNS", "IP", "CF", "OK", "URL", "HTML", "TG", "ID", "WS"}

var snakeCaseOverrides = map[string]string{}

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

		newData, err := embeddedLang.ReadFile("lang/" + name)
		if err != nil {
			fmt.Printf("[WARN] Embedded file unreadable: %s: %v\n", name, err)
			continue
		}

		if oldData, err := os.ReadFile(dst); err == nil {
			if string(oldData) == string(newData) {
				continue
			}
			fmt.Printf("[INFO] Update erkannt: %s\n", name)
		} else {
			fmt.Printf("[INFO] Neue Datei: %s\n", name)
		}

		if err := os.WriteFile(dst, newData, 0644); err != nil {
			fmt.Printf("[WARN] write failed: %s: %v\n", dst, err)
		} else {
			fmt.Printf("[INFO] gespeichert: %s\n", dst)
		}
	}
}
