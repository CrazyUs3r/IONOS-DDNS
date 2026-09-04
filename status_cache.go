// Package main

package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ============================================================================
// STATSU FILE
// ============================================================================

type statusUpdate struct {
	FQDN     string
	IPv4     string
	IPv6     string
	Provider string
}

func updateStatusFileBatch(updates []statusUpdate) error {
	if len(updates) == 0 {
		return nil
	}

	now := time.Now().Format(statusTimestampLayout)
	changedUpdates := make([]statusUpdate, 0, len(updates))

	statusMutex.Lock()

	domains, err := currentStatusDomainsLocked()
	if err != nil {
		statusMutex.Unlock()

		return err
	}

	for _, u := range updates {
		fqdn := strings.TrimSpace(u.FQDN)
		if fqdn == "" {
			continue
		}

		key := existingStatusDomainKey(domains, fqdn)
		if key == "" {
			key = fqdn
		}

		history, exists := domains[key]

		if exists && statusUpdateUnchanged(history, u) {
			continue
		}

		history.Provider = u.Provider
		history.LastChanged = now
		history.IPs = append(history.IPs, IPEntry{
			Time: now,
			IPv4: u.IPv4,
			IPv6: u.IPv6,
		})

		if excess := len(history.IPs) - MaxStatusHistoryItems; excess > 0 {
			copy(history.IPs, history.IPs[excess:])
			history.IPs = history.IPs[:MaxStatusHistoryItems]
		}

		domains[key] = history
		changedUpdates = append(changedUpdates, u)
	}

	pruned := pruneOrphanStatusDomainsMap(domains)

	changed := len(changedUpdates) > 0 || len(pruned) > 0
	if changed {
		statusPersistDirty = true
	}

	if statusPersistDirty {
		err = writeStatusDomainsLocked(domains)
		if err == nil {
			statusPersistDirty = false
		}
	}

	statusMutex.Unlock()

	if err != nil {
		return err
	}

	if !changed {
		return nil
	}

	for _, domain := range pruned {
		debugLog("STATUS", domain, "Orphaned domain pruned from status")
	}

	if err := updateDomainsCache(); err != nil {
		debugLog(
			"CACHE",
			"",
			fmt.Sprintf(
				t(
					phrases().ErrUpdateDomainsCache,
					"updateDomainsCache failed: %v",
				),
				err,
			),
		)
	}

	for _, u := range changedUpdates {
		broadcastUpdate("domain_update", map[string]any{
			"domain": u.FQDN,
			"ipv4":   u.IPv4,
			"ipv6":   u.IPv6,
			"time":   now,
		})
	}

	return nil
}

func statusUpdateUnchanged(history DomainHistory, update statusUpdate) bool {
	if history.Provider != update.Provider {
		return false
	}

	if len(history.IPs) == 0 {
		return false
	}

	last := history.IPs[len(history.IPs)-1]

	return last.IPv4 == update.IPv4 &&
		last.IPv6 == update.IPv6
}

func currentStatusDomainsLocked() (map[string]DomainHistory, error) {
	if statusDomains != nil {
		return statusDomains, nil
	}

	loaded, err := loadStatusDomainsFromDiskLocked()
	if err != nil {
		return nil, err
	}

	statusDomains = loaded

	return statusDomains, nil
}

func loadStatusDomainsFromDiskLocked() (map[string]DomainHistory, error) {
	path, err := checkedUpdatePath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]DomainHistory), nil
		}

		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: fmt.Sprintf("Failed to read status file %s: %v", path, err),
		})

		return nil, err
	}

	loaded := make(map[string]DomainHistory)
	if err := json.Unmarshal(data, &loaded); err != nil {
		if moveErr := moveBrokenStatusFile(path, "Broken status file", err); moveErr != nil {
			return nil, moveErr
		}

		return make(map[string]DomainHistory), nil
	}

	if loaded == nil {
		if moveErr := moveBrokenStatusFile(path, "Invalid/null status file", nil); moveErr != nil {
			return nil, moveErr
		}

		return make(map[string]DomainHistory), nil
	}

	return loaded, nil
}

func moveBrokenStatusFile(path, description string, parseErr error) error {
	brokenFile := fmt.Sprintf(
		"%s.broken.%s",
		path,
		time.Now().Format("20060102_150405.000000000"),
	)

	if err := os.Rename(path, brokenFile); err != nil {
		log(LogContext{
			Level:  LogError,
			Action: ActionError,
			Message: fmt.Sprintf(
				"Failed to backup invalid status file %s: %v",
				path,
				err,
			),
		})

		return fmt.Errorf("backup invalid status file %s: %w", path, err)
	}

	message := fmt.Sprintf("%s moved to %s", description, brokenFile)
	if parseErr != nil {
		message += fmt.Sprintf(" (%v)", parseErr)
	}

	log(LogContext{
		Level:   LogWarn,
		Action:  ActionServer,
		Message: message,
	})

	return nil
}

func checkedUpdatePath() (string, error) {
	path := strings.TrimSpace(updatePath)
	if path == "" {
		return "", errors.New("updatePath is empty")
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create status directory %s: %w", dir, err)
	}

	return path, nil
}

func writeStatusDomainsLocked(domains map[string]DomainHistory) error {
	path, err := checkedUpdatePath()
	if err != nil {
		return err
	}

	if domains == nil {
		domains = make(map[string]DomainHistory)
	}

	if err := writeStatusDomainsAtomic(path, domains); err != nil {
		return err
	}

	statusDomains = domains

	return nil
}

func writeStatusDomainsAtomic(path string, domains map[string]DomainHistory) error {
	data, err := json.MarshalIndent(domains, "", " ")
	if err != nil {
		log(LogContext{
			Level:  LogError,
			Action: ActionError,
			Message: fmt.Sprintf(
				t(phrases().ErrMarshalStatusFile, "Failed to marshal status file: %v"),
				err,
			),
		})

		return err
	}

	dir := filepath.Dir(path)
	base := filepath.Base(path)

	tmpFile, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		log(LogContext{
			Level:  LogError,
			Action: ActionError,
			Message: fmt.Sprintf(
				t(phrases().ErrWriteTempStatusFile, "Failed to create temp status file: %v"),
				err,
			),
		})

		return err
	}

	tmpPath := tmpFile.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tmpPath)
		}
	}()

	fail := func(err error) error {
		_ = tmpFile.Close()

		return err
	}

	if err := tmpFile.Chmod(0o600); err != nil {
		return fail(fmt.Errorf("chmod temp status file %s: %w", tmpPath, err))
	}

	if _, err := tmpFile.Write(data); err != nil {
		log(LogContext{
			Level:  LogError,
			Action: ActionError,
			Message: fmt.Sprintf(
				t(phrases().ErrWriteTempStatusFile, "Failed to write temp status file: %v"),
				err,
			),
		})

		return fail(err)
	}

	if err := tmpFile.Sync(); err != nil {
		return fail(fmt.Errorf("sync temp status file %s: %w", tmpPath, err))
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp status file %s: %w", tmpPath, err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		log(LogContext{
			Level:  LogError,
			Action: ActionError,
			Message: fmt.Sprintf(
				t(phrases().ErrReplaceStatusFile, "Failed to replace status file: %v"),
				err,
			),
		})

		return err
	}
	removeTemp = false

	if dirHandle, err := os.Open(dir); err == nil {
		if err := dirHandle.Sync(); err != nil {
			debugLog("STATUS", "", fmt.Sprintf("Status directory sync failed: %v", err))
		}
		_ = dirHandle.Close()
	}

	return nil
}

func cloneStatusDomains(src map[string]DomainHistory) map[string]DomainHistory {
	if src == nil {
		return make(map[string]DomainHistory)
	}

	dst := make(map[string]DomainHistory, len(src))
	for domain, history := range src {
		history.IPs = append([]IPEntry(nil), history.IPs...)
		dst[domain] = history
	}

	return dst
}

func existingStatusDomainKey(domains map[string]DomainHistory, fqdn string) string {
	if _, ok := domains[fqdn]; ok {
		return fqdn
	}

	for key := range domains {
		if strings.EqualFold(key, fqdn) {
			return key
		}
	}

	return ""
}

func pruneOrphanStatusDomainsMap(domains map[string]DomainHistory) []string {
	if domains == nil {
		return nil
	}

	cfgMu.RLock()
	configured := make(map[string]struct{}, len(cfg.DomainConfigs))
	for _, domainConfig := range cfg.DomainConfigs {
		configured[strings.ToLower(strings.TrimSpace(domainConfig.FQDN))] = struct{}{}
	}
	cfgMu.RUnlock()

	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	pruned := make([]string, 0)

	for fqdn, history := range domains {
		if _, ok := configured[strings.ToLower(strings.TrimSpace(fqdn))]; ok {
			continue
		}
		if history.LastChanged == "" {
			continue
		}

		lastChanged, err := time.ParseInLocation(statusTimestampLayout, history.LastChanged, time.Local)
		if err != nil || !lastChanged.Before(cutoff) {
			continue
		}

		delete(domains, fqdn)
		pruned = append(pruned, fqdn)
	}

	return pruned
}

// ============================================================================
// CACHING
// ============================================================================

func updateDomainsCache() error {
	snapshot, err := snapshotStatusDomains()
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(snapshot, "", " ")
	if err != nil {
		return err
	}

	sum := sha256.Sum256(data)
	etag := fmt.Sprintf(`"%x"`, sum)
	now := time.Now().UTC().Truncate(time.Second)

	domainsCache.mu.Lock()
	if domainsCache.ETag != etag || len(domainsCache.Data) == 0 {
		domainsCache.Data = data
		domainsCache.ETag = etag
		domainsCache.LastModified = now
	} else if domainsCache.LastModified.IsZero() {
		domainsCache.LastModified = now
	}
	domainsCache.mu.Unlock()

	return nil
}

func snapshotStatusDomains() (map[string]DomainHistory, error) {
	statusMutex.Lock()
	defer statusMutex.Unlock()

	current, err := currentStatusDomainsLocked()
	if err != nil {
		return nil, err
	}

	return cloneStatusDomains(current), nil
}

func updateMetricsCache() error {
	stats := apiMetrics.GetStats()

	data, err := json.MarshalIndent(stats, "", " ")
	if err != nil {
		debugLog("CACHE", "", fmt.Sprintf(t(phrases().ErrMetricsCacheMarshal, "Metrics cache marshal error: %v"), err))

		return err
	}

	sum := sha256.Sum256(data)
	etag := fmt.Sprintf(`"%x"`, sum)
	now := time.Now().UTC().Truncate(time.Second)

	metricsCache.mu.Lock()
	if metricsCache.ETag != etag || len(metricsCache.Data) == 0 {
		metricsCache.Data = data
		metricsCache.ETag = etag
		metricsCache.LastModified = now
	} else if metricsCache.LastModified.IsZero() {
		metricsCache.LastModified = now
	}
	metricsCache.mu.Unlock()

	return nil
}

func serveCachedJSON(w http.ResponseWriter, r *http.Request, cache *CachedResponse) {
	cache.mu.RLock()
	data := append([]byte(nil), cache.Data...)
	etag := cache.ETag
	lastMod := cache.LastModified
	cache.mu.RUnlock()

	if len(data) == 0 {
		data = []byte("{}")
		if etag == "" {
			etag = `"0"`
		}
		if lastMod.IsZero() {
			lastMod = time.Now().UTC().Truncate(time.Second)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", etag)
	w.Header().Set("Last-Modified", lastMod.UTC().Format(http.TimeFormat))
	w.Header().Set("Cache-Control", "public, max-age=5")

	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)

		return
	}

	if ifModSince := r.Header.Get("If-Modified-Since"); ifModSince != "" {
		if parsed, err := http.ParseTime(ifModSince); err == nil {
			if !lastMod.After(parsed) {
				w.WriteHeader(http.StatusNotModified)

				return
			}
		}
	}

	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)

		return
	}

	if _, err := w.Write(data); err != nil {
		debugLog("HTTP", "", fmt.Sprintf(t(phrases().ErrResponseWrite, "Response write failed: %v"), err))
	}
}

func cacheRefreshInterval() time.Duration {
	cfgMu.RLock()
	interval := cfg.Interval
	cfgMu.RUnlock()

	switch {
	case interval <= 60:
		return 5 * time.Second
	case interval <= 300:
		return 15 * time.Second
	default:
		return 30 * time.Second
	}
}

func startCacheRefresher() {
	ticker := time.NewTicker(cacheRefreshInterval())

	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				debugLog("CACHE", "", fmt.Sprintf(t(phrases().ErrPanicRecovered, "🚨 Panic recovered: %v"), recovered))
			}
			ticker.Stop()
		}()

		for {
			select {
			case <-shutdownCtx.Done():
				debugLog("CACHE", "", t(phrases().CacheRefresherStopped, "Cache refresher stopped (shutdown)"))

				return

			case <-ticker.C:
				func() {
					defer func() {
						if recovered := recover(); recovered != nil {
							debugLog("CACHE", "", fmt.Sprintf(t(phrases().ErrPanicRefreshCycle, "Panic in refresh cycle: %v"), recovered))
						}
					}()

					if err := updateDomainsCache(); err != nil {
						debugLog("CACHE", "", fmt.Sprintf(t(phrases().ErrDomainCacheRefresh, "Domain cache refresh failed: %v"), err))
					}

					if err := updateMetricsCache(); err != nil {
						debugLog("CACHE", "", fmt.Sprintf(t(phrases().ErrMetricsCacheRefresh, "Metrics cache refresh failed: %v"), err))
					}
				}()
			}
		}
	}()
}
