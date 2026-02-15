// Package main
package main

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

// ============================================================================
// STATUS FILE
// ============================================================================
func updateStatusFile(fqdn, ipv4, ipv6, provider string) {
	statusMutex.Lock()
	defer statusMutex.Unlock()

	domains := make(map[string]DomainHistory)

	if b, err := os.ReadFile(updatePath); err == nil {
		if err := json.Unmarshal(b, &domains); err != nil {
			log(LogContext{
				Level:   LogError,
				Action:  ActionError,
				Message: fmt.Sprintf("Failed to parse status file: %v", err),
			})
			return
		}
	}

	h := domains[fqdn]
	h.Provider = provider
	h.LastChanged = time.Now().Local().Format("02.01.2006 15:04:05")

	newEntry := IPEntry{
		Time: time.Now().Local().Format("02.01.2006 15:04:05"),
		IPv4: ipv4,
		IPv6: ipv6,
	}

	h.IPs = append(h.IPs, newEntry)
	if len(h.IPs) > MaxStatusHistoryItems {
		h.IPs = h.IPs[len(h.IPs)-MaxStatusHistoryItems:]
	}

	domains[fqdn] = h

	js, err := json.MarshalIndent(domains, "", "  ")
	if err != nil {
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: fmt.Sprintf("Failed to marshal status file: %v", err),
		})
		return
	}

	tmp := updatePath + ".tmp"

	if err := os.WriteFile(tmp, js, 0644); err != nil {
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: fmt.Sprintf("Failed to write temp status file: %v", err),
		})
		return
	}

	if err := os.Rename(tmp, updatePath); err != nil {
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: fmt.Sprintf("Failed to replace status file: %v", err),
		})
		return
	}

	go func() {
		if err := updateDomainsCache(); err != nil {
			debugLog("CACHE", "", fmt.Sprintf("updateDomainsCache failed: %v", err))
		}
	}()

	broadcastUpdate("domain_update", map[string]interface{}{
		"domain": fqdn,
		"ipv4":   ipv4,
		"ipv6":   ipv6,
		"time":   newEntry.Time,
	})
}

// ============================================================================
// CACHING
// ============================================================================
func updateDomainsCache() error {
	statusMutex.Lock()
	defer statusMutex.Unlock()

	domains := make(map[string]DomainHistory)

	if b, err := os.ReadFile(updatePath); err == nil {
		if err := json.Unmarshal(b, &domains); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	data, err := json.Marshal(domains)
	if err != nil {
		return err
	}

	etag := fmt.Sprintf(`"%x"`, md5.Sum(data))

	domainsCache.mu.Lock()
	domainsCache.Data = data
	domainsCache.ETag = etag
	domainsCache.LastModified = time.Now().Local()
	domainsCache.mu.Unlock()

	return nil
}

func updateMetricsCache() error {
	stats := apiMetrics.GetStats()

	data, err := json.Marshal(stats)
	if err != nil {
		debugLog("CACHE", "", fmt.Sprintf("Metrics cache marshal error: %v", err))
		return err
	}

	etag := fmt.Sprintf(`"%x"`, md5.Sum(data))

	metricsCache.mu.Lock()
	metricsCache.Data = data
	metricsCache.ETag = etag
	metricsCache.LastModified = time.Now().Local()
	metricsCache.mu.Unlock()

	return nil
}

func serveCachedJSON(w http.ResponseWriter, r *http.Request, cache *CachedResponse) {
	cache.mu.RLock()
	data := cache.Data
	etag := cache.ETag
	lastMod := cache.LastModified
	cache.mu.RUnlock()

	if len(data) == 0 {
		data = []byte("{}")
		if etag == "" {
			etag = `"0"`
		}
		if lastMod.IsZero() {
			lastMod = time.Now().Local()
		}
	}

	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	if ifModSince := r.Header.Get("If-Modified-Since"); ifModSince != "" {
		if t, err := http.ParseTime(ifModSince); err == nil {
			if !lastMod.After(t) {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", etag)
	w.Header().Set("Last-Modified", lastMod.UTC().Format(http.TimeFormat))
	w.Header().Set("Cache-Control", "public, max-age=5")

	if _, err := w.Write(data); err != nil {
		debugLog("HTTP", "", fmt.Sprintf("Response write failed: %v", err))
	}
}

func startCacheRefresher() {
	ticker := time.NewTicker(5 * time.Second)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				debugLog("CACHE", "", fmt.Sprintf("🚨 Panic recovered: %v", r))
			}
			ticker.Stop()
		}()

		for {
			select {
			case <-shutdownCtx.Done():
				debugLog("CACHE", "", "Cache refresher stopped (shutdown)")
				return

			case <-ticker.C:
				func() {
					defer func() {
						if r := recover(); r != nil {
							debugLog("CACHE", "", fmt.Sprintf("Panic in refresh cycle: %v", r))
						}
					}()

					if err := updateDomainsCache(); err != nil {
						debugLog("CACHE", "", fmt.Sprintf("Domain cache refresh failed: %v", err))
					}

					if err := updateMetricsCache(); err != nil {
						debugLog("CACHE", "", fmt.Sprintf("Metrics cache refresh failed: %v", err))
					}
				}()
			}
		}
	}()
}
