// Package main
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type apiMetricsSnapshot struct {
	TotalRequests        int64       `json:"total_requests"`
	SuccessRequests      int64       `json:"success_requests"`
	FailedRequests       int64       `json:"failed_requests"`
	RateLimitHits        int64       `json:"rate_limit_hits"`
	ServerErrors         int64       `json:"server_errors"`
	ClientErrors         int64       `json:"client_errors"`
	AverageLatencyMs     int64       `json:"avg_latency_ms"`
	HourlyStats          [24]int     `json:"hourly_stats"`
	HourlyLatencyMs      [24]int64   `json:"hourly_latency_ms"`
	RequestTimestamps    []time.Time `json:"request_timestamps"`
	LastSuccessTime      time.Time   `json:"last_success_at"`
	LastError            string      `json:"last_error"`
	LastErrorTime        time.Time   `json:"last_error_at"`
	SavedAt              time.Time   `json:"saved_at"`
	DailyGET             int64       `json:"daily_get"`
	DailyPOST            int64       `json:"daily_post"`
	DailyPUT             int64       `json:"daily_put"`
	DailyDELETE          int64       `json:"daily_delete"`
	DailyNIC             int64       `json:"daily_nic"`
	DailyReset           time.Time   `json:"daily_reset"`
	HourlyReset          time.Time   `json:"hourly_reset"`
	LatencySamples       [1000]int64 `json:"latency_samples"`
	LatencySampleIdx     int         `json:"latency_sample_idx"`
	LatencySampleCount   int         `json:"latency_sample_count"`
	IPLatencySum         int64       `json:"ip_latency_sum_ms"`
	IPLatencyCount       int64       `json:"ip_latency_count"`
	IPLatencyAvgMs       int64       `json:"ip_latency_avg_ms"`
	IPLatencySamples     [200]int64  `json:"ip_latency_samples"`
	IPLatencySampleIdx   int         `json:"ip_latency_sample_idx"`
	IPLatencySampleCount int         `json:"ip_latency_sample_count"`
	LastIPCheckTime      time.Time   `json:"last_ip_check_at"`
}

var percentileBufPool = sync.Pool{
	New: func() any {
		buf := make([]int64, 0, 1000)
		return &buf
	},
}

type APIMetrics struct {
	sync.Mutex
	TotalRequests        int64
	SuccessRequests      int64
	FailedRequests       int64
	RateLimitHits        int64
	ServerErrors         int64
	ClientErrors         int64
	LatencySum           time.Duration
	LatencyCount         int64
	AverageLatency       time.Duration
	HourlyLatencySum     [24]time.Duration
	HourlyLatencyCount   [24]int64
	HourlyLatency        [24]time.Duration
	LastError            string
	LastErrorTimestamp   time.Time
	LastSuccessTimestamp time.Time
	RequestTimestamps    []time.Time
	HourlyStats          [24]int
	lastHour             int64
	LatencySamples       [1000]int64
	LatencySampleIdx     int
	LatencySampleCount   int
	DailyGET             int64
	DailyPOST            int64
	DailyPUT             int64
	DailyDELETE          int64
	DailyNIC             int64
	DailyReset           time.Time
	HourlyReset          time.Time
	IPLatencySum         time.Duration
	IPLatencyCount       int64
	IPLatencyAvg         time.Duration
	IPLatencySamples     [200]int64
	IPLatencySampleIdx   int
	IPLatencySampleCount int
	LastIPCheckTime      time.Time
	providerAnyError     atomic.Bool
}

// ============================================================================
// METRICS
// ============================================================================

func (m *APIMetrics) RecordSuccess(method string, duration time.Duration) {
	m.Lock()
	now := time.Now()
	m.TotalRequests++
	m.SuccessRequests++
	m.LastSuccessTimestamp = now

	m.cleanupOldTimestamps(now)
	m.RequestTimestamps = append(m.RequestTimestamps, now)

	hour := now.Hour()
	if hour >= 0 && hour < 24 {
		if !m.HourlyReset.IsZero() && now.Day() != m.HourlyReset.Day() {
			m.HourlyStats = [24]int{}
			m.HourlyLatency = [24]time.Duration{}
			m.HourlyLatencySum = [24]time.Duration{}
			m.HourlyLatencyCount = [24]int64{}
		}
		m.HourlyReset = now
		m.HourlyStats[hour]++
		m.updateLatency(duration, hour)
	}
	m.incrementDailyMethod(method, now)
	m.providerAnyError.Store(false)
	m.Unlock()

	m.signalStatsUpdate()
}

func (m *APIMetrics) RecordError(method string, statusCode int, err error, duration time.Duration) {
	m.Lock()
	now := time.Now()
	m.TotalRequests++
	m.FailedRequests++
	m.LastError = err.Error()
	m.LastErrorTimestamp = now

	m.cleanupOldTimestamps(now)
	m.RequestTimestamps = append(m.RequestTimestamps, now)

	hour := now.Hour()
	if hour >= 0 && hour < 24 {
		if !m.HourlyReset.IsZero() && now.Day() != m.HourlyReset.Day() {
			m.HourlyStats = [24]int{}
			m.HourlyLatency = [24]time.Duration{}
			m.HourlyLatencySum = [24]time.Duration{}
			m.HourlyLatencyCount = [24]int64{}
		}
		m.HourlyReset = now
		m.HourlyStats[hour]++
		m.updateLatency(duration, hour)
	}

	switch {
	case statusCode == 429:
		m.RateLimitHits++
	case statusCode >= 500:
		m.ServerErrors++
	case statusCode >= 400:
		m.ClientErrors++
	case statusCode == 0:
		m.ClientErrors++
	}
	m.incrementDailyMethod(method, now)
	m.providerAnyError.Store(true)
	m.Unlock()
	m.signalStatsUpdate()
}

func (m *APIMetrics) signalStatsUpdate() {
	select {
	case metricsSignal <- struct{}{}:
	default:
		// Channel ist voll → ein Update ist bereits unterwegs, reicht.
	}
}

func (m *APIMetrics) updateLatency(duration time.Duration, hour int) {
	m.LatencySum += duration
	m.LatencyCount++
	if m.LatencyCount > 0 {
		m.AverageLatency = (m.LatencySum / time.Duration(m.LatencyCount)).Round(time.Millisecond)
	}

	m.HourlyLatencySum[hour] += duration
	m.HourlyLatencyCount[hour]++
	if m.HourlyLatencyCount[hour] > 0 {
		m.HourlyLatency[hour] = (m.HourlyLatencySum[hour] / time.Duration(m.HourlyLatencyCount[hour])).Round(time.Millisecond)
	}

	ms := duration.Milliseconds()
	m.LatencySamples[m.LatencySampleIdx] = ms
	m.LatencySampleIdx = (m.LatencySampleIdx + 1) % len(m.LatencySamples)
	if m.LatencySampleCount < len(m.LatencySamples) {
		m.LatencySampleCount++
	}
}

func (m *APIMetrics) incrementDailyMethod(method string, now time.Time) {
	if !m.DailyReset.IsZero() &&
		(now.Year() != m.DailyReset.Year() ||
			now.Month() != m.DailyReset.Month() ||
			now.Day() != m.DailyReset.Day()) {

		m.DailyGET = 0
		m.DailyPOST = 0
		m.DailyPUT = 0
		m.DailyDELETE = 0
		m.DailyNIC = 0
	}

	m.DailyReset = now

	switch method {
	case MethodGET:
		m.DailyGET++
	case MethodPOST:
		m.DailyPOST++
	case MethodPUT:
		m.DailyPUT++
	case MethodDELETE:
		m.DailyDELETE++
	case MethodNIC:
		m.DailyNIC++
	}
}

func (m *APIMetrics) RecordIPLatency(duration time.Duration) {
	m.Lock()
	defer m.Unlock()
	m.IPLatencySum += duration
	m.IPLatencyCount++
	m.IPLatencyAvg = (m.IPLatencySum / time.Duration(m.IPLatencyCount)).Round(time.Millisecond)
	m.LastIPCheckTime = time.Now()
	ms := duration.Milliseconds()
	m.IPLatencySamples[m.IPLatencySampleIdx] = ms
	m.IPLatencySampleIdx = (m.IPLatencySampleIdx + 1) % len(m.IPLatencySamples)
	if m.IPLatencySampleCount < len(m.IPLatencySamples) {
		m.IPLatencySampleCount++
	}
}

func (m *APIMetrics) calcPercentile(p float64) time.Duration {
	if m.LatencySampleCount == 0 {
		return 0
	}
	count := m.LatencySampleCount

	bufPtr := percentileBufPool.Get().(*[]int64)
	buf := (*bufPtr)[:0]
	if cap(buf) < count {
		buf = make([]int64, count)
	} else {
		buf = buf[:count]
	}

	if count < len(m.LatencySamples) {
		copy(buf, m.LatencySamples[:count])
	} else {
		start := m.LatencySampleIdx
		for i := range count {
			buf[i] = m.LatencySamples[(start+i)%len(m.LatencySamples)]
		}
	}

	slices.Sort(buf)

	idx := max(int(float64(count-1)*p), 0)
	if idx >= count {
		idx = count - 1
	}
	result := time.Duration(buf[idx]) * time.Millisecond

	*bufPtr = buf[:0]
	percentileBufPool.Put(bufPtr)

	return result
}

func (m *APIMetrics) cleanupOldTimestamps(now time.Time) {
	if len(m.RequestTimestamps) == 0 {
		return
	}

	threshold := now.Add(-1 * time.Hour)

	cutIdx := 0
	for cutIdx < len(m.RequestTimestamps) && !m.RequestTimestamps[cutIdx].After(threshold) {
		cutIdx++
	}

	if cutIdx > 0 {
		n := copy(m.RequestTimestamps, m.RequestTimestamps[cutIdx:])
		m.RequestTimestamps = m.RequestTimestamps[:n]
	}

	const maxTimestamps = 3600
	if len(m.RequestTimestamps) > maxTimestamps {
		cutIdx := len(m.RequestTimestamps) - maxTimestamps
		n := copy(m.RequestTimestamps, m.RequestTimestamps[cutIdx:])
		m.RequestTimestamps = m.RequestTimestamps[:n]
	}
}

func (m *APIMetrics) GetStats() map[string]any {
	m.Lock()
	defer m.Unlock()
	return m.getStatsUnsafe()
}

func (m *APIMetrics) getUsageColor(p float64) string {
	if p > 90 {
		return "#f87171"
	}
	if p > 70 {
		return "#facc15"
	}
	return "#4ade80"
}

func reorderHourlyStatsToChronological(hourlyData [24]int) [24]int {
	currentHour := time.Now().Hour()
	var chronological [24]int
	for i := range 24 {
		hourIndex := (currentHour - 23 + i + 24) % 24
		chronological[i] = hourlyData[hourIndex]
	}
	return chronological
}

func reorderHourlyLatencyToChronological(hourlyData [24]time.Duration) [24]time.Duration {
	currentHour := time.Now().Hour()
	var chronological [24]time.Duration
	for i := range 24 {
		hourIndex := (currentHour - 23 + i + 24) % 24
		chronological[i] = hourlyData[hourIndex]
	}
	return chronological
}

func (m *APIMetrics) getStatsUnsafe() map[string]any {
	currentCount := len(m.RequestTimestamps)

	limit := float64(cfg.HourlyRateLimit)
	percent := (float64(currentCount) / limit) * 100
	if percent > 100 {
		percent = 100
	}

	successRate := 0.0
	if m.TotalRequests > 0 {
		successRate = float64(m.SuccessRequests) / float64(m.TotalRequests) * 100
	}

	chronologicalStats := reorderHourlyStatsToChronological(m.HourlyStats)
	chronologicalLatency := reorderHourlyLatencyToChronological(m.HourlyLatency)

	p50 := m.calcPercentile(0.50)
	p85 := m.calcPercentile(0.85)
	p99 := m.calcPercentile(0.99)

	lastSuccessAge := -1.0
	if !m.LastSuccessTimestamp.IsZero() {
		lastSuccessAge = time.Since(m.LastSuccessTimestamp).Seconds()
	}

	lastErrorAge := -1.0
	if !m.LastErrorTimestamp.IsZero() {
		lastErrorAge = time.Since(m.LastErrorTimestamp).Seconds()
	}

	ipAvg := "-"
	if m.IPLatencyCount > 0 {
		ipAvg = m.IPLatencyAvg.String()
	}
	lastIPCheck := "-"
	if !m.LastIPCheckTime.IsZero() {
		lastIPCheck = m.LastIPCheckTime.Format("15:04:05")
	}

	return map[string]any{
		"total_requests":        m.TotalRequests,
		"success_rate":          fmt.Sprintf("%.2f%%", successRate),
		"avg_latency":           m.AverageLatency.String(),
		"p50_latency":           p50.String(),
		"p85_latency":           p85.String(),
		"p99_latency":           p99.String(),
		"server_errors":         m.ServerErrors,
		"client_errors":         m.ClientErrors,
		"last_success_time":     m.LastSuccessTimestamp.Format("15:04:05"),
		"last_success_age_secs": lastSuccessAge,
		"last_error_age_secs":   lastErrorAge,
		"usage_count":           currentCount,
		"usage_percent":         fmt.Sprintf("%.1f", percent),
		"usage_color":           m.getUsageColor(percent),
		"hourly_stats":          chronologicalStats,
		"hourly_latency":        chronologicalLatency,
		"hourly_limit":          cfg.HourlyRateLimit,
		"daily_get":             m.DailyGET,
		"daily_post":            m.DailyPOST,
		"daily_put":             m.DailyPUT,
		"daily_delete":          m.DailyDELETE,
		"daily_nic":             m.DailyNIC,
		"ip_latency_avg":        ipAvg,
		"ip_latency_count":      m.IPLatencyCount,
		"last_ip_check":         lastIPCheck,
		"uptime_secs":           int64(time.Since(startTime).Seconds()),
	}
}

func ensureMetricsFile(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	_, err := os.Stat(path)
	if err == nil {
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}

	empty := apiMetricsSnapshot{SavedAt: time.Now()}
	b, _ := json.Marshal(empty)
	return os.WriteFile(path, b, 0o600)
}

func (m *APIMetrics) SaveToFile(path string) error {
	if err := ensureMetricsFile(path); err != nil {
		return err
	}

	m.Lock()
	snap := apiMetricsSnapshot{
		TotalRequests:        m.TotalRequests,
		SuccessRequests:      m.SuccessRequests,
		FailedRequests:       m.FailedRequests,
		RateLimitHits:        m.RateLimitHits,
		ServerErrors:         m.ServerErrors,
		ClientErrors:         m.ClientErrors,
		AverageLatencyMs:     m.AverageLatency.Milliseconds(),
		HourlyStats:          m.HourlyStats,
		LastError:            m.LastError,
		LastSuccessTime:      m.LastSuccessTimestamp,
		LastErrorTime:        m.LastErrorTimestamp,
		SavedAt:              time.Now(),
		RequestTimestamps:    make([]time.Time, len(m.RequestTimestamps)),
		DailyGET:             m.DailyGET,
		DailyPOST:            m.DailyPOST,
		DailyPUT:             m.DailyPUT,
		DailyDELETE:          m.DailyDELETE,
		DailyNIC:             m.DailyNIC,
		DailyReset:           m.DailyReset,
		HourlyReset:          m.HourlyReset,
		LatencySamples:       m.LatencySamples,
		LatencySampleIdx:     m.LatencySampleIdx,
		LatencySampleCount:   m.LatencySampleCount,
		IPLatencySum:         m.IPLatencySum.Milliseconds(),
		IPLatencyCount:       m.IPLatencyCount,
		IPLatencyAvgMs:       m.IPLatencyAvg.Milliseconds(),
		IPLatencySamples:     m.IPLatencySamples,
		IPLatencySampleIdx:   m.IPLatencySampleIdx,
		IPLatencySampleCount: m.IPLatencySampleCount,
		LastIPCheckTime:      m.LastIPCheckTime,
	}
	copy(snap.RequestTimestamps, m.RequestTimestamps)

	for i := range 24 {
		snap.HourlyLatencyMs[i] = m.HourlyLatency[i].Milliseconds()
	}
	m.Unlock()

	b, err := json.MarshalIndent(snap, "", " ")
	if err != nil {
		return err
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (m *APIMetrics) LoadFromFile(path string) error {
	if err := ensureMetricsFile(path); err != nil {
		return err
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(b) == 0 {
		return nil
	}

	var snap apiMetricsSnapshot
	if err := json.Unmarshal(b, &snap); err != nil {
		return errors.New("metrics.json konnte nicht gelesen werden (invalid JSON)")
	}

	m.Lock()
	m.TotalRequests = snap.TotalRequests
	m.SuccessRequests = snap.SuccessRequests
	m.FailedRequests = snap.FailedRequests
	m.RateLimitHits = snap.RateLimitHits
	m.ServerErrors = snap.ServerErrors
	m.ClientErrors = snap.ClientErrors
	m.AverageLatency = time.Duration(snap.AverageLatencyMs) * time.Millisecond
	m.HourlyStats = snap.HourlyStats

	for i := range 24 {
		m.HourlyLatency[i] = time.Duration(snap.HourlyLatencyMs[i]) * time.Millisecond
	}

	m.LastSuccessTimestamp = snap.LastSuccessTime
	m.LastError = snap.LastError
	m.LastErrorTimestamp = snap.LastErrorTime

	if !snap.DailyReset.IsZero() && snap.DailyReset.Day() == time.Now().Day() {
		m.DailyGET = snap.DailyGET
		m.DailyPOST = snap.DailyPOST
		m.DailyPUT = snap.DailyPUT
		m.DailyDELETE = snap.DailyDELETE
		m.DailyNIC = snap.DailyNIC
		m.DailyReset = snap.DailyReset
		if !snap.HourlyReset.IsZero() && snap.HourlyReset.Day() == time.Now().Day() {
			m.HourlyReset = snap.HourlyReset
		}
	}

	m.LatencySamples = snap.LatencySamples
	m.LatencySampleIdx = snap.LatencySampleIdx
	m.LatencySampleCount = snap.LatencySampleCount
	m.IPLatencySum = time.Duration(snap.IPLatencySum) * time.Millisecond
	m.IPLatencyCount = snap.IPLatencyCount
	m.IPLatencyAvg = time.Duration(snap.IPLatencyAvgMs) * time.Millisecond
	m.IPLatencySamples = snap.IPLatencySamples
	m.IPLatencySampleIdx = snap.IPLatencySampleIdx
	m.IPLatencySampleCount = snap.IPLatencySampleCount
	m.LastIPCheckTime = snap.LastIPCheckTime

	m.RequestTimestamps = nil
	if len(snap.RequestTimestamps) > 0 {
		now := time.Now()
		threshold := now.Add(-1 * time.Hour)

		for _, t := range snap.RequestTimestamps {
			if t.After(threshold) && t.Before(now.Add(5*time.Minute)) {
				m.RequestTimestamps = append(m.RequestTimestamps, t)
			}
		}
	}

	m.lastHour = time.Now().Unix() / 3600
	m.Unlock()

	return nil
}

func startMetricsAutosave(interval time.Duration) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			_ = apiMetrics.SaveToFile(metricsPersistPath)
		}
	}()
}

func setLatestMetrics(stats map[string]any) {
	latestMetricsMu.Lock()
	latestMetrics = stats
	latestMetricsMu.Unlock()
	select {
	case metricsSignal <- struct{}{}:
	default:
	}
}

func metricsBroadcasterLoop() {
	go func() {
		for range metricsSignal {
			stats := apiMetrics.GetStats()

			latestMetricsMu.Lock()
			latestMetrics = stats
			latestMetricsMu.Unlock()

			broadcastUpdate("metrics", stats)
		}
	}()
}

func handleMetricsReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != MethodPOST {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !validateTriggerToken(r) {
		w.WriteHeader(http.StatusUnauthorized)
		if err := json.NewEncoder(w).Encode(map[string]string{"error": "invalid token"}); err != nil {
			debugLog("API", "", fmt.Sprintf("Failed to encode error response: %v", err))
		}
		return
	}

	apiMetrics.Lock()
	apiMetrics.TotalRequests = 0
	apiMetrics.SuccessRequests = 0
	apiMetrics.FailedRequests = 0
	apiMetrics.RateLimitHits = 0
	apiMetrics.ServerErrors = 0
	apiMetrics.ClientErrors = 0
	apiMetrics.LatencySum = 0
	apiMetrics.LatencyCount = 0
	apiMetrics.AverageLatency = 0
	apiMetrics.HourlyStats = [24]int{}
	apiMetrics.HourlyLatency = [24]time.Duration{}
	apiMetrics.HourlyLatencySum = [24]time.Duration{}
	apiMetrics.HourlyLatencyCount = [24]int64{}
	apiMetrics.RequestTimestamps = nil
	apiMetrics.LastError = ""
	apiMetrics.LastErrorTimestamp = time.Time{}
	apiMetrics.LastSuccessTimestamp = time.Time{}
	apiMetrics.LatencySamples = [1000]int64{}
	apiMetrics.LatencySampleIdx = 0
	apiMetrics.LatencySampleCount = 0
	apiMetrics.IPLatencySum = 0
	apiMetrics.IPLatencyCount = 0
	apiMetrics.IPLatencyAvg = 0
	apiMetrics.IPLatencySamples = [200]int64{}
	apiMetrics.IPLatencySampleIdx = 0
	apiMetrics.IPLatencySampleCount = 0
	apiMetrics.LastIPCheckTime = time.Time{}
	apiMetrics.Unlock()

	if err := apiMetrics.SaveToFile(metricsPersistPath); err != nil {
		debugLog("API", getClientIP(r), "Failed to save empty metrics: "+err.Error())
	}

	stats := apiMetrics.GetStats()
	setLatestMetrics(stats)
	broadcastNotification("📊 "+phrases().MetricsResetNotification, "info")

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "reset_success"}); err != nil {
		debugLog("API", "", fmt.Sprintf("Failed to encode reset response: %v", err))
	}
}

func handlePrometheusMetrics(w http.ResponseWriter, _ *http.Request) {
	stats := apiMetrics.GetStats()

	toFloat := func(v any) float64 {
		switch x := v.(type) {
		case int64:
			return float64(x)
		case int:
			return float64(x)
		case float64:
			return x
		default:
			return 0
		}
	}

	lines := []string{
		"# HELP dyndns_total_requests Total API requests",
		"# TYPE dyndns_total_requests counter",
		fmt.Sprintf("dyndns_total_requests %.0f", toFloat(stats["total_requests"])),
		"# HELP dyndns_server_errors Server errors (5xx)",
		"# TYPE dyndns_server_errors counter",
		fmt.Sprintf("dyndns_server_errors %.0f", toFloat(stats["server_errors"])),
		"# HELP dyndns_client_errors Client errors (4xx)",
		"# TYPE dyndns_client_errors counter",
		fmt.Sprintf("dyndns_client_errors %.0f", toFloat(stats["client_errors"])),
		"# HELP dyndns_uptime_seconds Uptime in seconds",
		"# TYPE dyndns_uptime_seconds gauge",
		fmt.Sprintf("dyndns_uptime_seconds %.0f", toFloat(stats["uptime_secs"])),
		"# HELP dyndns_ip_check_count Total IP checks",
		"# TYPE dyndns_ip_check_count counter",
		fmt.Sprintf("dyndns_ip_check_count %.0f", toFloat(stats["ip_latency_count"])),
	}

	cfgMu.RLock()
	for _, dc := range cfg.DomainConfigs {
		safe := strings.ReplaceAll(dc.FQDN, ".", "_")
		safe = strings.ReplaceAll(safe, "-", "_")

		lines = append(lines,
			fmt.Sprintf(`dyndns_domain_%s_configured{fqdn=%q,provider=%q} 1`, safe, dc.FQDN, dc.Provider))
	}
	cfgMu.RUnlock()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	if _, err := fmt.Fprintln(w, strings.Join(lines, "\n")); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing metrics: %v\n", err)
	}
}
