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
	"sort"
	"time"
)

// ============================================================================
// METRICS
// ============================================================================
func (m *APIMetrics) RecordSuccess(method string, duration time.Duration) {
	m.Lock()
	now := time.Now().Local()
	m.TotalRequests++
	m.SuccessRequests++
	m.LastSuccessTimestamp = now

	m.cleanupOldTimestamps(now)
	m.RequestTimestamps = append(m.RequestTimestamps, now)

	hour := now.Hour()
	if hour >= 0 && hour < 24 {
		m.HourlyStats[hour]++
		m.updateLatency(duration, hour)
	}

	m.incrementDailyMethod(method, now)

	statsCopy := m.getStatsUnsafe()
	m.Unlock()

	setLatestMetrics(statsCopy)
}

func (m *APIMetrics) RecordError(method string, statusCode int, err error, duration time.Duration) {
	m.Lock()
	now := time.Now().Local()
	m.TotalRequests++
	m.FailedRequests++
	m.LastError = err.Error()
	m.LastErrorTimestamp = now

	m.cleanupOldTimestamps(now)
	m.RequestTimestamps = append(m.RequestTimestamps, now)

	hour := now.Hour()
	if hour >= 0 && hour < 24 {
		m.HourlyStats[hour]++
		if duration > 0 && statusCode > 0 {
			m.updateLatency(duration, hour)
		}
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

	statsCopy := m.getStatsUnsafe()
	m.Unlock()

	setLatestMetrics(statsCopy)
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
	m.LastIPCheckTime = time.Now().Local()
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
	samples := make([]int64, count)

	if count < len(m.LatencySamples) {
		copy(samples, m.LatencySamples[:count])
	} else {
		start := m.LatencySampleIdx
		for i := range count {
			samples[i] = m.LatencySamples[(start+i)%len(m.LatencySamples)]
		}
	}

	slices.Sort(samples)

	idx := max(int(float64(count-1)*p), 0)
	if idx >= count {
		idx = count - 1
	}
	return time.Duration(samples[idx]) * time.Millisecond
}

func (m *APIMetrics) cleanupOldTimestamps(now time.Time) {
	threshold := now.Add(-1 * time.Hour)

	validIdx := sort.Search(len(m.RequestTimestamps), func(i int) bool {
		return m.RequestTimestamps[i].After(threshold)
	})

	if validIdx > 0 {
		copy(m.RequestTimestamps, m.RequestTimestamps[validIdx:])
		m.RequestTimestamps = m.RequestTimestamps[:len(m.RequestTimestamps)-validIdx]
	}

	const maxTimestamps = 3600
	if len(m.RequestTimestamps) > maxTimestamps {
		cutIdx := len(m.RequestTimestamps) - maxTimestamps
		copy(m.RequestTimestamps, m.RequestTimestamps[cutIdx:])
		m.RequestTimestamps = m.RequestTimestamps[:maxTimestamps]
	}
}

func (m *APIMetrics) GetStats() map[string]interface{} {
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
	now := time.Now().Local()
	currentHour := now.Hour()

	var chronological [24]int
	for i := 0; i < 24; i++ {
		hourIndex := (currentHour - 23 + i + 24) % 24
		chronological[i] = hourlyData[hourIndex]
	}
	return chronological
}

func reorderHourlyLatencyToChronological(hourlyData [24]time.Duration) [24]time.Duration {
	now := time.Now().Local()
	currentHour := now.Hour()

	var chronological [24]time.Duration
	for i := 0; i < 24; i++ {
		hourIndex := (currentHour - 23 + i + 24) % 24
		chronological[i] = hourlyData[hourIndex]
	}
	return chronological
}

func (m *APIMetrics) getStatsUnsafe() map[string]interface{} {
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

	return map[string]interface{}{
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

	empty := apiMetricsSnapshot{SavedAt: time.Now().Local()}
	b, _ := json.MarshalIndent(empty, "", "  ")
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
		SavedAt:              time.Now().Local(),
		RequestTimestamps:    make([]time.Time, len(m.RequestTimestamps)),
		DailyGET:             m.DailyGET,
		DailyPOST:            m.DailyPOST,
		DailyPUT:             m.DailyPUT,
		DailyDELETE:          m.DailyDELETE,
		DailyNIC:             m.DailyNIC,
		DailyReset:           m.DailyReset,
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

	for i := 0; i < 24; i++ {
		snap.HourlyLatencyMs[i] = m.HourlyLatency[i].Milliseconds()
	}
	m.Unlock()

	b, err := json.MarshalIndent(snap, "", "  ")
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

	for i := 0; i < 24; i++ {
		m.HourlyLatency[i] = time.Duration(snap.HourlyLatencyMs[i]) * time.Millisecond
	}

	m.LastSuccessTimestamp = snap.LastSuccessTime
	m.LastError = snap.LastError
	m.LastErrorTimestamp = snap.LastErrorTime

	if !snap.DailyReset.IsZero() && snap.DailyReset.Day() == time.Now().Local().Day() {
		m.DailyGET = snap.DailyGET
		m.DailyPOST = snap.DailyPOST
		m.DailyPUT = snap.DailyPUT
		m.DailyDELETE = snap.DailyDELETE
		m.DailyNIC = snap.DailyNIC
		m.DailyReset = snap.DailyReset
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
		now := time.Now().Local()
		threshold := now.Add(-1 * time.Hour)

		for _, t := range snap.RequestTimestamps {
			if t.After(threshold) && t.Before(now.Add(5*time.Minute)) {
				m.RequestTimestamps = append(m.RequestTimestamps, t)
			}
		}
	}

	m.lastHour = time.Now().Local().Unix() / 3600
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

func setLatestMetrics(stats map[string]interface{}) {
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
			latestMetricsMu.RLock()
			stats := latestMetrics
			latestMetricsMu.RUnlock()
			if stats != nil {
				broadcastUpdate("metrics", stats)
			}
		}
	}()
}

func handleMetricsReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
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

	statsCopy := apiMetrics.getStatsUnsafe()
	apiMetrics.Unlock()

	if err := apiMetrics.SaveToFile(metricsPersistPath); err != nil {
		debugLog("API", getClientIP(r), "Failed to save empty metrics: "+err.Error())
	}

	setLatestMetrics(statsCopy)
	broadcastNotification("📊 "+T.MetricsResetNotification, "info")

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "reset_success"}); err != nil {
		debugLog("API", "", fmt.Sprintf("Failed to encode reset response: %v", err))
	}
}
