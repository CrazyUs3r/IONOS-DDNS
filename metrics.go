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
	HourlyReset          time.Time   `json:"hourly_reset"`
	LastIPCheckTime      time.Time   `json:"last_ip_check_at"`
	LastErrorTime        time.Time   `json:"last_error_at"`
	DailyReset           time.Time   `json:"daily_reset"`
	SavedAt              time.Time   `json:"saved_at"`
	LastSuccessTime      time.Time   `json:"last_success_at"`
	LastError            string      `json:"last_error"`
	RequestTimestamps    []time.Time `json:"request_timestamps"`
	LatencySamples       [1000]int64 `json:"latency_samples"`
	IPLatencySamples     [200]int64  `json:"ip_latency_samples"`
	HourlyStats          [24]int     `json:"hourly_stats"`
	HourlyLatencyMs      [24]int64   `json:"hourly_latency_ms"`
	HourlyLatencySumMs   [24]int64   `json:"hourly_latency_sum_ms,omitempty"`
	HourlyLatencyCount   [24]int64   `json:"hourly_latency_count,omitempty"`
	DailyDELETE          int64       `json:"daily_delete"`
	RateLimitHits        int64       `json:"rate_limit_hits"`
	SuccessRequests      int64       `json:"success_requests"`
	ClientErrors         int64       `json:"client_errors"`
	DailyGET             int64       `json:"daily_get"`
	DailyPOST            int64       `json:"daily_post"`
	DailyPUT             int64       `json:"daily_put"`
	LatencySumMs         int64       `json:"latency_sum_ms,omitempty"`
	DailyNIC             int64       `json:"daily_nic"`
	ServerErrors         int64       `json:"server_errors"`
	TotalRequests        int64       `json:"total_requests"`
	AverageLatencyMs     int64       `json:"avg_latency_ms"`
	LatencySampleIdx     int         `json:"latency_sample_idx"`
	LatencySampleCount   int         `json:"latency_sample_count"`
	IPLatencySum         int64       `json:"ip_latency_sum_ms"`
	IPLatencyCount       int64       `json:"ip_latency_count"`
	IPLatencyAvgMs       int64       `json:"ip_latency_avg_ms"`
	LatencyCount         int64       `json:"latency_count,omitempty"`
	IPLatencySampleIdx   int         `json:"ip_latency_sample_idx"`
	IPLatencySampleCount int         `json:"ip_latency_sample_count"`
	FailedRequests       int64       `json:"failed_requests"`
}

var percentileBufPool = sync.Pool{
	New: func() any {
		buf := make([]int64, 0, 1000)
		return &buf
	},
}

type APIMetrics struct {
	LastErrorTimestamp   time.Time
	LastIPCheckTime      time.Time
	HourlyReset          time.Time
	DailyReset           time.Time
	LastSuccessTimestamp time.Time
	LastError            string
	RequestTimestamps    []time.Time
	LatencySamples       [1000]int64
	IPLatencySamples     [200]int64
	HourlyStats          [24]int
	HourlyLatencySum     [24]time.Duration
	HourlyLatencyCount   [24]int64
	HourlyLatency        [24]time.Duration
	AverageLatency       time.Duration
	DailyPUT             int64
	LatencyCount         int64
	LatencySum           time.Duration
	ClientErrors         int64
	lastHour             int64
	ServerErrors         int64
	LatencySampleIdx     int
	LatencySampleCount   int
	DailyGET             int64
	DailyPOST            int64
	TotalRequests        int64
	DailyDELETE          int64
	DailyNIC             int64
	RateLimitHits        int64
	FailedRequests       int64
	IPLatencySum         time.Duration
	IPLatencyCount       int64
	IPLatencyAvg         time.Duration
	SuccessRequests      int64
	IPLatencySampleIdx   int
	IPLatencySampleCount int
	sync.Mutex
	providerAnyError atomic.Bool
}

func sameLocalDate(a, b time.Time) bool {
	aYear, aMonth, aDay := a.In(time.Local).Date()
	bYear, bMonth, bDay := b.In(time.Local).Date()

	return aYear == bYear &&
		aMonth == bMonth &&
		aDay == bDay
}

func (m *APIMetrics) resetHourlyMetricsIfNeeded(now time.Time) {
	if !m.HourlyReset.IsZero() &&
		!sameLocalDate(now, m.HourlyReset) {

		m.HourlyStats = [24]int{}
		m.HourlyLatency = [24]time.Duration{}
		m.HourlyLatencySum = [24]time.Duration{}
		m.HourlyLatencyCount = [24]int64{}
	}

	m.HourlyReset = now
}

// ============================================================================
// METRICS
// ============================================================================

func (m *APIMetrics) RecordSuccess(
	method string,
	duration time.Duration,
) {
	now := time.Now()

	m.Lock()

	m.TotalRequests++
	m.SuccessRequests++
	m.LastSuccessTimestamp = now

	m.cleanupOldTimestamps(now)
	m.RequestTimestamps = append(m.RequestTimestamps, now)

	hour := now.Hour()
	if hour >= 0 && hour < len(m.HourlyStats) {
		m.resetHourlyMetricsIfNeeded(now)

		m.HourlyStats[hour]++
		m.updateLatency(duration, hour)
	}

	m.incrementDailyMethod(method, now)
	m.providerAnyError.Store(false)

	m.Unlock()

	m.signalStatsUpdate()
}

func (m *APIMetrics) RecordError(
	method string,
	statusCode int,
	err error,
	duration time.Duration,
) {
	now := time.Now()

	m.Lock()

	m.TotalRequests++
	m.FailedRequests++
	if err != nil {
		m.LastError = err.Error()
	} else {
		m.LastError = ""
	}
	m.LastErrorTimestamp = now

	m.cleanupOldTimestamps(now)
	m.RequestTimestamps = append(m.RequestTimestamps, now)

	hour := now.Hour()
	if hour >= 0 && hour < len(m.HourlyStats) {
		m.resetHourlyMetricsIfNeeded(now)

		m.HourlyStats[hour]++
		m.updateLatency(duration, hour)
	}

	switch {
	case statusCode == http.StatusTooManyRequests:
		m.RateLimitHits++

	case statusCode >= http.StatusInternalServerError:
		m.ServerErrors++

	case statusCode >= http.StatusBadRequest:
		m.ClientErrors++

	case statusCode == 0:
		m.ClientErrors++
	}

	m.incrementDailyMethod(method, now)
	m.providerAnyError.Store(true)

	m.Unlock()

	m.signalStatsUpdate()
}

func (m *APIMetrics) incrementDailyMethod(method string, now time.Time) {
	if !m.DailyReset.IsZero() && !sameLocalDate(now, m.DailyReset) {

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

func (m *APIMetrics) refreshTimeWindows(now time.Time) {
	m.cleanupOldTimestamps(now)

	if !m.DailyReset.IsZero() && !sameLocalDate(now, m.DailyReset) {
		m.DailyGET = 0
		m.DailyPOST = 0
		m.DailyPUT = 0
		m.DailyDELETE = 0
		m.DailyNIC = 0
		m.DailyReset = now
	}

	m.resetHourlyMetricsIfNeeded(now)
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
	m.refreshTimeWindows(time.Now())
	currentCount := len(m.RequestTimestamps)

	cfgMu.RLock()
	hourlyRateLimit := cfg.HourlyRateLimit
	cfgMu.RUnlock()

	limit := float64(hourlyRateLimit)
	percent := 0.0
	if limit > 0 {
		percent = (float64(currentCount) / limit) * 100
	}
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
		"hourly_limit":          hourlyRateLimit,
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
	metricsPersistMu.Lock()
	defer metricsPersistMu.Unlock()

	if err := ensureMetricsFile(path); err != nil {
		return err
	}

	snap := m.snapshotForPersistence()

	data, err := json.MarshalIndent(snap, "", " ")
	if err != nil {
		return err
	}

	return writeFileAtomic(path, data)
}

func normalizeRingIndex(index, size int) int {
	if size <= 0 {
		return 0
	}
	index %= size
	if index < 0 {
		index += size
	}
	return index
}

func (m *APIMetrics) LoadFromFile(path string) error {
	snap, err := readAPIMetricsSnapshot(path)
	if err != nil {
		return err
	}
	if snap == nil {
		return nil
	}

	now := time.Now()
	m.Lock()
	defer m.Unlock()
	m.restoreSnapshot(*snap, now)
	return nil
}

func readAPIMetricsSnapshot(path string) (*apiMetricsSnapshot, error) {
	if err := ensureMetricsFile(path); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}

	var snap apiMetricsSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, errors.New("metrics.json konnte nicht gelesen werden (invalid JSON)")
	}
	return &snap, nil
}

func (m *APIMetrics) restoreSnapshot(snap apiMetricsSnapshot, now time.Time) {
	m.restoreRequestTotals(snap)
	m.restoreDailyMetrics(snap, now)
	m.restoreHourlyMetrics(snap, now)
	m.restoreLatencySamples(snap)
	m.restoreIPLatency(snap)
	m.restoreRequestTimestamps(snap.RequestTimestamps, now)
	m.lastHour = now.Unix() / 3600
}

func (m *APIMetrics) restoreRequestTotals(snap apiMetricsSnapshot) {
	m.TotalRequests = snap.TotalRequests
	m.SuccessRequests = snap.SuccessRequests
	m.FailedRequests = snap.FailedRequests
	m.RateLimitHits = snap.RateLimitHits
	m.ServerErrors = snap.ServerErrors
	m.ClientErrors = snap.ClientErrors
	m.AverageLatency = time.Duration(max(snap.AverageLatencyMs, 0)) * time.Millisecond
	if snap.LatencyCount > 0 && snap.LatencySumMs >= 0 {
		m.LatencyCount = snap.LatencyCount
		m.LatencySum = time.Duration(snap.LatencySumMs) * time.Millisecond
	} else if m.TotalRequests > 0 && m.AverageLatency > 0 {
		m.LatencyCount = m.TotalRequests
		m.LatencySum = m.AverageLatency * time.Duration(m.LatencyCount)
	}

	m.LastSuccessTimestamp = snap.LastSuccessTime
	m.LastError = snap.LastError
	m.LastErrorTimestamp = snap.LastErrorTime
}

func (m *APIMetrics) restoreDailyMetrics(snap apiMetricsSnapshot, now time.Time) {
	m.DailyGET = 0
	m.DailyPOST = 0
	m.DailyPUT = 0
	m.DailyDELETE = 0
	m.DailyNIC = 0
	m.DailyReset = time.Time{}

	if snap.DailyReset.IsZero() || !sameLocalDate(snap.DailyReset, now) {
		return
	}
	m.DailyGET = snap.DailyGET
	m.DailyPOST = snap.DailyPOST
	m.DailyPUT = snap.DailyPUT
	m.DailyDELETE = snap.DailyDELETE
	m.DailyNIC = snap.DailyNIC
	m.DailyReset = snap.DailyReset
}

func (m *APIMetrics) restoreHourlyMetrics(snap apiMetricsSnapshot, now time.Time) {
	m.HourlyStats = [24]int{}
	m.HourlyLatency = [24]time.Duration{}
	m.HourlyLatencySum = [24]time.Duration{}
	m.HourlyLatencyCount = [24]int64{}
	m.HourlyReset = time.Time{}

	if snap.HourlyReset.IsZero() || !sameLocalDate(snap.HourlyReset, now) {
		return
	}
	m.HourlyStats = snap.HourlyStats
	for i := range len(m.HourlyLatency) {
		m.restoreHourlyLatency(snap, i)
	}
	m.HourlyReset = snap.HourlyReset
}

func (m *APIMetrics) restoreHourlyLatency(snap apiMetricsSnapshot, hour int) {
	m.HourlyLatency[hour] = time.Duration(max(snap.HourlyLatencyMs[hour], 0)) * time.Millisecond
	if snap.HourlyLatencyCount[hour] > 0 && snap.HourlyLatencySumMs[hour] >= 0 {
		m.HourlyLatencyCount[hour] = snap.HourlyLatencyCount[hour]
		m.HourlyLatencySum[hour] = time.Duration(snap.HourlyLatencySumMs[hour]) * time.Millisecond
		return
	}
	if snap.HourlyStats[hour] > 0 && m.HourlyLatency[hour] > 0 {
		m.HourlyLatencyCount[hour] = int64(snap.HourlyStats[hour])
		m.HourlyLatencySum[hour] = m.HourlyLatency[hour] * time.Duration(m.HourlyLatencyCount[hour])
	}
}

func (m *APIMetrics) restoreLatencySamples(snap apiMetricsSnapshot) {
	m.LatencySamples = snap.LatencySamples
	m.LatencySampleIdx = normalizeRingIndex(snap.LatencySampleIdx, len(m.LatencySamples))
	m.LatencySampleCount = min(max(snap.LatencySampleCount, 0), len(m.LatencySamples))
}

func (m *APIMetrics) restoreIPLatency(snap apiMetricsSnapshot) {
	m.IPLatencySum = time.Duration(max(snap.IPLatencySum, 0)) * time.Millisecond
	m.IPLatencyCount = max(snap.IPLatencyCount, 0)
	m.IPLatencyAvg = time.Duration(max(snap.IPLatencyAvgMs, 0)) * time.Millisecond
	m.IPLatencySamples = snap.IPLatencySamples
	m.IPLatencySampleIdx = normalizeRingIndex(snap.IPLatencySampleIdx, len(m.IPLatencySamples))
	m.IPLatencySampleCount = min(max(snap.IPLatencySampleCount, 0), len(m.IPLatencySamples))
	m.LastIPCheckTime = snap.LastIPCheckTime
}

func (m *APIMetrics) restoreRequestTimestamps(timestamps []time.Time, now time.Time) {
	m.RequestTimestamps = nil
	threshold := now.Add(-1 * time.Hour)
	futureLimit := now.Add(5 * time.Minute)
	for _, timestamp := range timestamps {
		if timestamp.After(threshold) && timestamp.Before(futureLimit) {
			m.RequestTimestamps = append(m.RequestTimestamps, timestamp)
		}
	}
}

func (m *APIMetrics) snapshotForPersistence() apiMetricsSnapshot {
	m.Lock()
	defer m.Unlock()

	snap := apiMetricsSnapshot{
		TotalRequests:        m.TotalRequests,
		SuccessRequests:      m.SuccessRequests,
		FailedRequests:       m.FailedRequests,
		RateLimitHits:        m.RateLimitHits,
		ServerErrors:         m.ServerErrors,
		ClientErrors:         m.ClientErrors,
		AverageLatencyMs:     m.AverageLatency.Milliseconds(),
		LatencySumMs:         m.LatencySum.Milliseconds(),
		LatencyCount:         m.LatencyCount,
		HourlyStats:          m.HourlyStats,
		LastError:            m.LastError,
		LastSuccessTime:      m.LastSuccessTimestamp,
		LastErrorTime:        m.LastErrorTimestamp,
		SavedAt:              time.Now(),
		RequestTimestamps:    append([]time.Time(nil), m.RequestTimestamps...),
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

	for i := range len(m.HourlyLatency) {
		snap.HourlyLatencyMs[i] = m.HourlyLatency[i].Milliseconds()
		snap.HourlyLatencySumMs[i] = m.HourlyLatencySum[i].Milliseconds()
		snap.HourlyLatencyCount[i] = m.HourlyLatencyCount[i]
	}

	return snap
}

func startMetricsAutosave(interval time.Duration) {
	if interval <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_ = apiMetrics.SaveToFile(metricsPersistPath)
			case <-shutdownCtx.Done():
				return
			}
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
		for {
			select {
			case <-metricsSignal:
				stats := apiMetrics.GetStats()

				latestMetricsMu.Lock()
				latestMetrics = stats
				latestMetricsMu.Unlock()

				broadcastUpdate("metrics", stats)
			case <-shutdownCtx.Done():
				return
			}
		}
	}()
}

func handleMetricsReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != MethodPOST {
		http.Error(w, phrases().APIErrorMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}

	if !validateTriggerToken(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
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
	apiMetrics.DailyGET = 0
	apiMetrics.DailyPOST = 0
	apiMetrics.DailyPUT = 0
	apiMetrics.DailyDELETE = 0
	apiMetrics.DailyNIC = 0
	apiMetrics.DailyReset = time.Time{}
	apiMetrics.HourlyReset = time.Time{}
	apiMetrics.lastHour = 0
	apiMetrics.providerAnyError.Store(false)
	apiMetrics.Unlock()

	if err := apiMetrics.SaveToFile(metricsPersistPath); err != nil {
		debugLog("API", getClientIP(r), "Failed to save empty metrics: "+err.Error())
	}

	stats := apiMetrics.GetStats()
	setLatestMetrics(stats)
	broadcastNotification("📊 "+phrases().MetricsResetNotification, "info")

	writeJSON(w, http.StatusOK, map[string]string{"status": "reset_success"})
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
