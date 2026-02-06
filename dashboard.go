package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// ============================================================================
// WEBSOCKET
// ============================================================================
func (h *WSHub) run() {
	for {
		select {
		case c := <-h.register:
			h.mu.Lock()
			h.clients[c] = true
			n := len(h.clients)
			h.mu.Unlock()

			go c.writePump()
			go c.readPump(h)

			debugLog("WS", "", fmt.Sprintf("Client connected (total: %d)", n))

		case c := <-h.unregister:
			removed := false
			n := 0

			h.mu.Lock()
			if _, ok := h.clients[c]; ok {
				delete(h.clients, c)
				removed = true
				n = len(h.clients)

				func() {
					defer func() { _ = recover() }()
					c.closeSend()
				}()
			}
			h.mu.Unlock()

			if removed {
				debugLog("WS", "", fmt.Sprintf("Client disconnected (total: %d)", n))
				_ = c.conn.Close()
			}

		case msg := <-h.broadcast:
			h.mu.RLock()
			clients := make([]*WSClient, 0, len(h.clients))
			for c := range h.clients {
				clients = append(clients, c)
			}
			h.mu.RUnlock()

			for _, c := range clients {
				select {
				case c.send <- msg:
				default:
					debugLog("WS", "", "client send queue full - disconnecting")
					select {
					case h.unregister <- c:
					default:
						h.forceRemoveClient(c)
					}
				}
			}
		}
	}
}

func (c *WSClient) writePump() {
	ticker := time.NewTicker(WSPingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-shutdownCtx.Done():
			return

		case msg, ok := <-c.send:
			if !ok {
				return
			}
			_ = c.conn.SetWriteDeadline(time.Now().Local().Add(WSWriteTimeout))
			if err := c.conn.WriteJSON(msg); err != nil {
				return
			}

		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Local().Add(WSWriteTimeout))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (c *WSClient) readPump(h *WSHub) {
	defer func() {
		select {
		case h.unregister <- c:
		default:
			h.forceRemoveClient(c)
		}
	}()

	_ = c.conn.SetReadDeadline(time.Now().Local().Add(WSPongTimeout))
	c.conn.SetPongHandler(func(string) error {
		_ = c.conn.SetReadDeadline(time.Now().Local().Add(WSPongTimeout))
		return nil
	})

	for {
		if _, _, err := c.conn.ReadMessage(); err != nil {
			return
		}
	}
}

func (c *WSClient) closeSend() {
	c.closeOnce.Do(func() {
		close(c.send)
	})
}

func broadcastUpdate(updateType string, data interface{}) {
	msg := WSMessage{Type: updateType, Data: data}
	select {
	case wsHub.broadcast <- msg:
	default:
		debugLog("WS", "", "broadcast queue full - dropping message")
	}
}

func (h *WSHub) forceRemoveClient(c *WSClient) {
	h.mu.Lock()
	if _, ok := h.clients[c]; ok {
		delete(h.clients, c)
		func() {
			defer func() { _ = recover() }()
			c.closeSend()
		}()
	}
	h.mu.Unlock()
	_ = c.conn.Close()
}

// ============================================================================
// SVG CHARTS
// ============================================================================
func generateSVGChart(data [24]int) string {
	maxVal := 0
	for _, v := range data {
		if v > maxVal {
			maxVal = v
		}
	}
	renderMax := float64(maxVal) * 1.2
	if renderMax < 10 {
		renderMax = 10
	}

	width, height := 300.0, 60.0
	var points [][2]float64
	for i, val := range data {
		x := float64(i) * (width / 23.0)
		y := height - (float64(val) * height / renderMax)
		points = append(points, [2]float64{x, y})
	}

	var pathBuilder strings.Builder
	pathBuilder.WriteString(fmt.Sprintf("M %.1f,%.1f", points[0][0], points[0][1]))

	for i := 0; i < len(points)-1; i++ {
		p0, p1 := points[i], points[i+1]
		cp1x := p0[0] + (p1[0]-p0[0])/2
		pathBuilder.WriteString(fmt.Sprintf(" C %.1f,%.1f %.1f,%.1f %.1f,%.1f",
			cp1x, p0[1], cp1x, p1[1], p1[0], p1[1]))
	}
	pathData := pathBuilder.String()

	var labelsBuilder strings.Builder
	now := time.Now().Local()

	offsets := []int{24, 18, 12, 6, 0}

	for _, off := range offsets {
		h := now.Add(-time.Duration(off) * time.Hour).Hour()
		if off == 0 {
			labelsBuilder.WriteString(fmt.Sprintf(`<span style="color:#e5e7eb;">%02dh</span>`, h))
		} else {
			labelsBuilder.WriteString(fmt.Sprintf("<span>%02dh</span>", h))
		}
	}
	timeLabels := labelsBuilder.String()

	return fmt.Sprintf(`
<details class="card">
	<summary>📈 %s</summary>
	<div class="card-content" style="position:relative; padding-left:40px; margin-top:15px; padding-right:10px;">
		<div style="position:absolute; left:0; top:0; height:60px; font-size:0.6rem; color:gray; text-align:right; width:35px; pointer-events:none;">
			<div style="position:absolute; top:0; right:5px; transform: translateY(-50%%);">%.0f</div>
			<div style="position:absolute; top:30px; right:5px; transform: translateY(-50%%);">%.0f</div>
			<div style="position:absolute; top:60px; right:5px; transform: translateY(-50%%);">0</div>
		</div>
		<svg viewBox="0 0 300 60" preserveAspectRatio="none" style="width:100%%; height:60px; display:block; border-bottom: 1px solid rgba(255,255,255,0.1);">
			<path d="%s L 300,60 L 0,60 Z" fill="rgba(56,189,248,0.1)"/>
			<path d="%s" fill="none" stroke="#38bdf8" stroke-width="2" stroke-linecap="round"/>
		</svg>

		<div style="display:flex; justify-content:space-between; font-size:0.6rem; margin-top:8px; color:gray;">
			%s
		</div>
	</div>
</details>`, T.RequestHistory, renderMax, renderMax/2, pathData, pathData, timeLabels)
}

func generateLatencyChart(data [24]time.Duration) string {
	var maxMs float64
	pointsData := make([]float64, 24)
	for i, v := range data {
		ms := float64(v.Milliseconds())
		pointsData[i] = ms
		if ms > maxMs {
			maxMs = ms
		}
	}
	renderMax := maxMs * 1.2
	if renderMax < 50 {
		renderMax = 50
	}

	width, height := 300.0, 60.0
	var points [][2]float64
	for i, val := range pointsData {
		x := float64(i) * (width / 23.0)
		y := height - (val * height / renderMax)
		points = append(points, [2]float64{x, y})
	}

	pathData := fmt.Sprintf("M %.1f,%.1f", points[0][0], points[0][1])
	for i := 0; i < len(points)-1; i++ {
		p0, p1 := points[i], points[i+1]
		cp1x := p0[0] + (p1[0]-p0[0])/2
		pathData += fmt.Sprintf(" C %.1f,%.1f %.1f,%.1f %.1f,%.1f", cp1x, p0[1], cp1x, p1[1], p1[0], p1[1])
	}

	var labelsBuilder strings.Builder
	now := time.Now().Local()

	offsets := []int{24, 18, 12, 6, 0}

	for _, off := range offsets {
		h := now.Add(-time.Duration(off) * time.Hour).Hour()
		if off == 0 {
			labelsBuilder.WriteString(fmt.Sprintf(`<span style="color:#e5e7eb;">%02dh</span>`, h))
		} else {
			labelsBuilder.WriteString(fmt.Sprintf("<span>%02dh</span>", h))
		}
	}
	timeLabels := labelsBuilder.String()

	return fmt.Sprintf(`
<details class="card">
	<summary>⚡ %s</summary>
	<div class="card-content" style="position:relative; padding-left:40px; margin-top:15px; padding-right:5px;">
		<div style="position:absolute; left:0; top:0; height:60px; font-size:0.55rem; color:gray; text-align:right; width:35px; pointer-events:none; font-family:monospace;">
			<div style="position:absolute; top:0; right:5px; transform:translateY(-50%%);">%.0fms</div>
			<div style="position:absolute; top:30px; right:5px; transform:translateY(-50%%);">%.0fms</div>
			<div style="position:absolute; top:60px; right:5px; transform:translateY(-50%%);">0</div>
		</div>
		<svg viewBox="0 0 300 60" preserveAspectRatio="none" style="width:100%%; height:60px; display:block; border-bottom: 1px solid rgba(255,255,255,0.1); overflow:visible;">
			<path d="%s L 300,60 L 0,60 Z" fill="rgba(139,92,246,0.15)"/>
			<path d="%s" fill="none" stroke="#a78bfa" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
		</svg>

		<div style="display:flex; justify-content:space-between; font-size:0.6rem; margin-top:8px; color:gray;">
			%s
		</div>
	</div>
</details>`, T.LatencyHistory, renderMax, renderMax/2, pathData, pathData, timeLabels)
}

func toInt24(v any) ([24]int, bool) {
	var out [24]int

	switch x := v.(type) {
	case [24]int:
		return x, true
	case []int:
		if len(x) != 24 {
			return out, false
		}
		for i := 0; i < 24; i++ {
			out[i] = x[i]
		}
		return out, true
	case []any:
		if len(x) != 24 {
			return out, false
		}
		for i := 0; i < 24; i++ {
			switch n := x[i].(type) {
			case int:
				out[i] = n
			case int64:
				out[i] = int(n)
			case float64:
				out[i] = int(n)
			case json.Number:
				iv, err := n.Int64()
				if err != nil {
					return out, false
				}
				out[i] = int(iv)
			default:
				return out, false
			}
		}
		return out, true
	default:
		return out, false
	}
}

func toDur24(v any) ([24]time.Duration, bool) {
	var out [24]time.Duration

	switch x := v.(type) {
	case [24]time.Duration:
		return x, true
	case []time.Duration:
		if len(x) != 24 {
			return out, false
		}
		for i := 0; i < 24; i++ {
			out[i] = x[i]
		}
		return out, true
	case []any:
		if len(x) != 24 {
			return out, false
		}
		for i := 0; i < 24; i++ {
			switch n := x[i].(type) {
			case time.Duration:
				out[i] = n
			case int64:
				out[i] = time.Duration(n) * time.Millisecond
			case int:
				out[i] = time.Duration(n) * time.Millisecond
			case float64:
				out[i] = time.Duration(int64(n)) * time.Millisecond
			case string:
				d, err := time.ParseDuration(n)
				if err != nil {
					return out, false
				}
				out[i] = d
			default:
				return out, false
			}
		}
		return out, true
	default:
		return out, false
	}
}

// ============================================================================
// METRICS
// ============================================================================
func (m *APIMetrics) RecordSuccess(duration time.Duration) {
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

	statsCopy := m.getStatsUnsafe()
	m.Unlock()

	setLatestMetrics(statsCopy)
}

func (m *APIMetrics) RecordError(statusCode int, err error, duration time.Duration) {
	m.Lock()
	now := time.Now().Local()
	m.TotalRequests++
	m.FailedRequests++
	m.LastError = err.Error()
	m.LastErrorTimestamp = now

	m.cleanupOldTimestamps(now)
	if len(m.RequestTimestamps) >= 5000 {
		m.RequestTimestamps = m.RequestTimestamps[len(m.RequestTimestamps)-3600:]
	}

	m.RequestTimestamps = append(m.RequestTimestamps, now)

	hour := now.Hour()
	if hour >= 0 && hour < 24 {
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
	}

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
}

func (m *APIMetrics) cleanupOldTimestamps(now time.Time) {
	threshold := now.Add(-1 * time.Hour)
	validIdx := len(m.RequestTimestamps)
	for i, t := range m.RequestTimestamps {
		if t.After(threshold) {
			validIdx = i
			break
		}
	}

	if validIdx > 0 && validIdx <= len(m.RequestTimestamps) {
		m.RequestTimestamps = append([]time.Time(nil), m.RequestTimestamps[validIdx:]...)
	}

	const maxTimestamps = 3600
	if len(m.RequestTimestamps) > maxTimestamps {
		m.RequestTimestamps = append([]time.Time(nil), m.RequestTimestamps[len(m.RequestTimestamps)-maxTimestamps:]...)
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

	return map[string]interface{}{
		"total_requests":    m.TotalRequests,
		"success_rate":      fmt.Sprintf("%.2f%%", successRate),
		"avg_latency":       m.AverageLatency.String(),
		"server_errors":     m.ServerErrors,
		"client_errors":     m.ClientErrors,
		"last_success_time": m.LastSuccessTimestamp.Format("15:04:05"),
		"usage_count":       currentCount,
		"usage_percent":     fmt.Sprintf("%.1f", percent),
		"usage_color":       m.getUsageColor(percent),
		"hourly_stats":      chronologicalStats,
		"hourly_latency":    chronologicalLatency,
		"hourly_limit":      cfg.HourlyRateLimit,
	}
}

func ensureMetricsFile(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
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
	return os.WriteFile(path, b, 0644)
}

func (m *APIMetrics) SaveToFile(path string) error {
	if err := ensureMetricsFile(path); err != nil {
		return err
	}

	m.Lock()
	snap := apiMetricsSnapshot{
		TotalRequests:     m.TotalRequests,
		SuccessRequests:   m.SuccessRequests,
		FailedRequests:    m.FailedRequests,
		RateLimitHits:     m.RateLimitHits,
		ServerErrors:      m.ServerErrors,
		ClientErrors:      m.ClientErrors,
		AverageLatencyMs:  m.AverageLatency.Milliseconds(),
		HourlyStats:       m.HourlyStats,
		LastError:         m.LastError,
		LastSuccessTime:   m.LastSuccessTimestamp,
		LastErrorTime:     m.LastErrorTimestamp,
		SavedAt:           time.Now().Local(),
		RequestTimestamps: make([]time.Time, len(m.RequestTimestamps)),
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
	if err := os.WriteFile(tmp, b, 0644); err != nil {
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

// ============================================================================
// DASHBOARD HTTP HANDLER
// ============================================================================

func createMux() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/favicon.svg", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		theme := q.Get("theme")
		level := q.Get("level") // ok|warn|err
		blink := q.Get("blink") == "1"

		bg := "#1e293b" // dark
		textColor := "white"
		if theme == "light" {
			bg = "#f8fafc"
			textColor = "#0f172a"
		}

		// Ampel-Farben
		statusColor := "#22c55e" // ok grün
		symbol := "✓"
		switch level {
		case "warn":
			statusColor = "#facc15" // gelb
			symbol = "!"
		case "err":
			statusColor = "#ef4444" // rot
			symbol = "✕"
		}

		// Blink: wir machen den Badge bei blink=1 transparent -> Frame-Wechsel wirkt wie Blinken
		badgeOpacity := "1"
		if blink && level == "err" {
			badgeOpacity = "0"
		}

		svg := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
	<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">
	<rect width="64" height="64" rx="14" fill="%s"/>

	<!-- Main icon -->
	<text x="32" y="40" text-anchor="middle" font-size="32"
			font-family="Apple Color Emoji, Segoe UI Emoji, Noto Color Emoji">🌐</text>

	<!-- Status badge (Ampel) -->
	<g opacity="%s">
		<circle cx="48" cy="48" r="10" fill="%s"/>
		<text x="48" y="52" text-anchor="middle" font-size="14" font-weight="800"
			fill="white" font-family="system-ui">%s</text>
	</g>

	<!-- Optional tiny label for theme readability -->
	<circle cx="14" cy="14" r="4" fill="%s" opacity="0.35"/>
	</svg>`, bg, badgeOpacity, statusColor, symbol, textColor)

		w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		_, _ = w.Write([]byte(svg))
	})

	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			debugLog("WS", "", fmt.Sprintf("Upgrade failed: %v", err))
			return
		}

		client := &WSClient{
			conn: conn,
			send: make(chan WSMessage, 64),
		}

		stats := apiMetrics.GetStats()
		client.send <- WSMessage{Type: "initial", Data: stats}

		wsHub.register <- client
	})

	mux.HandleFunc("/api/domains", func(w http.ResponseWriter, r *http.Request) {
		serveCachedJSON(w, r, domainsCache)
	})

	mux.HandleFunc("/api/trigger", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1024)
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		clientIP := getClientIP(r)

		if !validateTriggerToken(r) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "invalid or missing trigger token",
			})

			debugLog("API", clientIP, "Trigger blocked: Invalid token")
			return
		}

		if !globalTriggerLimiter.Allow() {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "10")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":               "global rate limit exceeded",
				"retry_after_seconds": 10,
			})

			debugLog("API", clientIP, "Trigger blocked: Global rate limit")
			return
		}

		ipLimiter := ipTriggerLimiter.GetLimiter(clientIP)
		if !ipLimiter.Allow() {
			remaining := ipLimiter.Remaining()

			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "10")
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":               "IP rate limit exceeded",
				"retry_after_seconds": 10,
				"remaining":           remaining,
			})

			debugLog("API", clientIP, "Trigger blocked: IP rate limit")
			return
		}

		if !updateInProgress.CompareAndSwap(false, true) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":  "update already in progress",
				"status": "busy",
			})

			debugLog("API", clientIP, "Trigger blocked: Update already running")
			return
		}

		go func() {
			defer updateInProgress.Store(false)

			debugLog("API", clientIP, "Manual update triggered")
			runUpdate(false)
		}()

		remaining := ipLimiter.Remaining()

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":               "triggered",
			"message":              "update started",
			"rate_limit_remaining": remaining,
		})
	})

	mux.HandleFunc("/api/trigger/status", func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)
		ipLimiter := ipTriggerLimiter.GetLimiter(clientIP)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ip":                 clientIP,
			"remaining_requests": ipLimiter.Remaining(),
			"update_in_progress": updateInProgress.Load(),
			"global_limit":       globalTriggerLimiter.Remaining(),
		})
	})

	mux.HandleFunc("/api/export", func(w http.ResponseWriter, r *http.Request) {
		statusMutex.Lock()
		defer statusMutex.Unlock()

		exportData := map[string]interface{}{
			"timestamp": time.Now().Local().Format(time.RFC3339),
			"metrics":   apiMetrics.GetStats(),
		}

		if b, err := os.ReadFile(updatePath); err == nil {
			var domains map[string]DomainHistory
			json.Unmarshal(b, &domains)
			exportData["domains"] = domains
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=dyndns-export.json")

		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.Encode(exportData)
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		isHealthy := lastOk.Load()
		stats := apiMetrics.GetStats()

		if successTime, ok := stats["last_success_time"].(string); ok {
			if successTime != "" {
			}
		}

		var total int64
		switch v := stats["total_requests"].(type) {
		case int64:
			total = v
		case int:
			total = int64(v)
		case float64:
			total = int64(v)
		}
		if total > 10 {
			successRateStr, _ := stats["success_rate"].(string)
			var rate float64
			fmt.Sscanf(successRateStr, "%f%%", &rate)

			if rate < 50.0 {
				isHealthy = false
			}
		}

		if !isHealthy {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":      "unhealthy",
				"reason":      "high error rate or no recent success",
				"api_metrics": stats,
			})
			return
		}

		if r.URL.Query().Get("detailed") == "true" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":      "healthy",
				"api_metrics": stats,
			})
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		serveCachedJSON(w, r, metricsCache)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		statusMutex.Lock()
		data := make(map[string]interface{})
		if fileData, err := os.ReadFile(updatePath); err == nil {
			_ = json.Unmarshal(fileData, &data)
		}
		statusMutex.Unlock()

		statusClass, statusText := "status-ok", T.StatusOk
		if !lastOk.Load() {
			statusClass, statusText = "status-error", T.StatusErr
		}

		var logs []LogEntry
		if b, err := os.ReadFile(logPath); err == nil {
			lines := strings.Split(string(b), "\n")
			for i := len(lines) - 1; i >= 0 && len(logs) < 500; i-- {
				if strings.TrimSpace(lines[i]) == "" {
					continue
				}
				var e LogEntry
				if json.Unmarshal([]byte(lines[i]), &e) == nil {
					logs = append(logs, e)
				}
			}
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!DOCTYPE html><html><head>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<title>`+html.EscapeString(T.DashTitle)+`</title>
		<link id="favicon" rel="icon" type="image/svg+xml" href="/favicon.svg?theme=dark">
		<style>
		* {box-sizing: border-box; margin: 0; padding: 0;}

		:root {
			--bg: #0f172a; --card: #1e293b; --text: #f8fafc; --border: #334155;
			--success: #4ade80; --error: #f87171; --warning: #facc15;
		}
		[data-theme="light"] {
			--bg: #f8fafc; --card: #ffffff; --text: #0f172a; --border: #e2e8f0;
		}
		
		body {
			font-family: system-ui, -apple-system, sans-serif;
			background: var(--bg);
			color: var(--text);
			padding: 10px;
			transition: background 0.3s, color 0.3s;
		}
		
		.container {max-width: 1200px; margin: 0 auto;}

		.header {
			display: flex;
			justify-content: space-between;
			align-items: center;
			margin-bottom: 20px;
			padding: 15px;
			background: var(--card);
			border-radius: 12px;
			border: 1px solid var(--border);
		}
		
		.theme-toggle {
			background: var(--border);
			border: none;
			padding: 8px 16px;
			border-radius: 8px;
			cursor: pointer;
			color: var(--text);
			font-size: 1.2rem;
		}

		.status-banner {
			display: flex;
			justify-content: space-between;
			align-items: center;
			padding: 15px 20px;
			border-radius: 12px;
			margin-bottom: 20px;
			font-weight: 600;
			border: 1px solid rgba(255,255,255,0.1);
		}
		.status-ok {background: rgba(34,197,94,0.15); color: var(--success);}
		.status-error {background: rgba(239,68,68,0.15); color: var(--error);}

		.card {
			background: var(--card);
			padding: 0;
			margin-bottom: 15px;
			border-radius: 12px;
			border: 1px solid var(--border);
			overflow: hidden;
		}
		
		details.card {
			padding: 0;
		}
		
		details.card > summary {
			cursor: pointer;
			padding: 15px 20px;
			font-weight: 600;
			list-style: none;
			display: flex;
			justify-content: space-between;
			align-items: center;
			user-select: none;
		}
		
		details.card > summary::-webkit-details-marker {display: none;}
		
		details.card > summary::after {
			content: '▼';
			transition: transform 0.2s;
			font-size: 0.8em;
			opacity: 0.5;
		}
		
		details.card[open] > summary::after {
			transform: rotate(-180deg);
		}
		
		.card-content {
			padding: 0 20px 20px 20px;
		}

		.search-box {
			width: 100%;
			padding: 12px 16px;
			background: var(--card);
			border: 1px solid var(--border);
			border-radius: 8px;
			color: var(--text);
			font-size: 1rem;
			margin-bottom: 15px;
		}

		.log-filters {
			display: flex;
			gap: 8px;
			margin-bottom: 15px;
			flex-wrap: wrap;
		}
		
		.filter-btn {
			padding: 6px 12px;
			background: var(--border);
			border: 1px solid transparent;
			border-radius: 6px;
			cursor: pointer;
			color: var(--text);
			font-size: 0.85rem;
			transition: all 0.2s;
		}
		
		.filter-btn:hover {
			border-color: var(--success);
		}
		
		.filter-btn.active {
			background: var(--success);
			color: white;
		}

		.copy-btn {
			background: transparent;
			border: 1px solid var(--border);
			padding: 4px 8px;
			border-radius: 4px;
			cursor: pointer;
			font-size: 0.9rem;
			transition:  all 0.2s;
			color: var(--text); 
		}
		
		.copy-btn:hover {
			background: var(--success);
			border-color: var(--success);
			color: white;  
		}

		.toast {
			position: fixed;
			top: 20px;
			right: 20px;
			background: var(--card);
			border: 1px solid var(--border);
			padding: 15px 20px;
			border-radius: 8px;
			box-shadow: 0 4px 12px rgba(0,0,0,0.3);
			transform: translateX(400px);
			transition: transform 0.3s;
			z-index: 1000;
			max-width: 300px;
		}
		
		.toast.show {
			transform: translateX(0);
		}

		.badge {
			padding: 3px 8px;
			border-radius: 4px;
			font-size: 0.7rem;
			color: #fff;
			font-weight: bold;
			display: inline-block;
			margin-right: 6px;
		}
		.v4 {background: #0ea5e9;}
		.v6 {background: #8b5cf6;}

		.log-entry {
			padding: 10px;
			margin-bottom: 6px;
			border-radius: 6px;
			font-size: 0.85rem;
			background: rgba(255,255,255,0.03);
		}
		
		.log-entry.hidden {display: none;}

		.action-btn {
			background: var(--success);
			color: white;
			border: none;
			padding: 10px 20px;
			border-radius: 8px;
			cursor: pointer;
			font-weight: 600;
			transition: all 0.2s;
		}
		
		.action-btn:hover {
			transform: translateY(-2px);
			box-shadow: 0 4px 12px rgba(74, 222, 128, 0.3);
		}

		@media (max-width: 768px) {
			.header {flex-direction: column; gap: 10px;}
			.status-banner {flex-direction: column; text-align: center;}
		}

		.domain-card {
			display: flex;
			justify-content: space-between;
			align-items: center;
			padding: 15px;
			background: rgba(255,255,255,0.02);
			border-radius: 8px;
			margin-bottom: 10px;
		}
		
		.ip-display {
			display: flex;
			align-items: center;
			gap: 8px;
			font-family: 'Courier New', monospace;
		}
		</style>
	</head>
	<body>
	<div class="container">
		<div class="header">
			<h1>🌐 `+html.EscapeString(T.DashTitle)+`</h1>
			<div style="display: flex; gap: 10px; align-items: center;">
				<button class="action-btn" onclick="triggerUpdate()">🔄 Update</button>
				<button class="action-btn" onclick="exportData()">📥 Export</button>
				<button class="theme-toggle" onclick="toggleTheme()">🌓</button>
			</div>
		</div>
		
		<div class="status-banner `+statusClass+`">
			<span>`+statusText+`</span>
			<span>`+T.LastUpdate+`: <span id="lastUpdate">`+time.Now().Local().Format("15:04:05")+`</span></span>
		</div>
		
		<div id="toast" class="toast"></div>
		
		<input type="text" class="search-box" id="domainSearch" placeholder="🔍 Domain suchen..." oninput="filterDomains(this.value)">
	`)

		stats := apiMetrics.GetStats()
		hourlyStats, ok1 := toInt24(stats["hourly_stats"])
		hourlyLat, ok2 := toDur24(stats["hourly_latency"])

		if !ok1 {
			hourlyStats = [24]int{}
		}
		if !ok2 {
			hourlyLat = [24]time.Duration{}
		}

		chartSVG := generateSVGChart(hourlyStats)
		latencySVG := generateLatencyChart(hourlyLat)

		fmt.Fprintf(w, `
		<details class="card" open id="metrics-card">
			<summary>📊 %s </summary>
			<div class="card-content">
				<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-top: 10px;">
					<div><strong>`+T.TotalRequests+`:</strong> <span id="mTotal">%v</span></div>
					<div><strong>`+T.SuccessRate+`:</strong> <span id="mSuccess" style="color:var(--success)">%v</span></div>
					<div><strong>`+T.AvgLatency+`:</strong> <span id="mLatency">%v</span></div>
					<div><strong>`+T.Errors+`:</strong> <span id="mErrors">%v / %v</span></div>
				</div>
				<div style="margin-top: 20px;">
					<div style="display: flex; justify-content: space-between; align-items: baseline;
								font-size: 0.7rem; color: #94a3b8; margin-bottom: 6px;">
						<span style="letter-spacing: 0.04em;">`+T.HourlyLimitEst+`</span>
						<span id="mUsage" style="font-weight: 600; color: var(--text);">
							%v / %v `+T.RequestsLabel+`
						</span>
					</div>

					<div style="width: 100%%; background: #334155; height: 8px;
								border-radius: 999px; overflow: hidden;">
						<div id="mUsageBar"
							style="width: %s%%; height: 100%%; background: %s;
									transition: width 0.5s ease;">
						</div>
					</div>

					<div style="font-size: 0.65rem; color: #64748b; margin-top: 6px;">
						`+T.UsageLast60Min+`
					</div>
				</div>
            </div>
		</details>
		
		%s
		
		%s
		`,
			T.ApiPerformance,
			stats["total_requests"],
			stats["success_rate"],
			stats["avg_latency"],
			stats["client_errors"],
			stats["server_errors"],
			stats["usage_count"],
			stats["hourly_limit"],
			stats["usage_percent"],
			stats["usage_color"],
			chartSVG,
			latencySVG)

		if len(logs) > 0 {
			fmt.Fprintf(w, `
		<details class="card" id="logs-card">
			<summary>🧾 %s <span style="opacity:0.6; font-size:0.9em;">(%d entries)</span></summary>
			<div class="card-content">
				<div class="log-filters">
					<button class="filter-btn active" data-filter="all" onclick="filterLogs('all')">All</button>
					<button class="filter-btn" data-filter="ERR" onclick="filterLogs('ERR')">Errors</button>
					<button class="filter-btn" data-filter="WARN" onclick="filterLogs('WARN')">Warnings</button>
					<button class="filter-btn" data-filter="UPDATE" onclick="filterLogs('UPDATE')">Updates</button>
					<button class="filter-btn" data-filter="START" onclick="filterLogs('START')">Starts</button>
					<button class="filter-btn" data-filter="STOP" onclick="filterLogs('STOP')">Stop</button>
					<button class="filter-btn" data-filter="CREATE" onclick="filterLogs('CREATE')">Created</button>
					<button class="filter-btn" data-filter="CLEANUP" onclick="filterLogs('CLEANUP')">Cleanup</button>
				</div>
			<div id="logContainer" style="max-height: 300px; overflow-y: auto; font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 13px; padding-right: 5px;">
			`, T.SystemEvents, len(logs))

			for _, e := range logs {
				displayTime := e.Timestamp
				if len(displayTime) >= 16 {
					datePart := displayTime[8:10] + "." + displayTime[5:7] + "." + displayTime[0:4]
					timePart := displayTime[11:16]
					displayTime = datePart + " " + timePart
				}

				actionUpper := strings.ToUpper(e.Action)

				icon := "🔹"
				switch actionUpper {
				case "ERROR", "FAIL":
					icon = "⚠️"
				case "CLEANUP":
					icon = "🧹♻️"
				case "SUCCESS", "ADDED":
					icon = "✅"
				case "UPDATE":
					icon = "🔄"
				case "CREATE":
					icon = "🆕"
				}

				fmt.Fprintf(w, `
				<div class="log-entry"
					data-action="%s"
					data-level="%s"
					style="display: flex; align-items: flex-start; padding: 6px 8px;
							border-radius: 4px; margin-bottom: 4px; gap: 10px;
							background: rgba(255,255,255,0.03);">
					<span style="flex-shrink: 0; width: 20px; text-align: center;">%s</span>
					<span style="color: #888; white-space: nowrap; font-size: 0.85em;">%s</span>
					<div style="flex: 1; word-break: break-word;">
						%s
						<span style="opacity: 0.9;">%s</span>
					</div>
				</div>
				`,
					actionUpper,
					e.Level,
					icon,
					displayTime,
					func() string {
						if e.Domain == "" {
							return ""
						}
						return `<span style="font-weight: 600; color: #64b5f6; margin-right: 5px;">` +
							html.EscapeString(e.Domain) + `</span>`
					}(),
					html.EscapeString(e.Message),
				)
			}

			fmt.Fprint(w, `
				</div>
			</div>
		</details>
	    `)
		}

		var keys []string
		for k := range data {
			if !strings.HasPrefix(k, "_") {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)

		fmt.Fprint(w, `<div id="domainContainer">`)
		for _, k := range keys {
			var h DomainHistory
			b, _ := json.Marshal(data[k])
			_ = json.Unmarshal(b, &h)

			latest := IPEntry{}
			if len(h.IPs) > 0 {
				latest = h.IPs[len(h.IPs)-1]
			}

			safeID := sanitizeIDWithHash(k)

			fmt.Fprintf(w, `
		<details class="card domain-item" data-domain="%s">
			<summary>🌐 %s <span style="opacity:0.6; font-size:0.9em;">(%s)</span></summary>
			<div class="card-content">
				<div class="domain-card" style="border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 15px; margin-bottom: 10px;">
					<div>
						<div class="ip-display">
							<span class="badge v4">IPv4</span>
							<span id="ip4-%s">%s</span>
							<button class="copy-btn" onclick="copyIP(%q, %q)" title="Copy">📋</button>
						</div>
						<div class="ip-display" style="margin-top: 8px;">
							<span class="badge v6">IPv6</span>
							<span id="ip6-%s">%s</span>
							<button class="copy-btn" onclick="copyIP(%q, %q)" title="Copy">📋</button>
						</div>
					</div>
					<div style="text-align: right; opacity: 0.7;">
						<small>Zuletzt: %s</small>
					</div>
				</div>

				<div style="max-height: 200px; overflow-y: auto;">
					<table style="width: 100%%; font-size: 0.85em; border-collapse: collapse;">
						<thead style="text-align: left; opacity: 0.5; font-size: 0.7rem;">
							<tr>
								<th style="padding-bottom: 5px;">Zeitpunkt</th>
								<th style="padding-bottom: 5px;">IP Adressen</th>
							</tr>
						</thead>
						<tbody>`,
				html.EscapeString(k),
				html.EscapeString(k),
				html.EscapeString(h.Provider),
				safeID,
				html.EscapeString(latest.IPv4),
				latest.IPv4,
				"ip4-"+safeID,
				safeID,
				html.EscapeString(latest.IPv6),
				latest.IPv6,
				"ip6-"+safeID,
				html.EscapeString(latest.Time),
			)

			for i := len(h.IPs) - 2; i >= 0; i-- {
				e := h.IPs[i]
				fmt.Fprintf(w, `
			<tr style="border-top: 1px solid rgba(255,255,255,0.05);">
				<td style="padding: 8px 0; vertical-align: top; opacity: 0.7; font-family: monospace;">%s</td>
				<td style="padding: 8px 0;">
					<div style="display:flex; align-items:center; gap:5px;">
						<span class="badge v4" style="font-size:0.6rem; padding: 1px 4px;">v4</span> 
						<span style="opacity:0.9;">%s</span>
					</div>
					<div style="display:flex; align-items:center; gap:5px; margin-top:4px;">
						<span class="badge v6" style="font-size:0.6rem; padding: 1px 4px;">v6</span> 
						<span style="opacity:0.9;">%s</span>
					</div>
				</td>
			</tr>`,
					html.EscapeString(e.Time),
					html.EscapeString(e.IPv4),
					html.EscapeString(e.IPv6),
				)
			}

			if len(h.IPs) < 2 {
				fmt.Fprint(w, `<tr><td colspan="2" style="text-align:center; opacity:0.5; padding: 10px;">Keine weiteren Einträge</td></tr>`)
			}

			fmt.Fprint(w, `
						</tbody>
					</table>
				</div>
			</div>
		</details>`)
		}
		fmt.Fprint(w, `</div>`)

		fmt.Fprint(w, `
	<script>
	let blinkTimer = null;
	let currentLevel = 'ok';

	function faviconHref(theme, level, blink) {
	return '/favicon.svg?theme=' + encodeURIComponent(theme) +
			'&level=' + encodeURIComponent(level) +
			'&blink=' + (blink ? '1' : '0') +
			'&v=' + Date.now();
	}

	function applyFavicon(theme, level, blink) {
	const fav = document.getElementById('favicon');
	if (!fav) return;
	fav.href = faviconHref(theme, level, blink);
	}

	function setBlinking(theme, level) {
	if (blinkTimer) {
		clearInterval(blinkTimer);
		blinkTimer = null;
	}
	if (level !== 'err') return;

	let on = false;
	blinkTimer = setInterval(() => {
		on = !on;
		applyFavicon(theme, 'err', on);
	}, 700);
	}

	function parseDurationToMs(s) {
	s = (s || '').trim().toLowerCase();
	s = s.replace('µs', 'us');

	const m = s.match(/^([0-9]+(?:\.[0-9]+)?)(ms|s|us)$/);
	if (!m) return NaN;

	const val = parseFloat(m[1]);
	const unit = m[2];

	if (unit === 'ms') return val;
	if (unit === 's') return val * 1000;
	if (unit === 'us') return val / 1000;
	return NaN;
	}

	function toNum(v, fallback = 0) {
		if (v == null) return fallback;
		if (typeof v === "number") return v;
		const s = String(v).replace(",", ".").replace("%", "").trim();
		const n = Number(s);
		return Number.isFinite(n) ? n : fallback;
	}

	function calcLevelFromMetrics(m) {
		const total = toNum(m.total_requests, 0);
		const successRate = toNum(m.success_rate, 100);

		const clientErr = toNum(m.client_errors, 0);
		const serverErr = toNum(m.server_errors, 0);
		const totalErr = clientErr + serverErr;

		// harte Fehlerbedingungen
		if (totalErr > 0) return 'err';
		if (total >= 5 && successRate <= 0) return 'err';
		if (total >= 10 && successRate < 50) return 'err';

		// Latenzbedingungen
		const ms = parseDurationToMs(m.avg_latency);
		if (Number.isFinite(ms)) {
			if (ms >= 1000) return 'err';
			if (ms >= 300) return 'warn';
		}

		// Warn bei schlechter Erfolgsrate
		if (total >= 10 && successRate < 90) return 'warn';

		return 'ok';
	}	



	function toggleTheme() {
	const html = document.documentElement;
	const current = html.getAttribute('data-theme') || 'dark';
	const next = current === 'dark' ? 'light' : 'dark';
	html.setAttribute('data-theme', next);
	localStorage.setItem('theme', next);

	applyFavicon(next, currentLevel, false);
	setBlinking(next, currentLevel);

	showToast('Theme: ' + next);
	}

	const savedTheme = localStorage.getItem('theme') || 'dark';
	document.documentElement.setAttribute('data-theme', savedTheme);

	let ws = null;
	let reconnectTimer = null;
	let reconnectDelay = 1000; // startet mit 1s, steigert sich bis max
	const reconnectDelayMax = 10000;

	function connectWS() {
	const proto = location.protocol === 'https:' ? 'wss://' : 'ws://';
	ws = new WebSocket(proto + location.host + '/ws');

	ws.onmessage = (e) => {
		const msg = JSON.parse(e.data);

		if (msg.type === 'initial' || msg.type === 'metrics') {
		updateMetrics(msg.data);

		const theme = localStorage.getItem('theme') || 'dark';
		const level = calcLevelFromMetrics(msg.data);

		currentLevel = level;
		applyFavicon(theme, currentLevel, false);
		setBlinking(theme, currentLevel);
		return;
		}

		if (msg.type === 'domain_update') {
		updateDomainDisplay(msg.data);
		return;
		}
	};

	ws.onerror = (err) => {
		console.error('WebSocket error:', err);
		showToast('WebSocket connection lost', 'error');
	};

	ws.onclose = () => {
		console.log('WebSocket closed, reconnecting...');
		scheduleReconnect();
	};

	// wenn verbunden -> delay zurücksetzen
	ws.onopen = () => {
		reconnectDelay = 1000;
		if (reconnectTimer) {
		clearTimeout(reconnectTimer);
		reconnectTimer = null;
		}
	};
	}

	function scheduleReconnect() {
	if (reconnectTimer) return;

	reconnectTimer = setTimeout(() => {
		reconnectTimer = null;
		connectWS();
	}, reconnectDelay);

	reconnectDelay = Math.min(reconnectDelay * 2, reconnectDelayMax);
	}

	function sanitizeBase(s) {
	s = (s || '').toLowerCase();
	let out = '';
	for (const ch of s) {
		const code = ch.charCodeAt(0);
		const isAZ = code >= 97 && code <= 122;
		const is09 = code >= 48 && code <= 57;
		if (isAZ || is09 || ch === '-' || ch === '_') out += ch;
		else if (ch === '.') out += '-';
	}
	return out || 'x';
	}

	async function shortHash8(str) {
	const s = str || '';
	if (!(window.crypto && crypto.subtle && window.TextEncoder)) {
		return '00000000';
	}
	const data = new TextEncoder().encode(s);
	const buf = await crypto.subtle.digest('SHA-1', data);
	const bytes = new Uint8Array(buf);
	let hex = '';
	for (const b of bytes) hex += b.toString(16).padStart(2, '0');
	return hex.slice(0, 8);
	}

	async function makeSafeID(domain) {
	const base = sanitizeBase(domain);
	const sfx = await shortHash8(domain);
	if (!base || base === 'x') return 'd-' + sfx;
	return base + '-' + sfx;
	}

	async function updateDomainDisplay(data) {
	const safeID = await makeSafeID(data.domain);
	const ip4El = document.getElementById('ip4-' + safeID);
	const ip6El = document.getElementById('ip6-' + safeID);

	if (ip4El && data.ipv4) ip4El.textContent = data.ipv4;
	if (ip6El && data.ipv6) ip6El.textContent = data.ipv6;

	showToast('✓ ' + data.domain + ' updated');
	}

	function updateMetrics(m) {
		// last update time
		const last = document.getElementById('lastUpdate');
		if (last) last.textContent = new Date().toLocaleTimeString();

		// basic metrics
		const elTotal = document.getElementById('mTotal');
		if (elTotal && m.total_requests != null) elTotal.textContent = m.total_requests;

		const elSuccess = document.getElementById('mSuccess');
		if (elSuccess && m.success_rate != null) elSuccess.textContent = m.success_rate;

		const elLatency = document.getElementById('mLatency');
		if (elLatency && m.avg_latency != null) elLatency.textContent = m.avg_latency;

		const elErrors = document.getElementById('mErrors');
		if (elErrors) {
			const c = m.client_errors != null ? m.client_errors : "?";
			const s = m.server_errors != null ? m.server_errors : "?";
			elErrors.textContent = String(c) + " / " + String(s);
		}

		// usage / limit
		const elUsage = document.getElementById('mUsage');
		if (elUsage) {
			const used = m.usage_count != null ? m.usage_count : "?";
			const lim = m.hourly_limit != null ? m.hourly_limit : "?";
			elUsage.textContent = String(used) + " / " + String(lim) + " Requests";
		}

		const bar = document.getElementById('mUsageBar');
		if (bar) {
			const p = (m.usage_percent != null) ? Number(m.usage_percent) : 0;
			bar.style.width = String(isFinite(p) ? p : 0) + "%";
			if (m.usage_color) bar.style.background = m.usage_color;
		}
	}

	function filterLogs(filter) {
		document.querySelectorAll('.filter-btn').forEach(btn => {
        if (btn.dataset.filter === filter) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
    });

    document.querySelectorAll('.log-entry').forEach(entry => {
        const action = (entry.dataset.action || '').toUpperCase();
        const level = (entry.dataset.level || '').toUpperCase();
        const filterUpper = filter.toUpperCase();

        if (filter === 'all') {
            entry.style.display = '';
            return;
        }

        let shouldShow = false;
        
        if (filterUpper === 'ERR' && level === 'ERR') {
            shouldShow = true;
        } else if (filterUpper === 'WARN' && level === 'WARN') {
            shouldShow = true;
        } else if (action === filterUpper) {
            shouldShow = true;
        }

        entry.style.display = shouldShow ? '' : 'none';
    });
}

	function copyIP(ip, elementId) {
		navigator.clipboard.writeText(ip).then(() => {
			showToast('✓ Copied: ' + ip);
		}).catch(() => {
			showToast('Copy failed', 'error');
		});
	}

	function showToast(message, type = 'success') {
		const toast = document.getElementById('toast');
		toast.textContent = message;
		toast.style.borderLeft = type === 'error' ? '4px solid var(--error)' : '4px solid var(--success)';
		toast.classList.add('show');
		setTimeout(() => toast.classList.remove('show'), 3000);
	}

	function filterDomains(query) {
		const domains = document.querySelectorAll('.domain-item');
		query = query.toLowerCase();
		domains.forEach(domain => {
			const name = domain.getAttribute('data-domain').toLowerCase();
			domain.style.display = name.includes(query) ? 'block' : 'none';
		});
	}

	function exportData() {
		fetch('/api/export')
			.then(r => r.blob())
			.then(blob => {
				const url = URL.createObjectURL(blob);
				const a = document.createElement('a');
				a.href = url;
				a.download = 'dyndns-export-' + new Date().toISOString().split('T')[0] + '.json';
				a.click();
				showToast('✓ Export started');
			})
			.catch(() => showToast('Export failed', 'error'));
	}

	function triggerUpdate() {
		const token = localStorage.getItem('triggerToken') || '';
		fetch('/api/trigger', {
			method: 'POST',
			headers: token ? {'X-Trigger-Token': token} : {}
		})
		.then(r => r.json())
		.then(j => {
			if (j && j.error) showToast(j.error, 'error');
			else showToast('✓ Update triggered');
		})
		.catch(() => showToast('Trigger failed', 'error'));
	}


	document.querySelectorAll('details.card').forEach(details => {
	  const id = details.id;
	  const saved = id ? localStorage.getItem('collapse-' + id) : null;

	  if (saved === 'open') {
		details.setAttribute('open', '');
	  } else if (saved === 'closed') {
		details.removeAttribute('open');
	  } else {
		if (id === 'metrics-card') details.setAttribute('open', '');
		else details.removeAttribute('open');
	  }

	  if (id) {
		details.addEventListener('toggle', () => {
		  localStorage.setItem('collapse-' + id, details.open ? 'open' : 'closed');
		});
	  }
	});
	const theme = localStorage.getItem('theme') || 'dark';
	const initialMetrics = {
	avg_latency: (document.getElementById('mLatency')?.textContent || '').trim(),
	success_rate: (document.getElementById('mSuccess')?.textContent || '').trim(),
	client_errors: (document.getElementById('mErrors')?.textContent || '0 / 0').split('/')[0],
	server_errors: (document.getElementById('mErrors')?.textContent || '0 / 0').split('/')[1],
	total_requests: (document.getElementById('mTotal')?.textContent || '0').trim(),
	};
	currentLevel = calcLevelFromMetrics(initialMetrics);
	applyFavicon(theme, currentLevel, false);
	setBlinking(theme, currentLevel);
	</script>
	</div>
	</body>
	</html>
	`)
	})

	return mux
}
