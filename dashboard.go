package main

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"os"
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
		case conn := <-h.register:
			h.mu.Lock()
			h.clients[conn] = true
			h.mu.Unlock()

			go h.keepAlive(conn)

			debugLog("WS", "", fmt.Sprintf("Client connected (total: %d)", len(h.clients)))

		case conn := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[conn]; ok {
				delete(h.clients, conn)
				conn.Close()
			}
			h.mu.Unlock()
			debugLog("WS", "", fmt.Sprintf("Client disconnected (total: %d)", len(h.clients)))

		case message := <-h.broadcast:
			h.mu.RLock()
			clients := make([]*websocket.Conn, 0, len(h.clients))
			for conn := range h.clients {
				clients = append(clients, conn)
			}
			h.mu.RUnlock()

			for _, c := range clients {
				c.SetWriteDeadline(time.Now().Add(WSWriteTimeout))
				if err := c.WriteJSON(message); err != nil {
					debugLog("WS", "", fmt.Sprintf("Write failed: %v", err))
					h.unregister <- c
				}
			}
		}
	}
}

func (h *WSHub) keepAlive(conn *websocket.Conn) {
	ticker := time.NewTicker(WSPingInterval)
	defer ticker.Stop()

	defer func() {
		if r := recover(); r != nil {
			debugLog("WS", "", fmt.Sprintf("Panic in keepAlive: %v", r))
		}
		h.unregister <- conn
	}()

	conn.SetReadDeadline(time.Now().Add(WSPongTimeout))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(WSPongTimeout))
		return nil
	})

	for {
		select {
		case <-shutdownCtx.Done():
			debugLog("WS", "", "Shutdown - closing keepAlive")
			h.unregister <- conn
			return

		case <-ticker.C:
			conn.SetWriteDeadline(time.Now().Add(WSWriteTimeout))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				debugLog("WS", "", "Ping failed, closing connection")
				h.unregister <- conn
				return
			}
		}
	}
}

func broadcastUpdate(updateType string, data interface{}) {
	msg := WSMessage{Type: updateType, Data: data}
	select {
	case wsHub.broadcast <- msg:
	default:
		debugLog("WS", "", "broadcast queue full - dropping message")
	}
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
	now := time.Now()
	for i := 0; i < 5; i++ {
		h := now.Add(time.Duration(-24+(i*6)) * time.Hour).Hour()
		labelsBuilder.WriteString(fmt.Sprintf("<span>%02dh</span>", h))
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

	now := time.Now()
	timeLabels := ""
	for i := 0; i < 5; i++ {
		h := now.Add(time.Duration(-24+(i*6)) * time.Hour).Hour()
		timeLabels += fmt.Sprintf("<span>%02dh</span>", h)
	}

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

// ============================================================================
// METRICS
// ============================================================================

func (m *APIMetrics) RecordSuccess(duration time.Duration) {
	m.Lock()
	m.trackHistory()

	now := time.Now()
	m.TotalRequests++
	m.SuccessRequests++
	m.LastSuccessTimestamp = now

	m.cleanupOldTimestamps(now)
	m.RequestTimestamps = append(m.RequestTimestamps, now)

	hour := now.Hour()
	if hour >= 0 && hour < 24 {
		m.HourlyStats[hour]++
		m.updateLatency(duration)
	}

	statsCopy := m.getStatsUnsafe()
	m.Unlock()

	go broadcastUpdate("metrics", statsCopy)
}

func (m *APIMetrics) RecordError(statusCode int, err error, duration time.Duration) {
	m.Lock()

	m.trackHistory()

	now := time.Now()
	m.TotalRequests++
	m.FailedRequests++
	m.LastError = err.Error()
	m.LastErrorTimestamp = now

	m.cleanupOldTimestamps(now)
	if len(m.RequestTimestamps) >= 5000 {
		m.RequestTimestamps = m.RequestTimestamps[len(m.RequestTimestamps)-3600:]
	}

	m.RequestTimestamps = append(m.RequestTimestamps, now)

	m.HourlyStats[23]++
	m.updateLatency(duration)

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

	go broadcastUpdate("metrics", statsCopy)
}

func (m *APIMetrics) updateLatency(duration time.Duration) {
	if m.AverageLatency == 0 {
		m.AverageLatency = duration
	} else {
		m.AverageLatency = (m.AverageLatency + duration) / 2
	}
	m.AverageLatency = m.AverageLatency.Round(time.Millisecond)

	if m.HourlyLatency[23] == 0 {
		m.HourlyLatency[23] = duration
	} else {
		m.HourlyLatency[23] = (m.HourlyLatency[23] + duration) / 2
	}
}

func (m *APIMetrics) cleanupOldTimestamps(now time.Time) {
	threshold := now.Add(-1 * time.Hour)

	validIdx := 0
	for i, t := range m.RequestTimestamps {
		if t.After(threshold) {
			validIdx = i
			break
		}
	}

	if validIdx > 0 {
		newSlice := make([]time.Time, len(m.RequestTimestamps)-validIdx)
		copy(newSlice, m.RequestTimestamps[validIdx:])
		m.RequestTimestamps = newSlice
	}
	const maxTimestamps = 3600
	if len(m.RequestTimestamps) > maxTimestamps {
		excess := len(m.RequestTimestamps) - maxTimestamps
		newSlice := make([]time.Time, maxTimestamps)
		copy(newSlice, m.RequestTimestamps[excess:])
		m.RequestTimestamps = newSlice
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

func (m *APIMetrics) trackHistory() {
	now := time.Now()
	currentHourUnix := now.Unix() / 3600

	if m.lastHour == 0 {
		m.lastHour = currentHourUnix
		return
	}

	if currentHourUnix != m.lastHour {
		diff := int(currentHourUnix - m.lastHour)
		if diff > 0 {
			if diff >= 24 {
				m.HourlyStats = [24]int{}
				m.HourlyLatency = [24]time.Duration{}
			} else {
				for i := 0; i < 24-diff; i++ {
					m.HourlyStats[i] = m.HourlyStats[i+diff]
					m.HourlyLatency[i] = m.HourlyLatency[i+diff]
				}
				for i := 24 - diff; i < 24; i++ {
					m.HourlyStats[i] = 0
					m.HourlyLatency[i] = 0
				}
			}
			m.lastHour = currentHourUnix
		}
	}
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
		"hourly_stats":      m.HourlyStats,
		"hourly_latency":    m.HourlyLatency,
		"hourly_limit":      cfg.HourlyRateLimit,
	}
}

// ============================================================================
// DASHBOARD HTTP HANDLER
// ============================================================================

func createMux() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			debugLog("WS", "", fmt.Sprintf("Upgrade failed: %v", err))
			return
		}

		conn.SetReadDeadline(time.Now().Add(WSPongTimeout))
		conn.SetPongHandler(func(string) error {
			conn.SetReadDeadline(time.Now().Add(WSPongTimeout))
			return nil
		})

		wsHub.register <- conn

		stats := apiMetrics.GetStats()
		conn.SetWriteDeadline(time.Now().Add(WSWriteTimeout))
		conn.WriteJSON(WSMessage{Type: "initial", Data: stats})

		go func() {
			defer func() { wsHub.unregister <- conn }()
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					break
				}
			}
		}()
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
			"timestamp": time.Now().Format(time.RFC3339),
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

		if total, ok := stats["total_requests"].(int64); ok && total > 10 {
			successRateStr := stats["success_rate"].(string)
			// Parse "95.5%" -> 95.5
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
			<span>`+T.LastUpdate+`: <span id="lastUpdate">`+time.Now().Format("15:04:05")+`</span></span>
		</div>
		
		<div id="toast" class="toast"></div>
		
		<input type="text" class="search-box" id="domainSearch" placeholder="🔍 Domain suchen..." oninput="filterDomains(this.value)">
	`)

		stats := apiMetrics.GetStats()
		chartSVG := generateSVGChart(stats["hourly_stats"].([24]int))
		latencySVG := generateLatencyChart(stats["hourly_latency"].([24]time.Duration))

		fmt.Fprintf(w, `
		<details class="card" open id="metrics-card">
			<summary>📊 `+T.ApiPerformance+`</summary>
			<div class="card-content">
				<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-top: 10px;">
					<div><strong>`+T.TotalRequests+`:</strong> %v</div>
					<div><strong>`+T.SuccessRate+`:</strong> <span style="color:var(--success)">%v</span></div>
					<div><strong>`+T.AvgLatency+`:</strong> %v</div>
					<div><strong>`+T.Errors+`:</strong> %v / %v</div>
				</div>
                <div style="margin-top: 20px;">
                    <div style="display: flex; justify-content: space-between; font-size: 0.7rem; color: #94a3b8; margin-bottom: 4px;">
                        <span>STÜNDLICHES LIMIT (EST.)</span>
                        <span>%v / %v Requests</span> </div>
                    <div style="width: 100%%; background: #334155; height: 8px; border-radius: 4px; overflow: hidden;">
                        <div style="width: %s%%; height: 100%%; background: %s; transition: width 0.5s ease;"></div>
                    </div>
                    <div style="font-size: 0.65rem; color: #64748b; margin-top: 4px;">Basierend auf Requests der letzten 60 Minuten</div>
                </div>
            </div>
		</details>
		
		%s
		
		%s
	`,
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
	    <summary>🧾 %s</summary>
	    <div class="card-content">
	        <div class="log-filters">
				<button class="filter-btn active" data-filter="all" onclick="filterLogs('all')">All</button>
				<button class="filter-btn" data-filter="ERR" onclick="filterLogs('ERR')">Errors</button>
				<button class="filter-btn" data-filter="WARN" onclick="filterLogs('WARN')">Warnings</button>
				<button class="filter-btn" data-filter="UPDATE" onclick="filterLogs('UPDATE')">Updates</button>
				<button class="filter-btn" data-filter="START" onclick="filterLogs('START')">Starts</button>
				<button class="filter-btn" data-filter="CREATE" onclick="filterLogs('CREATE')">Created</button>
				<button class="filter-btn" data-filter="CLEANUP" onclick="filterLogs('CLEANUP')">Cleanup</button>
			</div>
		<div id="logContainer" style="max-height: 300px; overflow-y: auto; font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 13px; padding-right: 5px;">
	    `, T.SystemEvents)

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
				case "ERROR", "FAIL", "CLEANUP":
					icon = "⚠️"
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

			safeID := strings.ReplaceAll(k, ".", "-")

			fmt.Fprintf(w, `
		<details class="card domain-item" data-domain="%s">
			<summary>🌐 %s <span style="opacity:0.6; font-size:0.9em;">(%s)</span></summary>
			<div class="card-content">
				<div class="domain-card" style="border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 15px; margin-bottom: 10px;">
					<div>
						<div class="ip-display">
							<span class="badge v4">IPv4</span>
							<span id="ip4-%s">%s</span>
							<button class="copy-btn" onclick="copyIP('%s', 'ip4-%s')" title="Copy">📋</button>
						</div>
						<div class="ip-display" style="margin-top: 8px;">
							<span class="badge v6">IPv6</span>
							<span id="ip6-%s">%s</span>
							<button class="copy-btn" onclick="copyIP('%s', 'ip6-%s')" title="Copy">📋</button>
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
				html.EscapeString(k), html.EscapeString(k), html.EscapeString(h.Provider),
				safeID, html.EscapeString(latest.IPv4), html.EscapeString(latest.IPv4), safeID,
				safeID, html.EscapeString(latest.IPv6), html.EscapeString(latest.IPv6), safeID,
				html.EscapeString(latest.Time))

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
	function toggleTheme() {
		const html = document.documentElement;
		const current = html.getAttribute('data-theme') || 'dark';
		const next = current === 'dark' ? 'light' : 'dark';
		html.setAttribute('data-theme', next);
		localStorage.setItem('theme', next);
		showToast('Theme: ' + next);
	}

	const savedTheme = localStorage.getItem('theme') || 'dark';
	document.documentElement.setAttribute('data-theme', savedTheme);

	const proto = location.protocol === 'https:' ? 'wss://' : 'ws://';
	let ws = new WebSocket(proto + location.host + '/ws');
	ws.onmessage = (e) => {
		const data = JSON.parse(e.data);
		if (data.type === 'metrics') {
				updateMetrics(data.data);
		} else if (data.type === 'domain_update') {
    		updateDomainDisplay(data.data);
	 }
	};

	ws.onerror = (err) => {
		console.error('WebSocket error:', err);
		showToast('WebSocket connection lost', 'error');
	};

	
	ws.onclose = () => {
		console.log('WebSocket closed, reconnecting in 5s...');
		setTimeout(() => {
 		   location.reload();
		}, 5000);
	};

	function updateDomainDisplay(data) {
		const safeID = data.domain.replace(/\./g, '-');
		const ip4El = document.getElementById('ip4-' + safeID);
	 const ip6El = document.getElementById('ip6-' + safeID);

	 if (ip4El && data.ipv4) ip4El.textContent = data.ipv4;
	  if (ip6El && data.ipv6) ip6El.textContent = data.ipv6;

		showToast('✓ ' + data.domain + ' updated');
	}
	
	function updateMetrics(data) {
		document.getElementById('lastUpdate').textContent = new Date().toLocaleTimeString();
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
	</script>
	</div>
	</body>
	</html>
	`)
	})

	return mux
}
