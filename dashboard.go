// Package main
package main

import (
	"bufio"
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

func broadcastNotification(message string, level string) {
	if level == "" {
		level = "info"
	}
	broadcastUpdate("notification", map[string]string{
		"message": message,
		"level":   level,
	})
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
	fmt.Fprintf(&pathBuilder, "M %.1f,%.1f", points[0][0], points[0][1])

	for i := 0; i < len(points)-1; i++ {
		p0, p1 := points[i], points[i+1]
		cp1x := p0[0] + (p1[0]-p0[0])/2
		fmt.Fprintf(&pathBuilder, " C %.1f,%.1f %.1f,%.1f %.1f,%.1f",
			cp1x, p0[1], cp1x, p1[1], p1[0], p1[1])
	}
	pathData := pathBuilder.String()

	var labelsBuilder strings.Builder
	now := time.Now().Local()

	offsets := []int{24, 18, 12, 6, 0}

	for _, off := range offsets {
		h := now.Add(-time.Duration(off) * time.Hour).Hour()
		if off == 0 {
			fmt.Fprintf(&labelsBuilder, `<span style="color:#e5e7eb;">%02dh</span>`, h)
		} else {
			fmt.Fprintf(&labelsBuilder, "<span>%02dh</span>", h)
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
			fmt.Fprintf(&labelsBuilder, `<span style="color:#e5e7eb;">%02dh</span>`, h)
		} else {
			fmt.Fprintf(&labelsBuilder, "<span>%02dh</span>", h)
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
// DASHBOARD HTTP HANDLER
// ============================================================================
func buildSettingsModal(c Config) string {
	dnsStr := strings.Join(c.DNSServers, ", ")
	if dnsStr == "" {
		dnsStr = "–"
	}

	dryStr := "Nein"
	if c.DryRun {
		dryStr = "Ja ⚠️"
	}

	return `<div id="settingsOverlay" class="modal-overlay" onclick="closeSettingsOutside(event)">` +
		`<div class="modal">` +
		`<div class="modal-header">` +
		`<h2>⚙️ Einstellungen</h2>` +
		`<button class="modal-close" onclick="closeSettings()">✕</button>` +
		`</div>` +
		`<div class="modal-body">` +

		`<div class="s-section">` +
		`<h3>🔐 Sicherheit</h3>` +
		`<div class="s-row" style="flex-direction:column;align-items:stretch;gap:8px;">` +
		`<span class="s-label">Trigger Token (lokal im Browser)</span>` +
		`<input type="password" id="s-token" class="s-input" placeholder="Token eingeben..." autocomplete="off">` +
		`<button class="s-btn" onclick="saveToken()">💾 Token speichern</button>` +
		`</div></div>` +

		`<div class="s-section">` +
		`<h3>🌐 Domains verwalten</h3>` +
		`<div id="settings-domain-list" style="margin-bottom: 15px; display: flex; flex-direction: column; gap: 8px;">` +
		`` +
		`</div>` +

		`<div style="background: rgba(255,255,255,0.05); padding: 12px; border-radius: 8px; border: 1px dashed var(--border);">` +
		`<h4 style="font-size: 0.75rem; margin-bottom: 8px; opacity: 0.8; text-transform: uppercase;">Neue Domain hinzufügen</h4>` +
		`<input type="text" id="new-domain-fqdn" class="s-input" placeholder="z.B. home.example.com" style="margin-bottom: 8px;">` +
		`<select id="new-domain-provider" class="s-input" style="margin-bottom: 8px;" onchange="toggleProviderFields()">` +
		`<option value="IONOS">IONOS</option>` +
		`<option value="CLOUDFLARE">Cloudflare</option>` +
		`<option value="IPV64">IPv64</option>` +
		`</select>` +

		`<div id="fields-ionos">` +
		`<input type="text" id="new-ionos-prefix" class="s-input" placeholder="API Prefix" style="margin-bottom: 8px;">` +
		`<input type="password" id="new-ionos-secret" class="s-input" placeholder="API Secret">` +
		`</div>` +
		`<div id="fields-cloudflare" style="display:none;">` +
		`<input type="text" id="new-cf-token" class="s-input" placeholder="API Token (empfohlen)" style="margin-bottom: 8px;">` +
		`<div style="font-size: 0.65rem; text-align: center; margin: 4px 0; opacity: 0.4;">— ODER —</div>` +
		`<input type="text" id="new-cf-email" class="s-input" placeholder="Cloudflare Email" style="margin-bottom: 8px;">` +
		`<input type="password" id="new-cf-secret" class="s-input" placeholder="Global API Key">` +
		`</div>` +
		`<div id="fields-ipv64" style="display:none;">` +
		`<input type="password" id="new-ipv64-token" class="s-input" placeholder="IPv64 API Token">` +
		`</div>` +

		`<button class="s-btn" onclick="addDomainToList()" style="margin-top: 12px; background: var(--success); color: white; border: none; width: 100%;">` +
		`➕ Zur Liste hinzufügen` +
		`</button>` +
		`</div>` +
		`</div>` +

		`<div class="s-section">` +
		`<h3>🖥️ System-Status</h3>` +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">IP-Modus</span><span class="s-val">%s</span></div>`, html.EscapeString(c.IPMode)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">Intervall</span><span class="s-val">%ds</span></div>`, c.Interval) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">Health Port</span><span class="s-val">%s</span></div>`, html.EscapeString(c.HealthPort)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">DNS Server</span><span class="s-val">%s</span></div>`, html.EscapeString(dnsStr)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">Dry-Run</span><span class="s-val">%s</span></div>`, dryStr) +
		`</div>` +

		`<div style="margin-top: 20px; padding: 15px; background: rgba(var(--success-rgb), 0.1); border-radius: 8px; border: 1px solid var(--success);">` +
		`<p style="font-size: 0.75rem; margin-bottom: 10px; opacity: 0.8; text-align: center;">Änderungen an den Domains erfordern einen Neustart der Validierung.</p>` +
		`<button class="action-btn" style="width: 100%; margin: 0;" onclick="saveFullConfig()">💾 Alles Speichern & Übernehmen</button>` +
		`</div>` +

		`</div></div></div>`
}

type safeDomainConfig struct {
	FQDN       string `json:"fqdn"`
	Provider   string `json:"provider"`
	APIPrefix  string `json:"api_prefix,omitempty"`
	APISecret  string `json:"api_secret,omitempty"`
	CFToken    string `json:"cf_token,omitempty"`
	CFEmail    string `json:"cf_email,omitempty"`
	CFSecret   string `json:"cf_secret,omitempty"`
	IPv64Token string `json:"ipv64_token,omitempty"`
}

func safeDomainConfigs(dcs []DomainConfig) []safeDomainConfig {
	out := make([]safeDomainConfig, len(dcs))
	for i, dc := range dcs {
		out[i] = safeDomainConfig{
			FQDN:     dc.FQDN,
			Provider: string(dc.Provider),
		}
	}
	return out
}

func createMux() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/favicon.svg", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		theme := q.Get("theme")
		level := q.Get("level")
		blink := q.Get("blink") == "1"

		bg := "#1e293b"
		textColor := "white"
		if theme == "light" {
			bg = "#f8fafc"
			textColor = "#0f172a"
		}

		statusColor := "#22c55e"
		symbol := "✓"
		switch level {
		case "warn":
			statusColor = "#facc15"
			symbol = "!"
		case "err":
			statusColor = "#ef4444"
			symbol = "✕"
		}

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

	mux.HandleFunc("/api/save-config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !validateTriggerToken(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		var payload struct {
			DomainConfigs []safeDomainConfig `json:"domain_configs"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		existing := make(map[string]DomainConfig)
		for _, dc := range cfg.DomainConfigs {
			existing[strings.ToLower(dc.FQDN)] = dc
		}

		newConfigs := make([]DomainConfig, 0, len(payload.DomainConfigs))
		for _, sc := range payload.DomainConfigs {
			fqdn := strings.ToLower(strings.TrimSpace(sc.FQDN))
			if fqdn == "" {
				continue
			}
			if found, ok := existing[fqdn]; ok {
				newConfigs = append(newConfigs, found)
			} else {
				newConfigs = append(newConfigs, DomainConfig{
					FQDN:       fqdn,
					Provider:   ProviderType(strings.ToUpper(sc.Provider)),
					APIPrefix:  sc.APIPrefix,
					APISecret:  sc.APISecret,
					CFToken:    sc.CFToken,
					CFEmail:    sc.CFEmail,
					CFSecret:   sc.CFSecret,
					IPv64Token: sc.IPv64Token,
				})
			}
		}

		cfg.DomainConfigs = newConfigs
		if err := validateDomainConfigs(); err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}

		if err := saveConfigToFile(); err != nil {
			http.Error(w, "Save failed", http.StatusInternalServerError)
			return
		}

		forceNextUpdate.Store(true)

		debugLog("API", getClientIP(r), "✅ Configuration via Dashboard aktualisiert")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "saved"})
	})

	mux.HandleFunc("/api/domain/delete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !validateTriggerToken(r) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid token"})
			return
		}
		domain := strings.TrimSpace(r.URL.Query().Get("domain"))
		if domain == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "domain parameter missing"})
			return
		}
		for _, dc := range cfg.DomainConfigs {
			if strings.EqualFold(dc.FQDN, domain) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "domain still active in config"})
				return
			}
		}
		statusMutex.Lock()
		defer statusMutex.Unlock()
		var fileData map[string]interface{}
		if b, err := os.ReadFile(updatePath); err == nil {
			_ = json.Unmarshal(b, &fileData)
		}
		if fileData == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "no status file found"})
			return
		}
		if _, exists := fileData[domain]; !exists {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "domain not found in status"})
			return
		}
		delete(fileData, domain)
		if b, err := json.MarshalIndent(fileData, "", "  "); err == nil {
			tmp := updatePath + ".tmp"
			if err := os.WriteFile(tmp, b, 0644); err == nil {
				_ = os.Rename(tmp, updatePath)
			}
		}
		debugLog("API", getClientIP(r), fmt.Sprintf("🗑️ Domain aus Status gelöscht: %s", domain))
		broadcastNotification(fmt.Sprintf("🗑️ %s aus Status entfernt", domain), "info")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "domain": domain})
	})

	mux.HandleFunc("/api/trigger", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1024)

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		clientIP := getClientIP(r)

		if !validateTriggerToken(r) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			if err := json.NewEncoder(w).Encode(map[string]string{
				"error": "invalid or missing trigger token",
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			debugLog("API", clientIP, "Trigger blocked: Invalid token")
			return
		}

		if !globalTriggerLimiter.Allow() {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "10")
			w.WriteHeader(http.StatusTooManyRequests)
			if err := json.NewEncoder(w).Encode(map[string]interface{}{
				"error":               "global rate limit exceeded",
				"retry_after_seconds": 10,
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			debugLog("API", clientIP, "Trigger blocked: Global rate limit")
			broadcastNotification("⚠️ Update Rate Limit erreicht - bitte warten", "warning")
			return
		}

		ipLimiter := ipTriggerLimiter.GetLimiter(clientIP)
		if !ipLimiter.Allow() {
			remaining := ipLimiter.Remaining()
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "10")
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
			w.WriteHeader(http.StatusTooManyRequests)
			if err := json.NewEncoder(w).Encode(map[string]interface{}{
				"error":               "IP rate limit exceeded",
				"retry_after_seconds": 10,
				"remaining":           remaining,
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			debugLog("API", clientIP, "Trigger blocked: IP rate limit")
			broadcastNotification("⚠️ Zu viele Update-Requests - bitte 10s warten", "warning")
			return
		}

		if !updateInProgress.CompareAndSwap(false, true) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			if err := json.NewEncoder(w).Encode(map[string]interface{}{
				"error":  "update already in progress",
				"status": "busy",
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			debugLog("API", clientIP, "Trigger blocked: Update already running")
			broadcastNotification("ℹ️ Update läuft bereits", "info")
			return
		}

		go func() {
			defer updateInProgress.Store(false)
			debugLog("API", clientIP, "Manual update triggered (force cache refresh)")
			broadcastNotification("🔄 Manuelles Update gestartet (Cache wird neu geladen)", "info")
			forceNextUpdate.Store(true)
			runUpdate(false)
		}()

		remaining := ipLimiter.Remaining()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
		w.WriteHeader(http.StatusAccepted)
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"status":               "triggered",
			"message":              "update started",
			"rate_limit_remaining": remaining,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	mux.HandleFunc("/api/trigger/status", func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)
		ipLimiter := ipTriggerLimiter.GetLimiter(clientIP)

		if !ipLimiter.Allow() {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"ip":                 clientIP,
			"remaining_requests": ipLimiter.Remaining(),
			"update_in_progress": updateInProgress.Load(),
			"global_limit":       globalTriggerLimiter.Remaining(),
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	mux.HandleFunc("/api/export", func(w http.ResponseWriter, _ *http.Request) {
		statusMutex.Lock()
		defer statusMutex.Unlock()

		exportData := map[string]interface{}{
			"timestamp": time.Now().Local().Format(time.RFC3339),
			"metrics":   apiMetrics.GetStats(),
		}

		if b, err := os.ReadFile(updatePath); err == nil {
			var domains map[string]DomainHistory
			if err := json.Unmarshal(b, &domains); err == nil {
				exportData["domains"] = domains
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=dyndns-export.json")

		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(exportData); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	mux.HandleFunc("/api/metrics/reset", handleMetricsReset)

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		isHealthy := lastOk.Load()
		hasRun := schedulerRanOnce.Load()
		stats := apiMetrics.GetStats()

		var total int64
		switch v := stats["total_requests"].(type) {
		case int64:
			total = v
		case int:
			total = int64(v)
		case float64:
			total = int64(v)
		}

		healthReason := ""
		degradedMode := false

		if !hasRun {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "starting",
				"reason": "waiting for first scheduler run",
			})
			return
		}

		if total > 10 {
			if successRateStr, ok := stats["success_rate"].(string); ok {
				var rate float64
				if _, err := fmt.Sscanf(successRateStr, "%f%%", &rate); err == nil {
					if rate < 20.0 {
						isHealthy = false
						healthReason = "critical: success rate below 20%"
					} else if rate < 50.0 {
						degradedMode = true
						healthReason = "degraded: success rate below 50%, operating on cache"
					}
				}
			}
		}

		if !isHealthy && healthReason == "" {
			healthReason = "last scheduler run failed (IP fetch, zone load or record update error)"
		}

		if degradedMode && isHealthy {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if err := json.NewEncoder(w).Encode(map[string]interface{}{
				"status":      "degraded",
				"reason":      healthReason,
				"api_metrics": stats,
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

		if !isHealthy {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			if err := json.NewEncoder(w).Encode(map[string]interface{}{
				"status":      "unhealthy",
				"reason":      healthReason,
				"api_metrics": stats,
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

		if r.URL.Query().Get("detailed") == "true" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if err := json.NewEncoder(w).Encode(map[string]interface{}{
				"status":      "healthy",
				"api_metrics": stats,
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("OK")); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		serveCachedJSON(w, r, metricsCache)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
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
		var logTimeRange string

		type logCachePayload struct {
			Logs         []LogEntry `json:"logs"`
			LogTimeRange string     `json:"log_time_range"`
		}

		loadFromDiskCache := func() bool {
			logStat, err := os.Stat(logPath)
			if err != nil {
				return false
			}
			cacheStat, err := os.Stat(logCachePath)
			if err != nil {
				return false
			}
			if logStat.ModTime().After(cacheStat.ModTime()) {
				return false
			}
			b, err := os.ReadFile(logCachePath)
			if err != nil {
				return false
			}
			var payload logCachePayload
			if err := json.Unmarshal(b, &payload); err != nil {
				return false
			}
			logs = payload.Logs
			logTimeRange = payload.LogTimeRange
			return true
		}

		if !loadFromDiskCache() {
			if f, err := os.Open(logPath); err == nil {
				limit := cfg.MaxLogLines
				ring := make([]string, limit)
				head, count := 0, 0

				scanner := bufio.NewScanner(f)
				scanner.Buffer(make([]byte, 64*1024), 64*1024)
				for scanner.Scan() {
					if line := strings.TrimSpace(scanner.Text()); line != "" {
						ring[head%limit] = line
						head++
						count++
					}
				}
				_ = f.Close()

				formatTs := func(ts string) string {
					t, err := time.Parse("2006-01-02T15:04:05", ts)
					if err != nil {
						return ts
					}
					return t.Format("02.01.2006 15:04:05")
				}

				if count > limit {
					count = limit
				}
				for i := 1; i <= count; i++ {
					line := ring[(head-i+limit)%limit]
					var e LogEntry
					if json.Unmarshal([]byte(line), &e) == nil {
						e.Timestamp = formatTs(e.Timestamp)
						logs = append(logs, e)
					}
				}
				if len(logs) > 0 {
					latest := logs[0].Timestamp
					oldest := logs[len(logs)-1].Timestamp
					logTimeRange = fmt.Sprintf("%s — %s", oldest, latest)
				}
			}

			if payload, err := json.Marshal(logCachePayload{Logs: logs, LogTimeRange: logTimeRange}); err == nil {
				_ = os.WriteFile(logCachePath, payload, 0644)
			}
		}
		jsConfigSafe, _ := json.Marshal(safeDomainConfigs(cfg.DomainConfigs))
		if jsConfigSafe == nil {
			jsConfigSafe = []byte("[]")
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, "<!DOCTYPE html><html><head>\n"+
			"<meta charset=\"utf-8\">\n"+
			"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"+
			"<title>%s</title>\n"+
			"<link id=\"favicon\" rel=\"icon\" type=\"image/svg+xml\" href=\"/favicon.svg?theme=dark\">\n"+
			"<script>const initialConfig = %s;</script>\n",
			html.EscapeString(T.DashTitle),
			string(jsConfigSafe),
		)
		_, _ = fmt.Fprint(w, `<style>
		* {box-sizing: border-box; margin: 0; padding: 0;}


		:root {
			--bg: #0f172a; --card: #1e293b; --text: #f8fafc; --border: #334155;
			--success: #4ade80; --error: #f87171; --warning: #facc15;
			--btn-bg: #1e3a5f; --btn-text: #93c5fd; --btn-border: #3b82f6;
			--btn-hover: #1d4ed8; --btn-shadow: rgba(59,130,246,0.4);
		}
		[data-theme="light"] {
			--bg: #f8fafc; --card: #ffffff; --text: #0f172a; --border: #e2e8f0;
			--btn-bg: #eff6ff; --btn-text: #1d4ed8; --btn-border: #93c5fd;
			--btn-hover: #dbeafe; --btn-shadow: rgba(59,130,246,0.25);
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
			background: var(--btn-bg);
			color: var(--btn-text);
			border: 1px solid var(--btn-border);
			padding: 10px 20px;
			border-radius: 8px;
			cursor: pointer;
			font-weight: 600;
			transition: all 0.2s;
		}

		.action-btn:hover {
			background: var(--btn-hover);
			transform: translateY(-2px);
			box-shadow: 0 4px 12px var(--btn-shadow);
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

		.domain-status-dot {
			display: inline-block;
			width: 10px;
			height: 10px;
			border-radius: 50%;
			margin-right: 6px;
			flex-shrink: 0;
		}
		.dot-ok   { background: #4ade80; box-shadow: 0 0 6px #4ade8099; }
		.dot-warn { background: #facc15; box-shadow: 0 0 6px #facc1599; }
		.dot-idle { background: #475569; }

		@keyframes dot-pulse {
			0%, 100% { opacity: 1; transform: scale(1); }
			50%       { opacity: 0.5; transform: scale(0.8); }
		}
		.dot-recent { animation: dot-pulse 1.4s ease-in-out infinite; }

		.changed-badge {
			display: inline-block;
			font-size: 0.65rem;
			padding: 1px 7px;
			border-radius: 999px;
			background: rgba(74,222,128,0.15);
			border: 1px solid rgba(74,222,128,0.4);
			color: #4ade80;
			margin-left: 8px;
			vertical-align: middle;
			font-weight: 600;
			letter-spacing: 0.02em;
		}

		.menu-btn {
			background: var(--border); border: none;
			padding: 8px 13px; border-radius: 8px;
			cursor: pointer; color: var(--text);
			font-size: 1.2rem; line-height: 1;
			transition: background 0.15s;
		}
		.menu-btn:hover { background: var(--btn-border); color: #fff; }

		.modal-overlay {
			position: fixed; inset: 0;
			background: rgba(0,0,0,0.6);
			z-index: 2000;
			display: flex; align-items: center; justify-content: center;
			opacity: 0; pointer-events: none;
			transition: opacity 0.2s;
		}
		.modal-overlay.open { opacity: 1; pointer-events: all; }
		.modal {
			background: var(--card);
			border: 1px solid var(--border);
			border-radius: 14px;
			width: min(560px, 96vw);
			max-height: 88vh;
			overflow-y: auto;
			box-shadow: 0 24px 64px rgba(0,0,0,0.5);
			transform: translateY(-16px);
			transition: transform 0.2s;
		}
		.modal-overlay.open .modal { transform: translateY(0); }
		.modal-header {
			display: flex; justify-content: space-between; align-items: center;
			padding: 16px 20px 14px;
			border-bottom: 1px solid var(--border);
			position: sticky; top: 0; background: var(--card); z-index: 1;
			border-radius: 14px 14px 0 0;
		}
		.modal-header h2 { font-size: 1rem; font-weight: 700; }
		.modal-close {
			background: none; border: none; cursor: pointer;
			color: var(--text); opacity: 0.45; font-size: 1.3rem;
			transition: opacity 0.15s; padding: 2px 6px;
		}
		.modal-close:hover { opacity: 1; }
		.modal-body { padding: 18px 20px 22px; }
		.s-section { margin-bottom: 20px; }
		.s-section h3 {
			font-size: 0.68rem; font-weight: 700; letter-spacing: 0.08em;
			text-transform: uppercase; color: #64748b; margin-bottom: 10px;
		}
		.s-row {
			display: flex; justify-content: space-between; align-items: center;
			padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.05);
			font-size: 0.85rem; gap: 12px;
		}
		.s-row:last-child { border-bottom: none; }
		.s-label { opacity: 0.65; white-space: nowrap; }
		.s-val { font-family: monospace; color: var(--btn-text); text-align: right; word-break: break-all; }
		.s-input {
			width: 100%; padding: 8px 11px;
			background: rgba(255,255,255,0.05);
			border: 1px solid var(--border); border-radius: 7px;
			color: var(--text); font-size: 0.875rem;
		}
		.s-input:focus { outline: none; border-color: var(--btn-border); }
		.s-btn {
			width: 100%; padding: 9px;
			background: var(--btn-bg); color: var(--btn-text);
			border: 1px solid var(--btn-border); border-radius: 7px;
			cursor: pointer; font-weight: 600; font-size: 0.85rem;
			transition: background 0.2s; margin-top: 6px;
		}
		.s-btn:hover { background: var(--btn-hover); }
		.domain-pill {
			display: flex; align-items: center; justify-content: space-between;
			padding: 8px 10px; border-radius: 8px;
			background: rgba(255,255,255,0.03);
			border: 1px solid var(--border); margin-bottom: 6px;
			font-size: 0.85rem;
		}
		.domain-pill code { font-size: 0.82rem; }
		.provider-badge {
			font-size: 0.65rem; padding: 1px 7px; border-radius: 999px;
			font-weight: 700; white-space: nowrap;
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
				<button class="menu-btn" onclick="openSettings()" title="Einstellungen">⋮</button>
			</div>
		</div>
		
		<div class="status-banner `+statusClass+`">
			<span>`+statusText+`</span>
			<span>
              `+T.LastUpdate+`: <span id="lastUpdate">`+time.Now().Local().Format("15:04:05")+`</span>
              <span style="opacity:0.6; margin: 0 8px;">|</span>
              🕒 <span id="clock">--:--:--</span>
            </span>
		</div>
		
		<div id="toast" class="toast"></div>
	`)

		_, _ = fmt.Fprintf(w, "%s", buildSettingsModal(cfg))

		latestMetricsMu.RLock()
		stats := latestMetrics
		latestMetricsMu.RUnlock()
		if stats == nil {
			stats = apiMetrics.GetStats()
		}
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

		hasIPv64 := false
		for _, dc := range cfg.DomainConfigs {
			if dc.Provider == ProviderIPv64 {
				hasIPv64 = true
				break
			}
		}
		nicHTML := ""
		if hasIPv64 {
			nicHTML = `<div style="display:flex; justify-content:space-between; padding:4px 8px; background:rgba(251,191,36,0.08); border-radius:5px; grid-column:1/-1;">` +
				`<span style="font-size:0.7rem; color:#94a3b8; font-weight:600;">NIC <span style="font-weight:400; opacity:0.6;">(IPv64 Updates)</span></span>` +
				`<span id="mDailyNIC" style="font-size:0.95rem; font-weight:700; color:#fbbf24; font-family:monospace;">` +
				fmt.Sprintf("%v", stats["daily_nic"]) +
				`</span></div>`
		}

		_, _ = fmt.Fprintf(w, `
		<details class="card">
			<summary>⚙️ `+T.ConfigHeading+`</summary>
			<div class="card-content">
				<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px;">
					<div><strong>`+T.MaxLogLines+`:</strong> %d</div>
					<div><strong>`+T.MaxAPIRetries+`:</strong> %d</div>
					<div><strong>`+T.MaxConcurrent+`:</strong> %d</div>
					<div><strong>`+T.Interval+`:</strong> %ds</div>
				</div>
			</div>
		</details>
		`,
			cfg.MaxLogLines,
			cfg.MaxAPIRetries,
			cfg.MaxConcurrent,
			cfg.Interval,
		)

		_, _ = fmt.Fprintf(w, `
		<details class="card" open id="metrics-card">
			<summary style="display:flex; justify-content:space-between; align-items:center;">📊 %s<button class="action-btn" style="background:var(--error); font-size:0.7rem; padding:3px 10px; margin-left:auto;" onclick="event.preventDefault(); resetMetrics()">🗑️ Reset</button></summary>
			<div class="card-content">
				<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-top: 10px;">
					<div><strong>`+T.TotalRequests+`:</strong> <span id="mTotal">%v</span></div>
					<div><strong>`+T.SuccessRate+`:</strong> <span id="mSuccess" style="color:var(--success)">%v</span></div>
					<div><strong>`+T.AvgLatency+`:</strong> <span id="mLatency">%v</span></div>
					<div title="Client Errors (inkl. Netzwerk) / Server Errors"><strong>`+T.Errors+`:</strong> <span id="mErrors">%v / %v</span></div>
				</div>
				<div style="margin-top: 14px; padding: 12px 14px; background: rgba(139,92,246,0.08); border: 1px solid rgba(139,92,246,0.2); border-radius: 8px;">
					<div style="font-size: 0.68rem; color: #94a3b8; letter-spacing: 0.06em; margin-bottom: 8px; font-weight: 600; text-transform: uppercase;">Latenz Percentile</div>
					<div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; text-align: center;">
						<div style="padding: 8px; background: rgba(74,222,128,0.08); border-radius: 6px; border: 1px solid rgba(74,222,128,0.2);">
							<div style="font-size: 0.65rem; color: #94a3b8; margin-bottom: 3px; letter-spacing: 0.05em;">P50</div>
							<div id="mP50" style="font-size: 1.05rem; font-weight: 700; color: #4ade80; font-family: monospace;">%v</div>
						</div>
						<div style="padding: 8px; background: rgba(250,204,21,0.08); border-radius: 6px; border: 1px solid rgba(250,204,21,0.2);">
							<div style="font-size: 0.65rem; color: #94a3b8; margin-bottom: 3px; letter-spacing: 0.05em;">P85</div>
							<div id="mP85" style="font-size: 1.05rem; font-weight: 700; color: #facc15; font-family: monospace;">%v</div>
						</div>
						<div style="padding: 8px; background: rgba(248,113,113,0.08); border-radius: 6px; border: 1px solid rgba(248,113,113,0.2);">
							<div style="font-size: 0.65rem; color: #94a3b8; margin-bottom: 3px; letter-spacing: 0.05em;">P99</div>
							<div id="mP99" style="font-size: 1.05rem; font-weight: 700; color: #f87171; font-family: monospace;">%v</div>
						</div>
					</div>
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
				<div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-top:14px;">
					<div style="padding:12px 14px; background:rgba(56,189,248,0.08); border:1px solid rgba(56,189,248,0.2); border-radius:8px;">
						<div style="font-size:0.68rem; color:#94a3b8; letter-spacing:0.06em; margin-bottom:8px; font-weight:600; text-transform:uppercase;">Heute &middot; HTTP-Methoden</div>
						<div style="display:grid; grid-template-columns:1fr 1fr; gap:6px;">
							<div style="display:flex; justify-content:space-between; padding:4px 8px; background:rgba(74,222,128,0.08); border-radius:5px;">
								<span style="font-size:0.7rem; color:#94a3b8; font-weight:600;">GET</span>
								<span id="mDailyGET" style="font-size:0.95rem; font-weight:700; color:#4ade80; font-family:monospace;">%v</span>
							</div>
							<div style="display:flex; justify-content:space-between; padding:4px 8px; background:rgba(96,165,250,0.08); border-radius:5px;">
								<span style="font-size:0.7rem; color:#94a3b8; font-weight:600;">POST</span>
								<span id="mDailyPOST" style="font-size:0.95rem; font-weight:700; color:#60a5fa; font-family:monospace;">%v</span>
							</div>
							<div style="display:flex; justify-content:space-between; padding:4px 8px; background:rgba(250,204,21,0.08); border-radius:5px;">
								<span style="font-size:0.7rem; color:#94a3b8; font-weight:600;">PUT</span>
								<span id="mDailyPUT" style="font-size:0.95rem; font-weight:700; color:#facc15; font-family:monospace;">%v</span>
							</div>
							<div style="display:flex; justify-content:space-between; padding:4px 8px; background:rgba(248,113,113,0.08); border-radius:5px;">
								<span style="font-size:0.7rem; color:#94a3b8; font-weight:600;">DEL</span>
								<span id="mDailyDELETE" style="font-size:0.95rem; font-weight:700; color:#f87171; font-family:monospace;">%v</span>
							</div>
							%s
						</div>
					</div>
					<div style="padding:12px 14px; background:rgba(167,139,250,0.08); border:1px solid rgba(167,139,250,0.2); border-radius:8px;">
						<div style="font-size:0.68rem; color:#94a3b8; letter-spacing:0.06em; margin-bottom:8px; font-weight:600; text-transform:uppercase;">IP-Check Latenz</div>
						<div style="text-align:center; padding:4px 0;">
							<div id="mIPLatency" style="font-size:1.4rem; font-weight:700; color:#a78bfa; font-family:monospace;">%v</div>
							<div style="font-size:0.65rem; color:#64748b; margin-top:4px;">&#216; aus <span id="mIPCount">%v</span> Checks</div>
							<div style="font-size:0.65rem; color:#64748b; margin-top:2px;">Letzter: <span id="mLastIPCheck">%v</span></div>
						</div>
					</div>
				</div>
            </div>
		</details>
		
		%s
		
		%s
		`,
			T.APIPerformance,
			stats["total_requests"],
			stats["success_rate"],
			stats["avg_latency"],
			stats["client_errors"],
			stats["server_errors"],
			stats["p50_latency"],
			stats["p85_latency"],
			stats["p99_latency"],
			stats["usage_count"],
			stats["hourly_limit"],
			stats["usage_percent"],
			stats["usage_color"],
			stats["daily_get"],
			stats["daily_post"],
			stats["daily_put"],
			stats["daily_delete"],
			nicHTML,
			stats["ip_latency_avg"],
			stats["ip_latency_count"],
			stats["last_ip_check"],
			chartSVG,
			latencySVG)

		if len(logs) > 0 {
			_, _ = fmt.Fprintf(w, `
                     <details class="card" id="logs-card">
                          <summary>
                          🧾 %s 
                      <span style="opacity:0.6; font-size:0.9em; margin-left: 10px;">
                          (%d entries) 
                     <span style="margin-left: 10px; border-left: 1px solid #ccc; padding-left: 10px;">
                     🕒 %s
                     </span>
                     </span>
                       </summary>
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
                               <button class="filter-btn" data-filter="SKIP" onclick="filterLogs('SKIP')">Skip</button>
                           </div>
                       <div id="logContainer" style="max-height: 300px; overflow-y: auto; font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 13px; padding-right: 5px;">
                       `, T.SystemEvents, len(logs), logTimeRange)

			for _, e := range logs {
				displayTime := e.Timestamp
				if t, err := time.Parse(time.RFC3339, e.Timestamp); err == nil {
					displayTime = t.Local().Format("02.01.2006 15:04")
				}

				actionUpper := strings.ToUpper(e.Action)

				icon := "🔹"
				switch actionUpper {
				case "START":
					icon = "🚀"
				case "STOP":
					icon = "🛑"
				case "UPDATE":
					icon = "🔄"
				case "CREATE":
					icon = "🆕"
				case "CURRENT":
					icon = "✓"
				case "RETRY":
					icon = "🔁"
				case "ERROR", "FAIL":
					icon = "❌"
				case "CONFIG":
					icon = "⚙️"
				case "ZONE":
					icon = "🌐"
				case "DRY-RUN":
					icon = "🔍"
				case "CLEANUP":
					icon = "🧹"
				case "SKIP":
					icon = "⏭️"
				case "API":
					icon = "🔌"
				case "SERVER":
					icon = "🖥️"
				case "SUCCESS", "ADDED":
					icon = "✅"
				}

				_, _ = fmt.Fprintf(w, `
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

			_, _ = fmt.Fprint(w, `
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

		_, _ = fmt.Fprint(w, `<input type="text" class="search-box" id="domainSearch" placeholder="🔍 Domain suchen..." oninput="filterDomains(this.value)"><div id="domainContainer">`)

		configuredDomains := make(map[string]struct{})
		for _, dc := range cfg.DomainConfigs {
			configuredDomains[strings.ToLower(strings.TrimSuffix(dc.FQDN, "."))] = struct{}{}
		}

		var newestChange time.Time
		for _, k := range keys {
			var dh DomainHistory
			if b, err := json.Marshal(data[k]); err == nil {
				_ = json.Unmarshal(b, &dh)
			}
			if dh.LastChanged != "" {
				if t, err := time.Parse("02.01.2006 15:04:05", dh.LastChanged); err == nil {
					if t.After(newestChange) {
						newestChange = t
					}
				}
			}
		}

		for _, k := range keys {
			var h DomainHistory
			b, _ := json.Marshal(data[k])
			_ = json.Unmarshal(b, &h)

			latest := IPEntry{}
			if len(h.IPs) > 0 {
				latest = h.IPs[len(h.IPs)-1]
			}

			safeID := sanitizeIDWithHash(k)

			_, isActive := configuredDomains[strings.ToLower(strings.TrimSuffix(k, "."))]
			isOrphan := !isActive

			dotClass := "domain-status-dot dot-idle"
			dotTitle := "Noch kein Update gesehen"
			changedBadge := `<span id="badge-` + safeID + `" class="changed-badge" style="display:none;">🔄 gerade geändert</span>`
			if h.LastChanged != "" {
				if t, err := time.Parse("02.01.2006 15:04:05", h.LastChanged); err == nil {
					switch {
					case time.Since(t) < 15*time.Minute:
						dotClass = "domain-status-dot dot-ok dot-recent"
						dotTitle = "Gerade geändert: " + h.LastChanged
						changedBadge = `<span id="badge-` + safeID + `" class="changed-badge">🔄 gerade geändert</span>`
					case !newestChange.IsZero() && t.Before(newestChange.Add(-time.Minute)):
						dotClass = "domain-status-dot dot-warn"
						dotTitle = "Letzte Änderung: " + h.LastChanged + " · Andere Domain wurde seitdem aktualisiert"
					default:
						dotClass = "domain-status-dot dot-ok"
						dotTitle = "Aktiv · Letzte Änderung: " + h.LastChanged
					}
				}
			}

			orphanStyle := ""
			orphanLabel := ""
			deleteBtn := ""
			if isOrphan {
				orphanStyle = ` style="border-color: rgba(248,113,113,0.5);"`
				orphanLabel = `<span style="font-size:0.65rem; padding:1px 7px; border-radius:999px; background:rgba(248,113,113,0.15); border:1px solid rgba(248,113,113,0.4); color:#f87171; margin-left:8px; font-weight:600;">nicht mehr konfiguriert</span>`
				deleteBtn = `<button class="action-btn" style="background:rgba(248,113,113,0.15); color:#f87171; border-color:rgba(248,113,113,0.5); font-size:0.7rem; padding:3px 10px; margin-left:auto;" onclick="event.preventDefault(); event.stopPropagation(); deleteDomain('` + html.EscapeString(k) + `', this)">🗑️ Entfernen</button>`
			}

			_, _ = fmt.Fprintf(w, `
		<details class="card domain-item" data-domain="%s"%s>
			<summary style="display:flex; align-items:center;">`+
				`<span id="dot-`+safeID+`" class="%s" title="%s"></span>`+
				`🌐 %s <span style="opacity:0.6; font-size:0.9em; margin-left:5px;">(%s)</span>%s%s%s`+
				`</summary>
			<div class="card-content">
				<div class="domain-card" style="border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 15px; margin-bottom: 10px;">
					<div>
						<div class="ip-display">
							<span class="badge v4">IPv4</span>
							<span id="ip4-%s">%s</span>
							<button class="copy-btn" onclick="copyIP('%s')" title="Copy">📋</button>
						</div>
						<div class="ip-display" style="margin-top: 8px;">
							<span class="badge v6">IPv6</span>
							<span id="ip6-%s">%s</span>
							<button class="copy-btn" onclick="copyIP('%s')" title="Copy">📋</button>
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
				orphanStyle,
				dotClass,
				dotTitle,
				html.EscapeString(k),
				html.EscapeString(h.Provider),
				changedBadge,
				orphanLabel,
				deleteBtn,
				safeID,
				html.EscapeString(latest.IPv4),
				html.EscapeString(latest.IPv4),
				safeID,
				html.EscapeString(latest.IPv6),
				html.EscapeString(latest.IPv6),
				html.EscapeString(latest.Time),
			)

			for i := len(h.IPs) - 2; i >= 0; i-- {
				e := h.IPs[i]
				_, _ = fmt.Fprintf(w, `
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
				_, _ = fmt.Fprint(w, `<tr><td colspan="2" style="text-align:center; opacity:0.5; padding: 10px;">Keine weiteren Einträge</td></tr>`)
			}

			_, _ = fmt.Fprint(w, `
						</tbody>
					</table>
				</div>
			</div>
		</details>`)
		}
		_, _ = fmt.Fprint(w, `</div>`)

		_, _ = fmt.Fprint(w, `
	<script>
	let blinkTimer = null;
	let currentLevel = 'ok';
	let ws = null;
	let reconnectTimer = null;
	let reconnectDelay = 1000;
	const reconnectDelayMax = 10000;

   let tempDomainConfigs = [];

   if (typeof initialConfig !== 'undefined' && initialConfig !== null) {
       tempDomainConfigs = Array.isArray(initialConfig) ? [...initialConfig] : [];
   }

	document.addEventListener('DOMContentLoaded', () => {
		const savedTheme = localStorage.getItem('theme') || 'dark';
		document.documentElement.setAttribute('data-theme', savedTheme);

		renderSettingsDomainList();

		const initialMetrics = {
			avg_latency: (document.getElementById('mLatency')?.textContent || '').trim(),
			success_rate: (document.getElementById('mSuccess')?.textContent || '').trim(),
			total_requests: (document.getElementById('mTotal')?.textContent || '0').trim(),
		};
		currentLevel = calcLevelFromMetrics(initialMetrics);
		applyFavicon(savedTheme, currentLevel, false);
		setBlinking(savedTheme, currentLevel);

		document.querySelectorAll('details.card').forEach(details => {
			const id = details.id;
			const saved = id ? localStorage.getItem('collapse-' + id) : null;
			if (saved === 'open') details.setAttribute('open', '');
			else if (saved === 'closed') details.removeAttribute('open');
			
			if (id) {
				details.addEventListener('toggle', () => {
					localStorage.setItem('collapse-' + id, details.open ? 'open' : 'closed');
				});
			}
		});

		startClock();
		connectWS();
		document.addEventListener('keydown', e => { if (e.key === 'Escape') closeSettings(); });
	});

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
		if (blinkTimer) { clearInterval(blinkTimer); blinkTimer = null; }
		if (level !== 'err') return;
		let on = false;
		blinkTimer = setInterval(() => {
			on = !on;
			applyFavicon(theme, 'err', on);
		}, 700);
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

	function parseDurationToMs(s) {
		s = (s || '').trim().toLowerCase().replace('µs', 'us');
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
		const successAge = toNum(m.last_success_age_secs, -1);
		const errorAge   = toNum(m.last_error_age_secs,   -1);
		const recovered = successAge >= 0 && errorAge >= 0 && successAge < errorAge;
		const hasActiveError = errorAge >= 0 && !recovered;

		if (hasActiveError) return errorAge > 600 ? 'warn' : 'err';
		if (total >= 5 && successRate <= 0) return 'err';
		if (total >= 10 && successRate < 50) return 'err';

		const ms = parseDurationToMs(m.avg_latency);
		if (Number.isFinite(ms)) {
			if (ms >= 1000) return 'err';
			if (ms >= 300) return 'warn';
		}
		if (total >= 10 && successRate < 90) return 'warn';
		return 'ok';
	}

	function updateMetrics(m) {
		const setTxt = (id, val) => { const el = document.getElementById(id); if(el) el.textContent = val; };
		setTxt('lastUpdate', new Date().toLocaleTimeString());
		setTxt('mTotal', m.total_requests);
		setTxt('mSuccess', m.success_rate);
		setTxt('mLatency', m.avg_latency);
		setTxt('mErrors', (m.client_errors || 0) + " / " + (m.server_errors || 0));
		setTxt('mP50', m.p50_latency);
		setTxt('mP85', m.p85_latency);
		setTxt('mP99', m.p99_latency);
		
		const bar = document.getElementById('mUsageBar');
		if (bar) {
			const p = (m.usage_percent != null) ? Number(m.usage_percent) : 0;
			bar.style.width = String(isFinite(p) ? p : 0) + "%";
			if (m.usage_color) bar.style.background = m.usage_color;
		}

		setTxt('mDailyGET', m.daily_get);
		setTxt('mDailyPOST', m.daily_post);
		setTxt('mDailyPUT', m.daily_put);
		setTxt('mDailyDELETE', m.daily_delete);
		setTxt('mDailyNIC', m.daily_nic);
		setTxt('mIPLatency', m.ip_latency_avg);
		setTxt('mIPCount', m.ip_latency_count);
		setTxt('mLastIPCheck', m.last_ip_check);
	}

	function connectWS() {
		const proto = location.protocol === 'https:' ? 'wss://' : 'ws://';
		ws = new WebSocket(proto + location.host + '/ws');
		ws.onmessage = (e) => {
			const msg = JSON.parse(e.data);
			if (msg.type === 'initial' || msg.type === 'metrics') {
				updateMetrics(msg.data);
				const theme = localStorage.getItem('theme') || 'dark';
				currentLevel = calcLevelFromMetrics(msg.data);
				applyFavicon(theme, currentLevel, false);
				setBlinking(theme, currentLevel);
			} else if (msg.type === 'domain_update') {
				updateDomainDisplay(msg.data);
			} else if (msg.type === 'notification') {
				showToast(msg.data.message, msg.data.level || 'info');
			}
		};
		ws.onclose = () => scheduleReconnect();
		ws.onopen = () => { reconnectDelay = 1000; if(reconnectTimer) clearTimeout(reconnectTimer); };
	}

	function scheduleReconnect() {
		if (reconnectTimer) return;
		reconnectTimer = setTimeout(() => { reconnectTimer = null; connectWS(); }, reconnectDelay);
		reconnectDelay = Math.min(reconnectDelay * 2, reconnectDelayMax);
	}

	function showToast(message, type = 'success') {
		const toast = document.getElementById('toast');
		if(!toast) return;
		toast.textContent = message;
		let borderColor = 'var(--success)';
		let duration = 3000;
		if(type === 'error') { borderColor = 'var(--error)'; duration = 5000; }
		else if(type === 'warning') { borderColor = '#facc15'; duration = 4000; }
		else if(type === 'info') { borderColor = '#3b82f6'; duration = 2500; }
		toast.style.borderLeft = '4px solid ' + borderColor;
		toast.classList.add('show');
		setTimeout(() => toast.classList.remove('show'), duration);
	}

	function copyIP(text) {
		if (!text || text === 'N/A' || text === '-') {
			showToast('❌ Keine IP zum Kopieren', 'error');
			return;
		}
		const fallback = (t) => {
			const ta = document.createElement("textarea"); ta.value = t;
			ta.style.position = "fixed"; ta.style.left = "-9999px";
			document.body.appendChild(ta); ta.focus(); ta.select();
			try { document.execCommand('copy'); showToast('✓ Kopiert: ' + t); } 
			catch (err) { showToast('❌ Fehler', 'error'); }
			document.body.removeChild(ta);
		};
		if (navigator.clipboard && window.isSecureContext) {
			navigator.clipboard.writeText(text).then(() => showToast('✓ Kopiert: ' + text)).catch(() => fallback(text));
		} else fallback(text);
	}

	function filterLogs(filter) {
		document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.toggle('active', btn.dataset.filter === filter));
		document.querySelectorAll('.log-entry').forEach(entry => {
			const action = (entry.dataset.action || '').toUpperCase();
			const level = (entry.dataset.level || '').toUpperCase();
			if (filter === 'all') { entry.style.display = ''; return; }
			const shouldShow = (filter.toUpperCase() === 'ERR' && level === 'ERR') || 
							   (filter.toUpperCase() === 'WARN' && level === 'WARN') || 
							   (action === filter.toUpperCase());
			entry.style.display = shouldShow ? '' : 'none';
		});
	}

	function triggerUpdate() {
		const token = localStorage.getItem('triggerToken') || '';
		showToast('⏳ Update wird gestartet...', 'info');
		fetch('/api/trigger', { method: 'POST', headers: token ? {'X-Trigger-Token': token} : {} })
		.then(r => r.json().then(j => {
			if (j.error) showToast('⚠️ ' + j.error, 'warning');
			else showToast('✅ Update gestartet', 'success');
		})).catch(() => showToast('❌ Verbindungsfehler', 'error'));
	}

	function exportData() {
		fetch('/api/export').then(r => r.blob()).then(blob => {
			const url = URL.createObjectURL(blob);
			const a = document.createElement('a');
			a.href = url; a.download = 'dyndns-export-' + new Date().toISOString().split('T')[0] + '.json';
			a.click(); showToast('✓ Export gestartet');
		}).catch(() => showToast('Export fehlgeschlagen', 'error'));
	}

	function sanitizeBase(s) {
		s = (s || '').toLowerCase();
		let out = '';
		for (const ch of s) {
			const code = ch.charCodeAt(0);
			if ((code >= 97 && code <= 122) || (code >= 48 && code <= 57) || ch === '-' || ch === '_') out += ch;
			else if (ch === '.') out += '-';
		}
		return out || 'x';
	}

	async function shortHash8(str) {
		if (!(window.crypto && crypto.subtle)) return '00000000';
		const data = new TextEncoder().encode(str || '');
		const buf = await crypto.subtle.digest('SHA-1', data);
		return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 8);
	}

	async function makeSafeID(domain) {
		const base = sanitizeBase(domain);
		const sfx = await shortHash8(domain);
		return (base === 'x' ? 'd-' : base + '-') + sfx;
	}

	async function updateDomainDisplay(data) {
		const safeID = await makeSafeID(data.domain);
		const ip4El = document.getElementById('ip4-' + safeID);
		const ip6El = document.getElementById('ip6-' + safeID);
		if (ip4El && data.ipv4) ip4El.textContent = data.ipv4;
		if (ip6El && data.ipv6) ip6El.textContent = data.ipv6;
		const dotEl = document.getElementById('dot-' + safeID);
		if (dotEl) {
			dotEl.className = 'domain-status-dot dot-ok dot-recent';
			setTimeout(() => { if(dotEl) dotEl.classList.remove('dot-recent'); }, 3600000);
		}
		showToast('✓ ' + data.domain + ' updated');
	}

	function openSettings() {
		document.getElementById('settingsOverlay').classList.add('open');
		const saved = localStorage.getItem('triggerToken') || '';
		const inp = document.getElementById('s-token');
		if (inp) inp.placeholder = saved ? '●●●●●● (gespeichert)' : 'Token eingeben...';
		renderSettingsDomainList();
	}

	function closeSettings() { 
		const el = document.getElementById('settingsOverlay');
		if(el) el.classList.remove('open'); 
	}
	
	function closeSettingsOutside(e) { if (e.target.id === 'settingsOverlay') closeSettings(); }

	function saveToken() {
		const val = (document.getElementById('s-token').value || '').trim();
		if (val) {
			localStorage.setItem('triggerToken', val);
			document.getElementById('s-token').value = '';
			document.getElementById('s-token').placeholder = '●●●●●● (gespeichert)';
			showToast('✅ Token gespeichert', 'success');
		} else {
			localStorage.removeItem('triggerToken');
			document.getElementById('s-token').placeholder = 'Token eingeben...';
			showToast('🗑️ Token gelöscht', 'info');
		}
	}

	function renderSettingsDomainList() {
		const container = document.getElementById('settings-domain-list');
		if (!container) return;
		container.innerHTML = '';
		tempDomainConfigs.forEach((d, index) => {
			const div = document.createElement('div');
			div.className = 'domain-pill';
			div.innerHTML = '<span><strong>' + d.fqdn + '</strong> <small>(' + d.provider + ')</small></span>' +
			                '<button onclick="removeDomainFromList(' + index + ')" style="background:none; border:none; color:var(--error); cursor:pointer; font-weight:bold;">✕</button>';
			container.appendChild(div);
		});
	}

	function toggleProviderFields() {
		const p = document.getElementById('new-domain-provider').value;
		document.getElementById('fields-ionos').style.display = p === 'IONOS' ? 'block' : 'none';
		document.getElementById('fields-cloudflare').style.display = p === 'CLOUDFLARE' ? 'block' : 'none';
		document.getElementById('fields-ipv64').style.display = p === 'IPV64' ? 'block' : 'none';
	}

	function addDomainToList() {
		const fqdn = document.getElementById('new-domain-fqdn').value.trim();
		const provider = document.getElementById('new-domain-provider').value;
		if(!fqdn) return showToast('FQDN fehlt', 'error');

		let entry = { fqdn: fqdn, provider: provider };
		if(provider === 'IONOS') {
			entry.api_prefix = document.getElementById('new-ionos-prefix').value;
			entry.api_secret = document.getElementById('new-ionos-secret').value;
		} else if(provider === 'CLOUDFLARE') {
			entry.cf_token = document.getElementById('new-cf-token').value;
			entry.cf_email = document.getElementById('new-cf-email').value;
			entry.cf_secret = document.getElementById('new-cf-secret').value;
		} else if(provider === 'IPV64') {
			entry.ipv64_token = document.getElementById('new-ipv64-token').value;
		}
		tempDomainConfigs.push(entry);
		renderSettingsDomainList();
		document.getElementById('new-domain-fqdn').value = '';
	}

	function removeDomainFromList(index) {
		tempDomainConfigs.splice(index, 1);
		renderSettingsDomainList();
	}

	async function saveFullConfig() {
		if(!confirm("Configuration speichern?")) return;
		const token = localStorage.getItem('triggerToken') || '';
		try {
			const r = await fetch('/api/save-config', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', 'X-Trigger-Token': token },
				body: JSON.stringify({ domain_configs: tempDomainConfigs })
			});
			if (r.ok) {
				showToast('✅ Gespeichert!', 'success');
				setTimeout(() => location.reload(), 1200);
			} else {
				const txt = await r.text();
				showToast('❌ Fehler: ' + txt, 'error');
			}
		} catch (e) { showToast('❌ Netzwerkfehler', 'error'); }
	}

	function resetMetrics() {
		if (!confirm('Möchtest du wirklich alle Metriken (Statistiken) löschen?')) return;
		const token = localStorage.getItem('triggerToken') || '';
		fetch('/api/metrics/reset', {
			method: 'POST',
			headers: token ? {'X-Trigger-Token': token} : {}
		})
		.then(r => {
			if (r.ok) { showToast('✅ Metriken zurückgesetzt', 'success'); }
			else { showToast('❌ Reset fehlgeschlagen', 'error'); }
		})
		.catch(() => showToast('❌ Verbindungsfehler', 'error'));
	}

	function filterDomains(query) {
		document.querySelectorAll('.domain-item').forEach(d => {
			const name = (d.getAttribute('data-domain') || '').toLowerCase();
			d.style.display = name.includes(query.toLowerCase()) ? '' : 'none';
		});
	}

	function deleteDomain(domain, btn) {
		if (!confirm('Domain "' + domain + '" wirklich aus dem Status entfernen?')) return;
		const token = localStorage.getItem('triggerToken') || '';
		btn.disabled = true;
		btn.textContent = '⏳';
		fetch('/api/domain/delete?domain=' + encodeURIComponent(domain), {
			method: 'POST',
			headers: token ? {'X-Trigger-Token': token} : {}
		})
		.then(r => r.json().then(j => ({ status: r.status, json: j })))
		.then(({ status, json: j }) => {
			if (status === 200) {
				const card = btn.closest('.domain-item');
				if (card) { card.style.transition = 'opacity 0.4s'; card.style.opacity = '0'; setTimeout(() => card.remove(), 400); }
				showToast('🗑️ ' + domain + ' entfernt', 'success');
			} else {
				btn.disabled = false; btn.textContent = '🗑️ Entfernen';
				showToast('❌ ' + (j.error || 'Fehler beim Löschen'), 'error');
			}
		})
		.catch(() => { btn.disabled = false; btn.textContent = '🗑️ Entfernen'; showToast('❌ Verbindungsfehler', 'error'); });
	}

	function fallbackCopy(text) {
		const ta = document.createElement('textarea');
		ta.value = text; ta.style.position = 'fixed'; ta.style.left = '-9999px';
		document.body.appendChild(ta); ta.focus(); ta.select();
		try { document.execCommand('copy'); showToast('✓ Kopiert: ' + text, 'success'); }
		catch { showToast('❌ Kopieren fehlgeschlagen', 'error'); }
		document.body.removeChild(ta);
	}

	function startClock() {
		const el = document.getElementById('clock');
		if (!el) return;
		const tick = () => { 
			const d = new Date();
			el.textContent = [d.getHours(), d.getMinutes(), d.getSeconds()].map(n => String(n).padStart(2, '0')).join(':');
		};
		tick(); setInterval(tick, 1000);
	}
	</script>
	</div>
	</body>
	</html>
	`)
	})

	return mux
}