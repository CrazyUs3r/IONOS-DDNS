// Package main
package main

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed http/dashboard.css
var cssData string

//go:embed http/dashboard.js
var jsData string

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
			<div class="card-content chart-wrap pr-10">
				<div class="chart-y-axis req">
					<div class="chart-y-label top">%.0f</div>
					<div class="chart-y-label middle">%.0f</div>
					<div class="chart-y-label bottom">0</div>
				</div>
				<svg viewBox="0 0 300 60" preserveAspectRatio="none" class="chart-svg">
					<path d="%s L 300,60 L 0,60 Z" fill="rgba(56,189,248,0.1)"/>
					<path d="%s" fill="none" stroke="#38bdf8" stroke-width="2" stroke-linecap="round"/>
				</svg>

				<div class="chart-x-labels">
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
			fmt.Fprintf(&labelsBuilder, `<span class="current">%02dh</span>`, h)
		} else {
			fmt.Fprintf(&labelsBuilder, "<span>%02dh</span>", h)
		}
	}
	timeLabels := labelsBuilder.String()

	return fmt.Sprintf(`
		<details class="card">
			<summary>⚡ %s</summary>
			<div class="card-content chart-wrap pr-5">
				<div class="chart-y-axis latency">
					<div class="chart-y-label top">%.0fms</div>
					<div class="chart-y-label middle">%.0fms</div>
					<div class="chart-y-label bottom">0</div>
				</div>
				<svg viewBox="0 0 300 60" preserveAspectRatio="none" class="chart-svg chart-svg-overflow">
					<path d="%s L 300,60 L 0,60 Z" fill="rgba(139,92,246,0.15)"/>
					<path d="%s" fill="none" stroke="#a78bfa" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
				</svg>

				<div class="chart-x-labels">
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
		for i := range 24 {
			out[i] = x[i]
		}
		return out, true
	case []any:
		if len(x) != 24 {
			return out, false
		}
		for i := range 24 {
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
		for i := range 24 {
			out[i] = x[i]
		}
		return out, true
	case []any:
		if len(x) != 24 {
			return out, false
		}
		for i := range 24 {
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
	securitySection := buildSettingsSecuritySection()
	systemSection := buildSettingsSystemSection(c)
	domainsSection := buildSettingsDomainsSection()
	notifySection := buildSettingsNotifySection(c)

	return `<div id="settingsOverlay" class="modal-overlay" onclick="closeSettingsOutside(event)">` +
		`<div class="modal">` +
		`<div class="modal-header">` +
		`<h2>⚙️ ` + T.SettingsTitle + `</h2>` +
		`<button class="modal-close" onclick="closeSettings()">✕</button>` +
		`</div>` +
		`<div class="modal-body">` +

		buildSettingsCollapsibleSection(T.SettingsSecurity, securitySection, false) +
		buildSettingsCollapsibleSection(T.SettingsSystem, systemSection, true) +
		buildSettingsCollapsibleSection(T.SettingsDomains, domainsSection, false) +
		buildSettingsCollapsibleSection(T.SettingsNotify, notifySection, false) +

		buildSettingsSaveSection() +

		`</div></div></div>`
}

func buildSettingsCollapsibleSection(title, body string, open bool) string {
	openAttr := ""
	if open {
		openAttr = " open"
	}

	return `<details class="s-section s-collapsible"` + openAttr + `>` +
		`<summary class="s-section-summary">` +
		`<span>` + title + `</span>` +
		`<span class="s-section-chevron">▾</span>` +
		`</summary>` +
		`<div class="s-section-content">` + body + `</div>` +
		`</details>`
}

func buildSettingsSubSection(id, title, body string) string {
	idAttr := ""
	if id != "" {
		idAttr = ` id="` + id + `"`
	}

	return `<details class="s-subsection"` + idAttr + `>` +
		`<summary class="s-subsection-summary">` +
		`<span>` + title + `</span>` +
		`<span class="s-subsection-chevron">▾</span>` +
		`</summary>` +
		`<div class="s-subsection-content">` + body + `</div>` +
		`</details>`
}

func buildSettingsIPModeOptions(current string) string {
	var out strings.Builder

	for _, m := range []string{IPModeBoth, IPModeV4, IPModeV6} {
		sel := ""
		if m == current {
			sel = ` selected`
		}
		fmt.Fprintf(&out, `<option value="%s"%s>%s</option>`, m, sel, m)
	}

	return out.String()
}

func buildSettingsNotifyEventCheckboxes(current []string) string {
	active := make(map[string]bool)
	for _, e := range current {
		active[strings.ToUpper(strings.TrimSpace(e))] = true
	}

	events := []struct{ code, label, desc string }{
		{"UPDATE", T.NotifyEventUpdateLabel, T.NotifyEventUpdateDesc},
		{"CREATE", T.NotifyEventCreateLabel, T.NotifyEventCreateDesc},
		{"ERROR", T.NotifyEventErrorLabel, T.NotifyEventErrorDesc},
		{"START", T.NotifyEventStartLabel, T.NotifyEventStartDesc},
		{"STOP", T.NotifyEventStopLabel, T.NotifyEventStopDesc},
		{"CLEANUP", T.NotifyEventCleanupLabel, T.NotifyEventCleanupDesc},
	}

	var out strings.Builder
	out.WriteString(`<div class="notify-events-list">`)

	for _, ev := range events {
		chk := ""
		if active[ev.code] {
			chk = HTMLChecked
		}

		fmt.Fprintf(&out, `<label class="notify-event-item">`+
			`<input type="checkbox" name="notify-event" value="%s"%s>`+
			`<span class="notify-event-text">`+
			`<span class="notify-event-title">%s</span>`+
			`<span class="notify-event-desc">%s</span>`+
			`</span></label>`,
			ev.code, chk, ev.label, ev.desc)
	}

	out.WriteString(`</div>`)
	return out.String()
}

func checkedAttr(v bool) string {
	if v {
		return HTMLChecked
	}
	return ""
}

func checkboxLabel(v bool) string {
	if v {
		return T.SettingsCheckboxActive
	}
	return T.SettingsCheckboxDeactive
}

func buildSettingsSecuritySection() string {
	return `<div class="s-row s-row-stack s-gap-8">` +
		`<span class="s-label">` + T.SettingsTriggerToken + `</span>` +
		`<div class="input-with-action">` +
		`<input type="password" id="s-token" class="s-input" placeholder="` + T.SettingsTokenPlaceholder + `" autocomplete="off">` +
		`<button type="button" class="input-action-btn" onclick="togglePassword('s-token', this)">👁️</button>` +
		`</div>` +
		`<button class="s-btn" onclick="saveToken()">` + T.SettingsTokenSave + `</button>` +
		`</div>`
}

func buildSettingsSystemSection(c Config) string {
	return `<div class="s-row">` +
		`<span class="s-label">` + T.SettingsIPMode + `</span>` +
		`<select id="cfg-ip-mode" class="s-input s-select-auto-sm">` +
		buildSettingsIPModeOptions(c.IPMode) +
		`</select>` +
		`</div>` +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsInterval+`</span>`+
			`<input type="number" id="cfg-interval" class="s-input s-input-sm-right" min="30" max="86400" value="%d"></div>`, c.Interval) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsHealthPort+`</span>`+
			`<input type="text" id="cfg-health-port" class="s-input s-input-sm-right" value="%s"></div>`, html.EscapeString(c.HealthPort)) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsIface+` <small class="s-label-hint-inline">`+T.SettingsIfaceHint+`</small></span>`+
			`<input type="text" id="cfg-iface" class="s-input s-input-md" placeholder="`+T.SettingsIfacePlaceholder+`" value="%s"></div>`, html.EscapeString(c.IfaceName)) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsDNS+` <small class="s-label-hint-inline">(`+T.SettingsDNSHint+`)</small></span>`+
			`<input type="text" id="cfg-dns" class="s-input s-input-lg" placeholder="1.1.1.1:53, 8.8.8.8:53" value="%s"></div>`,
			html.EscapeString(strings.Join(c.DNSServers, ", ")),
		) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsMaxLog+`</span>`+
			`<input type="number" id="cfg-max-log" class="s-input s-input-sm-right" min="100" max="50000" value="%d"></div>`, c.MaxLogLines) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsMaxRetries+`</span>`+
			`<input type="number" id="cfg-max-retries" class="s-input s-input-sm-right" min="0" max="20" value="%d"></div>`, c.MaxAPIRetries) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsMaxConcurrent+`</span>`+
			`<input type="number" id="cfg-max-concurrent" class="s-input s-input-sm-right" min="1" max="20" value="%d"></div>`, c.MaxConcurrent) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsHourlyLimit+`</span>`+
			`<input type="number" id="cfg-hourly-limit" class="s-input s-input-sm-right" min="100" max="100000" value="%d"></div>`, c.HourlyRateLimit) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsIPv4Endpoints+`<small class="s-label-hint-block">(`+T.SettingsDNSHint+`)</small></span>`+
			`<input type="text" id="cfg-ipv4_endpoints" class="s-input s-input-lg" placeholder="https://4.ident.me/, https://4.tnedi.me/" value="%s"></div>`,
			html.EscapeString(strings.Join(c.IPv4Endpoints, ", ")),
		) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsIPv6Endpoints+`<small class="s-label-hint-block">(`+T.SettingsDNSHint+`)</small></span>`+
			`<input type="text" id="cfg-ipv6_endpoints" class="s-input s-input-lg" placeholder="https://6.ident.me/, https://6.tnedi.me/" value="%s"></div>`,
			html.EscapeString(strings.Join(c.IPv6Endpoints, ", ")),
		) +

		`<div class="s-row"><span class="s-label">` + T.SettingsLanguage + `</span>` +
		`<select id="cfg-lang" class="s-input s-select-auto-md">` +
		buildDynamicLangOptions(c.Lang) +
		`</select></div>` +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsDryRun+`<small class="s-label-hint-block">`+T.SettingsDryRunHint+`</small></span>`+
			`<label class="s-checkbox-container">`+
			`<input type="checkbox" id="cfg-dry-run" class="s-checkbox-dynamic" onchange="updateCheckboxLabel(this)"`+
			` data-label-on="%s" data-label-off="%s"%s>`+
			`<span class="s-checkbox-text">%s</span></label></div>`,
			T.SettingsCheckboxActive, T.SettingsCheckboxDeactive,
			checkedAttr(c.DryRun),
			checkboxLabel(c.DryRun),
		) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">Debug-Modus <small class="s-label-hint-block">`+T.SettingsDebugVerboseHint+`</small></span>`+
			`<label class="s-checkbox-container">`+
			`<input type="checkbox" id="cfg-debug" class="s-checkbox-dynamic" onchange="updateCheckboxLabel(this)"`+
			` data-label-on="%s" data-label-off="%s"%s>`+
			`<span class="s-checkbox-text">%s</span></label></div>`,
			T.SettingsCheckboxActive, T.SettingsCheckboxDeactive,
			checkedAttr(c.DebugEnabled),
			checkboxLabel(c.DebugEnabled),
		) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">Debug HTTP Raw <small class="s-label-hint-block">`+T.SettingsDebugHTTPHint+`</small></span>`+
			`<label class="s-checkbox-container">`+
			`<input type="checkbox" id="cfg-debug-http" class="s-checkbox-dynamic" onchange="updateCheckboxLabel(this)"`+
			` data-label-on="%s" data-label-off="%s"%s>`+
			`<span class="s-checkbox-text">%s</span></label></div>`,
			T.SettingsCheckboxActive, T.SettingsCheckboxDeactive,
			checkedAttr(c.DebugHTTPRaw),
			checkboxLabel(c.DebugHTTPRaw),
		)
}

func buildSettingsDomainsSection() string {
	addDomainForm := `<div class="add-domain-box">` +
		`<input type="text" id="new-domain-fqdn" class="s-input mb-8" placeholder="` + T.SettingsDomainPlaceholder + `">` +
		`<input type="number" id="new-domain-ttl" class="s-input mb-8" placeholder="TTL (z. B. 60)" min="1" step="1">` +
		`<select id="new-domain-provider" class="s-input mb-8" onchange="toggleProviderFields()">` +
		`<option value="IONOS">IONOS</option>` +
		`<option value="CLOUDFLARE">Cloudflare</option>` +
		`<option value="IPV64">IPv64</option>` +
		`</select>` +
		`<div id="fields-ionos">` +
		`<input type="text" id="new-ionos-prefix" class="s-input mb-8" placeholder="` + T.SettingsAPIPrefix + `">` +
		`<div class="input-with-action mt-8">` +
		`<input type="password" id="new-ionos-secret" class="s-input" placeholder="` + T.SettingsAPISecret + `">` +
		`<button type="button" class="input-action-btn" onclick="togglePassword('new-ionos-secret', this)">👁️</button>` +
		`</div>` +
		`</div>` +
		`<div id="fields-cloudflare" class="is-hidden">` +
		`<input type="text" id="new-cf-token" class="s-input mb-8" placeholder="` + T.SettingsCFTokenHint + `">` +
		`<div class="center-note">` + T.SettingsCFOr + `</div>` +
		`<input type="text" id="new-cf-email" class="s-input mb-8" placeholder="` + T.SettingsCFEmail + `">` +
		`<div class="input-with-action mt-8">` +
		`<input type="password" id="new-cf-secret" class="s-input" placeholder="` + T.SettingsCFGlobalKey + `">` +
		`<button type="button" class="input-action-btn" onclick="togglePassword('new-cf-secret', this)">👁️</button>` +
		`</div>` +
		`<label class="inline-check">` +
		`<input type="checkbox" id="new-cf-proxied"> Cloudflare Proxy aktivieren` +
		`</label>` +
		`</div>` +
		`<div id="fields-ipv64" class="is-hidden">` +
		`<div class="input-with-action mt-8">` +
		`<input type="password" id="new-ipv64-token" class="s-input" placeholder="` + T.SettingsIPv64Token + `">` +
		`<button type="button" class="input-action-btn" onclick="togglePassword('new-ipv64-token', this)">👁️</button>` +
		`</div>` +
		`</div>` +
		`<button class="s-btn s-btn-success-full" onclick="addDomainToList()">` +
		T.SettingsAddBtn +
		`</button>` +
		`</div>`

	return `<div id="settings-domain-list" class="settings-domain-list"></div>` +
		buildSettingsSubSection("add-domain-section", T.SettingsAddDomain, addDomainForm)
}

func buildSettingsNotifySection(c Config) string {
	notifyEventsSection := `<div class="s-row s-row-stack s-gap-6">` +
		`<span class="s-label">` + T.SettingsNotifyEvents + `</span>` +
		buildSettingsNotifyEventCheckboxes(c.Notifications.Events) +
		`</div>`

	telegramSection := `<div class="notify-box notify-telegram">` +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsTGChatID+`</span>`+
			`<input type="text" id="cfg-tg-chat-id" class="s-input s-input-lg"`+
			` placeholder="-100xxxxxxxxx" value="%s"></div>`,
			html.EscapeString(c.Notifications.Telegram.ChatID)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsTGToken+`</span>`+
			`<div class="input-with-action">`+
			`<input type="password" id="cfg-tg-token" class="s-input s-input-lg"`+
			` placeholder="`+T.SettingsTokenUnchanged+`" value="%s">`+
			`<button type="button" class="input-action-btn" onclick="togglePassword('cfg-tg-token', this)">👁️</button>`+
			`</div></div>`,
			html.EscapeString(c.Notifications.Telegram.Token)) +
		`</div>`

	gotifySection := `<div class="notify-box notify-gotify">` +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsGotifyURL+`</span>`+
			`<input type="text" id="cfg-gotify-url" class="s-input s-input-lg"`+
			` placeholder="https://gotify.example.com" value="%s"></div>`,
			html.EscapeString(c.Notifications.Gotify.URL)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsGotifyToken+`</span>`+
			`<div class="input-with-action">`+
			`<input type="password" id="cfg-gotify-token" class="s-input s-input-lg"`+
			` placeholder="`+T.SettingsTokenUnchanged+`" value="%s">`+
			`<button type="button" class="input-action-btn" onclick="togglePassword('cfg-gotify-token', this)">👁️</button>`+
			`</div></div>`,
			html.EscapeString(c.Notifications.Gotify.Token)) +
		`</div>`

	webhookSection := `<div class="notify-box notify-webhook">` +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">URL</span>`+
			`<input type="text" id="cfg-webhook-url" class="s-input s-input-lg"`+
			` placeholder="https://your-endpoint.com/api" value="%s"></div>`,
			html.EscapeString(c.Notifications.Webhook.URL)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">Secret <small class="s-label-hint-inline">(opt.)</small></span>`+
			`<div class="input-with-action">`+
			`<input type="password" id="cfg-webhook-secret" class="s-input s-input-lg"`+
			` placeholder="`+T.SettingsTokenUnchanged+`" value="%s">`+
			`<button type="button" class="input-action-btn" onclick="togglePassword('cfg-webhook-secret', this)">👁️</button>`+
			`</div></div>`,
			html.EscapeString(c.Notifications.Webhook.Secret)) +
		`</div>`

	mqttSection := `<div class="notify-box notify-mqtt">` +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">Broker</span>`+
			`<input type="text" id="cfg-mqtt-broker" class="s-input s-input-lg"`+
			` placeholder="tcp://192.168.1.10:1883" value="%s"></div>`,
			html.EscapeString(c.Notifications.MQTTConfig.Broker)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">Client ID</span>`+
			`<input type="text" id="cfg-mqtt-clientid" class="s-input s-input-lg"`+
			` placeholder="go-dyndns" value="%s"></div>`,
			html.EscapeString(c.Notifications.MQTTConfig.ClientID)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">Username</span>`+
			`<input type="text" id="cfg-mqtt-username" class="s-input s-input-lg"`+
			` placeholder="optional" value="%s"></div>`,
			html.EscapeString(c.Notifications.MQTTConfig.Username)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">Secret <small class="s-label-hint-inline">Password</small></span>`+
			`<div class="input-with-action">`+
			`<input type="password" id="cfg-mqtt-password" class="s-input s-input-lg"`+
			` placeholder="`+T.SettingsTokenUnchanged+`" value="%s">`+
			`<button type="button" class="input-action-btn" onclick="togglePassword('cfg-mqtt-password', this)">👁️</button>`+
			`</div></div>`,
			html.EscapeString(c.Notifications.MQTTConfig.Password)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">Topic</span>`+
			`<input type="text" id="cfg-mqtt-topic" class="s-input s-input-lg"`+
			` placeholder="dyndns/ip" value="%s"></div>`,
			html.EscapeString(c.Notifications.MQTTConfig.Topic)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">QoS</span>`+
			`<input type="number" min="0" max="2" id="cfg-mqtt-qos" class="s-input s-input-sm"`+
			` value="%d"></div>`,
			c.Notifications.MQTTConfig.QoS) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">Retain</span>`+
			`<label class="s-checkbox-container">`+
			`<input type="checkbox" id="cfg-mqtt-retain" class="s-checkbox-dynamic" onchange="updateCheckboxLabel(this)"`+
			` data-label-on="%s" data-label-off="%s"%s>`+
			`<span class="s-checkbox-text">%s</span></label></div>`,
			T.SettingsCheckboxActive,
			T.SettingsCheckboxDeactive,
			checkedAttr(c.Notifications.MQTTConfig.Retain),
			checkboxLabel(c.Notifications.MQTTConfig.Retain),
		) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">Auto Discovery <small class="s-label-hint-inline">Home Assistant</small></span>`+
			`<label class="s-checkbox-container">`+
			`<input type="checkbox" id="cfg-mqtt-discovery" class="s-checkbox-dynamic" onchange="updateCheckboxLabel(this)"`+
			` data-label-on="%s" data-label-off="%s"%s>`+
			`<span class="s-checkbox-text">%s</span></label></div>`,
			T.SettingsCheckboxActive,
			T.SettingsCheckboxDeactive,
			checkedAttr(c.Notifications.MQTTConfig.Discovery),
			checkboxLabel(c.Notifications.MQTTConfig.Discovery),
		) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">Discovery Prefix</span>`+
			`<input type="text" id="cfg-mqtt-discovery-prefix" class="s-input s-input-lg"`+
			` placeholder="homeassistant" value="%s"></div>`,
			html.EscapeString(c.Notifications.MQTTConfig.DiscoveryPrefix)) +
		`</div>`
	return fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsNotifyEnabled+`</span>`+
		`<label class="s-checkbox-container">`+
		`<input type="checkbox" id="cfg-notify-enabled" class="s-checkbox-dynamic" onchange="updateCheckboxLabel(this)"`+
		` data-label-on="%s" data-label-off="%s"%s>`+
		`<span class="s-checkbox-text">%s</span></label></div>`,
		T.SettingsCheckboxActive, T.SettingsCheckboxDeactive,
		checkedAttr(c.Notifications.Enabled),
		checkboxLabel(c.Notifications.Enabled),
	) +
		buildSettingsSubSection("", T.SettingsNotifyEvents, notifyEventsSection) +
		buildSettingsSubSection("", T.SettingsTelegramHeading, telegramSection) +
		buildSettingsSubSection("", T.SettingsGotifyHeading, gotifySection) +
		buildSettingsSubSection("", T.SettingsWebhookHeading, webhookSection) +
		buildSettingsSubSection("", T.SettingsMqttHeading, mqttSection)
}

func buildSettingsSaveSection() string {
	return `<div style="margin-top:20px;padding:15px;background:rgba(74,222,128,0.07);border-radius:8px;border:1px solid var(--success);">` +
		`<p style="font-size:0.75rem;margin-bottom:10px;opacity:0.8;text-align:center;">` +
		T.SettingsSaveHint + `<br>` +
		T.SettingsRestartHint +
		`</p>` +
		`<button class="action-btn" style="width:100%;margin:0;" onclick="saveFullConfig()">` + T.SettingsSaveBtn + `</button>` +
		`</div>`
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
	TTL        int    `json:"ttl,omitempty"`
	CFProxied  bool   `json:"cf_proxied,omitempty"`
}

type safeMQTTConfig struct {
	Broker          string `json:"broker"`
	ClientID        string `json:"client_id"`
	Username        string `json:"username"`
	Password        string `json:"password"`
	Topic           string `json:"topic"`
	QoS             byte   `json:"qos"`
	Retain          bool   `json:"retain"`
	Discovery       bool   `json:"discovery"`
	DiscoveryPrefix string `json:"discovery_prefix"`
}

type safeSystemConfig struct {
	IPMode          string         `json:"ip_mode"`
	IfaceName       string         `json:"iface_name"`
	HealthPort      string         `json:"health_port"`
	DNSServers      []string       `json:"dns_servers"`
	Interval        int            `json:"interval"`
	DryRun          bool           `json:"dry_run"`
	HourlyRateLimit int            `json:"hourly_rate_limit"`
	MaxConcurrent   int            `json:"max_concurrent"`
	MaxLogLines     int            `json:"max_log_lines"`
	MaxAPIRetries   int            `json:"max_api_retries"`
	Lang            string         `json:"lang"`
	NotifyEnabled   bool           `json:"notify_enabled"`
	NotifyEvents    []string       `json:"notify_events"`
	TelegramToken   string         `json:"telegram_token"`
	TelegramChatID  string         `json:"telegram_chat_id"`
	GotifyURL       string         `json:"gotify_url"`
	GotifyToken     string         `json:"gotify_token"`
	WebhookURL      string         `json:"webhook_url"`
	WebhookSecret   string         `json:"webhook_secret"`
	MQTT            safeMQTTConfig `json:"mqtt"`
	DebugEnabled    bool           `json:"debug_enabled"`
	DebugHTTPRaw    bool           `json:"debug_http_raw"`
	IPv4Endpoints   []string       `json:"ipv4_endpoints"`
	IPv6Endpoints   []string       `json:"ipv6_endpoints"`
}

type dashboardConfigPayload struct {
	DomainConfigs []safeDomainConfig `json:"domain_configs"`
	System        safeSystemConfig   `json:"system"`
}

func safeDomainConfigs(dcs []DomainConfig) []safeDomainConfig {
	out := make([]safeDomainConfig, len(dcs))
	for i, dc := range dcs {
		out[i] = safeDomainConfig{
			FQDN:       dc.FQDN,
			Provider:   string(dc.Provider),
			APIPrefix:  dc.APIPrefix,
			APISecret:  dc.APISecret,
			CFToken:    dc.CFToken,
			CFEmail:    dc.CFEmail,
			CFSecret:   dc.CFSecret,
			IPv64Token: dc.IPv64Token,
			TTL:        dc.TTL,
			CFProxied:  dc.CFProxied,
		}
	}
	return out
}

func currentSystemConfig() safeSystemConfig {
	return safeSystemConfig{
		IPMode:          cfg.IPMode,
		IfaceName:       cfg.IfaceName,
		HealthPort:      cfg.HealthPort,
		DNSServers:      cfg.DNSServers,
		Interval:        cfg.Interval,
		DryRun:          cfg.DryRun,
		HourlyRateLimit: cfg.HourlyRateLimit,
		MaxConcurrent:   cfg.MaxConcurrent,
		MaxLogLines:     cfg.MaxLogLines,
		MaxAPIRetries:   cfg.MaxAPIRetries,
		Lang:            cfg.Lang,
		NotifyEnabled:   cfg.Notifications.Enabled,
		NotifyEvents:    cfg.Notifications.Events,
		TelegramToken:   cfg.Notifications.Telegram.Token,
		TelegramChatID:  cfg.Notifications.Telegram.ChatID,
		GotifyURL:       cfg.Notifications.Gotify.URL,
		GotifyToken:     cfg.Notifications.Gotify.Token,
		WebhookURL:      cfg.Notifications.Webhook.URL,
		WebhookSecret:   cfg.Notifications.Webhook.Secret,
		MQTT: safeMQTTConfig{
			Broker:          cfg.Notifications.MQTTConfig.Broker,
			ClientID:        cfg.Notifications.MQTTConfig.ClientID,
			Username:        cfg.Notifications.MQTTConfig.Username,
			Password:        cfg.Notifications.MQTTConfig.Password,
			Topic:           cfg.Notifications.MQTTConfig.Topic,
			QoS:             cfg.Notifications.MQTTConfig.QoS,
			Retain:          cfg.Notifications.MQTTConfig.Retain,
			Discovery:       cfg.Notifications.MQTTConfig.Discovery,
			DiscoveryPrefix: cfg.Notifications.MQTTConfig.DiscoveryPrefix,
		},
		DebugEnabled:  cfg.DebugEnabled,
		DebugHTTPRaw:  cfg.DebugHTTPRaw,
		IPv4Endpoints: cfg.IPv4Endpoints,
		IPv6Endpoints: cfg.IPv6Endpoints,
	}
}

func dashboardI18NJSON() string {
	m := map[string]string{
		"theme":                 t(T.ThemeLabel, "Theme"),
		"no_ip_to_copy":         t(T.NoIPToCopy, "❌ No IP to copy"),
		"copied":                t(T.Copied, "✓ Copied: "),
		"copy_failed":           t(T.CopyFailed, "❌ Copy failed"),
		"update_starting":       t(T.UpdateStartingJS, "⏳ Update wird gestartet..."),
		"update_started":        t(T.UpdateStartedJS, "✅ Update gestartet"),
		"connection_error":      t(T.ConnectionErrorJS, "❌ Verbindungsfehler"),
		"export_started":        t(T.ExportStartedJS, "✓ Export gestartet"),
		"export_failed":         t(T.ExportFailedJS, "Export fehlgeschlagen"),
		"fqdn_missing":          t(T.FQDNMissingJS, "FQDN fehlt"),
		"save_config_confirm":   t(T.SaveConfigConfirmJS, "Alle Einstellungen in config.json speichern?"),
		"saved_reload":          t(T.SavedReloadJS, "✅ Gespeichert! Seite wird neu geladen..."),
		"error_prefix":          t(T.ErrorPrefixJS, "❌ Fehler: "),
		"reset_metrics_confirm": t(T.ResetMetricsConfirmJS, "Möchtest du wirklich alle Metriken (Statistiken) löschen?"),
		"metrics_reset_ok":      t(T.MetricsResetOKJS, "✅ Metriken zurückgesetzt"),
		"metrics_reset_failed":  t(T.MetricsResetFailedJS, "❌ Reset fehlgeschlagen"),
		"delete_domain_confirm": t(T.DeleteDomainConfirmJS, `Domain "{domain}" wirklich aus dem Status entfernen?`),
		"domain_removed":        t(T.DomainRemovedJS, "🗑️ {domain} entfernt"),
		"delete_failed":         t(T.DeleteFailedJS, "Fehler beim Löschen"),
		"remove_btn":            t(T.RemoveBtn, "🗑️ Entfernen"),
		"token_saved":           t(T.TokenSavedJS, "✅ Token gespeichert"),
		"token_deleted":         t(T.TokenDeletedJS, "🗑️ Token gelöscht"),
		"token_saved_masked":    t(T.TokenSavedMaskedJS, "●●●●●● (gespeichert)"),
		"token_enter":           t(T.TokenEnterJS, "Token eingeben..."),
		"domain_updated":        t(T.DomainUpdatedJS, "✓ {domain} updated"),
		"cleared":               t(T.ClearedJS, "Gelöscht."),
		"active":                t(T.ActiveJS, "Aktiv"),
		"inactive":              t(T.InactiveJS, "Inaktiv"),
	}

	b, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func formatUptime(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

func createMux() *http.ServeMux {
	mux := http.NewServeMux()

	registerStaticRoutes(mux)
	registerAPIroutes(mux)
	registerPageRoutes(mux)

	return mux
}

func registerStaticRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/favicon.svg", handleFavicon)
	mux.HandleFunc("/ws", handleWS)
	mux.HandleFunc("/metrics", handleMetrics)
	mux.HandleFunc("/health", handleHealth)
}

func registerAPIroutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/domains", handleAPIDomains)
	mux.HandleFunc("/api/config", handleAPIConfig)
	mux.HandleFunc("/api/languages", handleAPILanguages)
	mux.HandleFunc("/api/save-config", handleAPISaveConfig)
	mux.HandleFunc("/api/set-language", handleAPISetLanguage)
	mux.HandleFunc("/api/domain/delete", handleAPIDomainDelete)
	mux.HandleFunc("/api/trigger", handleAPITrigger)
	mux.HandleFunc("/api/trigger/status", handleAPITriggerStatus)
	mux.HandleFunc("/api/export", handleAPIExport)
	mux.HandleFunc("/api/metrics/reset", handleMetricsReset)
}

func registerPageRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/", handleDashboard)
}

func handleFavicon(w http.ResponseWriter, r *http.Request) {
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

		<text x="32" y="40" text-anchor="middle" font-size="32"
				font-family="Apple Color Emoji, Segoe UI Emoji, Noto Color Emoji">🌐</text>

		<g opacity="%s">
			<circle cx="48" cy="48" r="10" fill="%s"/>
			<text x="48" y="52" text-anchor="middle" font-size="14" font-weight="800"
				fill="white" font-family="system-ui">%s</text>
		</g>

		<circle cx="14" cy="14" r="4" fill="%s" opacity="0.35"/>
		</svg>`, bg, badgeOpacity, statusColor, symbol, textColor)

	w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	_, _ = w.Write([]byte(svg))
}

func handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		debugLog("WS", "", fmt.Sprintf(T.WSUpgradeFailed, err))
		return
	}

	client := &WSClient{
		conn: conn,
		send: make(chan WSMessage, 64),
	}

	stats := apiMetrics.GetStats()
	client.send <- WSMessage{Type: "initial", Data: stats}

	wsHub.register <- client
}

func handleAPIDomains(w http.ResponseWriter, r *http.Request) {
	serveCachedJSON(w, r, domainsCache)
}

func handleAPIConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	type fullConfigResponse struct {
		DomainConfigs []safeDomainConfig `json:"domain_configs"`
		System        safeSystemConfig   `json:"system"`
	}

	resp := fullConfigResponse{
		DomainConfigs: safeDomainConfigs(cfg.DomainConfigs),
		System:        currentSystemConfig(),
	}

	writeJSON(w, http.StatusOK, resp)
}

func handleAPILanguages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	langs, err := getAvailableLanguages(langDir)
	if err != nil {
		http.Error(w, T.CouldNotLoadLanguages, http.StatusInternalServerError)
		return
	}

	type langEntry struct {
		Code  string `json:"code"`
		Label string `json:"label"`
	}

	codes := make([]string, 0, len(langs))
	for code := range langs {
		codes = append(codes, code)
	}
	sort.Strings(codes)

	entries := make([]langEntry, 0, len(codes))
	for _, code := range codes {
		entries = append(entries, langEntry{
			Code:  code,
			Label: getLangLabel(code),
		})
	}

	writeJSON(w, http.StatusOK, entries)
}

func handleAPISaveConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !validateTriggerToken(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var payload dashboardConfigPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, T.JSONParseError, http.StatusBadRequest)
		return
	}

	cfgMu.Lock()
	applySystemConfigPayload(payload.System)
	cfg.DomainConfigs = mergeDomainConfigs(cfg.DomainConfigs, payload.DomainConfigs)
	cfgMu.Unlock()

	if err := validateDomainConfigs(); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	if err := saveConfigToFile(); err != nil {
		http.Error(w, T.SaveFailed, http.StatusInternalServerError)
		return
	}

	ResetHTTPClient()
	initNotifiers()
	forceNextUpdate.Store(true)
	lastCleanupNano.Store(0)

	debugLog("API", getClientIP(r), T.ConfigHeading)
	writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
}

func applySystemConfigPayload(sys safeSystemConfig) {
	applySystemCoreConfig(sys)
	applySystemRuntimeConfig(sys)
	applyNotificationConfig(sys)
	ensureNotificationsEnabled()
}

func applySystemCoreConfig(sys safeSystemConfig) {
	applyIPMode(sys.IPMode)

	if sys.Interval >= 30 {
		cfg.Interval = sys.Interval
	}
	if sys.HealthPort != "" {
		cfg.HealthPort = sys.HealthPort
	}

	cfg.IfaceName = sys.IfaceName

	if sys.DNSServers != nil {
		cfg.DNSServers = cleanDNSServers(sys.DNSServers)
	}
	if sys.MaxLogLines > 0 {
		cfg.MaxLogLines = sys.MaxLogLines
	}
	if sys.MaxAPIRetries >= 0 {
		cfg.MaxAPIRetries = sys.MaxAPIRetries
	}
	if sys.MaxConcurrent > 0 && sys.MaxConcurrent <= 20 {
		cfg.MaxConcurrent = sys.MaxConcurrent
	}
	if sys.HourlyRateLimit > 0 {
		cfg.HourlyRateLimit = sys.HourlyRateLimit
	}
	if sys.Lang != "" {
		cfg.Lang = sys.Lang
	}
}

func applySystemRuntimeConfig(sys safeSystemConfig) {
	cfg.DryRun = sys.DryRun
	cfg.DebugEnabled = sys.DebugEnabled
	cfg.DebugHTTPRaw = sys.DebugHTTPRaw
	cfg.IPv4Endpoints = sys.IPv4Endpoints
	cfg.IPv6Endpoints = sys.IPv6Endpoints
}

func applyNotificationConfig(sys safeSystemConfig) {
	cfg.Notifications.Enabled = sys.NotifyEnabled

	if sys.NotifyEvents != nil {
		cfg.Notifications.Events = sys.NotifyEvents
	}

	cfg.Notifications.Telegram.Token = sys.TelegramToken
	cfg.Notifications.Telegram.ChatID = sys.TelegramChatID

	cfg.Notifications.Gotify.URL = sys.GotifyURL
	cfg.Notifications.Gotify.Token = sys.GotifyToken

	cfg.Notifications.Webhook.URL = sys.WebhookURL
	cfg.Notifications.Webhook.Secret = sys.WebhookSecret

	cfg.Notifications.MQTTConfig.Broker = sys.MQTT.Broker
	cfg.Notifications.MQTTConfig.ClientID = sys.MQTT.ClientID
	cfg.Notifications.MQTTConfig.Username = sys.MQTT.Username
	cfg.Notifications.MQTTConfig.Password = sys.MQTT.Password
	cfg.Notifications.MQTTConfig.Topic = sys.MQTT.Topic
	cfg.Notifications.MQTTConfig.QoS = sys.MQTT.QoS
	cfg.Notifications.MQTTConfig.Retain = sys.MQTT.Retain
	cfg.Notifications.MQTTConfig.Discovery = sys.MQTT.Discovery
	cfg.Notifications.MQTTConfig.DiscoveryPrefix = sys.MQTT.DiscoveryPrefix
}

func applyIPMode(mode string) {
	switch strings.ToUpper(mode) {
	case IPModeV4, IPModeV6, IPModeBoth:
		cfg.IPMode = strings.ToUpper(mode)
	}
}

func ensureNotificationsEnabled() {
	if cfg.Notifications.Enabled {
		return
	}

	cfg.Notifications.Enabled = (cfg.Notifications.Telegram.Token != "" && cfg.Notifications.Telegram.ChatID != "") ||
		(cfg.Notifications.Gotify.URL != "" && cfg.Notifications.Gotify.Token != "") ||
		(cfg.Notifications.Webhook.URL != "") ||
		(cfg.Notifications.MQTTConfig.Broker != "" && cfg.Notifications.MQTTConfig.Topic != "")
}

func cleanDNSServers(in []string) []string {
	var cleaned []string
	for _, s := range in {
		for part := range strings.SplitSeq(s, ",") {
			if t := strings.TrimSpace(part); t != "" {
				cleaned = append(cleaned, t)
			}
		}
	}
	return cleaned
}

func mergeDomainConfigs(existingCfg []DomainConfig, incoming []safeDomainConfig) []DomainConfig {
	existing := make(map[string]DomainConfig)
	for _, dc := range existingCfg {
		existing[strings.ToLower(dc.FQDN)] = dc
	}

	newConfigs := make([]DomainConfig, 0, len(incoming))
	for _, sc := range incoming {
		fqdn := strings.ToLower(strings.TrimSpace(sc.FQDN))
		if fqdn == "" {
			continue
		}

		if found, ok := existing[fqdn]; ok {
			if sc.APIPrefix != "" {
				found.APIPrefix = sc.APIPrefix
			}
			if sc.APISecret != "" {
				found.APISecret = sc.APISecret
			}
			if sc.CFToken != "" {
				found.CFToken = sc.CFToken
			}
			if sc.CFEmail != "" {
				found.CFEmail = sc.CFEmail
			}
			if sc.CFSecret != "" {
				found.CFSecret = sc.CFSecret
			}
			if sc.IPv64Token != "" {
				found.IPv64Token = sc.IPv64Token
			}

			found.TTL = sc.TTL
			found.CFProxied = sc.CFProxied
			newConfigs = append(newConfigs, found)
			continue
		}

		newConfigs = append(newConfigs, DomainConfig{
			FQDN:       fqdn,
			Provider:   ProviderType(strings.ToUpper(sc.Provider)),
			APIPrefix:  sc.APIPrefix,
			APISecret:  sc.APISecret,
			CFToken:    sc.CFToken,
			CFEmail:    sc.CFEmail,
			CFSecret:   sc.CFSecret,
			IPv64Token: sc.IPv64Token,
			TTL:        sc.TTL,
			CFProxied:  sc.CFProxied,
		})
	}

	return newConfigs
}

func handleAPISetLanguage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !validateTriggerToken(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	lang := strings.TrimSpace(r.URL.Query().Get("lang"))
	if lang == "" {
		http.Error(w, T.LanguageParamMissing, http.StatusBadRequest)
		return
	}

	supported, err := getAvailableLanguages(langDir)
	if err != nil || !supported[lang] {
		http.Error(w, fmt.Sprintf(T.UnsupportedLanguage, lang), http.StatusBadRequest)
		return
	}

	if err := loadLanguage(lang); err != nil {
		http.Error(w, fmt.Sprintf(T.LanguageLoadFailed, err), http.StatusInternalServerError)
		return
	}

	cfg.Lang = lang
	if err := saveConfigToFile(); err != nil {
		debugLog("API", getClientIP(r), fmt.Sprintf(T.ConfigSaveWarnAfterLanguageChange, err))
	}

	debugLog("API", getClientIP(r), fmt.Sprintf(T.LanguageChangedLog, lang))
	broadcastNotification(fmt.Sprintf(T.LanguageChangedNotification, lang), "info")

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
		"lang":   lang,
	})
}

func handleAPIDomainDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !validateTriggerToken(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": T.InvalidToken})
		return
	}

	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	if domain == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": T.DomainParamMissing})
		return
	}

	for _, dc := range cfg.DomainConfigs {
		if strings.EqualFold(dc.FQDN, domain) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": T.DomainStillActiveInConfig})
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
		writeJSON(w, http.StatusNotFound, map[string]string{"error": T.NoStatusFileFound})
		return
	}

	if _, exists := fileData[domain]; !exists {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": T.DomainNotFoundInStatus})
		return
	}

	delete(fileData, domain)

	if b, err := json.MarshalIndent(fileData, "", "  "); err == nil {
		tmp := updatePath + ".tmp"
		if err := os.WriteFile(tmp, b, 0o600); err == nil {
			_ = os.Rename(tmp, updatePath)
		}
	}

	debugLog("API", getClientIP(r), fmt.Sprintf(T.DomainDeletedFromStatusLog, domain))
	broadcastNotification(fmt.Sprintf(T.DomainRemovedFromStatus, domain), "info")

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "deleted",
		"domain": domain,
	})
}

func handleAPITrigger(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1024)

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientIP := getClientIP(r)

	if !validateTriggerToken(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": T.InvalidOrMissingTriggerToken,
		})
		debugLog("API", clientIP, T.TriggerBlockedInvalidToken)
		return
	}

	if !globalTriggerLimiter.Allow() {
		w.Header().Set("Retry-After", "10")
		writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{
			"error":               T.GlobalRateLimitExceeded,
			"retry_after_seconds": 10,
		})
		debugLog("API", clientIP, T.TriggerBlockedGlobalRateLimit)
		broadcastNotification(T.RateLimitGlobal, "warning")
		return
	}

	ipLimiter := ipTriggerLimiter.GetLimiter(clientIP)
	if !ipLimiter.Allow() {
		remaining := ipLimiter.Remaining()
		w.Header().Set("Retry-After", "10")
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
		writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{
			"error":               T.IPRateLimitExceeded,
			"retry_after_seconds": 10,
			"remaining":           remaining,
		})
		debugLog("API", clientIP, T.TriggerBlockedIPRateLimit)
		broadcastNotification(T.TooManyUpdateRequestsWait, "warning")
		return
	}

	if !updateInProgress.CompareAndSwap(false, true) {
		writeJSON(w, http.StatusConflict, map[string]interface{}{
			"error":  T.UpdateAlreadyInProgressAPI,
			"status": T.TriggerStatusBusy,
		})
		debugLog("API", clientIP, T.TriggerBlockedUpdateRunning)
		broadcastNotification(T.UpdateAlreadyRunningNotification, "info")
		return
	}

	go func() {
		defer updateInProgress.Store(false)
		debugLog("API", clientIP, T.ManualUpdateTriggeredLog)
		broadcastNotification(T.ManualUpdateStartedNotification, "info")
		forceNextUpdate.Store(true)
		runUpdate(false)
	}()

	remaining := ipLimiter.Remaining()
	w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"status":               "triggered",
		"message":              T.UpdateStartedMessage,
		"rate_limit_remaining": remaining,
	})
}

func handleAPITriggerStatus(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	ipLimiter := ipTriggerLimiter.GetLimiter(clientIP)

	if !ipLimiter.Allow() {
		http.Error(w, T.APIErrorRateLimitExceeded, http.StatusTooManyRequests)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ip":                 clientIP,
		"remaining_requests": ipLimiter.Remaining(),
		"update_in_progress": updateInProgress.Load(),
		"global_limit":       globalTriggerLimiter.Remaining(),
	})
}

func handleAPIExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Metode not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !validateTriggerToken(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

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
}

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	serveCachedJSON(w, r, metricsCache)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	isHealthy := lastOk.Load()
	hasRun := schedulerRanOnce.Load()
	stats := apiMetrics.GetStats()

	total := getTotalRequests(stats)

	healthReason := ""
	degradedMode := false

	if !hasRun {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status": "starting",
			"reason": T.WaitingForFirstSchedulerRun,
		})
		return
	}

	if total > 10 {
		if successRateStr, ok := stats["success_rate"].(string); ok {
			var rate float64
			if _, err := fmt.Sscanf(successRateStr, "%f%%", &rate); err == nil {
				if rate < 20.0 {
					isHealthy = false
					healthReason = T.HealthCriticalSuccessRate
				} else if rate < 50.0 {
					degradedMode = true
					healthReason = T.HealthDegradedSuccessRate
				}
			}
		}
	}

	if !isHealthy && healthReason == "" {
		healthReason = T.HealthLastSchedulerFailed
	}

	if degradedMode && isHealthy {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":      "degraded",
			"reason":      healthReason,
			"api_metrics": stats,
		})
		return
	}

	if !isHealthy {
		writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"status":      "unhealthy",
			"reason":      healthReason,
			"api_metrics": stats,
		})
		return
	}

	if r.URL.Query().Get("detailed") == constTrue {
		handleDetailedHealth(w, stats)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

func getTotalRequests(stats map[string]interface{}) int64 {
	switch v := stats["total_requests"].(type) {
	case int64:
		return v
	case int:
		return int64(v)
	case float64:
		return int64(v)
	default:
		return 0
	}
}

func handleDetailedHealth(w http.ResponseWriter, stats map[string]interface{}) {
	lastV4, lastV6 := loadLastKnownIPs()

	statusMutex.Lock()
	lastUpdateTime := readLastUpdateTimeFromStatusFile()
	statusMutex.Unlock()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":           "healthy",
		"api_metrics":      stats,
		"last_known_ipv4":  lastV4,
		"last_known_ipv6":  lastV6,
		"last_update_time": lastUpdateTime,
	})
}

func readLastUpdateTimeFromStatusFile() string {
	if b, err := os.ReadFile(updatePath); err == nil {
		var domains map[string]DomainHistory
		if json.Unmarshal(b, &domains) == nil {
			for _, h := range domains {
				if h.LastChanged != "" {
					return h.LastChanged
				}
			}
		}
	}
	return ""
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	statusData := loadStatusData()
	statusClass, statusText := dashboardStatus()
	logs, logTimeRange := loadDashboardLogs()

	jsConfigSafe, _ := json.Marshal(safeDomainConfigs(cfg.DomainConfigs))
	if jsConfigSafe == nil {
		jsConfigSafe = []byte("[]")
	}

	jsSystemCfg, _ := json.Marshal(currentSystemConfig())
	if jsSystemCfg == nil {
		jsSystemCfg = []byte("{}")
	}

	stats := getDashboardStats()
	chartSVG, latencySVG, nicHTML := buildDashboardMetricsParts(stats)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	writeDashboardHeader(w, jsConfigSafe, jsSystemCfg)
	writeDashboardTop(w, statusClass, statusText)
	_, _ = fmt.Fprintf(w, "%s", buildSettingsModal(cfg))
	writeDashboardConfigCard(w)
	writeDashboardMetricsCard(w, stats, nicHTML, chartSVG, latencySVG)

	if cfg.DebugEnabled || cfg.DebugHTTPRaw {
		writeDebugCard(w)
	}
	if len(logs) > 0 {
		writeLogsCard(w, logs, logTimeRange)
	}

	writeDomainsCard(w, statusData)
	writeDashboardFooter(w)
	_ = r
}

func loadStatusData() map[string]interface{} {
	statusMutex.Lock()
	defer statusMutex.Unlock()

	data := make(map[string]interface{})
	if fileData, err := os.ReadFile(updatePath); err == nil {
		_ = json.Unmarshal(fileData, &data)
	}
	return data
}

func dashboardStatus() (string, string) {
	if !lastOk.Load() {
		return "status-error", T.StatusErr
	}
	return "status-ok", T.StatusOk
}

func getDashboardStats() map[string]interface{} {
	latestMetricsMu.RLock()
	stats := latestMetrics
	latestMetricsMu.RUnlock()

	if stats == nil {
		stats = apiMetrics.GetStats()
	}
	return stats
}

func buildDashboardMetricsParts(stats map[string]interface{}) (string, string, string) {
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
	nicHTML := buildNICHTML(stats)

	return chartSVG, latencySVG, nicHTML
}

func buildNICHTML(stats map[string]interface{}) string {
	hasIPv64 := false
	for _, dc := range cfg.DomainConfigs {
		if dc.Provider == ProviderIPv64 {
			hasIPv64 = true
			break
		}
	}
	if !hasIPv64 {
		return ""
	}

	return `<div style="display:flex; justify-content:space-between; padding:4px 8px; background:rgba(251,191,36,0.08); border-radius:5px; grid-column:1/-1;">` +
		`<span style="font-size:0.7rem; color:#94a3b8; font-weight:600;">NIC <span style="font-weight:400; opacity:0.6;">(` + T.NicIPv64Updates + `)</span></span>` +
		`<span id="mDailyNIC" style="font-size:0.95rem; font-weight:700; color:#fbbf24; font-family:monospace;">` +
		fmt.Sprintf("%v", stats["daily_nic"]) +
		`</span></div>`
}

type logCachePayload struct {
	Logs         []LogEntry `json:"logs"`
	LogTimeRange string     `json:"log_time_range"`
}

func loadDashboardLogs() ([]LogEntry, string) {
	var logs []LogEntry
	var logTimeRange string

	if loadLogsFromDiskCache(&logs, &logTimeRange) {
		return logs, logTimeRange
	}

	logs, logTimeRange = loadLogsFromMainFile()
	saveLogsToDiskCache(logs, logTimeRange)

	return logs, logTimeRange
}

func loadLogsFromDiskCache(logs *[]LogEntry, logTimeRange *string) bool {
	logCacheWriteMu.Lock()
	defer logCacheWriteMu.Unlock()

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
	if len(payload.Logs) == 0 {
		return false
	}

	*logs = payload.Logs
	*logTimeRange = payload.LogTimeRange
	return true
}

func loadLogsFromMainFile() ([]LogEntry, string) {
	f, err := os.Open(logPath)
	if err != nil {
		return nil, ""
	}
	defer func() {
		if err := f.Close(); err != nil {
			log(LogContext{
				Level:    LogError,
				Category: "FILE",
				Action:   ActionError,
				Message:  fmt.Sprintf("%s: %v", t(T.FileCloseError, "Failed to close file"), err),
			})
		}
	}()

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
	if err := scanner.Err(); err != nil {
		if err := scanner.Err(); err != nil {
			log(LogContext{
				Level:    LogError,
				Category: "FILE",
				Action:   ActionError,
				Message:  fmt.Sprintf("%s: %v", t(T.ScannerError, "Scanner error"), err),
			})
		}
	}

	if count > limit {
		count = limit
	}

	var logs []LogEntry
	for i := 1; i <= count; i++ {
		line := ring[(head-i+limit)%limit]
		var e LogEntry
		if json.Unmarshal([]byte(line), &e) == nil {
			e.Timestamp = formatDashboardLogTimestamp(e.Timestamp)
			logs = append(logs, e)
		}
	}

	logTimeRange := ""
	if len(logs) > 0 {
		latest := logs[0].Timestamp
		oldest := logs[len(logs)-1].Timestamp
		logTimeRange = fmt.Sprintf("%s — %s", oldest, latest)
	}

	return logs, logTimeRange
}

func saveLogsToDiskCache(logs []LogEntry, logTimeRange string) {
	payload, err := json.Marshal(logCachePayload{
		Logs:         logs,
		LogTimeRange: logTimeRange,
	})
	if err != nil {
		return
	}

	logCacheWriteMu.Lock()
	defer logCacheWriteMu.Unlock()

	tmp := logCachePath + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o600); err == nil {
		if err := os.Rename(tmp, logCachePath); err != nil {
			_ = os.Remove(tmp)
		}
	}
}

func formatDashboardLogTimestamp(ts string) string {
	t, err := time.Parse("2006-01-02T15:04:05", ts)
	if err != nil {
		return ts
	}
	return t.Format("02.01.2006 15:04:05")
}

func writeDashboardHeader(w http.ResponseWriter, jsConfigSafe, jsSystemCfg []byte) {
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html><html><head>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<title>%s</title>
		<link id="favicon" rel="icon" type="image/svg+xml" href="/favicon.svg?theme=dark">
		<style>%s</style>
		<script>const initialConfig = %s; const initialSystem = %s;</script>
	</head>
	<body>
	<div class="container">
		<div class="header">
			<h1>🌐 %s</h1>
			<div style="display: flex; gap: 10px; align-items: center;">
				<button class="action-btn" onclick="triggerUpdate()">🔄 `+T.Update+`</button>
				<button class="action-btn" onclick="exportData()">📥 `+T.ExportBtn+`</button>
				<button class="theme-toggle" onclick="toggleTheme()">🌓</button>
				<button class="menu-btn" onclick="openSettings()" title="`+T.SettingsTitle+`">⋮</button>
			</div>
		</div>`,
		html.EscapeString(T.DashTitle),
		cssData,
		string(jsConfigSafe),
		string(jsSystemCfg),
		html.EscapeString(T.DashTitle),
	)
}

func writeDashboardTop(w http.ResponseWriter, statusClass, statusText string) {
	_, _ = fmt.Fprintf(w, `
		<div class="status-banner `+statusClass+`">
			<span>`+statusText+`</span>
			<span>
				`+T.LastUpdate+`: <span id="lastUpdate">`+time.Now().Local().Format("15:04:05")+`</span>
				<span style="opacity:0.6; margin: 0 8px;">|</span>
				🕒 <span id="clock">--:--:--</span>
				<span style="opacity:0.6; margin: 0 8px;">|</span>
				⏱️ <span id="uptime">%s</span>
			</span>
		</div>

		<div id="toast" class="toast"></div>

		<details class="card" id="endpoint-card">
			<summary>📡 IP-Endpunkt Status</summary>
			<div class="card-content">
				<div id="endpoint-status" class="endpoint-status">
					<span style="opacity:0.4;font-size:0.82rem;">Warte auf ersten Check...</span>
				</div>
			</div>
		</details>
	`, formatUptime(time.Since(startTime)))
}

func writeDashboardConfigCard(w http.ResponseWriter) {
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
}

func writeDashboardMetricsCard(w http.ResponseWriter, stats map[string]interface{}, nicHTML, chartSVG, latencySVG string) {
	_, _ = fmt.Fprintf(w, `
	<details class="card" open id="metrics-card">
		<summary style="display:flex; justify-content:space-between; align-items:center;">📊 %s<button class="action-btn" style="background:var(--error); font-size:0.7rem; padding:3px 10px; margin-left:auto;" onclick="event.preventDefault(); resetMetrics()">🗑️ `+T.MetricsResetBtn+`</button></summary>
		<div class="card-content">
			<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-top: 10px;">
				<div><strong>`+T.TotalRequests+`:</strong> <span id="mTotal">%v</span></div>
				<div><strong>`+T.SuccessRate+`:</strong> <span id="mSuccess" style="color:var(--success)">%v</span></div>
				<div><strong>`+T.AvgLatency+`:</strong> <span id="mLatency">%v</span></div>
				<div title="`+T.ClientErrors+` / `+T.ServerErrors+`"><strong>`+T.Errors+`:</strong> <span id="mErrors">%v / %v</span></div>
			</div>
			<div style="margin-top: 14px; padding: 12px 14px; background: rgba(139,92,246,0.08); border: 1px solid rgba(139,92,246,0.2); border-radius: 8px;">
				<div style="font-size: 0.68rem; color: #94a3b8; letter-spacing: 0.06em; margin-bottom: 8px; font-weight: 600; text-transform: uppercase;">`+T.MetricLatencyPercentile+`</div>
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
				<div style="display: flex; justify-content: space-between; align-items: baseline; font-size: 0.7rem; color: #94a3b8; margin-bottom: 6px;">
					<span style="letter-spacing: 0.04em;">`+T.HourlyLimitEst+`</span>
					<span id="mUsage" style="font-weight: 600; color: var(--text);">
						%v / %v `+T.RequestsLabel+`
					</span>
				</div>
				<div style="width: 100%%; background: #334155; height: 8px; border-radius: 999px; overflow: hidden;">
					<div id="mUsageBar" style="width: %v%%; height: 100%%; background: %s; transition: width 0.5s ease;">
					</div>
				</div>
				<div style="font-size: 0.65rem; color: #64748b; margin-top: 6px;">
					`+T.UsageLast60Min+`
				</div>
			</div>
			<div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-top:14px;">
				<div style="padding:12px 14px; background:rgba(56,189,248,0.08); border:1px solid rgba(56,189,248,0.2); border-radius:8px;">
					<div style="font-size:0.68rem; color:#94a3b8; letter-spacing:0.06em; margin-bottom:8px; font-weight:600; text-transform:uppercase;">`+T.MetricHTTPMethods+`</div>
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
					<div style="font-size:0.68rem; color:#94a3b8; letter-spacing:0.06em; margin-bottom:8px; font-weight:600; text-transform:uppercase;">`+T.MetricIPLatency+`</div>
					<div style="text-align:center; padding:4px 0;">
						<div id="mIPLatency" style="font-size:1.4rem; font-weight:700; color:#a78bfa; font-family:monospace;">%v</div>
						<div style="font-size:0.65rem; color:#64748b; margin-top:4px;">`+T.MetricAvgFrom+` <span id="mIPCount">%v</span> `+T.ChecksLabel+`</div>
						<div style="font-size:0.65rem; color:#64748b; margin-top:2px;">`+T.MetricLastCheck+` <span id="mLastIPCheck">%v</span></div>
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
		latencySVG,
	)
}

func writeDebugCard(w http.ResponseWriter) {
	_, _ = fmt.Fprint(w, `
		<details class="card" id="debug-log-card" open>
			<summary>🐞 Debug Log <span id="debug-badge" class="debug-badge">LIVE</span></summary>
			<div class="card-content">
				<div class="debug-toolbar">
					<input type="text" id="debug-filter" placeholder="Filter..." 
						oninput="filterDebugLog(this.value)"
						class="debug-filter-input">
					<button onclick="clearDebugLog()" class="action-btn debug-clear-btn">🗑️ Clear</button>
					<label class="debug-autoscroll-label">
						<input type="checkbox" id="debug-autoscroll" checked>
						Auto-scroll
					</label>
				</div>
				<div id="debug-log-container" class="debug-log-box">
					<span class="debug-placeholder">Waiting for debug messages...</span>
				</div>
			</div>
		</details>
	`)
}

func writeLogsCard(w http.ResponseWriter, logs []LogEntry, logTimeRange string) {
	_, _ = fmt.Fprintf(w, `
	<details class="card" id="logs-card">
		<summary>
			🧾 %s 
			<span class="logs-summary-meta">
				(%d `+T.EntriesLabel+`)
				<span class="logs-summary-sep">
					🕒 %s
				</span>
			</span>
		</summary>
		<div class="card-content">
			<div class="log-filters">
				<button class="filter-btn active" data-filter="all" onclick="filterLogs('all')">`+T.FilterAll+`</button>
				<button class="filter-btn" data-filter="ERR" onclick="filterLogs('ERR')">`+T.FilterErrors+`</button>
				<button class="filter-btn" data-filter="WARN" onclick="filterLogs('WARN')">`+T.FilterWarnings+`</button>
				<button class="filter-btn" data-filter="UPDATE" onclick="filterLogs('UPDATE')">`+T.FilterUpdates+`</button>
				<button class="filter-btn" data-filter="START" onclick="filterLogs('START')">`+T.FilterStarts+`</button>
				<button class="filter-btn" data-filter="STOP" onclick="filterLogs('STOP')">`+T.FilterStop+`</button>
				<button class="filter-btn" data-filter="CREATE" onclick="filterLogs('CREATE')">`+T.FilterCreated+`</button>
				<button class="filter-btn" data-filter="CLEANUP" onclick="filterLogs('CLEANUP')">`+T.FilterCleanup+`</button>
				<button class="filter-btn" data-filter="SKIP" onclick="filterLogs('SKIP')">`+T.FilterSkip+`</button>
				<button class="filter-btn" data-filter="CONFIG" onclick="filterLogs('CONFIG')">`+T.FilterConfig+`</button>
			</div>
			<div id="logContainer" class="log-container">
	`, T.SystemEvents, len(logs), logTimeRange)

	for _, e := range logs {
		displayTime := e.Timestamp
		if t, err := time.Parse(time.RFC3339, e.Timestamp); err == nil {
			displayTime = t.Local().Format("02.01.2006 15:04")
		}

		actionUpper := strings.ToUpper(e.Action)
		icon := IconDefault
		if v, ok := actionIcons[actionUpper]; ok {
			icon = v
		}

		domainHTML := ""
		if e.Domain != "" {
			domainHTML = `<span class="log-entry-domain">` + html.EscapeString(e.Domain) + `</span>`
		}

		_, _ = fmt.Fprintf(w, `
		<div class="log-entry log-entry-row" data-action="%s" data-level="%s">
			<span class="log-entry-icon">%s</span>
			<span class="log-entry-time">%s</span>
			<div class="log-entry-body">
				%s
				<span class="log-entry-message">%s</span>
			</div>
		</div>
		`,
			actionUpper,
			e.Level,
			icon,
			displayTime,
			domainHTML,
			html.EscapeString(e.Message),
		)
	}

	_, _ = fmt.Fprint(w, `
			</div>
		</div>
	</details>
	`)
}

func writeDomainsCard(w http.ResponseWriter, data map[string]interface{}) {
	keys := domainKeysFromStatusData(data)
	configuredDomains := configuredDomainSet()
	newestChange := newestDomainChange(data, keys)

	_, _ = fmt.Fprint(w, `
	<details class="card" open id="domains-card">
		<summary>🌐 Domains</summary>
		<div class="card-content">
			<input type="text"
				class="search-box"
				id="domainSearch"
				placeholder="`+T.DomainSearchPlaceholder+`"
				oninput="filterDomains(this.value)">
			<div id="domainContainer">
	`)

	for _, k := range keys {
		h := parseDomainHistory(data[k])
		writeSingleDomainCard(w, k, h, configuredDomains, newestChange)
	}

	_, _ = fmt.Fprint(w, `
			</div>
		</div>
	</details>
	`)
}

func domainKeysFromStatusData(data map[string]interface{}) []string {
	var keys []string
	for k := range data {
		if !strings.HasPrefix(k, "_") {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

func configuredDomainSet() map[string]struct{} {
	configured := make(map[string]struct{})
	for _, dc := range cfg.DomainConfigs {
		configured[strings.ToLower(strings.TrimSuffix(dc.FQDN, "."))] = struct{}{}
	}
	return configured
}

func newestDomainChange(data map[string]interface{}, keys []string) time.Time {
	var newestChange time.Time
	for _, k := range keys {
		dh := parseDomainHistory(data[k])
		if dh.LastChanged == "" {
			continue
		}
		if t, err := time.Parse("02.01.2006 15:04:05", dh.LastChanged); err == nil && t.After(newestChange) {
			newestChange = t
		}
	}
	return newestChange
}

func parseDomainHistory(v interface{}) DomainHistory {
	var h DomainHistory
	b, _ := json.Marshal(v)
	_ = json.Unmarshal(b, &h)
	return h
}

func writeSingleDomainCard(w http.ResponseWriter, domain string, h DomainHistory, configuredDomains map[string]struct{}, newestChange time.Time) {
	latest := IPEntry{}
	if len(h.IPs) > 0 {
		latest = h.IPs[len(h.IPs)-1]
	}

	safeID := sanitizeIDWithHash(domain)
	_, isActive := configuredDomains[strings.ToLower(strings.TrimSuffix(domain, "."))]
	isOrphan := !isActive

	dotClass, dotTitle, changedBadge := buildDomainStatusVisuals(h, safeID, newestChange)
	orphanStyle, orphanLabel, deleteBtn := buildOrphanDomainVisuals(isOrphan, domain)

	_, _ = fmt.Fprintf(w, `
	<details class="card domain-item" data-domain="%s"%s>
		<summary class="domain-summary">
			<span id="dot-%s" class="%s" title="%s"></span>
			🌐 %s <span class="logs-summary-meta">(%s)</span>%s%s%s
		</summary>
		
		<div class="card-content">
			<div class="domain-card domain-card-head">
				<div class="domain-card-top">
					<div>
						<div class="ip-display">
							<span class="badge v4">IPv4</span>
							<span id="ip4-%s">%s</span>
							<button class="copy-btn" onclick="copyIP('%s')" title="Copy">📋</button>
						</div>
						<div class="ip-display domain-ip-row-spaced">
							<span class="badge v6">IPv6</span>
							<span id="ip6-%s">%s</span>
							<button class="copy-btn" onclick="copyIP('%s')" title="Copy">📋</button>
						</div>
					</div>
					<div class="domain-card-meta">
						<small>`+T.LastShort+` %s</small>
					</div>
				</div>
			</div>

			<div class="domain-history-box">
				<table class="domain-history-table">
					<thead class="domain-history-head">
						<tr>
							<th class="domain-history-th-time">`+T.TableTime+`</th>
							<th class="domain-history-th-ip">`+T.TableIPs+`</th>
						</tr>
					</thead>
					<tbody>`,
		html.EscapeString(domain),
		orphanStyle,
		safeID,
		dotClass,
		dotTitle,
		html.EscapeString(domain),
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

	writeDomainHistoryRows(w, h)

	_, _ = fmt.Fprint(w, `
					</tbody>
				</table>
			</div>
		</div>
	</details>`)
}

func buildDomainStatusVisuals(h DomainHistory, safeID string, newestChange time.Time) (string, string, string) {
	dotClass := "domain-status-dot dot-idle"
	dotTitle := T.DotTitleNoUpdate
	changedBadge := `<span id="badge-` + safeID + `" class="changed-badge" style="display:none;">` + T.BadgeChanged + `</span>`

	if h.LastChanged == "" {
		return dotClass, dotTitle, changedBadge
	}

	t, err := time.Parse("02.01.2006 15:04:05", h.LastChanged)
	if err != nil {
		return dotClass, dotTitle, changedBadge
	}

	switch {
	case time.Since(t) < 15*time.Minute:
		dotClass = "domain-status-dot dot-ok dot-recent"
		dotTitle = T.DotTitleChanged + h.LastChanged
		changedBadge = `<span id="badge-` + safeID + `" class="changed-badge">` + T.BadgeChanged + `</span>`
	case !newestChange.IsZero() && t.Before(newestChange.Add(-time.Minute)):
		dotClass = "domain-status-dot dot-warn"
		dotTitle = T.DotTitleLast + h.LastChanged + T.DotTitleOther
	default:
		dotClass = "domain-status-dot dot-ok"
		dotTitle = T.DotTitleActive + h.LastChanged
	}

	return dotClass, dotTitle, changedBadge
}

func buildOrphanDomainVisuals(isOrphan bool, domain string) (string, string, string) {
	if !isOrphan {
		return "", "", ""
	}

	orphanStyle := ` style="border-color: rgba(248,113,113,0.5);"`
	orphanLabel := `<span class="orphan-badge">` + T.NotConfiguredLabel + `</span>`
	deleteBtn := `<button class="action-btn btn-danger-soft" onclick="event.preventDefault(); event.stopPropagation(); deleteDomain('` + html.EscapeString(domain) + `', this)">` + T.RemoveBtn + `</button>`

	return orphanStyle, orphanLabel, deleteBtn
}

func writeDomainHistoryRows(w http.ResponseWriter, h DomainHistory) {
	for i := len(h.IPs) - 2; i >= 0; i-- {
		e := h.IPs[i]

		v4 := "—"
		if e.IPv4 != "" {
			v4 = html.EscapeString(e.IPv4)
		}

		v6 := "—"
		if e.IPv6 != "" {
			v6 = html.EscapeString(e.IPv6)
		}

		_, _ = fmt.Fprintf(w, `
			<tr class="domain-history-row">
				<td class="domain-history-td-time">
					%s
				</td>
				<td class="domain-history-td-ip">
					<div class="ip-history-stack">
						<div class="ip-history-row">
							<span class="badge v4 badge-fixed">v4</span>
							<span class="ip-history-value">%s</span>
						</div>
						<div class="ip-history-row">
							<span class="badge v6 badge-fixed">v6</span>
							<span class="ip-history-value break-all">%s</span>
						</div>
					</div>
				</td>
			</tr>`,
			html.EscapeString(e.Time),
			v4,
			v6,
		)
	}

	if len(h.IPs) < 2 {
		_, _ = fmt.Fprint(w, `<tr class="empty-history-row"><td colspan="2">`+T.NoMoreEntries+`</td></tr>`)
	}
}

func writeDashboardFooter(w http.ResponseWriter) {
	_, _ = fmt.Fprintf(w, `
	<script>
		window.I18N = %s;
	</script>
	<script>%s</script>
	</div>
	</body>
	</html>
	`, dashboardI18NJSON(), jsData)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
