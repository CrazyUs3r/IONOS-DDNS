// Package main
package main

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed templates/css/style.css
var cssData string

//go:embed templates/js/dashboard.js
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
	tooltipValues := make([]float64, len(data))

	for i, val := range data {
		x := float64(i) * (width / 23.0)
		y := height - (float64(val) * height / renderMax)
		points = append(points, [2]float64{x, y})
		tooltipValues[i] = float64(val)
	}

	tooltipPoints := buildChartTooltipPoints(points, tooltipValues, " req")

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
	now := time.Now()

	offsets := []int{24, 18, 12, 6, 0}

	for _, off := range offsets {
		h := now.Add(-time.Duration(off) * time.Hour).Hour()
		if off == 0 {
			fmt.Fprintf(&labelsBuilder, `<span class="chart-x-current">%02dh</span>`, h)
		} else {
			fmt.Fprintf(&labelsBuilder, "<span>%02dh</span>", h)
		}
	}
	timeLabels := labelsBuilder.String()

	return fmt.Sprintf(`
		<div class="card">
			<div class="card-header">📈 %s</div>
			<div class="card-content chart-wrap pr-10">
				<div class="chart-y-axis req">
					<div class="chart-y-label top">%.0f</div>
					<div class="chart-y-label middle">%.0f</div>
					<div class="chart-y-label bottom">0</div>
				</div>
					<svg viewBox="0 0 300 60" preserveAspectRatio="none" class="chart-svg">
						<path d="%s L 300,60 L 0,60 Z" fill="rgba(56,189,248,0.1)"/>
						<path d="%s" fill="none" stroke="#38bdf8" stroke-width="2" stroke-linecap="round"/>
						<line class="chart-hover-line" x1="0" y1="0" x2="0" y2="60"/>
						<circle class="chart-hover-dot" cx="0" cy="0" r="3"/>
						%s
					</svg>
				<div class="chart-x-labels">
					%s
				</div>
			</div>
		</div>`, T.RequestHistory, renderMax, renderMax/2, pathData, pathData, tooltipPoints, timeLabels)
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

	tooltipPoints := buildChartTooltipPoints(points, pointsData, " ms")

	var pathData strings.Builder
	fmt.Fprintf(&pathData, "M %.1f,%.1f", points[0][0], points[0][1])
	for i := 0; i < len(points)-1; i++ {
		p0, p1 := points[i], points[i+1]
		cp1x := p0[0] + (p1[0]-p0[0])/2
		fmt.Fprintf(&pathData, " C %.1f,%.1f %.1f,%.1f %.1f,%.1f", cp1x, p0[1], cp1x, p1[1], p1[0], p1[1])
	}

	var labelsBuilder strings.Builder
	now := time.Now()

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
		<div class="card">
			<div class="card-header">⚡ %s</div>
			<div class="card-content chart-wrap pr-5">
				<div class="chart-y-axis latency">
					<div class="chart-y-label top">%.0fms</div>
					<div class="chart-y-label middle">%.0fms</div>
					<div class="chart-y-label bottom">0</div>
				</div>
				<svg viewBox="0 0 300 60" preserveAspectRatio="none" class="chart-svg chart-svg-overflow">
					<path d="%s L 300,60 L 0,60 Z" fill="rgba(139,92,246,0.15)"/>
					<path d="%s" fill="none" stroke="#a78bfa" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
					<line class="chart-hover-line" x1="0" y1="0" x2="0" y2="60"/>
					<circle class="chart-hover-dot" cx="0" cy="0" r="3"/>
					%s
				</svg>
				<div class="chart-x-labels">
					%s
				</div>
			</div>
		</div>`, T.LatencyHistory, renderMax, renderMax/2, pathData.String(), pathData.String(), tooltipPoints, timeLabels)
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

func buildChartTooltipPoints(points [][2]float64, values []float64, unit string) string {
	var b strings.Builder
	now := time.Now()

	for i, p := range points {
		label := now.Add(-time.Duration(len(points)-1-i) * time.Hour).Format("15:00")

		fmt.Fprintf(&b,
			`<circle class="chart-point" cx="%.1f" cy="%.1f" r="4" data-x="%.1f" data-y="%.1f" data-value="%.0f" data-label="%s" data-unit="%s"></circle>`,
			p[0],
			p[1],
			p[0],
			p[1],
			values[i],
			html.EscapeString(label),
			html.EscapeString(unit),
		)
	}

	return b.String()
}

// ============================================================================
// DASHBOARD HTTP HANDLER
// ============================================================================
func buildSettingsInlineSection(title, body string) string {
	return `<div class="s-section s-section--spaced">` +
		`<div class="s-section-label s-section-label--heading">` + title + `</div>` +
		body +
		`</div>`
}

func buildSettingsSubSection(id, title, body string) string {
	idAttr := ""
	if id != "" {
		idAttr = ` id="` + id + `"`
	}

	return `<details class="s-subsection"` + idAttr + `><summary class="s-subsection-summary"><span>` + title + `</span><span class="s-subsection-chevron">▾</span></summary><div class="s-subsection-content">` + body + `</div></details>`
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
		{ActionUpdate, T.NotifyEventUpdateLabel, T.NotifyEventUpdateDesc},
		{ActionCreate, T.NotifyEventCreateLabel, T.NotifyEventCreateDesc},
		{ActionCurrent, T.NotifyEventCurrentLabel, T.NotifyEventCurrentDesc},
		{ActionInfo, T.NotifyEventInfoLabel, T.NotifyEventInfoDesc},
		{ActionRetry, T.NotifyEventRetryLabel, T.NotifyEventRetryDesc},
		{ActionError, T.NotifyEventErrorLabel, T.NotifyEventErrorDesc},
		{ActionStart, T.NotifyEventStartLabel, T.NotifyEventStartDesc},
		{ActionStop, T.NotifyEventStopLabel, T.NotifyEventStopDesc},
		{ActionConfig, T.NotifyEventConfigLabel, T.NotifyEventConfigDesc},
		{ActionZone, T.NotifyEventZoneLabel, T.NotifyEventZoneDesc},
		{ActionDryRun, T.NotifyEventDryRunLabel, T.NotifyEventDryRunDesc},
		{ActionCleanup, T.NotifyEventCleanupLabel, T.NotifyEventCleanupDesc},
		{ActionSkip, T.NotifyEventSkipLabel, T.NotifyEventSkipDesc},
		{ActionAPI, T.NotifyEventAPILabel, T.NotifyEventAPIDesc},
		{ActionServer, T.NotifyEventServerLabel, T.NotifyEventServerDesc},
	}

	var out strings.Builder
	out.WriteString(`<div class="notify-events-list">`)

	for _, ev := range events {
		chk := ""
		if active[ev.code] {
			chk = HTMLChecked
		}

		fmt.Fprintf(&out, `<label class="notify-event-item"><input type="checkbox" name="notify-event" value="%s"%s><span class="notify-event-text"><span class="notify-event-title">%s</span><span class="notify-event-desc">%s</span></span></label>`,
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

func selected(v bool) string {
	if v {
		return HTMLSelected
	}
	return ""
}

func buildSettingsSecuritySection() string {
	return `<div class="s-row s-row-stack s-gap-8"><span class="s-label">` + T.SettingsTriggerToken + `</span><div class="input-with-action"><input type="password" id="s-token" class="s-input" placeholder="` + T.SettingsTokenPlaceholder + `" autocomplete="off"><button type="button" class="input-action-btn" data-click="togglePassword('s-token', this)">👁️</button></div><button class="s-btn" data-click="saveToken()">` + T.SettingsTokenSave + `</button></div>`
}

func buildSettingsSystemSection(c Config) string {
	return `<div class="s-row"><span class="s-label">` + T.SettingsIPMode + `</span><select id="cfg-ip-mode" class="s-input s-select-auto-sm">` +
		buildSettingsIPModeOptions(c.IPMode) +
		`</select></div>` +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsInterval+`</span><input type="number" id="cfg-interval" class="s-input s-input-sm-right" min="30" max="86400" value="%d"></div>`, c.Interval) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsHealthPort+`</span><input type="text" id="cfg-health-port" class="s-input s-input-sm-right" value="%s"></div>`, html.EscapeString(c.HealthPort)) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsIface+` <small class="s-label-hint-inline">`+T.SettingsIfaceHint+`</small></span><input type="text" id="cfg-iface" class="s-input s-input-md" placeholder="`+T.SettingsIfacePlaceholder+`" value="%s"></div>`, html.EscapeString(c.IfaceName)) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsDNS+` <small class="s-label-hint-inline">(`+T.SettingsDNSHint+`)</small></span><input type="text" id="cfg-dns" class="s-input s-input-lg" placeholder="1.1.1.1, 8.8.8.8:53" value="%s"></div>`,
			html.EscapeString(strings.Join(c.DNSServers, ", ")),
		) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsMaxLog+`</span><input type="number" id="cfg-max-log" class="s-input s-input-sm-right" min="100" max="50000" value="%d"></div>`, c.MaxLogLines) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsMaxRetries+`</span><input type="number" id="cfg-max-retries" class="s-input s-input-sm-right" min="0" max="20" value="%d"></div>`, c.MaxAPIRetries) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsMaxConcurrent+`</span><input type="number" id="cfg-max-concurrent" class="s-input s-input-sm-right" min="1" max="20" value="%d"></div>`, c.MaxConcurrent) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsHourlyLimit+`</span><input type="number" id="cfg-hourly-limit" class="s-input s-input-sm-right" min="100" max="100000" value="%d"></div>`, c.HourlyRateLimit) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsIPv4Endpoints+`<small class="s-label-hint-block">(`+T.SettingsDNSHint+`)</small></span><input type="text" id="cfg-ipv4_endpoints" class="s-input s-input-lg" placeholder="https://4.ident.me/, https://4.tnedi.me/" value="%s"></div>`,
			html.EscapeString(strings.Join(c.IPv4Endpoints, ", ")),
		) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsIPv6Endpoints+`<small class="s-label-hint-block">(`+T.SettingsDNSHint+`)</small></span><input type="text" id="cfg-ipv6_endpoints" class="s-input s-input-lg" placeholder="https://6.ident.me/, https://6.tnedi.me/" value="%s"></div>`,
			html.EscapeString(strings.Join(c.IPv6Endpoints, ", ")),
		) +

		`<div class="s-row"><span class="s-label">` + T.SettingsLanguage + `</span><select id="cfg-lang" class="s-input s-select-auto-md">` +
		buildDynamicLangOptions(c.Lang) +
		`</select></div>` +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsDryRun+`<small class="s-label-hint-block">`+T.SettingsDryRunHint+`</small></span><label class="s-checkbox-container"><input type="checkbox" id="cfg-dry-run" class="s-checkbox-dynamic" data-change="updateCheckboxLabel(this)" data-label-on="%s" data-label-off="%s"%s><span class="s-checkbox-text">%s</span></label></div>`,
			T.SettingsCheckboxActive, T.SettingsCheckboxDeactive,
			checkedAttr(c.DryRun),
			checkboxLabel(c.DryRun),
		) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">Debug-Modus <small class="s-label-hint-block">`+T.SettingsDebugVerboseHint+`</small></span><label class="s-checkbox-container"><input type="checkbox" id="cfg-debug" class="s-checkbox-dynamic" data-change="updateCheckboxLabel(this)" data-label-on="%s" data-label-off="%s"%s><span class="s-checkbox-text">%s</span></label></div>`,
			T.SettingsCheckboxActive, T.SettingsCheckboxDeactive,
			checkedAttr(c.DebugEnabled),
			checkboxLabel(c.DebugEnabled),
		) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">Debug HTTP Raw <small class="s-label-hint-block">`+T.SettingsDebugHTTPHint+`</small></span><label class="s-checkbox-container"><input type="checkbox" id="cfg-debug-http" class="s-checkbox-dynamic" data-change="updateCheckboxLabel(this)" data-label-on="%s" data-label-off="%s"%s><span class="s-checkbox-text">%s</span></label></div>`,
			T.SettingsCheckboxActive, T.SettingsCheckboxDeactive,
			checkedAttr(c.DebugHTTPRaw),
			checkboxLabel(c.DebugHTTPRaw),
		)
}

func buildSettingsDomainsSection() string {
	addDomainForm := `<div class="add-domain-box"><input type="text" id="new-domain-fqdn" class="s-input mb-8" placeholder="` + T.SettingsDomainPlaceholder + `"><input type="number" id="new-domain-ttl" class="s-input mb-8" placeholder="TTL (z. B. 60)" min="1" step="1"><select id="new-domain-ip-mode" class="s-input mb-8"><option value="">` + T.SettingsIPMode + ` (` + T.SettingsIPMode + ` global)</option><option value="BOTH">BOTH – IPv4 + IPv6</option><option value="IPV4">IPV4 – nur IPv4</option><option value="IPV6">IPV6 – nur IPv6</option></select><select id="new-domain-provider" class="s-input mb-8" data-change="toggleProviderFields()"><option value="IONOS">IONOS</option><option value="CLOUDFLARE">Cloudflare</option><option value="IPV64">IPv64</option><option value="HETZNER">Hetzner DNS</option><option value="HETZNERCLOUD">Hetzner Cloud DNS</option></select><div id="fields-ionos"><input type="text" id="new-ionos-prefix" class="s-input mb-8" placeholder="` + T.SettingsAPIPrefix + `"><div class="input-with-action mt-8"><input type="password" id="new-ionos-secret" class="s-input" placeholder="` + T.SettingsAPISecret + `"><button type="button" class="input-action-btn" data-click="togglePassword('new-ionos-secret', this)">👁️</button></div></div><div id="fields-cloudflare" class="is-hidden"><input type="text" id="new-cf-token" class="s-input mb-8" placeholder="` + T.SettingsCFTokenHint + `"><div class="center-note">` + T.SettingsCFOr + `</div><input type="text" id="new-cf-email" class="s-input mb-8" placeholder="` + T.SettingsCFEmail + `"><div class="input-with-action mt-8"><input type="password" id="new-cf-secret" class="s-input" placeholder="` + T.SettingsCFGlobalKey + `"><button type="button" class="input-action-btn" data-click="togglePassword('new-cf-secret', this)">👁️</button></div><label class="inline-check"><input type="checkbox" id="new-cf-proxied"> ` + T.SettingsCFProxyLabel +
		`</label></div><div id="fields-ipv64" class="is-hidden"><div class="input-with-action mt-8"><input type="password" id="new-ipv64-token" class="s-input" placeholder="` + T.SettingsIPv64Token + `"><button type="button" class="input-action-btn" data-click="togglePassword('new-ipv64-token', this)">👁️</button></div></div><div id="fields-hetzner" class="is-hidden"><div class="input-with-action mt-8"><input type="password" id="new-hetzner-token" class="s-input" placeholder="Hetzner DNS API Token"><button type="button" class="input-action-btn" data-click="togglePassword('new-hetzner-token', this)">👁️</button></div></div><div id="fields-hetznercloud" class="is-hidden"><div class="input-with-action mt-8"><input type="password" id="new-hcloud-token" class="s-input" placeholder="Hetzner Cloud/Console Token"><button type="button" class="input-action-btn" data-click="togglePassword('new-hcloud-token', this)">👁️</button></div></div><div class="s-btn-row"><button class="s-btn s-btn-success-full" data-click="addDomainToList()">` +
		T.SettingsAddBtn +
		`</button><button type="button" class="s-btn s-btn--cancel" data-click="cancelEdit()">` +
		T.SettingsCancelBtn +
		`</button></div>`

	return `<div id="settings-domain-list" class="settings-domain-list"></div>` +
		buildSettingsSubSection("add-domain-section", T.SettingsAddDomain, addDomainForm)
}

func buildSettingsNotifySection(c Config) string {
	notifyEventsSection := `<div class="s-row s-row-stack s-gap-6"><span class="s-label">` + T.SettingsNotifyEvents + `</span>` +
		buildSettingsNotifyEventCheckboxes(c.Notifications.Events) +
		`</div>`

	telegramSection := `<div class="notify-box notify-telegram">` +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsTGChatID+`</span><input type="text" id="cfg-tg-chat-id" class="s-input s-input-lg" placeholder="-100xxxxxxxxx" value="%s"></div>`,
			html.EscapeString(c.Notifications.Telegram.ChatID)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsTGToken+`</span><div class="input-with-action"><input type="password" id="cfg-tg-token" class="s-input s-input-lg" placeholder="`+T.SettingsTokenUnchanged+`" value="%s"><button type="button" class="input-action-btn" data-click="togglePassword('cfg-tg-token', this)">👁️</button></div></div>`,
			html.EscapeString(c.Notifications.Telegram.Token)) +
		`</div>`

	gotifySection := `<div class="notify-box notify-gotify">` +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsGotifyURL+`</span><input type="text" id="cfg-gotify-url" class="s-input s-input-lg" placeholder="https://gotify.example.com" value="%s"></div>`,
			html.EscapeString(c.Notifications.Gotify.URL)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsGotifyToken+`</span><div class="input-with-action"><input type="password" id="cfg-gotify-token" class="s-input s-input-lg" placeholder="`+T.SettingsTokenUnchanged+`" value="%s"><button type="button" class="input-action-btn" data-click="togglePassword('cfg-gotify-token', this)">👁️</button></div></div>`,
			html.EscapeString(c.Notifications.Gotify.Token)) +
		`</div>`

	webhookSection := `<div class="notify-box notify-webhook">` +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">URL</span><input type="text" id="cfg-webhook-url" class="s-input s-input-lg" placeholder="https://your-endpoint.com/api" value="%s"></div>`,
			html.EscapeString(c.Notifications.Webhook.URL)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">Secret <small class="s-label-hint-inline">(opt.)</small></span><div class="input-with-action"><input type="password" id="cfg-webhook-secret" class="s-input s-input-lg" placeholder="`+T.SettingsTokenUnchanged+`" value="%s"><button type="button" class="input-action-btn" data-click="togglePassword('cfg-webhook-secret', this)">👁️</button></div></div>`,
			html.EscapeString(c.Notifications.Webhook.Secret)) +
		`</div>`

	mqttSection := `<div class="notify-box notify-mqtt">` +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">Broker</span><input type="text" id="cfg-mqtt-broker" class="s-input s-input-lg" placeholder="tcp://192.168.1.10:1883" value="%s"></div>`,
			html.EscapeString(c.Notifications.MQTTConfig.Broker)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">Client ID</span><input type="text" id="cfg-mqtt-clientid" class="s-input s-input-lg" placeholder="go-dyndns" value="%s"></div>`,
			html.EscapeString(c.Notifications.MQTTConfig.ClientID)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">Username</span><input type="text" id="cfg-mqtt-username" class="s-input s-input-lg" placeholder="optional" value="%s"></div>`,
			html.EscapeString(c.Notifications.MQTTConfig.Username)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">Secret <small class="s-label-hint-inline">Password</small></span><div class="input-with-action"><input type="password" id="cfg-mqtt-password" class="s-input s-input-lg" placeholder="`+T.SettingsTokenUnchanged+`" value="%s"><button type="button" class="input-action-btn" data-click="togglePassword('cfg-mqtt-password', this)">👁️</button></div></div>`,
			html.EscapeString(c.Notifications.MQTTConfig.Password)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">Topic</span><input type="text" id="cfg-mqtt-topic" class="s-input s-input-lg" placeholder="dyndns/ip" value="%s"></div>`,
			html.EscapeString(c.Notifications.MQTTConfig.Topic)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">QoS</span><input type="number" min="0" max="2" id="cfg-mqtt-qos" class="s-input s-input-sm" value="%d"></div>`,
			c.Notifications.MQTTConfig.QoS) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">Retain</span><label class="s-checkbox-container"><input type="checkbox" id="cfg-mqtt-retain" class="s-checkbox-dynamic" data-change="updateCheckboxLabel(this)" data-label-on="%s" data-label-off="%s"%s><span class="s-checkbox-text">%s</span></label></div>`,
			T.SettingsCheckboxActive,
			T.SettingsCheckboxDeactive,
			checkedAttr(c.Notifications.MQTTConfig.Retain),
			checkboxLabel(c.Notifications.MQTTConfig.Retain),
		) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">Auto Discovery <small class="s-label-hint-inline">Home Assistant</small></span><label class="s-checkbox-container"><input type="checkbox" id="cfg-mqtt-discovery" class="s-checkbox-dynamic" data-change="updateCheckboxLabel(this)" data-label-on="%s" data-label-off="%s"%s><span class="s-checkbox-text">%s</span></label></div>`,
			T.SettingsCheckboxActive,
			T.SettingsCheckboxDeactive,
			checkedAttr(c.Notifications.MQTTConfig.Discovery),
			checkboxLabel(c.Notifications.MQTTConfig.Discovery),
		) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">Discovery Prefix</span><input type="text" id="cfg-mqtt-discovery-prefix" class="s-input s-input-lg" placeholder="homeassistant" value="%s"></div>`,
			html.EscapeString(c.Notifications.MQTTConfig.DiscoveryPrefix)) +
		`</div>`

	emailSection := `<div class="notify-box notify-email">` +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">SMTP Host</span><input type="text" id="cfg-email-host" class="s-input s-input-lg" placeholder="smtp.gmail.com" value="%s"></div>`,
			html.EscapeString(c.Notifications.Email.Host)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">Port</span><input type="text" id="cfg-email-port" class="s-input s-input-sm" placeholder="587" value="%d"></div>`,
			c.Notifications.Email.Port) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">User</span><input type="text" id="cfg-email-user" class="s-input s-input-lg" value="%s"></div>`,
			html.EscapeString(c.Notifications.Email.Username)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">Passwort</span><div class="input-with-action"><input type="password" id="cfg-email-pass" class="s-input s-input-lg" placeholder="***" value="%s"><button type="button" class="input-action-btn" data-click="togglePassword('cfg-email-pass', this)">👁️</button></div></div>`,
			html.EscapeString(c.Notifications.Email.Password)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">Sender</span><input type="text" id="cfg-email-from" class="s-input s-input-lg" value="%s"></div>`,
			html.EscapeString(c.Notifications.Email.From)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">Empfänger</span><input type="text" id="cfg-email-to" class="s-input s-input-lg" placeholder="mail1@test.de, mail2@test.de" value="%s"></div>`,
			html.EscapeString(c.Notifications.Email.To)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">Subjekt</span><input type="text" id="cfg-email-subject-prefix" class="s-input s-input-lg" placeholder="[DynDNS]" value="%s"></div>`,
			html.EscapeString(c.Notifications.Email.SubjectPrefix)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">TLS Modus</span><select id="cfg-email-tls-mode" class="s-input s-input-lg"><option value="starttls" %s>STARTTLS (Standard)</option><option value="tls" %s>Direct TLS (SSL)</option><option value="plain" %s>Plain (Unverschlüsselt)</option></select></div>`,
			selected(c.Notifications.Email.TLSMode == "starttls" || c.Notifications.Email.TLSMode == ""),
			selected(c.Notifications.Email.TLSMode == "tls"),
			selected(c.Notifications.Email.TLSMode == "plain"),
		) +
		`</div>`

	testSection := `<div class="notify-test-box"><p>` + T.NotifyTestDesc + `</p><button class="s-btn notify-test-btn" id="notify-test-btn" data-click="sendNotifyTest()">` +
		T.NotifyBtnTest +
		`</button><div id="notify-test-result" class="notify-test-result"></div>
		</div>`

	return fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsNotifyEnabled+`</span><label class="s-checkbox-container"><input type="checkbox" id="cfg-notify-enabled" class="s-checkbox-dynamic" data-change="updateCheckboxLabel(this)" data-label-on="%s" data-label-off="%s"%s><span class="s-checkbox-text">%s</span></label></div>`,
		T.SettingsCheckboxActive, T.SettingsCheckboxDeactive,
		checkedAttr(c.Notifications.Enabled),
		checkboxLabel(c.Notifications.Enabled),
	) +

		buildSettingsSubSection("", T.SettingsNotifyEvents, notifyEventsSection) +
		buildSettingsSubSection("", T.SettingsTelegramHeading, telegramSection) +
		buildSettingsSubSection("", T.SettingsGotifyHeading, gotifySection) +
		buildSettingsSubSection("", T.SettingsWebhookHeading, webhookSection) +
		buildSettingsSubSection("", T.SettingsMqttHeading, mqttSection) +
		buildSettingsSubSection("", T.SettingsEmailHeading, emailSection) +
		testSection
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
	IPMode     string `json:"ip_mode,omitempty"`
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

type safeEmail struct {
	Host          string `json:"host"`
	Port          int    `json:"port"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	From          string `json:"from"`
	To            string `json:"to"`
	SubjectPrefix string `json:"subject_prefix"`
	TLSMode       string `json:"tls_mode"`
}

type safeSystemConfig struct {
	IPMode          string         `json:"ip_mode"`
	IfaceName       string         `json:"iface_name"`
	HealthPort      string         `json:"health_port"`
	DNSServers      []string       `json:"dns_servers"`
	Interval        int            `json:"interval"`
	DryRun          bool           `json:"dry_run"`
	DebugEnabled    bool           `json:"debug_enabled"`
	DebugHTTPRaw    bool           `json:"debug_http_raw"`
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
	Email           safeEmail      `json:"email"`
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
			IPMode:     dc.IPMode,
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
		DebugEnabled:    cfg.DebugEnabled,
		DebugHTTPRaw:    cfg.DebugHTTPRaw,
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
		Email: safeEmail{
			Host:          cfg.Notifications.Email.Host,
			Port:          cfg.Notifications.Email.Port,
			Username:      cfg.Notifications.Email.Username,
			Password:      cfg.Notifications.Email.Password,
			From:          cfg.Notifications.Email.From,
			To:            cfg.Notifications.Email.To,
			SubjectPrefix: cfg.Notifications.Email.SubjectPrefix,
			TLSMode:       cfg.Notifications.Email.TLSMode,
		},
		IPv4Endpoints: cfg.IPv4Endpoints,
		IPv6Endpoints: cfg.IPv6Endpoints,
	}
}

func dashboardI18NJSON() string {
	m := map[string]string{
		"theme":                         t(T.ThemeLabelJS, "Theme"),
		"no_ip_to_copy":                 t(T.NoIPToCopyJS, "❌ No IP to copy"),
		"copied":                        t(T.CopiedJS, "✓ Copied: "),
		"copy_failed":                   t(T.CopyFailedJS, "❌ Copy failed"),
		"copy_error":                    t(T.CopyFailedJS, "❌ Copy failed"),
		"update_starting":               t(T.UpdateStartingJS, "⏳ Starting update..."),
		"update_started":                t(T.UpdateStartedJS, "✅ Update started"),
		"connection_error":              t(T.ConnectionErrorJS, "❌ Connection error"),
		"export_started":                t(T.ExportStartedJS, "✓ Export started"),
		"export_failed":                 t(T.ExportFailedJS, "Export failed"),
		"fqdn_missing":                  t(T.FQDNMissingJS, "FQDN missing"),
		"domain_updated":                t(T.DomainUpdatedJS, "✓ {domain} updated"),
		"delete_domain_confirm":         t(T.DeleteDomainConfirmJS, `Domain "{domain}" remove from status?`),
		"domain_removed":                t(T.DomainRemovedJS, "🗑️ {domain} removed"),
		"delete_failed":                 t(T.DeleteFailedJS, "Deletion failed"),
		"remove_btn":                    t(T.RemoveBtn, "🗑️ Remove"),
		"save_config_confirm":           t(T.SaveConfigConfirmJS, "Save all settings to config.json?"),
		"saved_reload":                  t(T.SavedReloadJS, "✅ Saved! Reloading..."),
		"error_prefix":                  t(T.ErrorPrefixJS, "❌ Error: "),
		"loading_saving":                t(T.LoadingSavingJS, "⏳ Saving configuration..."),
		"loading_slow":                  t(T.LoadingSlowJS, "⚠️ Taking longer than expected..."),
		"reset_metrics_confirm":         t(T.ResetMetricsConfirmJS, "Clear all metrics?"),
		"metrics_reset_ok":              t(T.MetricsResetOKJS, "✅ Metrics reset"),
		"metrics_reset_failed":          t(T.MetricsResetFailedJS, "❌ Reset failed"),
		"token_saved":                   t(T.TokenSavedJS, "✅ Token saved"),
		"token_deleted":                 t(T.TokenDeletedJS, "🗑️ Token deleted"),
		"token_saved_masked":            t(T.TokenSavedMaskedJS, "●●●●●● (saved)"),
		"token_enter":                   t(T.TokenEnterJS, "Enter token..."),
		"cleared":                       t(T.ClearedJS, "Cleared."),
		"no_log_entries":                t(T.NoLogEntries, "No log entries visible"),
		"user_load_failed":              t(T.UserLoadFailedJS, "Failed to load"),
		"no_users_found":                t(T.NoUsersFoundJS, "No users found."),
		"user_created":                  t(T.UserCreatedJS, "User created"),
		"user_deleted":                  t(T.UserDeletedJS, "User deleted"),
		"role_changed":                  t(T.RoleChangedJS, "Role changed"),
		"role_admin":                    t(T.RoleAdminJS, "Admin"),
		"role_editor":                   t(T.RoleEditorJS, "Editor"),
		"role_viewer":                   t(T.RoleViewerJS, "Viewer"),
		"generic_error":                 t(T.GenericErrorJS, "Error"),
		"auth_user_min":                 t(T.AuthUserMinJS, "Username min. 3 characters"),
		"auth_pass_min":                 t(T.AuthPassMinJS, "Password min. 8 characters"),
		"edit_domain_cancelled":         t(T.EditDomainCancelledJS, "Edit cancelled"),
		"edit_domain_saved":             t(T.EditDomainSavedJS, "Changes saved"),
		"settings_add_btn":              t(T.SettingsAddBtnJS, "➕ Add to list"),
		"notify_test_success":           t(T.NotifyTestSuccess, "✅ Test message sent successfully!"),
		"notify_test_unauthorized":      t(T.NotifyTestUnauthorized, "❌ Unauthorized (check token)"),
		"notify_test_error":             t(T.NotifyTestError, "❌ Error while sending"),
		"notify_test_conn_error":        t(T.NotifyTestConnError, "❌ Connection error to server"),
		"notify_btn_sending":            t(T.NotifyBtnSending, "⏳ Sende..."),
		"notify_btn_test":               t(T.NotifyBtnTest, "🧪 Test-Nachricht senden"),
		"notify_no_notifier":            t(T.NotifyNoNotifier, "⚠️ Keine aktiven Notifier konfiguriert."),
		"notify_stat_success":           t(T.NotifyStatSuccess, "erfolgreich"),
		"nav_dashboard":                 t(T.NavDashboardJS, "🌐 Dashboard"),
		"nav_domains":                   t(T.NavDomainsJS, "🌐 Domains"),
		"nav_metrics":                   t(T.NavMetricsJS, "📊 Metrics"),
		"nav_logs":                      t(T.NavLogsJS, "🧾 Logs"),
		"nav_debug":                     t(T.NavDebugJS, "🐞 Debug"),
		"nav_settings":                  t(T.NavSettingsJS, "⚙️ Settings"),
		"nav_users":                     t(T.SettingsUserManagement, "👥 User Management"),
		"nav_diagnose":                  t(T.NavDiagnoseJS, "🩺 Diagnose"),
		"nav_backup":                    t(T.NavBackupJS, "💾 Backup & Restore"),
		"diagnose_title":                t(T.DiagnoseTitle, "Diagnose / Health Center"),
		"diagnose_loading":              t(T.DiagnoseLoading, "Loading diagnosis..."),
		"diagnose_load_failed":          t(T.DiagnoseLoadFailed, "Diagnosis failed"),
		"diagnose_connection_failed":    t(T.DiagnoseConnectionFailed, "Connection failed"),
		"diagnose_status_healthy":       t(T.DiagnoseStatusHealthy, "Healthy"),
		"diagnose_status_degraded":      t(T.DiagnoseStatusDegraded, "Degraded"),
		"diagnose_status_starting":      t(T.DiagnoseStatusStarting, "Starting"),
		"diagnose_status_unhealthy":     t(T.DiagnoseStatusUnhealthy, "Unhealthy"),
		"diagnose_system_title":         t(T.DiagnoseSystemTitle, "System"),
		"diagnose_ip_dns_title":         t(T.DiagnoseIPDNSTitle, "IP / DNS"),
		"diagnose_api_metrics_title":    t(T.DiagnoseAPIMetricsTitle, "API metrics"),
		"diagnose_config_title":         t(T.DiagnoseConfigTitle, "Config"),
		"diagnose_provider_title":       t(T.DiagnoseProviderTitle, "Provider"),
		"diagnose_notifier_title":       t(T.DiagnoseNotifierTitle, "Notifier"),
		"diagnose_warnings_title":       t(T.DiagnoseWarningsTitle, "Warnings"),
		"diagnose_files_title":          t(T.DiagnoseFilesTitle, "Files"),
		"diagnose_uptime":               t(T.DiagnoseUptime, "Uptime"),
		"diagnose_scheduler_ran":        t(T.DiagnoseSchedulerRan, "Scheduler ran"),
		"diagnose_last_run_ok":          t(T.DiagnoseLastRunOK, "Last run OK"),
		"diagnose_update_running":       t(T.DiagnoseUpdateRunning, "Update running"),
		"diagnose_active_updates":       t(T.DiagnoseActiveUpdates, "Active updates"),
		"diagnose_last_ipv4":            t(T.DiagnoseLastIPv4, "Last IPv4"),
		"diagnose_last_ipv6":            t(T.DiagnoseLastIPv6, "Last IPv6"),
		"diagnose_last_domain_change":   t(T.DiagnoseLastDomainChange, "Last domain change"),
		"diagnose_configured_domains":   t(T.DiagnoseConfiguredDomains, "Domains in status"),
		"diagnose_total_requests":       t(T.DiagnoseTotalRequests, "Total requests"),
		"diagnose_success_rate":         t(T.DiagnoseSuccessRate, "Success rate"),
		"diagnose_average_latency":      t(T.DiagnoseAverageLatency, "Average latency"),
		"diagnose_log_errors":           t(T.DiagnoseLogErrors, "Log errors"),
		"diagnose_log_warnings":         t(T.DiagnoseLogWarnings, "Log warnings"),
		"diagnose_ip_mode":              t(T.DiagnoseIPMode, "IP mode"),
		"diagnose_interval":             t(T.DiagnoseInterval, "Interval"),
		"diagnose_ipv4_endpoints":       t(T.DiagnoseIPv4Endpoints, "IPv4 endpoints"),
		"diagnose_ipv6_endpoints":       t(T.DiagnoseIPv6Endpoints, "IPv6 endpoints"),
		"diagnose_no_providers":         t(T.DiagnoseNoProviders, "No providers found"),
		"diagnose_no_notifiers":         t(T.DiagnoseNoNotifiers, "No notifiers"),
		"diagnose_no_config_warnings":   t(T.DiagnoseNoConfigWarnings, "No config warnings"),
		"diagnose_file_missing":         t(T.DiagnoseFileMissing, "missing"),
		"diagnose_bytes":                t(T.DiagnoseBytes, "bytes"),
		"diagnose_yes":                  t(T.DiagnoseYes, "Yes"),
		"diagnose_no":                   t(T.DiagnoseNo, "No"),
		"backup_download_success":       t(T.BackupDownloadSuccess, "✅ Backup downloaded"),
		"backup_download_failed":        t(T.BackupDownloadFailed, "❌ Backup failed"),
		"backup_select_file":            t(T.BackupSelectFile, "❌ Please select a backup file"),
		"backup_select_area":            t(T.BackupSelectArea, "❌ Please select at least one area"),
		"backup_confirm_title":          t(T.BackupConfirmTitle, "Really restore backup?"),
		"backup_confirm_config":         t(T.BackupConfirmConfig, "• Config will be overwritten"),
		"backup_confirm_status":         t(T.BackupConfirmStatus, "• Domain status will be overwritten"),
		"backup_confirm_users":          t(T.BackupConfirmUsers, "• Users will be overwritten"),
		"backup_confirm_hint":           t(T.BackupConfirmHint, "This action may replace existing data."),
		"backup_restore_running":        t(T.BackupRestoreRunning, "⏳ Restore running..."),
		"backup_restore_success_format": t(T.BackupRestoreSuccessFormat, "✅ Restored: {restored}"),
		"backup_restore_failed":         t(T.BackupRestoreFailed, "❌ Restore failed"),
		"nav_totp":                      t(T.NavTotpJS, "🔐 2FA / Account Security"),
		"totp_settings_load_failed":     t(T.TotpSettingsLoadFailedJS, "2FA settings could not be loaded"),
		"totp_action_failed":            t(T.TotpActionFailedJS, "2FA action failed"),
		"totp_badge_active":             t(T.TotpBadgeActiveJS, "🔐 2FA active"),
		"totp_badge_inactive":           t(T.TotpBadgeInactiveJS, "🔓 2FA inactive"),
	}

	b, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func createMux() *http.ServeMux {
	mux := http.NewServeMux()

	registerStaticRoutes(mux)
	registerAPIroutes(mux)
	registerPageRoutes(mux)

	return mux
}

func registerStaticRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/assets/style.css", handleDashboardCSS)
	mux.HandleFunc("/assets/dashboard.js", handleDashboardJS)
	mux.HandleFunc("/assets/i18n.js", handleDashboardI18NJS)
	mux.HandleFunc("/favicon.svg", handleFavicon)
	mux.HandleFunc("/ws", handleWS)
	mux.HandleFunc("/metrics", handleMetrics)
	mux.HandleFunc("/metrics/prometheus", handlePrometheusMetrics)
	mux.HandleFunc("/health", handleHealth)
}

func registerAPIroutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/domains", handleAPIDomains)
	mux.HandleFunc("/api/domains/html", handleAPIDomainsHTML)
	mux.HandleFunc("/api/config", handleAPIConfig)
	mux.HandleFunc("/api/languages", handleAPILanguages)
	mux.HandleFunc("/api/save-config", handleAPISaveConfig)
	mux.HandleFunc("/api/set-language", handleAPISetLanguage)
	mux.HandleFunc("/api/domain/delete", handleAPIDomainDelete)
	mux.HandleFunc("/api/ipv64/domain", handleAPIIPv64Domain)
	mux.HandleFunc("/api/trigger", handleAPITrigger)
	mux.HandleFunc("/api/trigger/status", handleAPITriggerStatus)
	mux.HandleFunc("/api/notify/test", handleAPINotifyTest)
	mux.HandleFunc("/api/export", handleAPIExport)
	mux.HandleFunc("/api/metrics/reset", handleMetricsReset)
	mux.HandleFunc("/api/users", handleAPIUsers)
	mux.HandleFunc("/api/users/", handleAPIUsersID)
	mux.HandleFunc("/api/logs", handleAPILogs)

	mux.HandleFunc("/api/diagnose", handleAPIDiagnose)
	mux.HandleFunc("/api/backup/download", handleAPIBackupDownload)
	mux.HandleFunc("/api/backup/restore", handleAPIBackupRestore)
}

func registerPageRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/logout", handleLogout)
	mux.HandleFunc("/setup", handleSetup)
	mux.HandleFunc("/login/totp", handleLoginTOTP)
	mux.HandleFunc("/settings/2fa", handleSettings2FA)
	mux.HandleFunc("/settings/2fa/qr", handleSettings2FAQRCode)
	mux.HandleFunc("/api/2fa/status", handleAPI2FAStatus)
	mux.HandleFunc("/", handleDashboard)
}

func dashboardHSTSEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("DASHBOARD_HSTS"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func setSecurityHeaders(w http.ResponseWriter, r *http.Request) {
	h := w.Header()

	h.Set("Content-Security-Policy", strings.Join([]string{
		"default-src 'self'",
		"base-uri 'none'",
		"object-src 'none'",
		"frame-ancestors 'none'",
		"form-action 'self'",
		"img-src 'self' data:",
		"style-src 'self' 'unsafe-inline'",
		"script-src 'self'",
		"script-src-elem 'self'",
		"script-src-attr 'none'",
		"connect-src 'self'",
	}, "; "))

	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")

	if r != nil && r.TLS != nil && dashboardHSTSEnabled() {
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w, r)
		next.ServeHTTP(w, r)
	})
}

func handleDashboardCSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = io.WriteString(w, cssData)
}

func handleDashboardJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = io.WriteString(w, jsData)
}

func handleDashboardI18NJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = fmt.Fprintf(w, "window.I18N = %s;\n", dashboardI18NJSON())
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

func validWebSocketOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

func handleWS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !validWebSocketOrigin(r) {
		http.Error(w, "invalid websocket origin", http.StatusForbidden)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		debugLog("WS", "", fmt.Sprintf(T.WSUpgradeFailed, err))
		return
	}

	conn.SetReadLimit(wsMaxInboundMessageSize)

	client := &WSClient{
		conn: conn,
		send: make(chan WSMessage, 128),
	}

	stats := apiMetrics.GetStats()
	client.send <- WSMessage{Type: "initial", Data: stats}

	wsHub.register <- client
}

func handleAPIDomains(w http.ResponseWriter, r *http.Request) {
	serveCachedJSON(w, r, domainsCache)
}

func handleAPIDomainsHTML(w http.ResponseWriter, r *http.Request) {
	if r.Method != MethodGET {
		http.Error(w, T.APIErrorMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}
	data := loadStatusData()
	var b strings.Builder
	writeDomainsCard(&b, data)
	writeJSON(w, http.StatusOK, map[string]any{
		"html":  b.String(),
		"count": len(domainKeysFromStatusData(data)),
	})
}

func handleAPIConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != MethodGET {
		http.Error(w, T.APIErrorMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}

	sess, _ := sessionFromRequest(r)
	isAdmin := !authEnabled || (sess != nil && sess.Role == RoleAdmin)

	type fullConfigResponse struct {
		DomainConfigs []safeDomainConfig `json:"domain_configs"`
		System        safeSystemConfig   `json:"system"`
	}

	sys := currentSystemConfig()

	if !isAdmin {
		sys.TelegramToken = maskSecret(sys.TelegramToken)
		sys.GotifyToken = maskSecret(sys.GotifyToken)
		sys.WebhookSecret = maskSecret(sys.WebhookSecret)
		sys.MQTT.Password = maskSecret(sys.MQTT.Password)
		sys.Email.Password = maskSecret(sys.Email.Password)
	}

	domains := safeDomainConfigs(cfg.DomainConfigs)
	if !isAdmin {
		for i := range domains {
			domains[i].APISecret = maskSecret(domains[i].APISecret)
			domains[i].CFToken = maskSecret(domains[i].CFToken)
			domains[i].CFSecret = maskSecret(domains[i].CFSecret)
			domains[i].IPv64Token = maskSecret(domains[i].IPv64Token)
		}
	}

	resp := fullConfigResponse{
		DomainConfigs: domains,
		System:        sys,
	}

	writeJSON(w, http.StatusOK, resp)
}

func maskSecret(s string) string {
	if s == "" {
		return ""
	}
	return "●●●●●●"
}

func handleAPILanguages(w http.ResponseWriter, r *http.Request) {
	if r.Method != MethodGET {
		http.Error(w, T.APIErrorMethodNotAllowed, http.StatusMethodNotAllowed)
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
	if r.Method != MethodPOST {
		http.Error(w, T.APIErrorMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}
	if !validateTriggerToken(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var payload dashboardConfigPayload
	if err := decodeJSONBody(w, r, &payload); err != nil {
		http.Error(w, T.JSONParseError, http.StatusBadRequest)
		return
	}

	var validationErr error
	cfgMu.Lock()
	oldCfg := cfg
	oldMaxConcurrent := cfg.MaxConcurrent
	applySystemConfigPayload(payload.System)
	cfg.DomainConfigs = mergeDomainConfigs(cfg.DomainConfigs, payload.DomainConfigs)
	validationErr = validateDomainConfigs()
	if validationErr != nil {
		cfg = oldCfg
		cfgMu.Unlock()
		http.Error(w, validationErr.Error(), http.StatusUnprocessableEntity)
		return
	}
	newMaxConcurrent := cfg.MaxConcurrent
	cfgMu.Unlock()

	if oldMaxConcurrent != newMaxConcurrent {
		setWorkerConcurrencyLimit(newMaxConcurrent)
	}

	if err := saveConfigToFile(); err != nil {
		http.Error(w, T.SaveFailed, http.StatusInternalServerError)
		return
	}

	ResetHTTPClient()
	invalidateSecretReplacer()
	go initNotifiers()
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
	setAtomicDebugFlags(sys.DebugEnabled, sys.DebugHTTPRaw)
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

	cfg.Notifications.Email.Host = sys.Email.Host
	cfg.Notifications.Email.Port = sys.Email.Port
	cfg.Notifications.Email.Username = sys.Email.Username
	cfg.Notifications.Email.Password = sys.Email.Password
	cfg.Notifications.Email.From = sys.Email.From
	cfg.Notifications.Email.To = sys.Email.To
	cfg.Notifications.Email.SubjectPrefix = sys.Email.SubjectPrefix
	cfg.Notifications.Email.TLSMode = sys.Email.TLSMode
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
		(cfg.Notifications.MQTTConfig.Broker != "" && cfg.Notifications.MQTTConfig.Topic != "") ||
		(cfg.Notifications.Email.Host != "" && cfg.Notifications.Email.To != "")
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
			if strings.TrimSpace(sc.Provider) != "" {
				found.Provider = normalizeProviderName(sc.Provider)
			}
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
			found.IPMode = sc.IPMode
			newConfigs = append(newConfigs, found)
			continue
		}

		newConfigs = append(newConfigs, DomainConfig{
			FQDN:       fqdn,
			Provider:   normalizeProviderName(sc.Provider),
			APIPrefix:  sc.APIPrefix,
			APISecret:  sc.APISecret,
			CFToken:    sc.CFToken,
			CFEmail:    sc.CFEmail,
			CFSecret:   sc.CFSecret,
			IPv64Token: sc.IPv64Token,
			TTL:        sc.TTL,
			CFProxied:  sc.CFProxied,
			IPMode:     sc.IPMode,
		})
	}

	sort.Slice(newConfigs, func(i, j int) bool {
		if newConfigs[i].Provider != newConfigs[j].Provider {
			return string(newConfigs[i].Provider) < string(newConfigs[j].Provider)
		}
		return newConfigs[i].FQDN < newConfigs[j].FQDN
	})

	return newConfigs
}

func handleAPISetLanguage(w http.ResponseWriter, r *http.Request) {
	if r.Method != MethodPOST {
		http.Error(w, T.APIErrorMethodNotAllowed, http.StatusMethodNotAllowed)
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

func handleAPIIPv64Domain(w http.ResponseWriter, r *http.Request) {
	if r.Method != MethodPOST {
		http.Error(w, T.APIErrorMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}
	if !validateTriggerToken(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": T.InvalidToken})
		return
	}

	var req struct {
		Action   string `json:"action"`
		FQDN     string `json:"fqdn"`
		APIToken string `json:"api_token"`
	}

	if err := decodeJSONBody(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": T.ErrInvalidJSON})
		return
	}

	req.FQDN = normalizeIPv64FQDN(req.FQDN)
	if req.FQDN == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": T.DomainIsEmpty})
		return
	}

	req.Action = strings.ToUpper(strings.TrimSpace(req.Action))
	if req.Action != MethodADD && req.Action != MethodDELETE {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": T.IPv64ActionInvalid})
		return
	}

	ctx := r.Context()

	dc, statusCode, err := selectIPv64DomainConfigForAction(ctx, req.Action, req.FQDN, req.APIToken)
	if err != nil {
		writeJSON(w, statusCode, map[string]string{"error": err.Error()})
		return
	}

	switch req.Action {
	case MethodADD:
		err = addIPv64Domain(ctx, dc, req.FQDN)
	case MethodDELETE:
		err = deleteIPv64Domain(ctx, dc, req.FQDN)
	}

	if err != nil {
		debugLog("API", getClientIP(r), fmt.Sprintf("IPv64 %s domain %s: %v", req.Action, req.FQDN, err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	action := "added"
	if req.Action == MethodDELETE {
		action = "deleted"
	}

	debugLog("API", getClientIP(r), fmt.Sprintf("IPv64 domain %s: %s", action, req.FQDN))
	writeJSON(w, http.StatusOK, map[string]string{
		"status": action,
		"fqdn":   req.FQDN,
	})
}

func handleAPIDomainDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != MethodPOST {
		http.Error(w, T.APIErrorMethodNotAllowed, http.StatusMethodNotAllowed)
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

	if isDomainActiveInConfig(domain) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": T.DomainStillActiveInConfig})
		return
	}

	statusMutex.Lock()
	deleteKey, statusCode, errMsg := deleteDomainFromStatus(domain)
	statusMutex.Unlock()

	if statusCode != http.StatusOK {
		writeJSON(w, statusCode, map[string]string{"error": errMsg})
		return
	}

	debugLog("API", getClientIP(r), fmt.Sprintf(T.DomainDeletedFromStatusLog, deleteKey))
	broadcastNotification(fmt.Sprintf(T.DomainRemovedFromStatus, deleteKey), "info")

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "deleted",
		"domain": deleteKey,
	})
}

func isDomainActiveInConfig(domain string) bool {
	for _, dc := range cfg.DomainConfigs {
		if strings.EqualFold(dc.FQDN, domain) {
			return true
		}
	}

	return false
}

func deleteDomainFromStatus(domain string) (string, int, string) {
	fileData, statusCode, errMsg := readStatusFileForDelete()
	if statusCode != http.StatusOK {
		return "", statusCode, errMsg
	}

	deleteKey, found := findStatusDomainKey(fileData, domain)
	if !found {
		return "", http.StatusNotFound, T.DomainNotFoundInStatus
	}

	delete(fileData, deleteKey)
	deleteDomainFromStatusCache(domain, deleteKey)

	if err := writeStatusFileData(fileData); err != nil {
		return "", http.StatusInternalServerError, err.Error()
	}

	return deleteKey, http.StatusOK, ""
}

func readStatusFileForDelete() (map[string]any, int, string) {
	b, err := os.ReadFile(updatePath)
	if err != nil {
		return nil, http.StatusNotFound, T.NoStatusFileFound
	}

	var fileData map[string]any
	if err := json.Unmarshal(b, &fileData); err != nil {
		return nil, http.StatusInternalServerError, err.Error()
	}

	if fileData == nil {
		return nil, http.StatusNotFound, T.NoStatusFileFound
	}

	return fileData, http.StatusOK, ""
}

func findStatusDomainKey(fileData map[string]any, domain string) (string, bool) {
	if _, exists := fileData[domain]; exists {
		return domain, true
	}

	for k := range fileData {
		if strings.EqualFold(k, domain) {
			return k, true
		}
	}

	return "", false
}

func deleteDomainFromStatusCache(domain, deleteKey string) {
	if statusDomains == nil {
		return
	}

	delete(statusDomains, deleteKey)

	for k := range statusDomains {
		if strings.EqualFold(k, domain) {
			delete(statusDomains, k)
		}
	}
}

func writeStatusFileData(fileData map[string]any) error {
	b, err := json.MarshalIndent(fileData, "", " ")
	if err != nil {
		return err
	}

	tmp := updatePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}

	if err := os.Rename(tmp, updatePath); err != nil {
		_ = os.Remove(tmp)
		return err
	}

	return nil
}

func handleAPITrigger(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1024)

	if r.Method != MethodPOST {
		http.Error(w, T.APIErrorMethodNotAllowed, http.StatusMethodNotAllowed)
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

	if !hasDomainConfig() {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": "No domains configured yet. Save config.json from the dashboard first.",
		})
		debugLog("API", clientIP, "Trigger blocked: no domains configured yet")
		return
	}

	if !globalTriggerLimiter.Allow() {
		w.Header().Set("Retry-After", "10")
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
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
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":               T.IPRateLimitExceeded,
			"retry_after_seconds": 10,
			"remaining":           remaining,
		})
		debugLog("API", clientIP, T.TriggerBlockedIPRateLimit)
		broadcastNotification(T.TooManyUpdateRequestsWait, "warning")
		return
	}

	if !updateInProgress.CompareAndSwap(false, true) {
		writeJSON(w, http.StatusConflict, map[string]any{
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
	writeJSON(w, http.StatusAccepted, map[string]any{
		"status":               "triggered",
		"message":              T.UpdateStartedMessage,
		"rate_limit_remaining": remaining,
	})
}

func handleAPINotifyTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != MethodPOST {
		http.Error(w, T.APIErrorMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}
	if !validateTriggerToken(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	notifyCfgMu.RLock()
	notifiers := notifyCfg.notifiers
	notifyCfgMu.RUnlock()

	if len(notifiers) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "no_notifiers",
			"message": "Keine aktiven Notifier konfiguriert",
			"sent":    0,
		})
		return
	}

	testMsg := NotifyMessage{
		Action:  ActionConfig,
		Domain:  "",
		Message: t(T.NotifyTestBody, "🔔 Test Notification: Your dashboard notification system is working perfectly!"),
		Level:   LogInfo,
	}

	type result struct {
		Name  string `json:"name"`
		OK    bool   `json:"ok"`
		Error string `json:"error,omitempty"`
	}

	results := make([]result, 0, len(notifiers))
	type syncSender interface {
		SendSync(msg NotifyMessage) error
	}

	for _, n := range notifiers {
		var err error
		if s, ok := n.(syncSender); ok {
			err = s.SendSync(testMsg)
		} else {
			err = n.Send(testMsg)
		}

		r := result{Name: n.Name(), OK: err == nil}
		if err != nil {
			r.Error = err.Error()
		}
		results = append(results, r)
	}

	sentCount := 0
	for _, r := range results {
		if r.OK {
			sentCount++
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "done",
		"sent":    sentCount,
		"total":   len(notifiers),
		"results": results,
	})
}

func handleAPITriggerStatus(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	ipLimiter := ipTriggerLimiter.GetLimiter(clientIP)

	if !ipLimiter.Allow() {
		http.Error(w, T.APIErrorRateLimitExceeded, http.StatusTooManyRequests)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ip":                 clientIP,
		"remaining_requests": ipLimiter.Remaining(),
		"update_in_progress": updateInProgress.Load(),
		"global_limit":       globalTriggerLimiter.Remaining(),
	})
}

func handleAPIExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != MethodGET {
		http.Error(w, T.APIErrorMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}

	if !validateTriggerToken(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	statusMutex.Lock()
	defer statusMutex.Unlock()

	exportData := map[string]any{
		"timestamp": time.Now().Format(time.RFC3339),
		"metrics":   apiMetrics.GetStats(),
	}

	if b, err := os.ReadFile(updatePath); err == nil {
		var domains map[string]DomainHistory
		if err := json.Unmarshal(b, &domains); err == nil {
			exportData["domains"] = domains
		}
	}

	if b, err := os.ReadFile(logPath); err == nil {
		var logEntries []LogEntry
		for line := range strings.SplitSeq(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var entry LogEntry
			if json.Unmarshal([]byte(line), &entry) == nil {
				logEntries = append(logEntries, entry)
			}
		}
		exportData["logs"] = logEntries
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
		writeJSON(w, http.StatusOK, map[string]any{
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
		writeJSON(w, http.StatusOK, map[string]any{
			"status":      "degraded",
			"reason":      healthReason,
			"api_metrics": stats,
		})
		return
	}

	if !isHealthy {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
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

func getTotalRequests(stats map[string]any) int64 {
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

func handleDetailedHealth(w http.ResponseWriter, stats map[string]any) {
	lastV4, lastV6 := loadLastKnownIPs()

	statusMutex.Lock()
	lastUpdateTime := readLastUpdateTimeFromStatusFile()
	statusMutex.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
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
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sess, _ := sessionFromRequest(r)
	isAdmin := !authEnabled || (sess != nil && sess.Role == RoleAdmin)
	isViewer := authEnabled && sess != nil && sess.Role == RoleViewer

	statusData := loadStatusData()
	statusClass, statusText := dashboardStatus()
	logs, logTimeRange := loadDashboardLogs()

	stats := getDashboardStats()
	chartSVG, latencySVG, nicHTML := buildDashboardMetricsParts(stats)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	w.Header().Set(
		"Cache-Control",
		"no-store, no-cache, must-revalidate, max-age=0",
	)
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	writeDashboardHeader(w, sess)
	writeDashboardTop(w, statusClass, statusText)
	writeDashboardMetricsCard(w, stats, nicHTML, chartSVG, latencySVG, isViewer)

	writeDomainsCard(w, statusData)
	writeDiagnoseSection(w)
	writeLogsCard(w, logs, logTimeRange)
	writeBackupSection(w, isAdmin)

	if cfg.DebugEnabled || cfg.DebugHTTPRaw {
		writeDebugCard(w)
	} else {
		_, _ = fmt.Fprint(w, `
	<div class="page-section" data-section="debug">
		<div class="card">
			<div class="card-header">🐞 `+T.DebugLogTitle+`</div>
			<div class="card-content">
				<p class="debug-disabled-note">Debug-Modus ist deaktiviert. Aktiviere ihn in den Einstellungen unter System → Debug-Modus.</p>
			</div>
		</div>
	</div>`)
	}

	writeSettingsSection(w, cfg)
	writeTOTPSection(w, sess, authEnabled && sess != nil)
	writeUsersSection(w, isAdmin)

	_, _ = fmt.Fprint(w, `<div id="settingsOverlay" class="modal-overlay"></div>`)

	writeDashboardFooter(w)
	_ = r
}

func loadStatusData() map[string]any {
	statusMutex.Lock()
	defer statusMutex.Unlock()

	data := make(map[string]any)
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

func getDashboardStats() map[string]any {
	latestMetricsMu.RLock()
	stats := latestMetrics
	latestMetricsMu.RUnlock()

	if stats == nil {
		stats = apiMetrics.GetStats()
	}
	return stats
}

func buildDashboardMetricsParts(stats map[string]any) (string, string, string) {
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

func buildNICHTML(stats map[string]any) string {
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

	return `<div class="nic-row"><span class="nic-label">NIC <span>(` + T.NicIPv64Updates + `)</span></span><span id="mDailyNIC" class="nic-value">` +
		fmt.Sprintf("%v", stats["daily_nic"]) +
		`</span></div>`
}

var (
	logMemCache      []LogEntry
	logMemCacheRange string
	logMemCacheTime  time.Time
	logMemCacheMu    sync.RWMutex
	logMemCacheTTL   = 10 * time.Second
)

func loadDashboardLogs() ([]LogEntry, string) {
	logMemCacheMu.RLock()
	if !logMemCacheTime.IsZero() && time.Since(logMemCacheTime) < logMemCacheTTL {
		logs := make([]LogEntry, len(logMemCache))
		copy(logs, logMemCache)
		r := logMemCacheRange
		logMemCacheMu.RUnlock()
		return logs, r
	}
	logMemCacheMu.RUnlock()

	logs, logTimeRange := loadLogsFromMainFile()

	logMemCacheMu.Lock()
	logMemCache = logs
	logMemCacheRange = logTimeRange
	logMemCacheTime = time.Now()
	logMemCacheMu.Unlock()

	return logs, logTimeRange
}

func loadDashboardLogsFresh() ([]LogEntry, string) {
	logs, logTimeRange := loadLogsFromMainFile()

	logMemCacheMu.Lock()
	logMemCache = logs
	logMemCacheRange = logTimeRange
	logMemCacheTime = time.Now()
	logMemCacheMu.Unlock()

	return logs, logTimeRange
}

func handleAPILogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != MethodGET {
		http.Error(w, T.APIErrorMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}

	logs, logTimeRange := loadDashboardLogsFresh()

	var b strings.Builder
	writeLogsCard(&b, logs, logTimeRange)

	writeJSON(w, http.StatusOK, map[string]any{
		"html":       b.String(),
		"count":      len(logs),
		"time_range": logTimeRange,
	})
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
		log(LogContext{
			Level:    LogError,
			Category: "FILE",
			Action:   ActionError,
			Message:  fmt.Sprintf("%s: %v", t(T.ScannerError, "Scanner error"), err),
		})
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

func formatDashboardLogTimestamp(ts string) string {
	t, err := time.Parse("2006-01-02T15:04:05", ts)
	if err != nil {
		return ts
	}
	return t.Format("02.01.2006 15:04:05")
}

func writeDashboardHeader(w http.ResponseWriter, sess *Session) {
	logoutBtn := ""
	userInfo := ""
	csrfMeta := ""
	userPage := ""
	totpPage := ""
	if authEnabled && sess != nil {
		csrfMeta = `<meta name="csrf-token" content="` + html.EscapeString(sess.CSRFToken) + `">`
		roleIcon := map[UserRole]string{
			RoleAdmin:  "👑",
			RoleEditor: "✏️",
			RoleViewer: "👁️",
		}[sess.Role]
		userInfo = fmt.Sprintf(`<span class="sidebar-user-info">%s %s</span>`, roleIcon, html.EscapeString(sess.Username))
		logoutBtn = `<form method="POST" action="/logout" class="logout-form"><input type="hidden" name="csrf_token" value="` + html.EscapeString(sess.CSRFToken) + `"><button type="submit" class="action-btn topbar-action-btn logout-btn">🚪 Logout</button></form>`
		totpPage = `<div class="nav-item" data-page="totp" data-click="navTo('totp')"><span class="nav-item-icon">🔐</span> 2FA / Konto-Sicherheit</div>`
		if sess.Role == RoleAdmin {
			userPage = `<div class="nav-item" data-page="users" data-click="navTo('users')">` + T.SettingsUserManagement + `</div>`
		}
	} else if !authEnabled {
		userPage = `<div class="nav-item" data-page="users" data-click="navTo('users')">` + T.SettingsUserManagement + `</div>`
	}

	_, _ = fmt.Fprintf(w, `<!DOCTYPE html><html><head>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<meta name="format-detection" content="telephone=no">
		<meta name="apple-mobile-web-app-capable" content="yes">
		<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
		<meta name="apple-mobile-web-app-title" content="IONOS-DDNS">
		`+csrfMeta+`
		<title>%s</title>
		<link id="favicon" rel="icon" type="image/svg+xml" href="/favicon.svg?theme=dark">
		<link rel="stylesheet" href="/assets/style.css">
	</head>
	<body>

	<div class="auth-bg">
		<div class="auth-sun"></div>
		<div class="auth-mountains"></div>
		<div class="auth-grid-floor"></div>
	</div>

	<div id="sidebar-overlay" data-click="closeSidebar()"></div>

	<div class="app-layout">
		<!-- ═══ SIDEBAR ═══ -->
		<nav id="sidebar" class="sidebar">
			<div class="sidebar-logo">
				<span>🌐</span>
				<div>
					<div>DynDNS</div>
					<small>Multi-Provider</small>
				</div>
			</div>

			<div class="nav-section-label">`+t(T.NavOverview, "Overview")+`</div>
			<div class="nav-item" data-page="dashboard" data-click="navTo('dashboard')">
				<span class="nav-item-icon">📊</span> `+T.NavDashboard+`
			</div>
			<div class="nav-item" data-page="domains" data-click="navTo('domains')">
				<span class="nav-item-icon">🌐</span> `+T.NavDomains+`
			</div>

			<div class="nav-section-label">`+t(T.NavMonitoring, "Monitoring")+`</div>
			<div class="nav-item" data-page="metrics" data-click="navTo('metrics')">
				<span class="nav-item-icon">📈</span> `+T.APIPerformance+`
			</div>
			<div class="nav-item" data-page="diagnose" data-click="navTo('diagnose')">
				<span class="nav-item-icon">🩺</span> `+t(T.DiagnoseTitle, "Diagnose / Health Center")+`
			</div>
			<div class="nav-item" data-page="logs" data-click="navTo('logs')">
				<span class="nav-item-icon">🧾</span> `+T.SystemEvents+`
			</div>
			<div class="nav-item" data-page="debug" data-click="navTo('debug')">
				<span class="nav-item-icon">🐞</span> `+T.DebugLogTitle+`
			</div>

			<div class="nav-section-label">`+t(T.NavTools, "Tools")+`</div>
			<div class="nav-item" data-page="backup" data-click="navTo('backup')">
				<span class="nav-item-icon">💾</span> `+t(T.BackupTitle, "Backup & Restore")+`
			</div>

			<div class="nav-section-label">`+t(T.NavConfig, "Config")+`</div>
			<div class="nav-item" data-page="settings" data-click="navTo('settings')">
				<span class="nav-item-icon">⚙️</span> `+T.SettingsTitle+`
			</div>
			%s
			%s

			<div class="nav-spacer"></div>

			<div class="sidebar-bottom">
				%s
				%s
			</div>
		</nav>

		<!-- ═══ RIGHT SIDE ═══ -->
		<div class="app-right">

			<!-- Topbar -->
			<header class="topbar">
				<button class="hamburger-btn" data-click="toggleSidebar()" aria-label="Menu">☰</button>
				<span id="page-title" class="topbar-title">📊 Dashboard</span>
				<div class="topbar-right">
					<button class="action-btn topbar-action-btn is-hidden"
						id="topbar-save-config-button"
						data-tooltip="`+html.EscapeString(T.SettingsSaveHint)+`"
						data-mouseenter="showNotifierTooltip()"
						data-focus="showNotifierTooltip()"
						data-click="saveFullConfig()">`+T.SettingsSaveBtn+`</button>

					<button class="action-btn topbar-action-btn"
						data-tooltip="`+html.EscapeString(T.SettingsUpdateHint)+`"
						data-mouseenter="showNotifierTooltip()"
						data-focus="showNotifierTooltip()"
						data-click="triggerUpdate()">🔄 `+T.Update+`</button>

					<button class="action-btn topbar-action-btn"
						data-tooltip="`+html.EscapeString(T.SettingsExportHint)+`"
						data-mouseenter="showNotifierTooltip()"
						data-focus="showNotifierTooltip()"
						data-click="exportData()">📥 `+T.ExportBtn+`</button>

					<div class="notif-wrap">
						<button class="theme-toggle notif-toggle"
							data-tooltip="`+html.EscapeString(T.SettingsNotifierHint)+`"
							data-mouseenter="showNotifierTooltip()"
							data-focus="showNotifierTooltip()"
							data-click="toggleNotifCenter()">🔔
							<span id="notif-badge" class="notif-badge"></span>
						</button>

						<div id="notif-panel" class="notif-panel">
							<div class="notif-panel-header">
								🔔 `+T.SettingsNotifyHint+`
							</div>
							<div id="notif-list"></div>
						</div>
					</div>

					<button class="theme-toggle"
						data-tooltip="`+html.EscapeString(T.SettingsThemeHint)+`"
						data-mouseenter="showNotifierTooltip()"
						data-focus="showNotifierTooltip()"
						data-click="toggleTheme()">🌓</button>
				</div>
			</header>

			<div id="toast" class="toast"></div>

			<!-- ═══ MAIN CONTENT ═══ -->
			<div class="main-content">
	`,
		html.EscapeString(T.DashboardTitle),
		totpPage,
		userPage,
		userInfo,
		logoutBtn,
	)
}

func buildNotifierStatusHTML() string {
	notifyCfgMu.RLock()
	notifiers := notifyCfg.notifiers
	notifyCfgMu.RUnlock()

	if len(notifiers) == 0 {
		return ""
	}

	icons := map[string]string{
		"Telegram": "✈️",
		"Gotify":   "📬",
		"Webhook":  "🔗",
		"mqtt":     "📡",
		"Email":    "✉️",
	}

	var sb strings.Builder
	sb.WriteString(`<span class="status-sep">|</span><span class="status-item status-notifier-group">`)

	for _, n := range notifiers {
		name := n.Name()
		icon := icons[name]
		if icon == "" {
			icon = "🔔"
		}

		connected := true
		if m, ok := n.(*mqttNotifier); ok {
			connected = m.isConnected()
		}

		stateClass := "notifier-icon--active"
		title := name + " " + T.NotifierActive
		if !connected {
			stateClass = "notifier-icon--disconnected"
			title = name + " " + T.NotifierDisconnected
		}

		fmt.Fprintf(&sb,
			`<span class="notifier-icon %s" title="%s" data-tooltip="%s" data-click="showNotifierTooltip()">%s</span>`,
			stateClass, esc(title), esc(title), esc(icon),
		)
	}

	sb.WriteString(`</span>`)
	return sb.String()
}

func writeDashboardTop(w http.ResponseWriter, statusClass, statusText string) {
	_, _ = fmt.Fprintf(w, `
	<div class="page-section" data-section="dashboard">
		<div class="status-banner %s">
			<div class="status-banner-left">
				<span>%s</span>
			</div>
			<div class="status-banner-meta">
				<span class="status-item status-item--clickable"
					title="`+html.EscapeString(T.TooltipLastCheck)+`"
					data-tooltip="`+html.EscapeString(T.TooltipLastCheck)+`"
					data-click="showNotifierTooltip()">
					%s: <span id="lastUpdate">%s</span>
				</span>
				<span class="status-sep">|</span>
				<span class="status-item status-item--clickable"
					title="`+html.EscapeString(T.TooltipClock)+`"
					data-tooltip="`+html.EscapeString(T.TooltipClock)+`"
					data-click="showNotifierTooltip()">
					🕒 <span id="clock">--:--:--</span>
				</span>
				<span class="status-sep">|</span>
				<span class="status-item status-uptime status-item--clickable"
					title="`+html.EscapeString(T.TooltipUptime)+`"
					data-tooltip="`+html.EscapeString(T.TooltipUptime)+`"
					data-click="showNotifierTooltip()">
					⏱️ <span id="uptime">--</span>
				</span>
				%s
			</div>
		</div>

		<div class="card" id="endpoint-card">
			<div class="card-header">`+T.IPEndpointStatusTitle+`</div>
			<div class="card-content">
				<div id="endpoint-status" class="endpoint-status">
					<span class="endpoint-waiting">`+T.IPEndpointStatusWaiting+`</span>
				</div>
			</div>
		</div>
		<div class="card">
			<div class="card-header">⚙️ `+T.ConfigHeading+`</div>
			<div class="card-content">
				<div class="config-overview-grid">
					<div><strong>`+T.MaxLogLines+`:</strong> %d</div>
					<div><strong>`+T.MaxAPIRetries+`:</strong> %d</div>
					<div><strong>`+T.MaxConcurrent+`:</strong> %d</div>
					<div><strong>`+T.Interval+`:</strong> %ds</div>
				</div>
			</div>
		</div>
	</div><!-- end dashboard section -->
	`,
		statusClass,
		statusText,
		T.LastUpdate,
		time.Now().Format("15:04:05"),
		buildNotifierStatusHTML(),
		cfg.MaxLogLines,
		cfg.MaxAPIRetries,
		cfg.MaxConcurrent,
		cfg.Interval,
	)
}

func buildUsersSection() string {
	return `<div id="users-list" class="users-list-wrap">
		 <div class="users-list-loading">` + T.UserLoading + `</div>
	</div>
	<div class="add-domain-box">
		<div class="users-add-title">` + T.UserNewTitle + `</div>
		<input type="text" id="new-user-name" class="s-input mb-8" placeholder="` + T.UserPlaceholderName + `">
		<div class="input-with-action mb-8">
			<input type="password" id="new-user-pass" class="s-input" placeholder="` + T.UserPlaceholderPass + `">
			<button type="button" class="input-action-btn" data-click="togglePassword('new-user-pass', this)">👁️</button>
		</div>
		<select id="new-user-role" class="s-input mb-8">
			<option value="viewer">` + T.UserRoleViewer + `</option>
			<option value="editor">` + T.UserRoleEditor + `</option>
			<option value="admin">` + T.UserRoleAdmin + `</option>
		</select>
		<button class="s-btn s-btn-success-full" data-click="addUser()">` + T.UserBtnCreate + `</button>
	</div>`
}

func writeDashboardMetricsCard(
	w http.ResponseWriter,
	stats map[string]any,
	nicHTML, chartSVG, latencySVG string,
	isViewer bool,
) {
	resetBtn := `<button class="action-btn metrics-reset-btn" data-click="event.preventDefault();resetMetrics()">🗑️ ` + T.MetricsResetBtn + `</button>`
	if isViewer {
		resetBtn = ""
	}
	_, _ = fmt.Fprintf(w, `
<div class="page-section" data-section="metrics">
	<div class="card" id="metrics-card">
		<div class="card-header card-header--space-between">
			📊 %s`+resetBtn+`
		</div>
		<div class="card-content">
			<!-- TOP STATS -->
			<div class="metrics-top-grid">
				<div>
					<strong>`+T.TotalRequests+`:</strong>
					<span id="mTotal">%v</span>
				</div>
				<div>
					<strong>`+T.SuccessRate+`:</strong>
					<span id="mSuccess" class="metric-success">%v</span>
				</div>
				<div>
					<strong>`+T.AvgLatency+`:</strong>
					<span id="mLatency">%v</span>
				</div>
				<div title="`+T.ClientErrors+` / `+T.ServerErrors+`">
					<strong>`+T.Errors+`:</strong>
					<span id="mErrors">%v / %v</span>
				</div>
			</div>

			<!-- LATENCY PERCENTILES -->
			<div class="latency-box">
				<div class="latency-box-label">
					`+T.MetricLatencyPercentile+`
				</div>
				<div class="latency-grid">
					<div class="latency-cell latency-cell--p50">
						<div class="latency-cell-label">P50</div>
						<div id="mP50" class="latency-cell-value">%v</div>
					</div>
					<div class="latency-cell latency-cell--p85">
						<div class="latency-cell-label">P85</div>
						<div id="mP85" class="latency-cell-value">%v</div>
					</div>
					<div class="latency-cell latency-cell--p99">
						<div class="latency-cell-label">P99</div>
						<div id="mP99" class="latency-cell-value">%v</div>
					</div>
				</div>
			</div>

			<!-- USAGE -->
			<div class="usage-section">
				<div class="usage-header">
					<span class="usage-limit-label">`+T.HourlyLimitEst+`</span>
					<span id="mUsage" class="usage-count">
						%v / %v `+T.RequestsLabel+`
					</span>
				</div>
				<div class="usage-track">
					<div id="mUsageBar" class="usage-bar" style="--usage-width:%v%%;--usage-color:%s;"></div>
				</div>
				<div class="usage-hint">
					`+T.UsageLast60Min+`
				</div>
			</div>

			<!-- BOTTOM GRID -->
			<div class="metrics-bottom-grid">
				<!-- HTTP METHODS -->
				<div class="http-methods-box">
					<div class="http-methods-label">
						`+T.MetricHTTPMethods+`
					</div>
					<div class="http-methods-grid">
						<div class="http-method-row http-method-row--get">
							<span class="http-method-key">GET</span>
							<span id="mDailyGET" class="http-method-val">%v</span>
						</div>
						<div class="http-method-row http-method-row--post">
							<span class="http-method-key">POST</span>
							<span id="mDailyPOST" class="http-method-val">%v</span>
						</div>
						<div class="http-method-row http-method-row--put">
							<span class="http-method-key">PUT</span>
							<span id="mDailyPUT" class="http-method-val">%v</span>
						</div>	
						<div class="http-method-row http-method-row--del">
							<span class="http-method-key">DEL</span>
							<span id="mDailyDELETE" class="http-method-val">%v</span>
						</div>

						%s

					</div>
				</div>

				<!-- IP LATENCY -->
				<div class="ip-latency-box">
					<div class="ip-latency-label">
						`+T.MetricIPLatency+`
					</div>
					<div class="ip-latency-center">
						<div id="mIPLatency" class="ip-latency-value">
							%v
						</div>
						<div class="ip-latency-meta">
							`+T.MetricAvgFrom+`
							<span id="mIPCount">%v</span>
							`+T.ChecksLabel+`
						</div>
						<div class="ip-latency-meta">
							`+T.MetricLastCheck+`
							<span id="mLastIPCheck">%v</span>
						</div>
					</div>
				</div>
			</div> <!-- metrics-bottom-grid -->
		</div> <!-- card-content -->
	</div> <!-- card -->

	%s
	%s

</div> <!-- page-section -->
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
	<div class="page-section" data-section="debug">
		<div class="card">
			<div class="card-header card-header--flex">
				🐞 `+T.DebugLogTitle+` <span class="debug-badge">`+T.DebugLogLive+`</span>
			</div>
			<div class="card-content">
				<div class="debug-toolbar">
					<input type="text" id="debug-filter" placeholder="`+T.DebugFilterPlaceholder+`"
						data-input="filterDebugLog(this.value)" class="debug-filter-input">
					<button data-click="clearDebugLog()" class="action-btn debug-clear-btn">`+T.DebugClearBtn+`</button>
					<label class="debug-autoscroll-label">
						<input type="checkbox" id="debug-autoscroll" checked> `+T.DebugAutoscroll+`
					</label>
				</div>
				<div id="debug-log-container" class="debug-log-box">
					<span class="debug-placeholder">`+T.DebugWaitingMsg+`</span>
				</div>
			</div>
		</div>
	</div>
	`)
}

func writeLogsCard(w io.Writer, logs []LogEntry, logTimeRange string) {
	entryCount := len(logs)
	timeRangeHTML := ""
	if logTimeRange != "" {
		timeRangeHTML = `<span class="logs-summary-sep">🕒 ` + logTimeRange + `</span>`
	}

	_, _ = fmt.Fprintf(w, `
	<div class="page-section" data-section="logs">
		<div class="card card--overflow-visible">
			<div class="card-header card-header--flex-wrap">
				🧾 %s
				<span class="logs-summary-meta">
					(%d `+T.EntriesLabel+`)
					%s
				</span>
			</div>
			<div class="card-content">
				<div class="log-filters">
					<button class="filter-btn active" data-filter="all" data-click="filterLogs('all')">`+T.FilterAll+`</button>
					<button class="filter-btn" data-filter="ERR" data-click="filterLogs('ERR')">`+T.FilterErrors+`</button>
					<button class="filter-btn" data-filter="WARN" data-click="filterLogs('WARN')">`+T.FilterWarnings+`</button>
					<button class="filter-btn" data-filter="UPDATE" data-click="filterLogs('UPDATE')">`+T.FilterUpdates+`</button>
					<button class="filter-btn" data-filter="START" data-click="filterLogs('START')">`+T.FilterStarts+`</button>
					<button class="filter-btn" data-filter="STOP" data-click="filterLogs('STOP')">`+T.FilterStop+`</button>
					<button class="filter-btn" data-filter="CREATE" data-click="filterLogs('CREATE')">`+T.FilterCreated+`</button>
					<button class="filter-btn" data-filter="CLEANUP" data-click="filterLogs('CLEANUP')">`+T.FilterCleanup+`</button>
					<button class="filter-btn" data-filter="SKIP" data-click="filterLogs('SKIP')">`+T.FilterSkip+`</button>
					<button class="filter-btn" data-filter="CONFIG" data-click="filterLogs('CONFIG')">`+T.FilterConfig+`</button>
					<button class="filter-btn" data-filter="INFO" data-click="filterLogs('INFO')">`+T.FilterInfo+`</button>
					<button class="filter-btn filter-btn--export" data-click="exportLogs('txt')">📄 TXT</button>
					<button class="filter-btn" data-click="exportLogs('json')">📋 JSON</button>
				</div>
				<div id="logContainer" class="log-container">
	`, T.SystemEvents, entryCount, timeRangeHTML)

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
		copyText := displayTime
		if e.Domain != "" {
			copyText += " [" + e.Domain + "]"
		}
		copyText += " " + e.Message

		_, _ = fmt.Fprintf(w, `
		<div class="log-entry log-entry-row" data-action="%s" data-level="%s" data-copy="%s">
			<span class="log-entry-icon">%s</span>
			<span class="log-entry-time">%s</span>
			<div class="log-entry-body">%s<span class="log-entry-message">%s</span></div>
			<button class="copy-btn log-copy-btn" data-click="copyLogEntry(this)" title="Kopieren">📋</button>
		</div>`,
			actionUpper, e.Level, html.EscapeString(copyText),
			icon, displayTime, domainHTML, html.EscapeString(e.Message),
		)
	}

	if len(logs) == 0 {
		_, _ = fmt.Fprintf(w, `<div class="log-empty">%s</div>`, T.NoMoreEntries)
	}

	_, _ = fmt.Fprint(w, `
				</div>
			</div>
		</div>
	</div>
	`)
}

func writeDomainsCard(w io.Writer, data map[string]any) {
	keys := domainKeysFromStatusData(data)
	configuredDomains := configuredDomainSet()
	newestChange := newestDomainChange(data, keys)

	hasIPv64 := false
	cfgMu.RLock()
	for _, dc := range cfg.DomainConfigs {
		if dc.Provider == ProviderIPv64 {
			hasIPv64 = true
			break
		}
	}
	cfgMu.RUnlock()

	_, _ = fmt.Fprint(w, `
	<div class="page-section" data-section="domains">
		<input type="text" class="search-box" id="domainSearch" inputmode="search" autocomplete="off"
			placeholder="`+T.DomainSearchPlaceholder+`" data-input="filterDomains(this.value)">
	`)

	if hasIPv64 {
		_, _ = fmt.Fprint(w, `
			<div class="card ipv64-mgmt-card">
				<div class="card-content">
					<div class="ipv64-mgmt-row">
						<div class="ipv64-mgmt-input-wrap">
							<label class="ipv64-mgmt-label">`+T.IPv64DomainFQDN+`</label>
							<input type="text" id="ipv64-domain-input" class="search-box ipv64-mgmt-input"
								placeholder="`+T.IPv64DomainPlaceholder+`">
						</div>
						<div class="ipv64-mgmt-input-wrap">
							<label class="ipv64-mgmt-label">`+T.IPv64DomainAPITokenOptional+`</span></label>
							<div class="input-with-action">
								<input type="password" id="ipv64-api-token-input" class="search-box ipv64-mgmt-input"
									placeholder="`+T.IPv64DomainPlaceholderToken+`">
								<button type="button" class="input-action-btn" data-click="togglePassword('ipv64-api-token-input', this)">👁️</button>
							</div>
						</div>
						<button class="action-btn btn--add-domain" data-click="ipv64AddDomain()">
							➕ `+T.IPv64ActionAdd+`
						</button>
						<button class="action-btn btn--del-domain" data-click="ipv64DeleteDomain()">
							🗑️ `+T.IPv64ActionDelete+`
						</button>
					</div>
					<div id="ipv64-domain-result" class="ipv64-result"></div>
				</div>
			</div>
		`)
	}

	_, _ = fmt.Fprint(w, `<div id="domainContainer">`)

	for _, k := range keys {
		h := parseDomainHistory(data[k])
		writeSingleDomainCard(w, k, h, configuredDomains, newestChange)
	}

	_, _ = fmt.Fprint(w, `
		</div> <!-- domainContainer -->
	</div> <!-- domains page-section -->
	`)
}

func writeSettingsSection(w http.ResponseWriter, c Config) {
	securitySection := buildSettingsSecuritySection()
	systemSection := buildSettingsSystemSection(c)
	domainsSection := buildSettingsDomainsSection()
	notifySection := buildSettingsNotifySection(c)

	_, _ = fmt.Fprint(w, `
	<div class="page-section" data-section="settings">
		<div class="card">
			<div class="card-header">⚙️ `+T.SettingsTitle+`</div>
			<div class="card-content">
				`+buildSettingsInlineSection(T.SettingsSecurity, securitySection)+`
				`+buildSettingsInlineSection(T.SettingsSystem, systemSection)+`
				`+buildSettingsInlineSection(T.SettingsDomains, domainsSection)+`
				`+buildSettingsInlineSection(T.SettingsNotify, notifySection)+`
			</div>
		</div>
	</div>
	`)
}

func writeTOTPSection(w http.ResponseWriter, sess *Session, enabled bool) {
	if !enabled {
		_, _ = fmt.Fprint(w, `<div class="page-section" data-section="totp"></div>`)
		return
	}

	_, _ = fmt.Fprint(w, `
	<div class="page-section" data-section="totp">
		<div class="card totp-settings-card">
			<div class="card-header">🔐 2FA / Konto-Sicherheit</div>
			<div class="card-content totp-settings-wrap" id="totp-settings-content">
				`+build2FASettingsFragmentForSession(sess, "", "")+`
			</div>
		</div>
	</div>
	`)
}

func writeUsersSection(w http.ResponseWriter, isAdmin bool) {
	if !isAdmin {
		_, _ = fmt.Fprint(w, `<div class="page-section" data-section="users"></div>`)
		return
	}
	_, _ = fmt.Fprint(w, `
	<div class="page-section" data-section="users">
		<div class="card">
			<div class="card-header">`+T.SettingsUserManagement+`</div>
			<div class="card-content">
				`+buildUsersSection()+`
			</div>
		</div>
	</div>
	`)
}

func domainKeysFromStatusData(data map[string]any) []string {
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

func newestDomainChange(data map[string]any, keys []string) time.Time {
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

func parseDomainHistory(v any) DomainHistory {
	var h DomainHistory
	b, _ := json.Marshal(v)
	_ = json.Unmarshal(b, &h)
	return h
}

func writeSingleDomainCard(w io.Writer, domain string, h DomainHistory, configuredDomains map[string]struct{}, newestChange time.Time) {
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
	<details class="card domain-item%s" data-domain="%s" data-ip-history="%s">
		<summary class="domain-summary">
			<span id="dot-%s" class="%s" title="%s"></span>
			🌐 %s <span class="logs-summary-meta">(%s) <span class="provider-status-dot" id="pstatus-%s"></span></span>%s%s%s
		</summary>
		
		<div class="card-content">
			<div class="domain-card domain-card-head">
				<div class="domain-card-top">
					<div>
						<div class="ip-display">
							<span class="badge v4">IPv4</span>
							<span id="ip4-%s">%s</span>
							<button class="copy-btn" data-click="copyIP('%s')" title="Copy">📋</button>
						</div>
						<div class="ip-display domain-ip-row-spaced">
							<span class="badge v6">IPv6</span>
							<span id="ip6-%s">%s</span>
							<button class="copy-btn" data-click="copyIP('%s')" title="Copy">📋</button>
						</div>
					</div>
					<div class="domain-card-meta" data-last-changed="%s" data-uptime-id="%s">
						<small>`+T.LastShort+` %s</small>
						<small class="domain-uptime-small">⏱️ <span id="uptime-%s">—</span></small>
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
		orphanStyle,
		esc(domain),
		func() string { b, _ := json.Marshal(h.IPs); return html.EscapeString(string(b)) }(),
		safeID,
		dotClass,
		dotTitle,
		esc(domain),
		esc(h.Provider),
		safeID,
		changedBadge,
		orphanLabel,
		deleteBtn,
		safeID,
		esc(latest.IPv4),
		jsString(latest.IPv4),
		safeID,
		esc(latest.IPv6),
		jsString(latest.IPv6),
		h.LastChanged,
		safeID,
		esc(latest.Time),
		safeID,
	)

	writeDomainHistoryRows(w, h)

	_, _ = fmt.Fprint(w, `
						</tbody>
					</table>
				</div>
			<div class="ip-timeline-wrap"></div>
		</div>
	</details>`)
}

func buildDomainStatusVisuals(h DomainHistory, safeID string, newestChange time.Time) (string, string, string) {
	dotClass := "domain-status-dot dot-idle"
	dotTitle := T.DotTitleNoUpdate
	changedBadge := `<span id="badge-` + safeID + `" class="changed-badge changed-badge--hidden">` + T.BadgeChanged + `</span>`

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
		changedBadge = `<span id="badge-` + safeID + `" class="changed-badge" data-changed-at="` + h.LastChanged + `">` + T.BadgeChanged + `</span>`
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
	orphanStyle := " domain-item--orphan"
	orphanLabel := `<span class="orphan-badge">` + esc(T.NotConfiguredLabel) + `</span>`

	deleteBtn := `<button class="action-btn btn-danger-soft" ` +
		`data-click="event.preventDefault();event.stopPropagation();` +
		`deleteDomain('` + jsString(domain) + `',this)">` +
		esc(T.RemoveBtn) + `</button>`

	return orphanStyle, orphanLabel, deleteBtn
}

func writeDomainHistoryRows(w io.Writer, h DomainHistory) {
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
	<footer class="dashboard-footer dashboard-footer--positioned">
		<div>
			<span>&copy; %d IONOS-DDNS Made with ❤️ by</span>
			<span class="dashboard-footer-sep">|</span>
			<a href="https://github.com/CrazyUs3r/IONOS-DDNS" target="_blank" rel="noopener noreferrer" class="dashboard-footer-link">CrazyUs3r</a>
		</div>
	</footer>

			</div><!-- end main-content -->
		</div><!-- end app-right -->
	</div><!-- end app-layout -->
	`, time.Now().Year())

	_, _ = fmt.Fprint(w, `
	<script src="/assets/i18n.js" defer></script>
	<script src="/assets/dashboard.js" defer></script>
	</body>
	</html>
	`)
}

// ============================================================================
// DIAGNOSE / HEALTH CENTER
// ============================================================================

func writeDiagnoseSection(w http.ResponseWriter) {
	_, _ = fmt.Fprint(w, `
	<div class="page-section" data-section="diagnose">
		<div class="card">
			<div class="card-header card-header--space-between">
				<span>🩺 `+t(T.DiagnoseTitle, "Diagnose / Health Center")+`</span>
				<button class="action-btn topbar-action-btn" data-click="refreshDiagnosis()">`+t(T.DiagnoseRefreshBtn, "🔄 Refresh")+`</button>
			</div>
			<div class="card-content">
				<div id="diagnose-content" class="diag-loading">
					`+t(T.DiagnoseLoading, "Loading diagnosis...")+`
				</div>
			</div>
		</div>
	</div>
	`)
}

func handleAPIDiagnose(w http.ResponseWriter, r *http.Request) {
	if r.Method != MethodGET {
		http.Error(w, T.APIErrorMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}

	writeJSON(w, http.StatusOK, buildDiagnosisPayload())
}

type diagnosisLogCounts struct {
	Errors   int
	Warnings int
}

type diagnosisConfigSnapshot struct {
	ProviderCounts map[string]int
	Warnings       []string
	Notifiers      map[string]bool
	Info           map[string]any
}

func buildDiagnosisPayload() map[string]any {
	stats := apiMetrics.GetStats()
	lastV4, lastV6 := loadLastKnownIPs()

	statusData := loadStatusData()
	domainKeys := domainKeysFromStatusData(statusData)
	newestChange := newestDomainChange(statusData, domainKeys)

	logs, _ := loadDashboardLogs()
	logCounts := countDiagnosisLogs(logs)

	cfgDiag := buildDiagnosisConfigSnapshot()
	mainStatus, reason := diagnosisMainStatus(cfgDiag.Warnings, logCounts.Warnings)

	return map[string]any{
		"status":             mainStatus,
		"reason":             reason,
		"uptime":             time.Since(startTime).Round(time.Second).String(),
		"scheduler_ran_once": schedulerRanOnce.Load(),
		"last_ok":            lastOk.Load(),
		"update_in_progress": updateInProgress.Load(),
		"active_updates":     activeUpdates.Load(),

		"last_known_ipv4":    lastV4,
		"last_known_ipv6":    lastV6,
		"last_domain_change": formatDiagnosisTime(newestChange),

		"configured_domains": len(domainKeys),
		"provider_counts":    cfgDiag.ProviderCounts,
		"warnings":           cfgDiag.Warnings,
		"log_errors":         logCounts.Errors,
		"log_warnings":       logCounts.Warnings,
		"api_metrics":        stats,
		"config":             cfgDiag.Info,
		"notifiers":          cfgDiag.Notifiers,

		"files": diagnosisFileInfos(),
	}
}

func countDiagnosisLogs(logs []LogEntry) diagnosisLogCounts {
	var counts diagnosisLogCounts

	for _, e := range logs {
		lvl := strings.ToUpper(e.Level)

		if strings.Contains(lvl, "ERR") || strings.Contains(lvl, "ERROR") {
			counts.Errors++
		}

		if strings.Contains(lvl, "WARN") {
			counts.Warnings++
		}
	}

	return counts
}

func buildDiagnosisConfigSnapshot() diagnosisConfigSnapshot {
	cfgCopy := cloneConfigForBackup()

	warnings := diagnoseDomainWarnings(cfgCopy.DomainConfigs)
	warnings = append(warnings, diagnoseGlobalConfigWarnings(cfgCopy)...)

	return diagnosisConfigSnapshot{
		ProviderCounts: diagnoseProviderCounts(cfgCopy.DomainConfigs),
		Warnings:       warnings,
		Notifiers:      diagnoseNotifiers(cfgCopy),
		Info:           diagnoseConfigInfo(cfgCopy),
	}
}

func diagnoseProviderCounts(domains []DomainConfig) map[string]int {
	counts := make(map[string]int)

	for _, dc := range domains {
		counts[string(dc.Provider)]++
	}

	return counts
}

func diagnoseDomainWarnings(domains []DomainConfig) []string {
	warnings := make([]string, 0)

	for _, dc := range domains {
		warnings = append(warnings, diagnoseSingleDomainWarnings(dc)...)
	}

	if len(domains) == 0 {
		warnings = append(warnings, t(T.DiagnoseNoDomainsConfigured, "No domains configured."))
	}

	return warnings
}

func diagnoseSingleDomainWarnings(dc DomainConfig) []string {
	warnings := make([]string, 0)

	if strings.TrimSpace(dc.FQDN) == "" {
		warnings = append(warnings, t(T.DiagnoseDomainWithoutFQDN, "A domain without FQDN is configured."))
	}

	if dc.TTL > 0 && dc.TTL < 60 {
		warnings = append(warnings, fmt.Sprintf(
			t(T.DiagnoseTTLTooLowFormat, "%s: TTL is very low."),
			diagnosisDomainName(dc),
		))
	}

	if msg := providerCredentialWarning(dc); msg != "" {
		warnings = append(warnings, msg)
	}

	return warnings
}

func diagnosisDomainName(dc DomainConfig) string {
	fqdn := strings.TrimSpace(dc.FQDN)
	if fqdn == "" {
		return t(T.DiagnoseUnknownDomain, "Unknown domain")
	}
	return fqdn
}

func providerCredentialWarning(dc DomainConfig) string {
	fqdn := diagnosisDomainName(dc)

	switch dc.Provider {
	case ProviderIONOS:
		if dc.APIPrefix == "" || dc.APISecret == "" {
			return fmt.Sprintf(
				t(T.DiagnoseIonosCredentialsIncompleteFormat, "%s: IONOS credentials incomplete."),
				fqdn,
			)
		}

	case ProviderCloudflare:
		if dc.CFToken == "" && (dc.CFEmail == "" || dc.CFSecret == "") {
			return fmt.Sprintf(
				t(T.DiagnoseCloudflareCredentialsIncompleteFormat, "%s: Cloudflare credentials incomplete."),
				fqdn,
			)
		}

	case ProviderIPv64:
		if dc.IPv64Token == "" {
			return fmt.Sprintf(
				t(T.DiagnoseIpv64TokenMissingFormat, "%s: IPv64 token missing."),
				fqdn,
			)
		}
	}

	return ""
}

func diagnoseGlobalConfigWarnings(cfg Config) []string {
	warnings := make([]string, 0)

	if cfg.DryRun {
		warnings = append(warnings, t(T.DiagnoseDryRunActive, "Dry-run is active: DNS changes are not written."))
	}

	if cfg.DebugEnabled {
		warnings = append(warnings, t(T.DiagnoseDebugActive, "Debug mode is active."))
	}

	if cfg.DebugHTTPRaw {
		warnings = append(warnings, t(T.DiagnoseHTTPRawDebugActive, "HTTP raw debug is active. Sensitive data may appear in logs."))
	}

	if cfg.Interval > 0 && cfg.Interval < 60 {
		warnings = append(warnings, t(T.DiagnoseIntervalLow, "Update interval is very low."))
	}

	return warnings
}

func diagnoseNotifiers(cfg Config) map[string]bool {
	return map[string]bool{
		"telegram": cfg.Notifications.Telegram.Token != "" && cfg.Notifications.Telegram.ChatID != "",
		"gotify":   cfg.Notifications.Gotify.URL != "" && cfg.Notifications.Gotify.Token != "",
		"webhook":  cfg.Notifications.Webhook.URL != "",
		"mqtt":     cfg.Notifications.MQTTConfig.Broker != "" && cfg.Notifications.MQTTConfig.Topic != "",
		"email":    cfg.Notifications.Email.Host != "" && cfg.Notifications.Email.To != "",
	}
}

func diagnoseConfigInfo(cfg Config) map[string]any {
	return map[string]any{
		"ip_mode":        cfg.IPMode,
		"interval":       cfg.Interval,
		"dry_run":        cfg.DryRun,
		"debug":          cfg.DebugEnabled,
		"debug_http_raw": cfg.DebugHTTPRaw,
		"max_log_lines":  cfg.MaxLogLines,
		"ipv4_endpoints": len(cfg.IPv4Endpoints),
		"ipv6_endpoints": len(cfg.IPv6Endpoints),
	}
}

func diagnosisMainStatus(warnings []string, logWarnings int) (string, string) {
	if !schedulerRanOnce.Load() {
		return "starting", t(T.DiagnoseReasonSchedulerNotRun, "Scheduler has not run yet.")
	}

	if !lastOk.Load() {
		return "unhealthy", t(T.DiagnoseReasonLastSchedulerFailed, "The last scheduler run failed.")
	}

	if len(warnings) > 0 || logWarnings > 0 {
		return "degraded", t(T.DiagnoseReasonWarningsButRunning, "There are warnings, but the service is running.")
	}

	return "healthy", t(T.DiagnoseReasonAllGood, "Everything looks good.")
}

func formatDiagnosisTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}

	return t.Format("02.01.2006 15:04:05")
}

func diagnosisFileInfos() []map[string]any {
	return []map[string]any{
		diagnoseFileInfo("config.json", configPath),
		diagnoseFileInfo("status/update.json", updatePath),
		diagnoseFileInfo("logs", logPath),
		diagnoseFileInfo("users.json", usersFilePath),
	}
}

func diagnoseFileInfo(name, path string) map[string]any {
	out := map[string]any{
		"name":   name,
		"exists": false,
	}

	if strings.TrimSpace(path) == "" {
		out["error"] = t(T.DiagnosePathEmpty, "path empty")
		return out
	}

	st, err := os.Stat(path)
	if err != nil {
		out["error"] = err.Error()
		return out
	}

	out["exists"] = true
	out["size"] = st.Size()
	out["modified"] = st.ModTime().Format("02.01.2006 15:04:05")
	return out
}

// ============================================================================
// BACKUP & RESTORE
// ============================================================================

type dashboardBackup struct {
	Version   int                      `json:"version"`
	App       string                   `json:"app"`
	CreatedAt string                   `json:"created_at"`
	Config    *Config                  `json:"config,omitempty"`
	Status    map[string]DomainHistory `json:"status,omitempty"`
	Users     []DashboardUser          `json:"users,omitempty"`
	Logs      []LogEntry               `json:"logs,omitempty"`
	Metrics   map[string]any           `json:"metrics,omitempty"`
}

func writeBackupSection(w http.ResponseWriter, isAdmin bool) {
	if !isAdmin {
		_, _ = fmt.Fprint(w, `
		<div class="page-section" data-section="backup">
			<div class="card">
				<div class="card-header">💾 `+t(T.BackupTitle, "Backup & Restore")+`</div>
				<div class="card-content">
					<div class="backup-warning">
						🔒 `+t(T.BackupAdminOnly, "Backup & Restore is only available for admins.")+`
					</div>
				</div>
			</div>
		</div>
		`)
		return
	}

	_, _ = fmt.Fprint(w, `
	<div class="page-section" data-section="backup">
		<div class="card">
			<div class="card-header">💾 `+t(T.BackupTitle, "Backup & Restore")+`</div>
			<div class="card-content">
				<div class="backup-grid">
					<div class="backup-box">
						<h3>`+t(T.BackupCreateTitle, "Create backup")+`</h3>
						<p>`+t(T.BackupCreateDesc, "Exports config, status, users, logs and current metrics as JSON.")+`</p>
						<button class="action-btn" data-click="downloadFullBackup()">`+t(T.BackupDownloadBtn, "⬇️ Download backup")+`</button>
						<div class="backup-hint">
							`+t(T.BackupSecretsHint, "Warning: The backup contains secrets and password hashes. Store it safely.")+`
						</div>
					</div>

					<div class="backup-box">
						<h3>`+t(T.BackupRestoreTitle, "Restore backup")+`</h3>
						<p>`+t(T.BackupRestoreDesc, "Select a previously created backup and choose which areas should be restored.")+`</p>

						<input type="file" id="backup-file" class="search-box" accept="application/json,.json">

						<label class="inline-check">
							<input type="checkbox" id="restore-config" checked>
							`+t(T.BackupRestoreConfig, "Restore config")+`
						</label>

						<label class="inline-check">
							<input type="checkbox" id="restore-status" checked>
							`+t(T.BackupRestoreStatus, "Restore domain status / history")+`
						</label>

						<label class="inline-check">
							<input type="checkbox" id="restore-users">
							`+t(T.BackupRestoreUsers, "Restore users")+`
						</label>

						<button class="action-btn btn-danger-soft backup-restore-btn" data-click="restoreFullBackup()">
							`+t(T.BackupRestoreStartBtn, "♻️ Start restore")+`
						</button>

						<div id="backup-result" class="backup-result"></div>
					</div>
				</div>
			</div>
		</div>
	</div>
	`)
}

func requireAdminAPI(w http.ResponseWriter, r *http.Request) bool {
	if !authEnabled {
		return true
	}

	sess, ok := sessionFromRequest(r)
	if !ok || sess == nil || sess.Role != RoleAdmin {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": t(T.BackupAdminRequired, "admin required"),
		})
		return false
	}

	return true
}

func cloneConfigForBackup() Config {
	cfgMu.RLock()
	defer cfgMu.RUnlock()

	cp := cfg
	cp.DomainConfigs = append([]DomainConfig(nil), cfg.DomainConfigs...)
	cp.DNSServers = append([]string(nil), cfg.DNSServers...)
	cp.IPv4Endpoints = append([]string(nil), cfg.IPv4Endpoints...)
	cp.IPv6Endpoints = append([]string(nil), cfg.IPv6Endpoints...)
	cp.Notifications.Events = append([]string(nil), cfg.Notifications.Events...)

	return cp
}

func readStatusBackup() map[string]DomainHistory {
	statusMutex.Lock()
	defer statusMutex.Unlock()

	out := make(map[string]DomainHistory)

	b, err := os.ReadFile(updatePath)
	if err != nil {
		return out
	}

	_ = json.Unmarshal(b, &out)
	return out
}

func handleAPIBackupDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != MethodGET {
		http.Error(w, T.APIErrorMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}
	if !requireAdminAPI(w, r) {
		return
	}

	cfgCopy := cloneConfigForBackup()
	logs, _ := loadDashboardLogsFresh()

	backup := dashboardBackup{
		Version:   1,
		App:       "dyndns-dashboard",
		CreatedAt: time.Now().Format(time.RFC3339),
		Config:    &cfgCopy,
		Status:    readStatusBackup(),
		Users:     loadUsers(),
		Logs:      logs,
		Metrics:   apiMetrics.GetStats(),
	}

	filename := "dyndns-backup-" + time.Now().Format("20060102-150405") + ".json"

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(backup); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func handleAPIBackupRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != MethodPOST {
		http.Error(w, T.APIErrorMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}

	if !requireAdminAPI(w, r) {
		return
	}

	req, status, err := parseBackupRestoreRequest(w, r)
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	restored, status, err := restoreSelectedBackup(req)
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	logBackupRestore(restored)

	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "restored",
		"restored": restored,
	})
}

type backupRestoreSelection struct {
	Config bool
	Status bool
	Users  bool
}

type backupRestoreRequest struct {
	Backup    dashboardBackup
	Selection backupRestoreSelection
}

func parseBackupRestoreRequest(w http.ResponseWriter, r *http.Request) (backupRestoreRequest, int, error) {
	const maxBackupSize = 16 << 20
	r.Body = http.MaxBytesReader(w, r.Body, maxBackupSize)
	if err := r.ParseMultipartForm(maxBackupSize); err != nil {
		return backupRestoreRequest{}, http.StatusBadRequest, err
	}

	selection := backupRestoreSelectionFromForm(r)
	if !selection.any() {
		return backupRestoreRequest{}, http.StatusBadRequest, fmt.Errorf("%s", t(T.BackupNothingSelected, "nothing selected"))
	}

	file, _, err := r.FormFile("backup")
	if err != nil {
		return backupRestoreRequest{}, http.StatusBadRequest, fmt.Errorf("%s", t(T.BackupFileMissing, "backup file missing"))
	}
	defer func() {
		if err := file.Close(); err != nil {
			debugLog("DASHBOARD", "", fmt.Sprintf(T.ErrBodyClose+": %v", err))
		}
	}()

	backup, err := decodeDashboardBackup(file)
	if err != nil {
		return backupRestoreRequest{}, http.StatusBadRequest, err
	}

	return backupRestoreRequest{
		Backup:    backup,
		Selection: selection,
	}, http.StatusOK, nil
}

func backupRestoreSelectionFromForm(r *http.Request) backupRestoreSelection {
	return backupRestoreSelection{
		Config: r.FormValue("config") == "1",
		Status: r.FormValue("status") == "1",
		Users:  r.FormValue("users") == "1",
	}
}

func (s backupRestoreSelection) any() bool {
	return s.Config || s.Status || s.Users
}

func decodeDashboardBackup(file io.Reader) (dashboardBackup, error) {
	var backup dashboardBackup

	err := json.NewDecoder(io.LimitReader(file, 16<<20)).Decode(&backup)
	if err != nil {
		return dashboardBackup{}, fmt.Errorf(
			t(T.BackupInvalidJSONFormat, "invalid backup json: %w"),
			err,
		)
	}

	return backup, nil
}

func restoreSelectedBackup(req backupRestoreRequest) ([]string, int, error) {
	restored := make([]string, 0, 3)

	if req.Selection.Config {
		status, err := restoreBackupConfig(req.Backup)
		if err != nil {
			return nil, status, err
		}
		restored = append(restored, "config")
	}

	if req.Selection.Status {
		status, err := restoreBackupStatus(req.Backup)
		if err != nil {
			return nil, status, err
		}
		restored = append(restored, "status")
	}

	if req.Selection.Users {
		status, err := restoreBackupUsers(req.Backup)
		if err != nil {
			return nil, status, err
		}
		restored = append(restored, "users")
	}

	return restored, http.StatusOK, nil
}

func restoreBackupConfig(backup dashboardBackup) (int, error) {
	if backup.Config == nil {
		return http.StatusBadRequest, fmt.Errorf("%s", t(T.BackupContainsNoConfig, "backup contains no config"))
	}

	oldCfg, err := applyBackupConfig(*backup.Config)
	if err != nil {
		return http.StatusUnprocessableEntity, err
	}

	if err := saveConfigToFile(); err != nil {
		restoreConfigInMemory(oldCfg)
		return http.StatusInternalServerError, fmt.Errorf(
			t(T.BackupConfigSaveFailedFormat, "config save failed: %w"),
			err,
		)
	}

	afterConfigRestore()
	return http.StatusOK, nil
}

func applyBackupConfig(newCfg Config) (Config, error) {
	cfgMu.Lock()
	defer cfgMu.Unlock()

	oldCfg := cfg
	cfg = newCfg

	if err := validateDomainConfigs(); err != nil {
		cfg = oldCfg
		return oldCfg, err
	}

	return oldCfg, nil
}

func restoreConfigInMemory(oldCfg Config) {
	cfgMu.Lock()
	cfg = oldCfg
	cfgMu.Unlock()
}

func afterConfigRestore() {
	ResetHTTPClient()
	invalidateSecretReplacer()

	go initNotifiers()

	forceNextUpdate.Store(true)
	lastCleanupNano.Store(0)
}

func restoreBackupStatus(backup dashboardBackup) (int, error) {
	if backup.Status == nil {
		return http.StatusBadRequest, fmt.Errorf("%s", t(T.BackupContainsNoStatus, "backup contains no status"))
	}

	b, err := json.MarshalIndent(backup.Status, "", "  ")
	if err != nil {
		return http.StatusInternalServerError, err
	}

	statusMutex.Lock()
	defer statusMutex.Unlock()

	if err := os.WriteFile(updatePath, b, 0o600); err != nil {
		return http.StatusInternalServerError, fmt.Errorf(
			t(T.BackupStatusRestoreFailedFormat, "status restore failed: %w"),
			err,
		)
	}

	statusDomains = backup.Status
	return http.StatusOK, nil
}

func restoreBackupUsers(backup dashboardBackup) (int, error) {
	if len(backup.Users) == 0 {
		return http.StatusBadRequest, fmt.Errorf("%s", t(T.BackupContainsNoUsers, "backup contains no users"))
	}

	if err := saveUsers(backup.Users); err != nil {
		return http.StatusInternalServerError, fmt.Errorf(
			t(T.BackupUsersRestoreFailedFormat, "users restore failed: %w"),
			err,
		)
	}

	sessionStore.DeleteAll()
	return http.StatusOK, nil
}

func logBackupRestore(restored []string) {
	log(LogContext{
		Level:  LogWarn,
		Action: ActionConfig,
		Message: fmt.Sprintf(
			t(T.BackupRestoredLogFormat, "Backup restored: %s"),
			strings.Join(restored, ", "),
		),
	})
}
