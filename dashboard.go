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

	ipModeOptions := func(current string) string {
		var out strings.Builder
		for _, m := range []string{"BOTH", "IPV4", "IPV6"} {
			sel := ""
			if m == current {
				sel = ` selected`
			}
			fmt.Fprintf(&out, `<option value="%s"%s>%s</option>`, m, sel, m)
		}
		return out.String()
	}

	notifyEventCheckboxes := func(current []string) string {
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
		out.WriteString(`<div style="display:flex;flex-direction:column;gap:6px;margin-top:4px;">`)
		for _, ev := range events {
			chk := ""
			if active[ev.code] {
				chk = ` checked`
			}
			fmt.Fprintf(&out, `<label style="display:flex;align-items:center;gap:10px;padding:6px 8px;`+
				`background:rgba(255,255,255,0.03);border-radius:6px;cursor:pointer;">`+
				`<input type="checkbox" name="notify-event" value="%s"%s `+
				`style="width:16px;height:16px;cursor:pointer;flex-shrink:0;">`+
				`<span style="display:flex;flex-direction:column;gap:1px;">`+
				`<span style="font-size:0.85rem;font-weight:600;">%s</span>`+
				`<span style="font-size:0.7rem;opacity:0.5;">%s</span>`+
				`</span></label>`,
				ev.code, chk, ev.label, ev.desc)
		}
		out.WriteString(`</div>`)
		return out.String()
	}

	return `<div id="settingsOverlay" class="modal-overlay" onclick="closeSettingsOutside(event)">` +
		`<div class="modal">` +
		`<div class="modal-header">` +
		`<h2>⚙️ ` + T.SettingsTitle + `</h2>` +
		`<button class="modal-close" onclick="closeSettings()">✕</button>` +
		`</div>` +
		`<div class="modal-body">` +

		`<div class="s-section">` +
		`<h3>` + T.SettingsSecurity + `</h3>` +
		`<div class="s-row" style="flex-direction:column;align-items:stretch;gap:8px;">` +
		`<span class="s-label">` + T.SettingsTriggerToken + `</span>` +
		`<div style="position:relative;width:100%;">` +
		`<input type="password" id="s-token" class="s-input" placeholder="` + T.SettingsTokenPlaceholder + `" autocomplete="off" style="padding-right:40px;">` +
		`<button type="button" onclick="togglePassword('s-token', this)" style="position:absolute;right:8px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;padding:0;font-size:16px;line-height:1;">👁️</button>` +
		`</div>` +
		`<button class="s-btn" onclick="saveToken()">` + T.SettingsTokenSave + `</button>` +
		`</div></div>` +

		`<div class="s-section">` +
		`<h3>` + T.SettingsSystem + `</h3>` +

		`<div class="s-row">` +
		`<span class="s-label">` + T.SettingsIPMode + `</span>` +
		`<select id="cfg-ip-mode" class="s-input" style="width:auto;min-width:110px;">` +
		ipModeOptions(c.IPMode) +
		`</select>` +
		`</div>` +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsInterval+`</span>`+
			`<input type="number" id="cfg-interval" class="s-input" style="width:90px;text-align:right;" min="30" max="86400" value="%d"></div>`, c.Interval) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsHealthPort+`</span>`+
			`<input type="text" id="cfg-health-port" class="s-input" style="width:90px;text-align:right;" value="%s"></div>`, html.EscapeString(c.HealthPort)) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsIface+` <small style="opacity:.5">`+T.SettingsIfaceHint+`</small></span>`+
			`<input type="text" id="cfg-iface" class="s-input" style="width:150px;" placeholder="`+T.SettingsIfacePlaceholder+`" value="%s"></div>`, html.EscapeString(c.IfaceName)) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsDNS+` <small style="opacity:.5">(`+T.SettingsDNSHint+`)</small></span>`+
			`<input type="text" id="cfg-dns" class="s-input" style="width:220px;" placeholder="1.1.1.1:53, 8.8.8.8:53" value="%s"></div>`, html.EscapeString(dnsStr)) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsMaxLog+`</span>`+
			`<input type="number" id="cfg-max-log" class="s-input" style="width:90px;text-align:right;" min="100" max="50000" value="%d"></div>`, c.MaxLogLines) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsMaxRetries+`</span>`+
			`<input type="number" id="cfg-max-retries" class="s-input" style="width:90px;text-align:right;" min="0" max="20" value="%d"></div>`, c.MaxAPIRetries) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsMaxConcurrent+`</span>`+
			`<input type="number" id="cfg-max-concurrent" class="s-input" style="width:90px;text-align:right;" min="1" max="20" value="%d"></div>`, c.MaxConcurrent) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsHourlyLimit+`</span>`+
			`<input type="number" id="cfg-hourly-limit" class="s-input" style="width:90px;text-align:right;" min="100" max="100000" value="%d"></div>`, c.HourlyRateLimit) +

		`<div class="s-row"><span class="s-label">` + T.SettingsLanguage + `</span>` +
		`<select id="cfg-lang" class="s-input" style="width:auto;min-width:160px;">` +
		buildDynamicLangOptions(c.Lang) +
		`</select></div>` +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsDryRun+` <small style="opacity:.5">`+T.SettingsDryRunHint+`</small></span>`+
			`<label style="display:flex;align-items:center;gap:6px;cursor:pointer;">`+
			`<input type="checkbox" id="cfg-dry-run" style="width:18px;height:18px;cursor:pointer;"%s>`+
			`<span style="font-size:0.8rem;opacity:0.7;">`+T.SettingsDryRunActive+`</span></label></div>`,
			func() string {
				if c.DryRun {
					return ` checked`
				}
				return ""
			}()) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">Debug-Modus <small style="opacity:.5">(verbose logs)</small></span>`+
			`<label style="display:flex;align-items:center;gap:6px;cursor:pointer;">`+
			`<input type="checkbox" id="cfg-debug" style="width:18px;height:18px;cursor:pointer;"%s>`+
			`<span style="font-size:0.8rem;opacity:0.7;">aktiviert</span></label></div>`,
			func() string {
				if c.DebugEnabled {
					return ` checked`
				}
				return ""
			}()) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">Debug HTTP Raw <small style="opacity:.5">(raw requests)</small></span>`+
			`<label style="display:flex;align-items:center;gap:6px;cursor:pointer;">`+
			`<input type="checkbox" id="cfg-debug-http" style="width:18px;height:18px;cursor:pointer;"%s>`+
			`<span style="font-size:0.8rem;opacity:0.7;">aktiviert</span></label></div>`,
			func() string {
				if c.DebugHTTPRaw {
					return ` checked`
				}
				return ""
			}()) +

		`</div>` +

		`<div class="s-section">` +
		`<h3>` + T.SettingsDomains + `</h3>` +
		`<div id="settings-domain-list" style="margin-bottom:15px;display:flex;flex-direction:column;gap:8px;"></div>` +

		`<div style="background:rgba(255,255,255,0.05);padding:12px;border-radius:8px;border:1px dashed var(--border);">` +
		`<h4 style="font-size:0.75rem;margin-bottom:8px;opacity:0.8;text-transform:uppercase;">` + T.SettingsAddDomain + `</h4>` +
		`<input type="text" id="new-domain-fqdn" class="s-input" placeholder="` + T.SettingsDomainPlaceholder + `" style="margin-bottom:8px;">` +
		`<select id="new-domain-provider" class="s-input" style="margin-bottom:8px;" onchange="toggleProviderFields()">` +
		`<option value="IONOS">IONOS</option>` +
		`<option value="CLOUDFLARE">Cloudflare</option>` +
		`<option value="IPV64">IPv64</option>` +
		`</select>` +
		`<div id="fields-ionos">` +
		`<input type="text" id="new-ionos-prefix" class="s-input" placeholder="` + T.SettingsAPIPrefix + `" style="margin-bottom:8px;">` +
		`<div style="position:relative;width:100%;margin-top:8px;">` +
		`<input type="password" id="new-ionos-secret" class="s-input" placeholder="` + T.SettingsAPISecret + `" style="padding-right:40px;">` +
		`<button type="button" onclick="togglePassword('new-ionos-secret', this)" style="position:absolute;right:8px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;padding:0;font-size:16px;line-height:1;">👁️</button>` +
		`</div>` +
		`</div>` +
		`<div id="fields-cloudflare" style="display:none;">` +
		`<input type="text" id="new-cf-token" class="s-input" placeholder="` + T.SettingsCFTokenHint + `" style="margin-bottom:8px;">` +
		`<div style="font-size:0.65rem;text-align:center;margin:4px 0;opacity:0.4;">` + T.SettingsCFOr + `</div>` +
		`<input type="text" id="new-cf-email" class="s-input" placeholder="` + T.SettingsCFEmail + `" style="margin-bottom:8px;">` +
		`<div style="position:relative;width:100%;">` +
		`<input type="password" id="new-cf-secret" class="s-input" placeholder="` + T.SettingsCFGlobalKey + `" style="padding-right:40px;">` +
		`<button type="button" onclick="togglePassword('new-cf-secret', this)" style="position:absolute;right:8px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;padding:0;font-size:16px;line-height:1;">👁️</button>` +
		`</div>` +
		`</div>` +
		`<div id="fields-ipv64" style="display:none;">` +
		`<div style="position:relative;width:100%;">` +
		`<input type="password" id="new-ipv64-token" class="s-input" placeholder="` + T.SettingsIPv64Token + `" style="padding-right:40px;">` +
		`<button type="button" onclick="togglePassword('new-ipv64-token', this)" style="position:absolute;right:8px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;padding:0;font-size:16px;line-height:1;">👁️</button>` +
		`</div>` +
		`</div>` +
		`<button class="s-btn" onclick="addDomainToList()" style="margin-top:12px;background:var(--success);color:white;border:none;width:100%;">` +
		T.SettingsAddBtn +
		`</button>` +
		`</div>` +
		`</div>` +

		`<div class="s-section">` +
		`<h3>` + T.SettingsNotify + `</h3>` +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsNotifyEnabled+`</span>`+
			`<label style="display:flex;align-items:center;gap:6px;cursor:pointer;">`+
			`<input type="checkbox" id="cfg-notify-enabled" style="width:18px;height:18px;cursor:pointer;"%s>`+
			`<span style="font-size:0.8rem;opacity:0.7;">`+T.SettingsNotifyOn+`</span></label></div>`,
			func() string {
				if c.Notifications.Enabled {
					return ` checked`
				}
				return ""
			}()) +

		`<div class="s-row" style="flex-direction:column;align-items:stretch;gap:6px;">` +
		`<span class="s-label">` + T.SettingsNotifyEvents + `</span>` +
		notifyEventCheckboxes(c.Notifications.Events) +
		`</div>` +

		`<div style="margin-top:10px;padding:10px;background:rgba(56,189,248,0.06);border-radius:7px;border:1px solid rgba(56,189,248,0.15);">` +
		`<div style="font-size:0.68rem;color:#94a3b8;font-weight:700;letter-spacing:.06em;text-transform:uppercase;margin-bottom:8px;">📱 ` + T.SettingsTelegramHeading + ` </div>` +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsTGChatID+`</span>`+
			`<input type="text" id="cfg-tg-chatid" class="s-input" style="width:160px;"`+
			` placeholder="-100xxxxxxxxx" value="%s"></div>`,
			html.EscapeString(c.Notifications.Telegram.ChatID)) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsTGToken+`</span>`+
			`<div style="position:relative;width:220px;">`+
			`<input type="password" id="cfg-tg-token" class="s-input" style="width:220px;padding-right:40px;"`+
			` placeholder="`+T.SettingsTokenUnchanged+`" value="%s">`+
			`<button type="button" onclick="togglePassword('cfg-tg-token', this)" style="position:absolute;right:8px;top:50%%;transform:translateY(-50%%);background:none;border:none;cursor:pointer;padding:0;font-size:16px;line-height:1;">👁️</button>`+
			`</div></div>`,
			html.EscapeString(c.Notifications.Telegram.Token)) +

		`</div>` +

		`<div style="margin-top:8px;padding:10px;background:rgba(167,139,250,0.06);border-radius:7px;border:1px solid rgba(167,139,250,0.15);">` +
		`<div style="font-size:0.68rem;color:#94a3b8;font-weight:700;letter-spacing:.06em;text-transform:uppercase;margin-bottom:8px;">🔔 ` + T.SettingsGotifyHeading + `</div>` +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsGotifyURL+`</span>`+
			`<input type="text" id="cfg-gotify-url" class="s-input" style="width:220px;"`+
			` placeholder="https://gotify.example.com" value="%s"></div>`,
			html.EscapeString(c.Notifications.Gotify.URL)) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+T.SettingsGotifyToken+`</span>`+
			`<div style="position:relative;width:220px;">`+
			`<input type="password" id="cfg-gotify-token" class="s-input" style="width:220px;padding-right:40px;"`+
			` placeholder="`+T.SettingsTokenUnchanged+`" value="%s">`+
			`<button type="button" onclick="togglePassword('cfg-gotify-token', this)" style="position:absolute;right:8px;top:50%%;transform:translateY(-50%%);background:none;border:none;cursor:pointer;padding:0;font-size:16px;line-height:1;">👁️</button>`+
			`</div></div>`,
			html.EscapeString(c.Notifications.Gotify.Token)) +

		`</div>` +
		`</div>` +

		`<div style="margin-top:20px;padding:15px;background:rgba(74,222,128,0.07);border-radius:8px;border:1px solid var(--success);">` +
		`<p style="font-size:0.75rem;margin-bottom:10px;opacity:0.8;text-align:center;">` +
		T.SettingsSaveHint + `<br>` +
		T.SettingsRestartHint +
		`</p>` +
		`<button class="action-btn" style="width:100%;margin:0;" onclick="saveFullConfig()">` + T.SettingsSaveBtn + `</button>` +
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

type safeSystemConfig struct {
	IPMode          string   `json:"ip_mode"`
	IfaceName       string   `json:"iface_name"`
	HealthPort      string   `json:"health_port"`
	DNSServers      []string `json:"dns_servers"`
	Interval        int      `json:"interval"`
	DryRun          bool     `json:"dry_run"`
	HourlyRateLimit int      `json:"hourly_rate_limit"`
	MaxConcurrent   int      `json:"max_concurrent"`
	MaxLogLines     int      `json:"max_log_lines"`
	MaxAPIRetries   int      `json:"max_api_retries"`
	Lang            string   `json:"lang"`
	NotifyEnabled   bool     `json:"notify_enabled"`
	NotifyEvents    []string `json:"notify_events"`
	TelegramToken   string   `json:"telegram_token"`
	TelegramChatID  string   `json:"telegram_chat_id"`
	GotifyURL       string   `json:"gotify_url"`
	GotifyToken     string   `json:"gotify_token"`
	DebugEnabled    bool     `json:"debug_enabled"`
	DebugHTTPRaw    bool     `json:"debug_http_raw"`
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
		DebugEnabled:    cfg.DebugEnabled,
		DebugHTTPRaw:    cfg.DebugHTTPRaw,
	}
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
	})

	mux.HandleFunc("/api/domains", func(w http.ResponseWriter, r *http.Request) {
		serveCachedJSON(w, r, domainsCache)
	})

	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
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
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/api/languages", func(w http.ResponseWriter, r *http.Request) {
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
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(entries)
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

		var payload dashboardConfigPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, T.JSONParseError, http.StatusBadRequest)
			return
		}

		sys := payload.System
		if sys.IPMode != "" {
			validModes := map[string]bool{"IPV4": true, "IPV6": true, "BOTH": true}
			if validModes[strings.ToUpper(sys.IPMode)] {
				cfg.IPMode = strings.ToUpper(sys.IPMode)
			}
		}
		if sys.Interval >= 30 {
			cfg.Interval = sys.Interval
		}
		if sys.HealthPort != "" {
			cfg.HealthPort = sys.HealthPort
		}
		cfg.IfaceName = sys.IfaceName
		if sys.DNSServers != nil {
			var cleaned []string
			for _, s := range sys.DNSServers {
				for _, part := range strings.Split(s, ",") {
					if t := strings.TrimSpace(part); t != "" {
						cleaned = append(cleaned, t)
					}
				}
			}
			cfg.DNSServers = cleaned
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
		cfg.DryRun = sys.DryRun
		cfg.DebugEnabled = sys.DebugEnabled
		cfg.DebugHTTPRaw = sys.DebugHTTPRaw

		cfg.Notifications.Enabled = sys.NotifyEnabled
		if sys.NotifyEvents != nil {
			cfg.Notifications.Events = sys.NotifyEvents
		}

		cfg.Notifications.Telegram.Token = sys.TelegramToken
		cfg.Notifications.Telegram.ChatID = sys.TelegramChatID
		cfg.Notifications.Gotify.URL = sys.GotifyURL
		cfg.Notifications.Gotify.Token = sys.GotifyToken

		if !cfg.Notifications.Enabled {
			cfg.Notifications.Enabled =
				cfg.Notifications.Telegram.Token != "" ||
					cfg.Notifications.Gotify.URL != ""
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
			http.Error(w, T.SaveFailed, http.StatusInternalServerError)
			return
		}

		ResetHTTPClient()
		initNotifiers()
		forceNextUpdate.Store(true)
		lastCleanup = time.Time{}

		debugLog("API", getClientIP(r), T.ConfigHeading)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "saved"})
	})

	mux.HandleFunc("/api/set-language", func(w http.ResponseWriter, r *http.Request) {
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

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "lang": lang})
	})

	mux.HandleFunc("/api/domain/delete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !validateTriggerToken(r) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": T.InvalidToken})
			return
		}
		domain := strings.TrimSpace(r.URL.Query().Get("domain"))
		if domain == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": T.DomainParamMissing})
			return
		}
		for _, dc := range cfg.DomainConfigs {
			if strings.EqualFold(dc.FQDN, domain) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": T.DomainStillActiveInConfig})
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
			_ = json.NewEncoder(w).Encode(map[string]string{"error": T.NoStatusFileFound})
			return
		}
		if _, exists := fileData[domain]; !exists {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": T.DomainNotFoundInStatus})
			return
		}
		delete(fileData, domain)
		if b, err := json.MarshalIndent(fileData, "", "  "); err == nil {
			tmp := updatePath + ".tmp"
			if err := os.WriteFile(tmp, b, 0644); err == nil {
				_ = os.Rename(tmp, updatePath)
			}
		}
		debugLog("API", getClientIP(r), fmt.Sprintf(T.DomainDeletedFromStatusLog, domain))
		broadcastNotification(fmt.Sprintf(T.DomainRemovedFromStatus, domain), "info")
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
				"error": T.InvalidOrMissingTriggerToken,
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			debugLog("API", clientIP, T.TriggerBlockedInvalidToken)
			return
		}

		if !globalTriggerLimiter.Allow() {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "10")
			w.WriteHeader(http.StatusTooManyRequests)
			if err := json.NewEncoder(w).Encode(map[string]interface{}{
				"error":               T.GlobalRateLimitExceeded,
				"retry_after_seconds": 10,
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			debugLog("API", clientIP, T.TriggerBlockedGlobalRateLimit)
			broadcastNotification(T.RateLimitGlobal, "warning")
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
				"error":               T.IPRateLimitExceeded,
				"retry_after_seconds": 10,
				"remaining":           remaining,
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			debugLog("API", clientIP, T.TriggerBlockedIPRateLimit)
			broadcastNotification(T.TooManyUpdateRequestsWait, "warning")
			return
		}

		if !updateInProgress.CompareAndSwap(false, true) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			if err := json.NewEncoder(w).Encode(map[string]interface{}{
				"error":  T.UpdateAlreadyInProgressAPI,
				"status": T.TriggerStatusBusy,
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
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
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
		w.WriteHeader(http.StatusAccepted)
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"status":               "triggered",
			"message":              T.UpdateStartedMessage,
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
			http.Error(w, T.RateLimitExceeded, http.StatusTooManyRequests)
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
				logCacheWriteMu.Lock()
				_ = os.WriteFile(logCachePath, payload, 0644)
				logCacheWriteMu.Unlock()
			}
		}
		jsConfigSafe, _ := json.Marshal(safeDomainConfigs(cfg.DomainConfigs))
		if jsConfigSafe == nil {
			jsConfigSafe = []byte("[]")
		}
		jsSystemCfg, _ := json.Marshal(currentSystemConfig())
		if jsSystemCfg == nil {
			jsSystemCfg = []byte("{}")
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
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

		_, _ = fmt.Fprint(w, `
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
				`<span style="font-size:0.7rem; color:#94a3b8; font-weight:600;">NIC <span style="font-weight:400; opacity:0.6;">(` + T.NicIPv64Updates + `)</span></span>` +
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

		if len(logs) > 0 {
			_, _ = fmt.Fprintf(w, `
                     <details class="card" id="logs-card">
                          <summary>
                          🧾 %s 
                      <span style="opacity:0.6; font-size:0.9em; margin-left: 10px;">
                          (%d `+T.EntriesLabel+`)
                     <span style="margin-left: 10px; border-left: 1px solid #ccc; padding-left: 10px;">
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

		_, _ = fmt.Fprint(w, `<input type="text" class="search-box" id="domainSearch" placeholder="`+T.DomainSearchPlaceholder+`" oninput="filterDomains(this.value)"><div id="domainContainer">`)

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
			dotTitle := T.DotTitleNoUpdate
			changedBadge := `<span id="badge-` + safeID + `" class="changed-badge" style="display:none;">` + T.BadgeChanged + `</span>`
			if h.LastChanged != "" {
				if t, err := time.Parse("02.01.2006 15:04:05", h.LastChanged); err == nil {
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
				}
			}

			orphanStyle := ""
			orphanLabel := ""
			deleteBtn := ""
			if isOrphan {
				orphanStyle = ` style="border-color: rgba(248,113,113,0.5);"`
				orphanLabel = `<span style="font-size:0.65rem; padding:1px 7px; border-radius:999px; background:rgba(248,113,113,0.15); border:1px solid rgba(248,113,113,0.4); color:#f87171; margin-left:8px; font-weight:600;">>` + T.NotConfiguredLabel + `</span>`
				deleteBtn = `<button class="action-btn" style="background:rgba(248,113,113,0.15); color:#f87171; border-color:rgba(248,113,113,0.5); font-size:0.7rem; padding:3px 10px; margin-left:auto;" onclick="event.preventDefault(); event.stopPropagation(); deleteDomain('` + html.EscapeString(k) + `', this)">` + T.RemoveBtn + `</button>`
			}

			_, _ = fmt.Fprintf(w, `
			<details class="card domain-item" data-domain="%s"%s>
				<summary style="display:flex; align-items:center;">
					<span id="dot-%s" class="%s" title="%s"></span>
					🌐 %s <span style="opacity:0.6; font-size:0.9em; margin-left:5px;">(%s)</span>%s%s%s
				</summary>
				<div class="card-content">
					<div class="domain-card" style="border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 15px; margin-bottom: 10px;">
						<div style="display: flex; justify-content: space-between; align-items: flex-start;">
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
								<small>`+T.LastShort+` %s</small>
							</div>
						</div>
					</div>

					<div style="max-height: 300px; overflow-y: auto; margin-top: 10px; border: 1px solid rgba(255,255,255,0.05); border-radius: 8px;">
						<table style="width: 100%%; border-collapse: collapse; table-layout: fixed;">
							<thead style="background: rgba(255,255,255,0.02); text-align: left; opacity: 0.5; font-size: 0.7rem;">
								<tr>
									<th style="padding: 10px; width: 140px;">`+T.TableTime+`</th>
									<th style="padding: 10px;">`+T.TableIPs+`</th>
								</tr>
							</thead>
							<tbody>`,
				html.EscapeString(k),
				orphanStyle,
				safeID,
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
					<td style="padding: 10px; vertical-align: top; font-family: monospace; font-size: 0.8rem; color: #94a3b8; white-space: nowrap;">
						%s
					</td>
					<td style="padding: 10px; vertical-align: top;">
						<div style="display: flex; flex-direction: column; gap: 6px;">
							<div style="display: flex; align-items: center; font-family: monospace; font-size: 0.85rem;">
								<span class="badge v4" style="width: 25px; margin-right: 8px; flex-shrink: 0; text-align: center;">v4</span>
								<span style="color: #e2e8f0;">%s</span>
							</div>
							<div style="display: flex; align-items: center; font-family: monospace; font-size: 0.85rem;">
								<span class="badge v6" style="width: 25px; margin-right: 8px; flex-shrink: 0; text-align: center;">v6</span>
								<span style="color: #e2e8f0; word-break: break-all;">%s</span>
							</div>
						</div>
					</td>
				</tr>`,
					html.EscapeString(e.Time),
					func() string {
						if e.IPv4 == "" {
							return "—"
						}
						return html.EscapeString(e.IPv4)
					}(),
					func() string {
						if e.IPv6 == "" {
							return "—"
						}
						return html.EscapeString(e.IPv6)
					}(),
				)
			}

			if len(h.IPs) < 2 {
				_, _ = fmt.Fprint(w, `<tr><td colspan="2" style="text-align:center; opacity:0.5; padding: 10px;">`+T.NoMoreEntries+`</td></tr>`)
			}

			_, _ = fmt.Fprint(w, `
						</tbody>
					</table>
				</div>
			</div>
		</details>`)
		}
		_, _ = fmt.Fprint(w, `</div>`)

		_, _ = fmt.Fprintf(w, `
			<script>%s</script>
		</div>
		</body>
		</html>
		`, jsData)

	})

	return mux
}