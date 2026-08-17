// Package main
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
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

//go:embed templates/js/auth.js
var authJSData string

var (
	dashboardCSSETag = contentETag(cssData)
	dashboardJSETag  = contentETag(jsData)
	authJSETag       = contentETag(authJSData)

	dashboardCSSGzip = gzipStatic(cssData)
	dashboardJSGzip  = gzipStatic(jsData)
	authJSGzip       = gzipStatic(authJSData)
)

func contentETag(content string) string {
	sum := sha256.Sum256([]byte(content))

	return `"` + hex.EncodeToString(sum[:]) + `"`
}

func gzipStatic(content string) []byte {
	var buf bytes.Buffer

	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil
	}

	if _, err := zw.Write([]byte(content)); err != nil {
		_ = zw.Close()
		return nil
	}
	if err := zw.Close(); err != nil {
		return nil
	}

	return buf.Bytes()
}

func acceptsGzip(r *http.Request) bool {
	for token := range strings.SplitSeq(r.Header.Get("Accept-Encoding"), ",") {
		parts := strings.Split(token, ";")
		if !strings.EqualFold(strings.TrimSpace(parts[0]), "gzip") {
			continue
		}

		quality := 1.0
		for _, param := range parts[1:] {
			key, value, ok := strings.Cut(strings.TrimSpace(param), "=")
			if !ok || !strings.EqualFold(strings.TrimSpace(key), "q") {
				continue
			}
			if q, err := strconv.ParseFloat(strings.TrimSpace(value), 64); err == nil {
				quality = q
			}
		}

		return quality > 0
	}

	return false
}

func encodedETag(etag string, gzipEncoded bool) string {
	if !gzipEncoded {
		return etag
	}

	return strings.TrimSuffix(etag, `"`) + `-gzip"`
}

func assetURL(path, etag string) string {
	version := strings.Trim(etag, `"`)
	if len(version) > 12 {
		version = version[:12]
	}

	return path + "?v=" + version
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

	for i := range len(points) - 1 {
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
		</div>`, esc(phrases().RequestHistory), renderMax, renderMax/2, pathData, pathData, tooltipPoints, timeLabels)
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
	for i := range len(points) - 1 {
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
		</div>`, esc(phrases().LatencyHistory), renderMax, renderMax/2, pathData.String(), pathData.String(), tooltipPoints, timeLabels)
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

		fmt.Fprintf(
			&b,
			`<circle class="chart-point" cx="%.1f" cy="%.1f" r="4" data-x="%.1f" data-y="%.1f" data-value="%.0f" data-label="%s" data-unit="%s"></circle>`,
			p[0],
			p[1],
			p[0],
			p[1],
			values[i],
			esc(label),
			esc(unit),
		)
	}

	return b.String()
}

// ============================================================================
// DASHBOARD HTTP HANDLER
// ============================================================================

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
		{ActionUpdate, esc(phrases().NotifyEventUpdateLabel), esc(phrases().NotifyEventUpdateDesc)},
		{ActionCreate, esc(phrases().NotifyEventCreateLabel), esc(phrases().NotifyEventCreateDesc)},
		{ActionCurrent, esc(phrases().NotifyEventCurrentLabel), esc(phrases().NotifyEventCurrentDesc)},
		{ActionInfo, esc(phrases().NotifyEventInfoLabel), esc(phrases().NotifyEventInfoDesc)},
		{ActionRetry, esc(phrases().NotifyEventRetryLabel), esc(phrases().NotifyEventRetryDesc)},
		{ActionError, esc(phrases().NotifyEventErrorLabel), esc(phrases().NotifyEventErrorDesc)},
		{ActionStart, esc(phrases().NotifyEventStartLabel), esc(phrases().NotifyEventStartDesc)},
		{ActionStop, esc(phrases().NotifyEventStopLabel), esc(phrases().NotifyEventStopDesc)},
		{ActionConfig, esc(phrases().NotifyEventConfigLabel), esc(phrases().NotifyEventConfigDesc)},
		{ActionZone, esc(phrases().NotifyEventZoneLabel), esc(phrases().NotifyEventZoneDesc)},
		{ActionDryRun, esc(phrases().NotifyEventDryRunLabel), esc(phrases().NotifyEventDryRunDesc)},
		{ActionCleanup, esc(phrases().NotifyEventCleanupLabel), esc(phrases().NotifyEventCleanupDesc)},
		{ActionSkip, esc(phrases().NotifyEventSkipLabel), esc(phrases().NotifyEventSkipDesc)},
		{ActionAPI, esc(phrases().NotifyEventAPILabel), esc(phrases().NotifyEventAPIDesc)},
		{ActionServer, esc(phrases().NotifyEventServerLabel), esc(phrases().NotifyEventServerDesc)},
		{ActionLogin, esc(phrases().NotifyEventLoginLabel), esc(phrases().NotifyEventLoginDesc)},
		{ActionLoginFail, esc(phrases().NotifyEventLoginFailedLabel), esc(phrases().NotifyEventLoginFailedDesc)},
		{ActionLogout, esc(phrases().NotifyEventLogoutLabel), esc(phrases().NotifyEventLogoutDesc)},
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
		return esc(phrases().SettingsCheckboxActive)
	}

	return esc(phrases().SettingsCheckboxDeactive)
}

func selected(v bool) string {
	if v {
		return HTMLSelected
	}

	return ""
}

func buildSettingsSecuritySection() string {
	return `<div class="s-row s-row-stack s-gap-8"><span class="s-label">` + esc(phrases().SettingsTriggerToken) + `</span><div class="input-with-action"><input type="password" id="s-token" class="s-input" placeholder="` + esc(phrases().SettingsTokenPlaceholder) + `" autocomplete="off"><button type="button" class="input-action-btn" data-click="togglePassword('s-token', this)">👁️</button></div><button class="s-btn" data-click="saveToken()">` + esc(phrases().SettingsTokenSave) + `</button></div>`
}

func buildNetworkInterfaceOptions(selectedName string) string {
	selectedName = strings.TrimSpace(selectedName)

	var out strings.Builder
	fmt.Fprintf(&out, `<option value=""%s>%s</option>`, selected(selectedName == ""), esc(phrases().SettingsIfacePlaceholder))

	interfaces, err := net.Interfaces()
	if err != nil {
		if selectedName != "" {
			fmt.Fprintf(&out, `<option value="%s" selected>%s</option>`, esc(selectedName), esc(selectedName))
		}

		return out.String()
	}

	sort.Slice(interfaces, func(i, j int) bool {
		return strings.ToLower(interfaces[i].Name) < strings.ToLower(interfaces[j].Name)
	})

	foundSelected := selectedName == ""
	for _, iface := range interfaces {
		name := strings.TrimSpace(iface.Name)
		if name == "" {
			continue
		}

		state := "DOWN"
		if iface.Flags&net.FlagUp != 0 {
			state = "UP"
		}

		label := fmt.Sprintf("%s (%s)", name, state)
		if name == selectedName {
			foundSelected = true
		}
		fmt.Fprintf(
			&out, `<option value="%s"%s>%s</option>`,
			esc(name),
			selected(name == selectedName),
			esc(label),
		)
	}

	if selectedName != "" && !foundSelected {
		label := selectedName + " [?]"
		fmt.Fprintf(&out, `<option value="%s" selected>%s</option>`, esc(selectedName), esc(label))
	}

	return out.String()
}

func buildSettingsSystemSection(c Config) string {
	return `<div class="s-row"><span class="s-label">` + esc(phrases().SettingsIPMode) + `</span><select id="cfg-ip-mode" class="s-input s-select-auto-sm">` +
		buildSettingsIPModeOptions(c.IPMode) +
		`</select></div>` +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+esc(phrases().SettingsInterval)+`</span><input type="number" id="cfg-interval" class="s-input s-input-sm-right" min="30" max="86400" value="%d"></div>`, c.Interval) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+esc(phrases().SettingsHealthPort)+`</span><input type="text" id="cfg-health-port" class="s-input s-input-sm-right" value="%s"></div>`, esc(c.HealthPort)) +

		`<div class="s-row"><span class="s-label">` + esc(phrases().SettingsIface) + ` <small class="s-label-hint-inline">` + esc(phrases().SettingsIfaceHint) + `</small></span><select id="cfg-iface" class="s-input s-input-md">` +
		buildNetworkInterfaceOptions(c.IfaceName) +
		`</select></div>` +

		fmt.Sprintf(
			`<div class="s-row"><span class="s-label">`+phrases().SettingsDNS+` <small class="s-label-hint-inline">(`+phrases().SettingsDNSHint+`)</small></span><input type="text" id="cfg-dns" class="s-input s-input-lg" placeholder="1.1.1.1, 8.8.8.8:53" value="%s"></div>`,
			esc(strings.Join(c.DNSServers, ", ")),
		) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+phrases().SettingsMaxLog+`</span><input type="number" id="cfg-max-log" class="s-input s-input-sm-right" min="100" max="50000" value="%d"></div>`, c.MaxLogLines) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+phrases().SettingsMaxRetries+`</span><input type="number" id="cfg-max-retries" class="s-input s-input-sm-right" min="0" max="20" value="%d"></div>`, c.MaxAPIRetries) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+phrases().SettingsMaxConcurrent+`</span><input type="number" id="cfg-max-concurrent" class="s-input s-input-sm-right" min="1" max="20" value="%d"></div>`, c.MaxConcurrent) +

		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+phrases().SettingsHourlyLimit+`</span><input type="number" id="cfg-hourly-limit" class="s-input s-input-sm-right" min="100" max="100000" value="%d"></div>`, c.HourlyRateLimit) +

		fmt.Sprintf(
			`<div class="s-row"><span class="s-label">`+phrases().SettingsIPv4Endpoints+`<small class="s-label-hint-block">(`+phrases().SettingsDNSHint+`)</small></span><input type="text" id="cfg-ipv4_endpoints" class="s-input s-input-lg" placeholder="https://4.ident.me/, https://4.tnedi.me/" value="%s"></div>`,
			esc(strings.Join(c.IPv4Endpoints, ", ")),
		) +

		fmt.Sprintf(
			`<div class="s-row"><span class="s-label">`+phrases().SettingsIPv6Endpoints+`<small class="s-label-hint-block">(`+phrases().SettingsDNSHint+`)</small></span><input type="text" id="cfg-ipv6_endpoints" class="s-input s-input-lg" placeholder="https://6.ident.me/, https://6.tnedi.me/" value="%s"></div>`,
			esc(strings.Join(c.IPv6Endpoints, ", ")),
		) +

		`<div class="s-row"><span class="s-label">` + esc(phrases().SettingsLanguage) + `</span><select id="cfg-lang" class="s-input s-select-auto-md">` +
		buildDynamicLangOptions(c.Lang) +
		`</select></div>` +

		fmt.Sprintf(
			`<div class="s-row"><span class="s-label">`+phrases().SettingsDryRun+`<small class="s-label-hint-block">`+phrases().SettingsDryRunHint+`</small></span><label class="s-checkbox-container"><input type="checkbox" id="cfg-dry-run" class="s-checkbox-dynamic" data-change="updateCheckboxLabel(this)" data-label-on="%s" data-label-off="%s"%s><span class="s-checkbox-text">%s</span></label></div>`,
			phrases().SettingsCheckboxActive, esc(phrases().SettingsCheckboxDeactive),
			checkedAttr(c.DryRun),
			checkboxLabel(c.DryRun),
		) +

		fmt.Sprintf(
			`<div class="s-row"><span class="s-label">`+phrases().SettingsDebugMode+` <small class="s-label-hint-block">`+phrases().SettingsDebugVerboseHint+`</small></span><label class="s-checkbox-container"><input type="checkbox" id="cfg-debug" class="s-checkbox-dynamic" data-change="updateCheckboxLabel(this)" data-label-on="%s" data-label-off="%s"%s><span class="s-checkbox-text">%s</span></label></div>`,
			phrases().SettingsCheckboxActive, esc(phrases().SettingsCheckboxDeactive),
			checkedAttr(c.DebugEnabled),
			checkboxLabel(c.DebugEnabled),
		) +

		fmt.Sprintf(
			`<div class="s-row"><span class="s-label">`+phrases().SettingsDebugHTTPRaw+` <small class="s-label-hint-block">`+phrases().SettingsDebugHTTPHint+`</small></span><label class="s-checkbox-container"><input type="checkbox" id="cfg-debug-http" class="s-checkbox-dynamic" data-change="updateCheckboxLabel(this)" data-label-on="%s" data-label-off="%s"%s><span class="s-checkbox-text">%s</span></label></div>`,
			phrases().SettingsCheckboxActive, esc(phrases().SettingsCheckboxDeactive),
			checkedAttr(c.DebugHTTPRaw),
			checkboxLabel(c.DebugHTTPRaw),
		)
}

func buildSettingsDomainsSection() string {
	addDomainForm := `<div class="add-domain-box"><input type="text" id="new-domain-fqdn" class="s-input mb-8" placeholder="` + esc(phrases().SettingsDomainPlaceholder) + `"><input type="number" id="new-domain-ttl" class="s-input mb-8" placeholder="` + esc(phrases().SettingsTTLPlaceholder) + `" min="1" step="1"><select id="new-domain-ip-mode" class="s-input mb-8" data-change="toggleRecordModeFields()"><option value="">` + esc(phrases().SettingsIPMode) + ` (` + esc(phrases().SettingsIPModeGlobal) + `)</option><option value="BOTH">` + esc(phrases().SettingsIPModeBoth) + `</option><option value="IPV4">` + esc(phrases().SettingsIPModeIPv4Only) + `</option><option value="IPV6">` + esc(phrases().SettingsIPModeIPv6Only) + `</option><option id="opt-ip-mode-cname" value="CNAME">CNAME</option></select><div id="fields-cname-target" class="is-hidden"><input type="text" id="new-domain-cname-target" class="s-input mb-8" placeholder="` + esc(phrases().SettingsCNAMETargetPlaceholder) + `"></div><select id="new-domain-provider" class="s-input mb-8" data-change="toggleProviderFields()"><option value="IONOS">IONOS</option><option value="CLOUDFLARE">Cloudflare</option><option value="IPV64">IPv64</option><option value="HETZNER">Hetzner DNS</option><option value="HETZNERCLOUD">Hetzner Cloud DNS</option><option value="FEBAS">Febas DynDNS</option><option value="DNSCALE">DNScale</option></select><div id="fields-ionos"><input type="text" id="new-ionos-prefix" class="s-input mb-8" placeholder="` + esc(phrases().SettingsAPIPrefix) + `"><div class="input-with-action mt-8"><input type="password" id="new-ionos-secret" class="s-input" placeholder="` + esc(phrases().SettingsAPISecret) + `"><button type="button" class="input-action-btn" data-click="togglePassword('new-ionos-secret', this)">👁️</button></div></div><div id="fields-cloudflare" class="is-hidden"><input type="text" id="new-cf-token" class="s-input mb-8" placeholder="` + esc(phrases().SettingsCFTokenHint) + `"><div class="center-note">` + esc(phrases().SettingsCFOr) + `</div><input type="text" id="new-cf-email" class="s-input mb-8" placeholder="` + esc(phrases().SettingsCFEmail) + `"><div class="input-with-action mt-8"><input type="password" id="new-cf-secret" class="s-input" placeholder="` + esc(phrases().SettingsCFGlobalKey) + `"><button type="button" class="input-action-btn" data-click="togglePassword('new-cf-secret', this)">👁️</button></div><label class="inline-check"><input type="checkbox" id="new-cf-proxied"> ` + esc(phrases().SettingsCFProxyLabel) +
		`</label></div><div id="fields-ipv64" class="is-hidden"><div class="input-with-action mt-8"><input type="password" id="new-ipv64-token" class="s-input" placeholder="` + esc(phrases().SettingsIPv64Token) + `"><button type="button" class="input-action-btn" data-click="togglePassword('new-ipv64-token', this)">👁️</button></div></div><div id="fields-hetzner" class="is-hidden"><div class="input-with-action mt-8"><input type="password" id="new-hetzner-token" class="s-input" placeholder="` + esc(phrases().SettingsHetznerDNSToken) + `"><button type="button" class="input-action-btn" data-click="togglePassword('new-hetzner-token', this)">👁️</button></div></div><div id="fields-hetznercloud" class="is-hidden"><div class="input-with-action mt-8"><input type="password" id="new-hcloud-token" class="s-input" placeholder="` + esc(phrases().SettingsHetznerCloudToken) + `"><button type="button" class="input-action-btn" data-click="togglePassword('new-hcloud-token', this)">👁️</button></div></div><div id="fields-febas" class="is-hidden"><div class="input-with-action mt-8"><input type="password" id="new-febas-update-url" class="s-input" placeholder="` + esc(phrases().SettingsFebasUpdateURL) + `"><button type="button" class="input-action-btn" data-click="togglePassword('new-febas-update-url', this)">👁️</button></div><small class="s-label-hint-block">` + esc(phrases().SettingsFebasUpdateURLHint) + `</small></div><div id="fields-dnscale" class="is-hidden"><div class="input-with-action mt-8"><input type="password" id="new-dnscale-api-key" class="s-input" placeholder="` + esc(phrases().SettingsDNScaleAPIKey) + `"><button type="button" class="input-action-btn" data-click="togglePassword('new-dnscale-api-key', this)">👁️</button></div><small class="s-label-hint-block">` + esc(phrases().SettingsDNScaleAPIKeyHint) + `</small></div><div class="s-btn-row"><button class="s-btn s-btn-success-full" data-click="addDomainToList()">` +
		phrases().SettingsAddBtn +
		`</button><button type="button" class="s-btn s-btn--cancel" data-click="cancelEdit()">` +
		phrases().SettingsCancelBtn +
		`</button></div>`

	return `<div id="settings-domain-list" class="settings-domain-list"></div>` +
		buildSettingsSubSection("add-domain-section", esc(phrases().SettingsAddDomain), addDomainForm)
}

func buildSettingsNotifySection(c Config) string {
	notifyEventsSection := `<div class="s-row s-row-stack s-gap-6"><span class="s-label">` + esc(phrases().SettingsNotifyEvents) + `</span>` +
		buildSettingsNotifyEventCheckboxes(c.Notifications.Events) +
		`</div>`

	telegramSection := `<div class="notify-box notify-telegram">` +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+phrases().SettingsTGChatID+`<small class="s-label-hint-block">(`+phrases().SettingsDNSHint+`)</small></span><input type="text" id="cfg-tg-chat-id" class="s-input s-input-lg" placeholder="123456789, -100xxxxxxxxx" value="%s"></div>`,
			esc(c.Notifications.Telegram.ChatID)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+phrases().SettingsTGToken+`</span><div class="input-with-action"><input type="password" id="cfg-tg-token" class="s-input s-input-lg" placeholder="`+phrases().SettingsTokenUnchanged+`" value="%s"><button type="button" class="input-action-btn" data-click="togglePassword('cfg-tg-token', this)">👁️</button></div></div>`,
			esc(c.Notifications.Telegram.Token)) +
		`</div>`

	gotifySection := `<div class="notify-box notify-gotify">` +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+phrases().SettingsGotifyURL+`</span><input type="text" id="cfg-gotify-url" class="s-input s-input-lg" placeholder="https://gotify.example.com" value="%s"></div>`,
			esc(c.Notifications.Gotify.URL)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+phrases().SettingsGotifyToken+`</span><div class="input-with-action"><input type="password" id="cfg-gotify-token" class="s-input s-input-lg" placeholder="`+phrases().SettingsTokenUnchanged+`" value="%s"><button type="button" class="input-action-btn" data-click="togglePassword('cfg-gotify-token', this)">👁️</button></div></div>`,
			esc(c.Notifications.Gotify.Token)) +
		`</div>`

	ntfySection := `<div class="notify-box notify-ntfy">` +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+phrases().SettingsNtfyURL+`</span><input type="text" id="cfg-ntfy-url" class="s-input s-input-lg" placeholder="https://ntfy.sh" value="%s"></div>`,
			esc(c.Notifications.Ntfy.URL)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+phrases().SettingsNtfyTopic+`</span><input type="text" id="cfg-ntfy-topic" class="s-input s-input-lg" placeholder="ddns" value="%s"></div>`,
			esc(c.Notifications.Ntfy.Topic)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+phrases().SettingsNtfyToken+`</span><div class="input-with-action"><input type="password" id="cfg-ntfy-token" class="s-input s-input-lg" placeholder="`+phrases().SettingsTokenUnchanged+`" value="%s"><button type="button" class="input-action-btn" data-click="togglePassword('cfg-ntfy-token', this)">👁️</button></div></div>`,
			esc(c.Notifications.Ntfy.Token)) +
		`</div>`

	webhookSection := `<div class="notify-box notify-webhook">` +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+phrases().SettingsWebhookURL+`</span><input type="text" id="cfg-webhook-url" class="s-input s-input-lg" placeholder="https://your-endpoint.com/api" value="%s"></div>`,
			esc(c.Notifications.Webhook.URL)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+phrases().SettingsWebhookSecret+` <small class="s-label-hint-inline">`+phrases().SettingsOptional+`</small></span><div class="input-with-action"><input type="password" id="cfg-webhook-secret" class="s-input s-input-lg" placeholder="`+phrases().SettingsTokenUnchanged+`" value="%s"><button type="button" class="input-action-btn" data-click="togglePassword('cfg-webhook-secret', this)">👁️</button></div></div>`,
			esc(c.Notifications.Webhook.Secret)) +
		`</div>`

	mqttSection := `<div class="notify-box notify-mqtt">` +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+phrases().SettingsMQTTBroker+`</span><input type="text" id="cfg-mqtt-broker" class="s-input s-input-lg" autocomplete="off" readonly data-unlock-input="1" placeholder="tcp://192.168.1.10:1883" value="%s"></div>`,
			esc(c.Notifications.MQTTConfig.Broker)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+phrases().SettingsMQTTClientID+`</span><input type="text" id="cfg-mqtt-clientid" class="s-input s-input-lg" autocomplete="off" readonly data-unlock-input="1" placeholder="go-dyndns" value="%s"></div>`,
			esc(c.Notifications.MQTTConfig.ClientID)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+phrases().SettingsMQTTUsername+`</span><input type="text" id="cfg-mqtt-username" class="s-input s-input-lg" autocomplete="off" readonly data-unlock-input="1" placeholder="`+phrases().SettingsOptionalPlaceholder+`" value="%s"></div>`,
			esc(c.Notifications.MQTTConfig.Username)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+phrases().SettingsMQTTSecret+` <small class="s-label-hint-inline">`+phrases().SettingsMQTTPassword+`</small></span><div class="input-with-action"><input type="password" id="cfg-mqtt-password" class="s-input s-input-lg" autocomplete="new-password" readonly data-unlock-input="1" placeholder="`+phrases().SettingsTokenUnchanged+`" value="%s"><button type="button" class="input-action-btn" data-click="togglePassword('cfg-mqtt-password', this)">👁️</button></div></div>`,
			esc(c.Notifications.MQTTConfig.Password)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+phrases().SettingsMQTTTopic+`</span><input type="text" id="cfg-mqtt-topic" class="s-input s-input-lg" autocomplete="off" readonly data-unlock-input="1" placeholder="dyndns/ip" value="%s"></div>`,
			esc(c.Notifications.MQTTConfig.Topic)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+phrases().SettingsMQTTQoS+`</span><input type="number" min="0" max="2" id="cfg-mqtt-qos" class="s-input s-input-sm" autocomplete="off" value="%d"></div>`,
			c.Notifications.MQTTConfig.QoS) +
		fmt.Sprintf(
			`<div class="s-row"><span class="s-label">`+phrases().SettingsMQTTRetain+`</span><label class="s-checkbox-container"><input type="checkbox" id="cfg-mqtt-retain" class="s-checkbox-dynamic" data-change="updateCheckboxLabel(this)" data-label-on="%s" data-label-off="%s"%s><span class="s-checkbox-text">%s</span></label></div>`,
			phrases().SettingsCheckboxActive,
			phrases().SettingsCheckboxDeactive,
			checkedAttr(c.Notifications.MQTTConfig.Retain),
			checkboxLabel(c.Notifications.MQTTConfig.Retain),
		) +
		fmt.Sprintf(
			`<div class="s-row"><span class="s-label">`+phrases().SettingsMQTTDiscovery+` <small class="s-label-hint-inline">`+phrases().SettingsMQTTHomeAssistant+`</small></span><label class="s-checkbox-container"><input type="checkbox" id="cfg-mqtt-discovery" class="s-checkbox-dynamic" data-change="updateCheckboxLabel(this)" data-label-on="%s" data-label-off="%s"%s><span class="s-checkbox-text">%s</span></label></div>`,
			phrases().SettingsCheckboxActive,
			phrases().SettingsCheckboxDeactive,
			checkedAttr(c.Notifications.MQTTConfig.Discovery),
			checkboxLabel(c.Notifications.MQTTConfig.Discovery),
		) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+phrases().SettingsMQTTDiscoveryPrefix+`</span><input type="text" id="cfg-mqtt-discovery-prefix" class="s-input s-input-lg" autocomplete="off" readonly data-unlock-input="1" placeholder="homeassistant" value="%s"></div>`,
			esc(c.Notifications.MQTTConfig.DiscoveryPrefix)) +
		`</div>`

	emailSection := `<div class="notify-box notify-email">` +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+phrases().SettingsEmailSMTPHost+`</span><input type="text" id="cfg-email-host" class="s-input s-input-lg" autocomplete="off" readonly data-unlock-input="1" placeholder="smtp.gmail.com" value="%s"></div>`,
			esc(c.Notifications.Email.Host)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+phrases().SettingsEmailPort+`</span><input type="text" id="cfg-email-port" class="s-input s-input-sm" autocomplete="off" readonly data-unlock-input="1" placeholder="587" value="%d"></div>`,
			c.Notifications.Email.Port) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+phrases().SettingsEmailUser+`</span><input type="text" id="cfg-email-user" class="s-input s-input-lg" autocomplete="off" readonly data-unlock-input="1" value="%s"></div>`,
			esc(c.Notifications.Email.Username)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+phrases().SettingsEmailPassword+`</span><div class="input-with-action"><input type="password" id="cfg-email-pass" class="s-input s-input-lg" autocomplete="new-password" readonly data-unlock-input="1" placeholder="***" value="%s"><button type="button" class="input-action-btn" data-click="togglePassword('cfg-email-pass', this)">👁️</button></div></div>`,
			esc(c.Notifications.Email.Password)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+phrases().SettingsEmailSender+`</span><input type="text" id="cfg-email-from" class="s-input s-input-lg" autocomplete="off" readonly data-unlock-input="1" value="%s"></div>`,
			esc(c.Notifications.Email.From)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+phrases().SettingsEmailRecipient+`</span><input type="text" id="cfg-email-to" class="s-input s-input-lg" autocomplete="off" readonly data-unlock-input="1" placeholder="mail1@test.de, mail2@test.de" value="%s"></div>`,
			esc(c.Notifications.Email.To)) +
		fmt.Sprintf(`<div class="s-row"><span class="s-label">`+phrases().SettingsEmailSubject+`</span><input type="text" id="cfg-email-subject-prefix" class="s-input s-input-lg" autocomplete="off" readonly data-unlock-input="1" placeholder="[DynDNS]" value="%s"></div>`,
			esc(c.Notifications.Email.SubjectPrefix)) +
		fmt.Sprintf(
			`<div class="s-row"><span class="s-label">`+phrases().SettingsEmailTLSMode+`</span><select id="cfg-email-tls-mode" class="s-input s-input-lg"><option value="starttls" %s>`+phrases().SettingsEmailTLSStartTLS+`</option><option value="tls" %s>`+phrases().SettingsEmailTLSDirectTLS+`</option><option value="plain" %s>`+phrases().SettingsEmailTLSPlain+`</option></select></div>`,
			selected(c.Notifications.Email.TLSMode == emailTLSModeStartTLS || c.Notifications.Email.TLSMode == ""),
			selected(c.Notifications.Email.TLSMode == emailTLSModeTLS),
			selected(c.Notifications.Email.TLSMode == emailTLSModePlain),
		) +
		`</div>`

	testSection := `<div class="notify-test-box"><p>` + esc(phrases().NotifyTestDesc) + `</p><button class="s-btn notify-test-btn" id="notify-test-btn" data-click="sendNotifyTest()">` +
		phrases().NotifyBtnTest +
		`</button><div id="notify-test-result" class="notify-test-result"></div>
		</div>`

	return fmt.Sprintf(
		`<div class="s-row"><span class="s-label">`+phrases().SettingsNotifyEnabled+`</span><label class="s-checkbox-container"><input type="checkbox" id="cfg-notify-enabled" class="s-checkbox-dynamic" data-change="updateCheckboxLabel(this)" data-label-on="%s" data-label-off="%s"%s><span class="s-checkbox-text">%s</span></label></div>`,
		phrases().SettingsCheckboxActive, esc(phrases().SettingsCheckboxDeactive),
		checkedAttr(c.Notifications.Enabled),
		checkboxLabel(c.Notifications.Enabled),
	) +

		buildSettingsSubSection("", esc(phrases().SettingsNotifyEvents), notifyEventsSection) +
		buildSettingsSubSection("", esc(phrases().SettingsTelegramHeading), telegramSection) +
		buildSettingsSubSection("", esc(phrases().SettingsGotifyHeading), gotifySection) +
		buildSettingsSubSection("", esc(phrases().SettingsNtfyHeading), ntfySection) +
		buildSettingsSubSection("", esc(phrases().SettingsWebhookHeading), webhookSection) +
		buildSettingsSubSection("", esc(phrases().SettingsMqttHeading), mqttSection) +
		buildSettingsSubSection("", esc(phrases().SettingsEmailHeading), emailSection) +
		testSection
}

type safeDomainConfig struct {
	CFSecret       string `json:"cf_secret,omitempty"`
	IPv64Token     string `json:"ipv64_token,omitempty"`
	APIPrefix      string `json:"api_prefix,omitempty"`
	APISecret      string `json:"api_secret,omitempty"`
	HetznerToken   string `json:"hetzner_token,omitempty"`
	CFToken        string `json:"cf_token,omitempty"`
	CFEmail        string `json:"cf_email,omitempty"`
	Provider       string `json:"provider"`
	CNAMETarget    string `json:"cname_target,omitempty"`
	FQDN           string `json:"fqdn"`
	APIKey         string `json:"api_key,omitempty"`
	FebasUpdateURL string `json:"febas_update_url,omitempty"`
	RecordMode     string `json:"record_mode,omitempty"`
	IPMode         string `json:"ip_mode,omitempty"`
	TTL            int    `json:"ttl,omitempty"`
	CFProxied      bool   `json:"cf_proxied,omitempty"`
}

type safeMQTTConfig struct {
	Broker          string `json:"broker"`
	ClientID        string `json:"client_id"`
	Username        string `json:"username"`
	Password        string `json:"password"`
	Topic           string `json:"topic"`
	DiscoveryPrefix string `json:"discovery_prefix"`
	QoS             byte   `json:"qos"`
	Retain          bool   `json:"retain"`
	Discovery       bool   `json:"discovery"`
}

type safeEmail struct {
	Host          string `json:"host"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	From          string `json:"from"`
	To            string `json:"to"`
	SubjectPrefix string `json:"subject_prefix"`
	TLSMode       string `json:"tls_mode"`
	Port          int    `json:"port"`
}

type safeSystemConfig struct {
	Email           safeEmail      `json:"email"`
	MQTT            safeMQTTConfig `json:"mqtt"`
	WebhookURL      string         `json:"webhook_url"`
	HealthPort      string         `json:"health_port"`
	IfaceName       string         `json:"iface_name"`
	WebhookSecret   string         `json:"webhook_secret"`
	TelegramToken   string         `json:"telegram_token"`
	NtfyToken       string         `json:"ntfy_token"`
	NtfyTopic       string         `json:"ntfy_topic"`
	NtfyURL         string         `json:"ntfy_url"`
	GotifyToken     string         `json:"gotify_token"`
	GotifyURL       string         `json:"gotify_url"`
	Lang            string         `json:"lang"`
	TelegramChatID  string         `json:"telegram_chat_id"`
	IPMode          string         `json:"ip_mode"`
	NotifyEvents    []string       `json:"notify_events"`
	DNSServers      []string       `json:"dns_servers"`
	IPv4Endpoints   []string       `json:"ipv4_endpoints"`
	IPv6Endpoints   []string       `json:"ipv6_endpoints"`
	MaxAPIRetries   int            `json:"max_api_retries"`
	MaxLogLines     int            `json:"max_log_lines"`
	MaxConcurrent   int            `json:"max_concurrent"`
	HourlyRateLimit int            `json:"hourly_rate_limit"`
	Interval        int            `json:"interval"`
	NotifyEnabled   bool           `json:"notify_enabled"`
	DebugHTTPRaw    bool           `json:"debug_http_raw"`
	DebugEnabled    bool           `json:"debug_enabled"`
	DryRun          bool           `json:"dry_run"`
}

func safeDomainConfigs(dcs []DomainConfig) []safeDomainConfig {
	out := make([]safeDomainConfig, len(dcs))
	for i, dc := range dcs {
		out[i] = safeDomainConfig{
			FQDN:           dc.FQDN,
			Provider:       string(dc.Provider),
			APIPrefix:      dc.APIPrefix,
			APISecret:      dc.APISecret,
			HetznerToken:   dc.HetznerToken,
			CFToken:        dc.CFToken,
			CFEmail:        dc.CFEmail,
			CFSecret:       dc.CFSecret,
			IPv64Token:     dc.IPv64Token,
			FebasUpdateURL: dc.FebasUpdateURL,
			APIKey:         dc.APIKey,
			TTL:            dc.TTL,
			CFProxied:      dc.CFProxied,
			IPMode:         dc.IPMode,
			RecordMode:     dc.RecordMode,
			CNAMETarget:    dc.CNAMETarget,
		}
	}

	return out
}

func snapshotConfig() Config {
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

func currentSystemConfig() safeSystemConfig {
	config := snapshotConfig()

	return safeSystemConfig{
		IPMode:          config.IPMode,
		IfaceName:       config.IfaceName,
		HealthPort:      config.HealthPort,
		DNSServers:      config.DNSServers,
		Interval:        config.Interval,
		DryRun:          config.DryRun,
		DebugEnabled:    config.DebugEnabled,
		DebugHTTPRaw:    config.DebugHTTPRaw,
		HourlyRateLimit: config.HourlyRateLimit,
		MaxConcurrent:   config.MaxConcurrent,
		MaxLogLines:     config.MaxLogLines,
		MaxAPIRetries:   config.MaxAPIRetries,
		Lang:            config.Lang,
		NotifyEnabled:   config.Notifications.Enabled,
		NotifyEvents:    config.Notifications.Events,
		TelegramToken:   config.Notifications.Telegram.Token,
		TelegramChatID:  config.Notifications.Telegram.ChatID,
		GotifyURL:       config.Notifications.Gotify.URL,
		GotifyToken:     config.Notifications.Gotify.Token,
		NtfyURL:         config.Notifications.Ntfy.URL,
		NtfyTopic:       config.Notifications.Ntfy.Topic,
		NtfyToken:       config.Notifications.Ntfy.Token,
		WebhookURL:      config.Notifications.Webhook.URL,
		WebhookSecret:   config.Notifications.Webhook.Secret,
		MQTT: safeMQTTConfig{
			Broker:          config.Notifications.MQTTConfig.Broker,
			ClientID:        config.Notifications.MQTTConfig.ClientID,
			Username:        config.Notifications.MQTTConfig.Username,
			Password:        config.Notifications.MQTTConfig.Password,
			Topic:           config.Notifications.MQTTConfig.Topic,
			QoS:             config.Notifications.MQTTConfig.QoS,
			Retain:          config.Notifications.MQTTConfig.Retain,
			Discovery:       config.Notifications.MQTTConfig.Discovery,
			DiscoveryPrefix: config.Notifications.MQTTConfig.DiscoveryPrefix,
		},
		Email: safeEmail{
			Host:          config.Notifications.Email.Host,
			Port:          config.Notifications.Email.Port,
			Username:      config.Notifications.Email.Username,
			Password:      config.Notifications.Email.Password,
			From:          config.Notifications.Email.From,
			To:            config.Notifications.Email.To,
			SubjectPrefix: config.Notifications.Email.SubjectPrefix,
			TLSMode:       config.Notifications.Email.TLSMode,
		},
		IPv4Endpoints: config.IPv4Endpoints,
		IPv6Endpoints: config.IPv6Endpoints,
	}
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
	mux.HandleFunc("/assets/auth.js", handleAuthJS)
	mux.HandleFunc("/assets/i18n.js", handleDashboardI18NJS)
	mux.HandleFunc("/favicon.svg", handleFavicon)
	mux.HandleFunc("/ws", handleWS)
	mux.HandleFunc("/metrics", handleMetrics)
	mux.HandleFunc("/metrics/prometheus", handlePrometheusMetrics)
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/health/live", handleLiveness)
	mux.HandleFunc("/health/ready", handleReadiness)
}

func registerAPIroutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/domains", handleAPIDomains)
	mux.HandleFunc("/api/domains/html", handleAPIDomainsHTML)
	mux.HandleFunc("/api/page", handleAPIPageSection)
	mux.HandleFunc("/api/config", handleAPIConfig)
	mux.HandleFunc("/api/system-stats", handleAPISystemStats)
	mux.HandleFunc("/api/languages", handleAPILanguages)
	mux.HandleFunc("/api/settings/system/save", handleAPISaveSystemSettings)
	mux.HandleFunc("/api/settings/notify/save", handleAPISaveNotifySettings)
	mux.HandleFunc("/api/settings/domains/save", handleAPISaveDomainSettings)
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
	mux.HandleFunc("/api/logs/delete", handleAPILogDelete)

	mux.HandleFunc("/api/diagnose", handleAPIDiagnose)
	mux.HandleFunc("/api/audit", handleAPIAudit)
	mux.HandleFunc("/api/audit/delete", handleAPIAuditDelete)
	mux.HandleFunc("/api/dns/propagation", handleAPIDNSPropagation)
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

	if requestUsesHTTPS(r) && dashboardHSTSEnabled() {
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
	serveDashboardAsset(
		w,
		r,
		"text/css; charset=utf-8",
		dashboardCSSETag,
		cssData,
		dashboardCSSGzip,
	)
}

func handleDashboardJS(w http.ResponseWriter, r *http.Request) {
	serveDashboardAsset(
		w,
		r,
		"text/javascript; charset=utf-8",
		dashboardJSETag,
		jsData,
		dashboardJSGzip,
	)
}

func handleAuthJS(w http.ResponseWriter, r *http.Request) {
	serveDashboardAsset(
		w,
		r,
		"text/javascript; charset=utf-8",
		authJSETag,
		authJSData,
		authJSGzip,
	)
}

func serveDashboardAsset(
	w http.ResponseWriter,
	r *http.Request,
	contentType string,
	etag string,
	content string,
	gzipped []byte,
) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, esc(phrases().APIErrorMethodNotAllowed), http.StatusMethodNotAllowed)

		return
	}

	useGzip := len(gzipped) > 0 && acceptsGzip(r)
	selectedETag := encodedETag(etag, useGzip)

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Header().Set("ETag", selectedETag)
	w.Header().Set("Vary", "Accept-Encoding")

	if strings.Contains(contentType, "javascript") {
		w.Header().Set("Content-Disposition", "inline")
	}
	if useGzip {
		w.Header().Set("Content-Encoding", "gzip")
	}

	for candidate := range strings.SplitSeq(r.Header.Get("If-None-Match"), ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == selectedETag || candidate == "*" {
			w.WriteHeader(http.StatusNotModified)

			return
		}
	}

	if r.Method == http.MethodHead {
		return
	}
	if useGzip {
		_, _ = w.Write(gzipped)
		return
	}

	_, _ = io.WriteString(w, content)
}

func handleDashboardI18NJS(w http.ResponseWriter, _ *http.Request) {
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
	w.Header().Set("Cache-Control", "public, max-age=86400")
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

	return strings.EqualFold(u.Host, externalRequestHost(r))
}

func handleWS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, esc(phrases().APIErrorMethodNotAllowed), http.StatusMethodNotAllowed)

		return
	}
	if !validWebSocketOrigin(r) {
		http.Error(w, "invalid websocket origin", http.StatusForbidden)

		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		debugLog("WS", "", fmt.Sprintf(phrases().WSUpgradeFailed, err))

		return
	}

	client := &WSClient{
		conn: conn,
		send: make(chan WSMessage, 128),
	}

	stats := apiMetrics.GetStats()
	if !client.enqueue(WSMessage{Type: "initial", Data: stats}) {
		_ = conn.Close()

		return
	}

	wsHub.register <- client
}

func handleAPIDomains(w http.ResponseWriter, r *http.Request) {
	serveCachedJSON(w, r, domainsCache)
}

func handleAPIDomainsHTML(w http.ResponseWriter, r *http.Request) {
	if r.Method != MethodGET {
		http.Error(w, esc(phrases().APIErrorMethodNotAllowed), http.StatusMethodNotAllowed)

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

func handleAPIPageSection(w http.ResponseWriter, r *http.Request) {
	if r.Method != MethodGET {
		http.Error(
			w,
			phrases().APIErrorMethodNotAllowed,
			http.StatusMethodNotAllowed,
		)

		return
	}

	page := strings.TrimSpace(r.URL.Query().Get("name"))

	sess, _ := sessionFromRequest(r)
	isAdmin := !authEnabled || (sess != nil && sess.Role == RoleAdmin)
	isViewer := authEnabled && sess != nil && sess.Role == RoleViewer

	var fragment strings.Builder

	renderers := map[string]func(){
		"dashboard": func() {
			statusClass, statusText := dashboardStatus()
			writeDashboardTop(
				&fragment,
				statusClass,
				statusText,
				snapshotConfig(),
			)
		},
		"metrics": func() {
			stats := getDashboardStats()
			chartSVG, latencySVG, nicHTML := buildDashboardMetricsParts(stats)

			writeDashboardMetricsCard(
				&fragment,
				stats,
				nicHTML,
				chartSVG,
				latencySVG,
				isViewer,
			)
		},
		"domains": func() {
			writeDomainsCard(&fragment, loadStatusData())
		},
		"diagnose": func() {
			writeDiagnoseSection(&fragment)
		},
		"audit": func() {
			writeAuditDNSSection(&fragment, isAdmin)
		},
		"logs": func() {
			logs, logTimeRange := loadDashboardLogs()
			writeLogsCard(&fragment, logs, logTimeRange)
		},
		"backup": func() {
			writeBackupSection(&fragment, isAdmin)
		},
		"debug": func() {
			writeDebugSection(&fragment, snapshotConfig())
		},
		"settings-security": func() {
			writeSettingsSecuritySubpage(&fragment)
		},
		"settings-system": func() {
			config := snapshotConfig()
			if !isAdmin {
				config = maskDashboardConfigSecrets(config)
			}
			writeSettingsSystemSubpage(&fragment, config)
		},
		"settings-domains": func() {
			writeSettingsDomainsSubpage(&fragment)
		},
		"settings-notify": func() {
			config := snapshotConfig()
			if !isAdmin {
				config = maskDashboardConfigSecrets(config)
			}
			writeSettingsNotifySubpage(&fragment, config)
		},
		"totp": func() {
			isAuthenticated := authEnabled && sess != nil
			writeTOTPSection(&fragment, sess, isAuthenticated)
		},
		"users": func() {
			writeUsersSection(&fragment, isAdmin)
		},
	}

	render, found := renderers[page]
	if !found {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": esc(phrases().UnsupportedPage),
		})

		return
	}

	render()

	writeJSON(w, http.StatusOK, map[string]any{
		"page": page,
		"html": fragment.String(),
	})
}

func handleAPISystemStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, esc(phrases().APIErrorMethodNotAllowed), http.StatusMethodNotAllowed)

		return
	}
	if authEnabled {
		if sess, ok := sessionFromRequest(r); !ok || sess == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})

			return
		}
	}

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, getDashboardSystemStats())
}

func handleAPIConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != MethodGET {
		http.Error(w, esc(phrases().APIErrorMethodNotAllowed), http.StatusMethodNotAllowed)

		return
	}

	type fullConfigResponse struct {
		DomainConfigs []safeDomainConfig `json:"domain_configs"`
		System        safeSystemConfig   `json:"system"`
	}

	sess, _ := sessionFromRequest(r)
	isAdmin := !authEnabled || (sess != nil && sess.Role == RoleAdmin)

	sys := currentSystemConfig()
	config := snapshotConfig()
	domains := safeDomainConfigs(config.DomainConfigs)

	if !isAdmin {
		maskSafeSystemConfigSecrets(&sys)
		maskSafeDomainConfigSecrets(domains)
	}

	writeJSON(w, http.StatusOK, fullConfigResponse{
		DomainConfigs: domains,
		System:        sys,
	})
}

const dashboardSecPlaceholderMask = "●●●●●●"

func maskSecret(s string) string {
	if s == "" {
		return ""
	}

	return dashboardSecPlaceholderMask
}

func isDashboardSecretMask(s string) bool {
	return strings.TrimSpace(s) == dashboardSecPlaceholderMask
}

func preserveDashboardSecret(incoming, current string) string {
	if isDashboardSecretMask(incoming) {
		return current
	}

	return incoming
}

func clearDashboardSecretMask(s string) string {
	if isDashboardSecretMask(s) {
		return ""
	}

	return s
}

func maskSafeSystemConfigSecrets(sys *safeSystemConfig) {
	if sys == nil {
		return
	}
	sys.TelegramToken = maskSecret(sys.TelegramToken)
	sys.GotifyToken = maskSecret(sys.GotifyToken)
	sys.NtfyToken = maskSecret(sys.NtfyToken)
	sys.WebhookSecret = maskSecret(sys.WebhookSecret)
	sys.MQTT.Password = maskSecret(sys.MQTT.Password)
	sys.Email.Password = maskSecret(sys.Email.Password)
}

func maskSafeDomainConfigSecrets(domains []safeDomainConfig) {
	for i := range domains {
		domains[i].APISecret = maskSecret(domains[i].APISecret)
		domains[i].HetznerToken = maskSecret(domains[i].HetznerToken)
		domains[i].CFToken = maskSecret(domains[i].CFToken)
		domains[i].CFSecret = maskSecret(domains[i].CFSecret)
		domains[i].IPv64Token = maskSecret(domains[i].IPv64Token)
		domains[i].FebasUpdateURL = maskSecret(domains[i].FebasUpdateURL)
		domains[i].APIKey = maskSecret(domains[i].APIKey)
	}
}

func maskDashboardConfigSecrets(config Config) Config {
	for i := range config.DomainConfigs {
		config.DomainConfigs[i].APISecret = maskSecret(config.DomainConfigs[i].APISecret)
		config.DomainConfigs[i].CFToken = maskSecret(config.DomainConfigs[i].CFToken)
		config.DomainConfigs[i].CFSecret = maskSecret(config.DomainConfigs[i].CFSecret)
		config.DomainConfigs[i].IPv64Token = maskSecret(config.DomainConfigs[i].IPv64Token)
		config.DomainConfigs[i].FebasUpdateURL = maskSecret(config.DomainConfigs[i].FebasUpdateURL)
		config.DomainConfigs[i].APIKey = maskSecret(config.DomainConfigs[i].APIKey)
	}

	config.Notifications.Telegram.Token = maskSecret(config.Notifications.Telegram.Token)
	config.Notifications.Gotify.Token = maskSecret(config.Notifications.Gotify.Token)
	config.Notifications.Ntfy.Token = maskSecret(config.Notifications.Ntfy.Token)
	config.Notifications.Webhook.Secret = maskSecret(config.Notifications.Webhook.Secret)
	config.Notifications.MQTTConfig.Password = maskSecret(config.Notifications.MQTTConfig.Password)
	config.Notifications.Email.Password = maskSecret(config.Notifications.Email.Password)

	return config
}

func handleAPILanguages(w http.ResponseWriter, r *http.Request) {
	p := phrases()

	if r.Method != MethodGET {
		http.Error(w, p.APIErrorMethodNotAllowed, http.StatusMethodNotAllowed)

		return
	}

	langs, err := getAvailableLanguages(langDir)
	if err != nil {
		http.Error(w, p.CouldNotLoadLanguages, http.StatusInternalServerError)

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

func handleAPISaveSystemSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != MethodPOST {
		http.Error(w, esc(phrases().APIErrorMethodNotAllowed), http.StatusMethodNotAllowed)

		return
	}
	if !validateTriggerToken(r) {
		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	var sys safeSystemConfig
	if err := decodeJSONBody(w, r, &sys); err != nil {
		http.Error(w, esc(phrases().JSONParseError), http.StatusBadRequest)

		return
	}

	configUpdateMu.Lock()
	defer configUpdateMu.Unlock()

	cfgMu.Lock()
	oldCfg := cfg
	oldMaxConcurrent := cfg.MaxConcurrent
	applySystemCoreConfig(sys)
	applySystemRuntimeConfig(sys)
	newMaxConcurrent := cfg.MaxConcurrent
	newDebugEnabled := cfg.DebugEnabled
	newDebugHTTPRaw := cfg.DebugHTTPRaw
	cfgMu.Unlock()

	if err := saveConfigToFile(); err != nil {
		cfgMu.Lock()
		cfg = oldCfg
		cfgMu.Unlock()
		ResetHTTPClient()

		http.Error(w, esc(phrases().SaveFailed), http.StatusInternalServerError)

		return
	}

	if oldMaxConcurrent != newMaxConcurrent {
		setWorkerConcurrencyLimit(newMaxConcurrent)
	}
	setAtomicDebugFlags(newDebugEnabled, newDebugHTTPRaw)

	ResetHTTPClient()
	forceNextUpdate.Store(true)

	debugLog("API", getClientIP(r), esc(phrases().SettingsSystem))
	writeJSON(w, http.StatusOK, map[string]string{status: "saved"})
}

func handleAPISaveNotifySettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != MethodPOST {
		http.Error(w, esc(phrases().APIErrorMethodNotAllowed), http.StatusMethodNotAllowed)

		return
	}
	if !validateTriggerToken(r) {
		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	var sys safeSystemConfig
	if err := decodeJSONBody(w, r, &sys); err != nil {
		http.Error(w, esc(phrases().JSONParseError), http.StatusBadRequest)

		return
	}

	configUpdateMu.Lock()
	defer configUpdateMu.Unlock()

	cfgMu.Lock()
	oldCfg := cfg
	applyNotificationConfig(sys)
	cfgMu.Unlock()

	if err := saveConfigToFile(); err != nil {
		cfgMu.Lock()
		cfg = oldCfg
		cfgMu.Unlock()
		invalidateSecretReplacer()

		http.Error(w, esc(phrases().SaveFailed), http.StatusInternalServerError)

		return
	}

	invalidateSecretReplacer()
	go initNotifiers()

	debugLog("API", getClientIP(r), esc(phrases().SettingsNotify))
	writeJSON(w, http.StatusOK, map[string]string{status: "saved"})
}

func handleAPISaveDomainSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != MethodPOST {
		http.Error(w, esc(phrases().APIErrorMethodNotAllowed), http.StatusMethodNotAllowed)

		return
	}
	if !validateTriggerToken(r) {
		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	var payload struct {
		DomainConfigs []safeDomainConfig `json:"domain_configs"`
	}
	if err := decodeJSONBody(w, r, &payload); err != nil {
		http.Error(w, esc(phrases().JSONParseError), http.StatusBadRequest)

		return
	}

	configUpdateMu.Lock()
	defer configUpdateMu.Unlock()

	cfgMu.Lock()
	oldCfg := cfg
	cfg.DomainConfigs = mergeDomainConfigs(cfg.DomainConfigs, payload.DomainConfigs)
	validationErr := validateDomainConfigList(cfg.DomainConfigs)
	if validationErr != nil {
		cfg = oldCfg
		cfgMu.Unlock()
		http.Error(w, validationErr.Error(), http.StatusUnprocessableEntity)

		return
	}
	cfgMu.Unlock()

	if err := saveConfigToFile(); err != nil {
		cfgMu.Lock()
		cfg = oldCfg
		cfgMu.Unlock()
		invalidateSecretReplacer()

		http.Error(w, esc(phrases().SaveFailed), http.StatusInternalServerError)

		return
	}

	invalidateSecretReplacer()
	forceNextUpdate.Store(true)
	lastCleanupNano.Store(0)

	debugLog("API", getClientIP(r), esc(phrases().SettingsDomains))
	writeJSON(w, http.StatusOK, map[string]string{status: "saved"})
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

	cfg.Notifications.Telegram.Token = preserveDashboardSecret(sys.TelegramToken, cfg.Notifications.Telegram.Token)
	cfg.Notifications.Telegram.ChatID = sys.TelegramChatID

	cfg.Notifications.Gotify.URL = sys.GotifyURL
	cfg.Notifications.Gotify.Token = preserveDashboardSecret(sys.GotifyToken, cfg.Notifications.Gotify.Token)

	cfg.Notifications.Ntfy.URL = sys.NtfyURL
	cfg.Notifications.Ntfy.Topic = sys.NtfyTopic
	cfg.Notifications.Ntfy.Token = preserveDashboardSecret(sys.NtfyToken, cfg.Notifications.Ntfy.Token)

	cfg.Notifications.Webhook.URL = sys.WebhookURL
	cfg.Notifications.Webhook.Secret = preserveDashboardSecret(sys.WebhookSecret, cfg.Notifications.Webhook.Secret)

	cfg.Notifications.MQTTConfig.Broker = sys.MQTT.Broker
	cfg.Notifications.MQTTConfig.ClientID = sys.MQTT.ClientID
	cfg.Notifications.MQTTConfig.Username = sys.MQTT.Username
	cfg.Notifications.MQTTConfig.Password = preserveDashboardSecret(sys.MQTT.Password, cfg.Notifications.MQTTConfig.Password)
	cfg.Notifications.MQTTConfig.Topic = sys.MQTT.Topic
	cfg.Notifications.MQTTConfig.QoS = sys.MQTT.QoS
	cfg.Notifications.MQTTConfig.Retain = sys.MQTT.Retain
	cfg.Notifications.MQTTConfig.Discovery = sys.MQTT.Discovery
	cfg.Notifications.MQTTConfig.DiscoveryPrefix = sys.MQTT.DiscoveryPrefix

	cfg.Notifications.Email.Host = sys.Email.Host
	cfg.Notifications.Email.Port = sys.Email.Port
	cfg.Notifications.Email.Username = sys.Email.Username
	cfg.Notifications.Email.Password = preserveDashboardSecret(sys.Email.Password, cfg.Notifications.Email.Password)
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
	existing := indexDomainConfigs(existingCfg)
	newConfigs := make([]DomainConfig, 0, len(incoming))

	for _, sc := range incoming {
		fqdn := strings.ToLower(strings.TrimSpace(sc.FQDN))
		if fqdn == "" {
			continue
		}

		found, ok := existing[fqdn]
		if ok {
			newConfigs = append(newConfigs, mergeExistingDomainConfig(found, sc))

			continue
		}
		newConfigs = append(newConfigs, newDomainConfig(fqdn, sc))
	}

	sortDomainConfigs(newConfigs)

	return newConfigs
}

func indexDomainConfigs(configs []DomainConfig) map[string]DomainConfig {
	indexed := make(map[string]DomainConfig, len(configs))
	for _, config := range configs {
		indexed[strings.ToLower(config.FQDN)] = config
	}

	return indexed
}

func mergeExistingDomainConfig(found DomainConfig, incoming safeDomainConfig) DomainConfig {
	oldProvider := found.Provider
	oldRecordMode := strings.ToUpper(strings.TrimSpace(found.RecordMode))
	oldCNAMETarget := normalizeDomain(found.CNAMETarget)

	newProvider := oldProvider
	if strings.TrimSpace(incoming.Provider) != "" {
		newProvider = normalizeProviderName(incoming.Provider)
	}

	if newProvider != oldProvider {
		clearForeignProviderSecrets(&found, newProvider)
	}

	newRecordMode := strings.ToUpper(strings.TrimSpace(incoming.RecordMode))
	newCNAMETarget := normalizeDomain(incoming.CNAMETarget)

	applyNonEmptyDashboardValue(&found.APIPrefix, incoming.APIPrefix)
	applyDashboardSecret(&found.APISecret, incoming.APISecret)
	applyDashboardSecret(&found.HetznerToken, incoming.HetznerToken)
	applyDashboardSecret(&found.CFToken, incoming.CFToken)
	applyNonEmptyDashboardValue(&found.CFEmail, incoming.CFEmail)
	applyDashboardSecret(&found.CFSecret, incoming.CFSecret)
	applyDashboardSecret(&found.IPv64Token, incoming.IPv64Token)
	applyDashboardSecret(&found.FebasUpdateURL, incoming.FebasUpdateURL)
	applyDashboardSecret(&found.APIKey, incoming.APIKey)

	found.Provider = newProvider
	found.TTL = incoming.TTL
	found.CFProxied = incoming.CFProxied
	found.IPMode = incoming.IPMode
	found.RecordMode = newRecordMode
	found.CNAMETarget = newCNAMETarget

	if newRecordMode == RecordModeCNAME {
		found.CNAMEPending = found.CNAMEPending ||
			oldRecordMode != RecordModeCNAME ||
			oldCNAMETarget != newCNAMETarget ||
			oldProvider != newProvider
	} else {
		found.CNAMEPending = false
	}

	return found
}

func clearForeignProviderSecrets(dc *DomainConfig, newProvider ProviderType) {
	if newProvider != ProviderIONOS {
		dc.APIPrefix = ""
		dc.APISecret = ""
	}
	if newProvider != ProviderHetzner && newProvider != ProviderHetznerCloud {
		dc.HetznerToken = ""
	}
	if newProvider != ProviderCloudflare {
		dc.CFToken = ""
		dc.CFEmail = ""
		dc.CFSecret = ""
	}
	if newProvider != ProviderIPv64 {
		dc.IPv64Token = ""
	}
	if newProvider != ProviderFebas {
		dc.FebasUpdateURL = ""
	}
	if newProvider != ProviderDNScale {
		dc.APIKey = ""
	}
}

func applyNonEmptyDashboardValue(destination *string, incoming string) {
	if incoming != "" {
		*destination = incoming
	}
}

func applyDashboardSecret(destination *string, incoming string) {
	if incoming != "" && !isDashboardSecretMask(incoming) {
		*destination = incoming
	}
}

func newDomainConfig(fqdn string, incoming safeDomainConfig) DomainConfig {
	recordMode := strings.ToUpper(strings.TrimSpace(incoming.RecordMode))

	return DomainConfig{
		FQDN:           fqdn,
		Provider:       normalizeProviderName(incoming.Provider),
		APIPrefix:      incoming.APIPrefix,
		APISecret:      clearDashboardSecretMask(incoming.APISecret),
		HetznerToken:   clearDashboardSecretMask(incoming.HetznerToken),
		CFToken:        clearDashboardSecretMask(incoming.CFToken),
		CFEmail:        incoming.CFEmail,
		CFSecret:       clearDashboardSecretMask(incoming.CFSecret),
		IPv64Token:     clearDashboardSecretMask(incoming.IPv64Token),
		FebasUpdateURL: clearDashboardSecretMask(incoming.FebasUpdateURL),
		APIKey:         clearDashboardSecretMask(incoming.APIKey),
		TTL:            incoming.TTL,
		CFProxied:      incoming.CFProxied,
		IPMode:         incoming.IPMode,
		RecordMode:     recordMode,
		CNAMETarget:    normalizeDomain(incoming.CNAMETarget),
		CNAMEPending:   recordMode == RecordModeCNAME,
	}
}

func sortDomainConfigs(configs []DomainConfig) {
	sort.Slice(configs, func(i, j int) bool {
		if configs[i].Provider != configs[j].Provider {
			return string(configs[i].Provider) < string(configs[j].Provider)
		}

		return configs[i].FQDN < configs[j].FQDN
	})
}

func handleAPISetLanguage(w http.ResponseWriter, r *http.Request) {
	p := phrases()

	if r.Method != MethodPOST {
		http.Error(w, p.APIErrorMethodNotAllowed, http.StatusMethodNotAllowed)

		return
	}

	if !validateTriggerToken(r) {
		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	lang := normalizeLang(r.URL.Query().Get("lang"))
	if lang == "" {
		http.Error(w, p.LanguageParamMissing, http.StatusBadRequest)

		return
	}

	supported, err := getAvailableLanguages(langDir)
	if err != nil || !supported[lang] {
		http.Error(
			w,
			fmt.Sprintf(p.UnsupportedLanguage, lang),
			http.StatusBadRequest,
		)

		return
	}

	configUpdateMu.Lock()
	defer configUpdateMu.Unlock()

	if err := loadLanguage(lang); err != nil {
		http.Error(
			w,
			fmt.Sprintf(p.LanguageLoadFailed, err),
			http.StatusInternalServerError,
		)

		return
	}

	cfgMu.Lock()
	cfg.Lang = lang
	cfgMu.Unlock()
	p = phrases()

	if err := saveConfigToFile(); err != nil {
		debugLog("API", getClientIP(r), fmt.Sprintf(p.ConfigSaveWarnAfterLanguageChange, err))
	}

	debugLog("API", getClientIP(r), fmt.Sprintf(p.LanguageChangedLog, lang))

	broadcastNotification(fmt.Sprintf(p.LanguageChangedNotification, lang), "info")

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
		"lang":   lang,
	})
}

func handleAPIIPv64Domain(w http.ResponseWriter, r *http.Request) {
	if r.Method != MethodPOST {
		http.Error(w, esc(phrases().APIErrorMethodNotAllowed), http.StatusMethodNotAllowed)

		return
	}
	if !validateTriggerToken(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": esc(phrases().InvalidToken)})

		return
	}

	var req struct {
		Action   string `json:"action"`
		FQDN     string `json:"fqdn"`
		APIToken string `json:"api_token"`
	}

	if err := decodeJSONBody(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": esc(phrases().ErrInvalidJSON)})

		return
	}

	req.FQDN = normalizeIPv64FQDN(req.FQDN)
	if req.FQDN == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": esc(phrases().DomainIsEmpty)})

		return
	}

	req.Action = strings.ToUpper(strings.TrimSpace(req.Action))
	if req.Action != MethodADD && req.Action != MethodDELETE {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": esc(phrases().IPv64ActionInvalid)})

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
		http.Error(w, esc(phrases().APIErrorMethodNotAllowed), http.StatusMethodNotAllowed)

		return
	}
	if !validateTriggerToken(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": esc(phrases().InvalidToken)})

		return
	}

	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	if domain == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": esc(phrases().DomainParamMissing)})

		return
	}

	if isDomainActiveInConfig(domain) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": esc(phrases().DomainStillActiveInConfig)})

		return
	}

	statusMutex.Lock()
	statusKey, statusCode, errMsg := findDomainInStatusLocked(domain)
	if statusCode == http.StatusOK {
		domains, err := currentStatusDomainsLocked()
		if err == nil {
			delete(domains, statusKey)
			if writeErr := writeStatusDomainsLocked(domains); writeErr != nil {
				statusMutex.Unlock()
				debugLog("API", getClientIP(r), fmt.Sprintf("Failed to persist update.json after removing %s: %v", statusKey, writeErr))
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": esc(phrases().SaveFailed)})

				return
			}
		}
	}
	statusMutex.Unlock()

	if statusCode != http.StatusOK {
		writeJSON(w, statusCode, map[string]string{"error": errMsg})

		return
	}

	if err := updateDomainsCache(); err != nil {
		debugLog("CACHE", "", fmt.Sprintf("updateDomainsCache failed after domain delete: %v", err))
	}

	forceNextUpdate.Store(true)
	lastCleanupNano.Store(0)

	debugLog("API", getClientIP(r), fmt.Sprintf("Removed %s from update.json; provider cleanup queued", statusKey))
	broadcastNotification("Provider cleanup queued for "+statusKey, "info")

	writeJSON(w, http.StatusAccepted, map[string]string{
		"status": "cleanup_queued",
		"domain": statusKey,
	})
}

func isDomainActiveInConfig(domain string) bool {
	config := snapshotConfig()

	for _, dc := range config.DomainConfigs {
		if strings.EqualFold(dc.FQDN, domain) {
			return true
		}
	}

	return false
}

func findDomainInStatusLocked(domain string) (string, int, string) {
	current, err := currentStatusDomainsLocked()
	if err != nil {
		if os.IsNotExist(err) {
			return "", http.StatusNotFound, esc(phrases().NoStatusFileFound)
		}

		return "", http.StatusInternalServerError, err.Error()
	}

	statusKey := existingStatusDomainKey(current, domain)
	if statusKey == "" {
		return "", http.StatusNotFound, esc(phrases().DomainNotFoundInStatus)
	}

	return statusKey, http.StatusOK, ""
}

func handleAPITrigger(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1024)

	if r.Method != MethodPOST {
		w.Header().Set("Allow", MethodPOST)
		http.Error(w, esc(phrases().APIErrorMethodNotAllowed), http.StatusMethodNotAllowed)

		return
	}

	clientIP := getClientIP(r)

	if !validateTriggerToken(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": esc(phrases().InvalidOrMissingTriggerToken),
		})
		debugLog("API", clientIP, esc(phrases().TriggerBlockedInvalidToken))

		return
	}

	if !hasDomainConfig() {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": esc(phrases().TriggerNoDomainsError),
		})
		debugLog("API", clientIP, esc(phrases().TriggerBlockedNoDomainsLog))

		return
	}

	if updateInProgress.Load() {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":  esc(phrases().UpdateAlreadyInProgressAPI),
			"status": esc(phrases().TriggerStatusBusy),
		})
		debugLog("API", clientIP, esc(phrases().TriggerBlockedUpdateRunning))
		broadcastNotification(phrases().UpdateAlreadyRunningNotification, "info")

		return
	}

	if !globalTriggerLimiter.Allow() {
		const retryAfter = 10
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":               esc(phrases().GlobalRateLimitExceeded),
			"retry_after_seconds": retryAfter,
		})
		debugLog("API", clientIP, esc(phrases().TriggerBlockedGlobalRateLimit))
		broadcastNotification(phrases().RateLimitGlobal, "warning")

		return
	}

	ipLimiter := ipTriggerLimiter.GetLimiter(clientIP)
	if !ipLimiter.Allow() {
		const retryAfter = 10
		remaining := ipLimiter.Remaining()
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		w.Header().Set("X-Ratelimit-Remaining", strconv.Itoa(remaining))
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":               esc(phrases().IPRateLimitExceeded),
			"retry_after_seconds": retryAfter,
			"remaining":           remaining,
		})
		debugLog("API", clientIP, esc(phrases().TriggerBlockedIPRateLimit))
		broadcastNotification(phrases().TooManyUpdateRequestsWait, "warning")

		return
	}

	if !tryClaimUpdate() {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":  esc(phrases().UpdateAlreadyInProgressAPI),
			"status": esc(phrases().TriggerStatusBusy),
		})
		debugLog("API", clientIP, esc(phrases().TriggerBlockedUpdateRunning))
		broadcastNotification(phrases().UpdateAlreadyRunningNotification, "info")

		return
	}

	remaining := ipLimiter.Remaining()
	w.Header().Set("X-Ratelimit-Remaining", strconv.Itoa(remaining))
	writeJSON(w, http.StatusAccepted, map[string]any{
		"status":               "triggered",
		"message":              esc(phrases().UpdateStartedMessage),
		"rate_limit_remaining": remaining,
	})

	go func(triggerIP string) {
		if !hasDomainConfig() {
			updateInProgress.Store(false)
			debugLog("API", triggerIP, esc(phrases().UpdateAbortedNoDomainsLog))

			return
		}

		debugLog("API", triggerIP, esc(phrases().ManualUpdateTriggeredLog))
		broadcastNotification(phrases().ManualUpdateStartedNotification, "info")

		forceNextUpdate.Store(true)
		runClaimedUpdate(false)
	}(clientIP)
}

func handleAPINotifyTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != MethodPOST {
		http.Error(w, esc(phrases().APIErrorMethodNotAllowed), http.StatusMethodNotAllowed)

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
			"message": esc(phrases().NotifyNoNotifier),
			"sent":    0,
		})

		return
	}

	testMsg := NotifyMessage{
		Action:  ActionConfig,
		Domain:  "",
		Message: t(phrases().NotifyTestBody, "🔔 Test Notification: Your dashboard notification system is working perfectly!"),
		Level:   LogInfo,
	}

	type result struct {
		Name  string `json:"name"`
		Error string `json:"error,omitempty"`
		OK    bool   `json:"ok"`
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
	if r.Method != MethodGET {
		w.Header().Set("Allow", MethodGET)
		http.Error(w, esc(phrases().APIErrorMethodNotAllowed), http.StatusMethodNotAllowed)

		return
	}

	if !validateTriggerToken(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": esc(phrases().InvalidOrMissingTriggerToken),
		})

		return
	}

	clientIP := getClientIP(r)
	ipLimiter := ipTriggerLimiter.GetLimiter(clientIP)

	writeJSON(w, http.StatusOK, map[string]any{
		"ip":                 clientIP,
		"remaining_requests": ipLimiter.Remaining(),
		"update_in_progress": updateInProgress.Load(),
		"active_updates":     activeUpdates.Load(),
		"global_limit":       globalTriggerLimiter.Remaining(),
	})
}

func handleAPIExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(
			w,
			esc(phrases().APIErrorMethodNotAllowed),
			http.StatusMethodNotAllowed,
		)

		return
	}

	if !validateTriggerToken(r) {
		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(
		"Content-Disposition",
		"attachment; filename=dyndns-export.json",
	)

	if err := streamDashboardExport(w); err != nil {
		debugLog("EXPORT", "", fmt.Sprintf("Export failed: %v", err))
	}
}

func streamDashboardExport(w io.Writer) error {
	if _, err := io.WriteString(w, `{"timestamp":`); err != nil {
		return err
	}

	if err := writeJSONValue(w, time.Now().Format(time.RFC3339)); err != nil {
		return err
	}

	if _, err := io.WriteString(w, `,"metrics":`); err != nil {
		return err
	}

	if err := writeJSONValue(w, apiMetrics.GetStats()); err != nil {
		return err
	}

	if _, err := io.WriteString(w, `,"domains":`); err != nil {
		return err
	}

	if err := streamDomainsJSON(w); err != nil {
		return err
	}

	if _, err := io.WriteString(w, `,"logs":[`); err != nil {
		return err
	}

	if err := streamLogEntriesJSON(w); err != nil {
		return err
	}

	_, err := io.WriteString(w, "]}\n")

	return err
}

func writeJSONValue(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)

	return encoder.Encode(value)
}

func streamDomainsJSON(w io.Writer) error {
	file, err := os.Open(updatePath)
	if err != nil {
		if os.IsNotExist(err) {
			_, writeErr := io.WriteString(w, "{}")

			return writeErr
		}

		return err
	}
	defer func() {
		if err := file.Close(); err != nil {
			debugLog("DASHBOARD", "", fmt.Sprintf(phrases().ErrBodyClose+": %v", err))
		}
	}()

	_, err = io.Copy(w, file)

	return err
}

func streamLogEntriesJSON(w io.Writer) error {
	file, err := os.Open(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}

		return err
	}
	defer func() {
		if err := file.Close(); err != nil {
			debugLog("DASHBOARD", "", fmt.Sprintf(phrases().ErrBodyClose+": %v", err))
		}
	}()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	first := true

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}

		if !json.Valid(line) {
			continue
		}

		if !first {
			if _, err := io.WriteString(w, ","); err != nil {
				return err
			}
		}

		if _, err := w.Write(line); err != nil {
			return err
		}

		first = false
	}

	return scanner.Err()
}

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	serveCachedJSON(w, r, metricsCache)
}

func healthDetailAuthorized(r *http.Request) bool {
	if r == nil {
		return false
	}

	if authEnabled {
		if sess, ok := sessionFromRequest(r); ok && sess.Role == RoleAdmin {
			return true
		}
	}

	expected := strings.TrimSpace(os.Getenv("DASHBOARD_HEALTH_TOKEN"))
	if expected == "" {
		return !authEnabled && envBool("DASHBOARD_ALLOW_PUBLIC_DETAILED_HEALTH")
	}

	provided := strings.TrimSpace(r.Header.Get("X-Health-Token"))
	if auth := strings.TrimSpace(r.Header.Get("Authorization")); strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		provided = strings.TrimSpace(auth[len("Bearer "):])
	}

	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	isHealthy := lastOk.Load()
	hasRun := schedulerRanOnce.Load()
	stats := apiMetrics.GetStats()
	total := getTotalRequests(stats)

	status := healthy
	reason := ""
	statusCode := http.StatusOK

	if !hasRun {
		status = starting
		reason = esc(phrases().WaitingForFirstSchedulerRun)
	} else if total > 10 {
		if successRateStr, ok := stats["success_rate"].(string); ok {
			var rate float64
			if _, err := fmt.Sscanf(successRateStr, "%f%%", &rate); err == nil {
				switch {
				case rate < 20.0:
					isHealthy = false
					status = unhealthy
					reason = esc(phrases().HealthCriticalSuccessRate)
					statusCode = http.StatusServiceUnavailable
				case rate < 50.0:
					status = "degraded"
					reason = esc(phrases().HealthDegradedSuccessRate)
				}
			}
		}
	}

	if hasRun && !isHealthy && status != unhealthy {
		status = unhealthy
		statusCode = http.StatusServiceUnavailable
		if reason == "" {
			reason = esc(phrases().HealthLastSchedulerFailed)
		}
	}

	if r.URL.Query().Get("detailed") == constTrue {
		if !healthDetailAuthorized(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "detailed health access denied"})

			return
		}
		handleDetailedHealth(w, statusCode, status, reason, stats)

		return
	}

	if status == healthy {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))

		return
	}

	writeJSON(w, statusCode, map[string]any{
		"status": status,
		"reason": reason,
	})
}

func handleLiveness(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

func handleReadiness(w http.ResponseWriter, _ *http.Request) {
	if !schedulerRanOnce.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("not ready"))

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

func handleDetailedHealth(w http.ResponseWriter, statusCode int, status, reason string, stats map[string]any) {
	lastV4, lastV6 := loadLastKnownIPs()

	statusMutex.Lock()
	lastUpdateTime := readLastUpdateTimeFromStatusFile()
	statusMutex.Unlock()

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, statusCode, map[string]any{
		"status":           status,
		"reason":           reason,
		"version":          Version,
		"built":            BuildDate,
		"api_metrics":      stats,
		"last_known_ipv4":  lastV4,
		"last_known_ipv6":  lastV6,
		"last_update_time": lastUpdateTime,
	})
}

func readLastUpdateTimeFromStatusFile() string {
	domains, err := snapshotStatusDomains()
	if err != nil {
		return ""
	}

	var newest time.Time
	for _, history := range domains {
		if history.LastChanged == "" {
			continue
		}

		changedAt, err := time.ParseInLocation(statusTimestampLayout, history.LastChanged, time.Local)
		if err == nil && changedAt.After(newest) {
			newest = changedAt
		}
	}

	if newest.IsZero() {
		return ""
	}

	return newest.Format(statusTimestampLayout)
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)

		return
	}

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, esc(phrases().APIErrorMethodNotAllowed), http.StatusMethodNotAllowed)

		return
	}

	sess, _ := sessionFromRequest(r)
	statusClass, statusText := dashboardStatus()
	config := snapshotConfig()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set(
		"Cache-Control",
		"no-store, no-cache, must-revalidate, max-age=0",
	)
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	writeDashboardHeader(w, sess)
	writeDashboardTop(w, statusClass, statusText, config)

	for _, page := range []string{
		"domains",
		"metrics",
		"diagnose",
		"audit",
		"logs",
		"debug",
		"backup",
		"settings-security",
		"settings-system",
		"settings-domains",
		"settings-notify",
		"totp",
		"users",
	} {
		writePagePlaceholder(w, page)
	}

	_, _ = fmt.Fprint(w, `<div id="settingsOverlay" class="modal-overlay"></div>`)
	writeDashboardFooter(w)
}

func writePagePlaceholder(w io.Writer, page string) {
	_, _ = fmt.Fprintf(w, `<div class="page-section page-section--placeholder" data-section="%s" data-loaded="0">
		<div class="card lazy-page-card">
			<div class="card-content page-loading">%s</div>
		</div>
	</div>`, esc(page), t(phrases().PageLoading, "⏳ Loading..."))
}

func writeDebugSection(w io.Writer, config Config) {
	if config.DebugEnabled || config.DebugHTTPRaw {
		writeDebugCard(w)

		return
	}

	_, _ = fmt.Fprint(w, `
	<div class="page-section" data-section="debug">
		<div class="card">
			<div class="card-header">🐞 `+phrases().DebugLogTitle+`</div>
			<div class="card-content">
				<p class="debug-disabled-note">`+phrases().DebugDisabledNote+`</p>
			</div>
		</div>
	</div>`)
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
		return "status-error", esc(phrases().StatusErr)
	}

	return "status-ok", esc(phrases().StatusOk)
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
	config := snapshotConfig()
	hasIPv64 := false
	for _, dc := range config.DomainConfigs {
		if dc.Provider == ProviderIPv64 {
			hasIPv64 = true

			break
		}
	}
	if !hasIPv64 {
		return ""
	}

	return `<div class="nic-row"><span class="nic-label">NIC <span>(` + esc(phrases().NicIPv64Updates) + `)</span></span><span id="mDailyNIC" class="nic-value">` +
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
		http.Error(w, esc(phrases().APIErrorMethodNotAllowed), http.StatusMethodNotAllowed)

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

func handleAPILogDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, esc(phrases().APIErrorMethodNotAllowed), http.StatusMethodNotAllowed)

		return
	}
	if !requireAdminAPI(w, r) {
		return
	}

	var body struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&body); err != nil || body.ID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing id"})

		return
	}

	logMutex.Lock()
	defer logMutex.Unlock()

	if logWriter != nil {
		_ = logWriter.Flush()
		logWriter = nil
	}
	if logFile != nil {
		_ = logFile.Close()
		logFile = nil
	}

	deleted, err := deleteLogEntryStreaming(logPath, body.ID)
	if err != nil {
		writeJSON(
			w,
			http.StatusInternalServerError,
			map[string]string{"error": err.Error()},
		)

		return
	}

	logMemCacheMu.Lock()
	logMemCache = nil
	logMemCacheTime = time.Time{}
	logMemCacheMu.Unlock()

	status := "not_found"
	if deleted {
		status = "deleted"
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status": status,
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
				Message:  fmt.Sprintf("%s: %v", t(phrases().FileCloseError, "Failed to close file"), err),
			})
		}
	}()

	config := snapshotConfig()
	limit := config.MaxLogLines
	if limit <= 0 {
		limit = DefaultMaxLogLines
	}
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
			Message:  fmt.Sprintf("%s: %v", t(phrases().ScannerError, "Scanner error"), err),
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
	t, err := time.Parse(statusTimestampLayoutT, ts)
	if err != nil {
		return ts
	}

	return t.Format(statusTimestampLayout)
}

func writeDashboardHeader(w http.ResponseWriter, sess *Session) {
	logoutBtn := ""
	userInfo := ""
	csrfMeta := ""
	userPage := ""
	totpPage := ""
	auditPage := ""
	if authEnabled && sess != nil {
		csrfMeta = `<meta name="csrf-token" content="` + esc(sess.CSRFToken) + `">`
		roleIcon := map[UserRole]string{
			RoleAdmin:  "👑",
			RoleEditor: "✏️",
			RoleViewer: "👁️",
		}[sess.Role]
		userInfo = fmt.Sprintf(`<span class="sidebar-user-info">%s %s</span>`, roleIcon, esc(sess.Username))
		logoutBtn = `<form method="POST" action="/logout" class="logout-form"><input type="hidden" name="csrf_token" value="` + esc(sess.CSRFToken) + `"><button type="submit" class="action-btn topbar-action-btn logout-btn">` + esc(phrases().LogoutLabel) + `</button></form>`
		totpPage = `<button type="button" class="nav-item" data-page="totp" data-click="navTo('totp')">` + esc(phrases().NavTotpJS) + `</button>`
		if sess.Role == RoleAdmin {
			userPage = `<button type="button" class="nav-item" data-page="users" data-click="navTo('users')">` + esc(phrases().SettingsUserManagement) + `</button>`
			auditPage = `<button type="button" class="nav-item" data-page="audit" data-click="navTo('audit')">` + esc(phrases().NavAuditJS) + `</button>`
		}
	} else if !authEnabled {
		userPage = `<button type="button" class="nav-item" data-page="users" data-click="navTo('users')">` + esc(phrases().SettingsUserManagement) + `</button>`
		auditPage = `<button type="button" class="nav-item" data-page="audit" data-click="navTo('audit')">` + esc(phrases().NavAuditJS) + `</button>`
	}

	_, _ = fmt.Fprintf(
		w, `<!DOCTYPE html><html><head>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<meta name="format-detection" content="telephone=no">
		<meta name="apple-mobile-web-app-capable" content="yes">
		<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
		<meta name="apple-mobile-web-app-title" content="IONOS-DDNS">
		`+csrfMeta+`
		<title>%s</title>
		<link id="favicon" rel="icon" type="image/svg+xml" href="/favicon.svg?theme=dark">
		<link rel="stylesheet" href="`+assetURL("/assets/style.css", dashboardCSSETag)+`">
	</head>
	<body class="dashboard-runtime">

	<div class="auth-bg" aria-hidden="true">
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
					<small>`+t(phrases().MultiProvider, "Multi-Provider")+`</small>
				</div>
			</div>

			<div class="nav-section-label">`+t(phrases().NavOverview, "Overview")+`</div>
			<button type="button" class="nav-item" data-page="dashboard" data-click="navTo('dashboard')">
				<span class="nav-item-icon">📊</span> `+phrases().NavDashboard+`
			</button>
			<button type="button" class="nav-item" data-page="domains" data-click="navTo('domains')">
				<span class="nav-item-icon">🌐</span> `+phrases().NavDomains+`
			</button>

			<div class="nav-section-label">`+t(phrases().NavMonitoring, "Monitoring")+`</div>
			<button type="button" class="nav-item" data-page="metrics" data-click="navTo('metrics')">
				<span class="nav-item-icon">📈</span> `+phrases().APIPerformance+`
			</button>
			<button type="button" class="nav-item" data-page="diagnose" data-click="navTo('diagnose')">
				<span class="nav-item-icon">🩺</span> `+t(phrases().DiagnoseTitle, "Diagnose / Health Center")+`
			</button>
			<button type="button" class="nav-item" data-page="logs" data-click="navTo('logs')">
				<span class="nav-item-icon">🧾</span> `+phrases().SystemEvents+`
			</button>
			<button type="button" class="nav-item" data-page="debug" data-click="navTo('debug')">
				<span class="nav-item-icon">🐞</span> `+phrases().DebugLogTitle+`
			</button>

			<div class="nav-section-label">`+t(phrases().NavTools, "Tools")+`</div>
			<button type="button" class="nav-item" data-page="backup" data-click="navTo('backup')">
				<span class="nav-item-icon">💾</span> `+t(phrases().BackupTitle, "Backup & Restore")+`
			</button>
			`+auditPage+`

			<div class="nav-section-label">`+t(phrases().NavConfig, "Config")+`</div>
			<button type="button" class="nav-item nav-item--group" id="settings-group-toggle" data-click="toggleSettingsSubmenu()" aria-expanded="false" aria-controls="settings-submenu">
				<span class="nav-item-icon">⚙️</span> `+phrases().SettingsTitle+`
				<span class="nav-item-chevron">▾</span>
			</button>
			<div class="nav-submenu" id="settings-submenu">
				<button type="button" class="nav-item nav-item--sub" data-page="settings-security" data-click="navTo('settings-security')">
					 `+phrases().SettingsSecurity+`
				</button>
				<button type="button" class="nav-item nav-item--sub" data-page="settings-system" data-click="navTo('settings-system')">
					`+phrases().SettingsSystem+`
				</button>
				<button type="button" class="nav-item nav-item--sub" data-page="settings-domains" data-click="navTo('settings-domains')">
					 `+phrases().SettingsDomains+`
				</button>
				<button type="button" class="nav-item nav-item--sub" data-page="settings-notify" data-click="navTo('settings-notify')">
					 `+phrases().SettingsNotify+`
				</button>
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
				<button type="button" class="hamburger-btn" data-click="toggleSidebar()" aria-label="Menu" aria-controls="sidebar" aria-expanded="false">☰</button>
				<span id="page-title" class="topbar-title">`+t(phrases().NavDashboardJS, "📊 Dashboard")+`</span>
				<div class="topbar-right">
					<button class="action-btn topbar-action-btn is-hidden"
						id="topbar-save-config-button"
						data-tooltip="`+esc(phrases().SettingsSaveHint)+`"
						data-mouseenter="showNotifierTooltip()"
						data-focus="showNotifierTooltip()"
						data-click="saveCurrentSettingsSection()">`+phrases().SettingsSaveBtn+`</button>

					<button class="action-btn topbar-action-btn"
						id="update-button"
						data-tooltip="`+esc(phrases().SettingsUpdateHint)+`"
						data-mouseenter="showNotifierTooltip()"
						data-focus="showNotifierTooltip()"
						data-click="triggerUpdate()">🔄 `+phrases().Update+`</button>

					<button class="action-btn topbar-action-btn"
						data-tooltip="`+esc(phrases().SettingsExportHint)+`"
						data-mouseenter="showNotifierTooltip()"
						data-focus="showNotifierTooltip()"
						data-click="exportData()">📥 `+phrases().ExportBtn+`</button>

					<div class="notif-wrap">
						<button type="button" class="theme-toggle notif-toggle"
							aria-controls="notif-panel"
							aria-expanded="false"
							data-tooltip="`+esc(phrases().SettingsNotifierHint)+`"
							data-mouseenter="showNotifierTooltip()"
							data-focus="showNotifierTooltip()"
							data-click="toggleNotifCenter()">🔔
							<span id="notif-badge" class="notif-badge"></span>
						</button>

						<div id="notif-panel" class="notif-panel">
							<div class="notif-panel-header">
								🔔 `+phrases().SettingsNotifyHint+`
							</div>
							<div id="notif-list"></div>
						</div>
					</div>

					<button class="theme-toggle"
						data-tooltip="`+esc(phrases().SettingsThemeHint)+`"
						data-mouseenter="showNotifierTooltip()"
						data-focus="showNotifierTooltip()"
						data-click="toggleTheme()">🌓</button>
				</div>
			</header>

			<div id="toast" class="toast"></div>

			<!-- ═══ MAIN CONTENT ═══ -->
			<div class="main-content">
	`,
		esc(phrases().DashboardTitle),
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
		"Ntfy":     "📝",
		"Webhook":  "🔗",
		"Mqtt":     "📡",
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
		title := name + " " + esc(phrases().NotifierActive)
		if !connected {
			stateClass = "notifier-icon--disconnected"
			title = name + " " + esc(phrases().NotifierDisconnected)
		}

		fmt.Fprintf(
			&sb,
			`<span class="notifier-icon %s" title="%s" data-tooltip="%s" data-click="showNotifierTooltip()">%s</span>`,
			stateClass, esc(title), esc(title), esc(icon),
		)
	}

	sb.WriteString(`</span>`)

	return sb.String()
}

func writeDashboardTop(w io.Writer, statusClass, statusText string, config Config) {
	_, _ = fmt.Fprintf(
		w, `
	<div class="page-section" data-section="dashboard">
		<div class="status-banner %s">
			<div class="status-banner-left">
				<span>%s</span>
			</div>
			<div class="status-banner-meta">
				<span class="status-item status-item--clickable"
					title="`+esc(phrases().TooltipLastCheck)+`"
					data-tooltip="`+esc(phrases().TooltipLastCheck)+`"
					data-click="showNotifierTooltip()">
					%s: <span id="lastUpdate">%s</span>
				</span>
				<span class="status-sep">|</span>
				<span class="status-item status-item--clickable"
					title="`+esc(phrases().TooltipClock)+`"
					data-tooltip="`+esc(phrases().TooltipClock)+`"
					data-click="showNotifierTooltip()">
					🕒 <span id="clock">--:--:--</span>
				</span>
				<span class="status-sep">|</span>
				<span class="status-item status-uptime status-item--clickable"
					title="`+esc(phrases().TooltipUptime)+`"
					data-tooltip="`+esc(phrases().TooltipUptime)+`"
					data-click="showNotifierTooltip()">
					⏱️ <span id="uptime">--</span>
				</span>
				%s
			</div>
		</div>

		<div class="card system-stats-card" id="system-stats-card">
			<div class="card-header card-header--space-between">
				<span>🖥️ `+t(phrases().SystemStatsTitle, "System load")+`</span>
				<span id="systemStatsUpdated" class="system-stats-updated">`+t(phrases().SystemStatsLoading, "Loading …")+`</span>
			</div>
			<div class="card-content">
				<div class="system-metrics-grid">
					<div class="system-metric">
						<div class="system-metric-head"><span>`+t(phrases().SystemStatsCPU, "CPU")+`</span><strong id="sysCpu">--</strong></div>
						<div class="system-progress"><div id="sysCpuBar" class="system-progress-bar"></div></div>
						<div id="sysCpuSub" class="system-metric-sub">`+t(phrases().SystemStatsCPUDetecting, "Detecting CPU usage")+`</div>
					</div>
					<div class="system-metric">
						<div class="system-metric-head"><span>`+t(phrases().SystemStatsMemory, "RAM")+`</span><strong id="sysMem">--</strong></div>
						<div class="system-progress"><div id="sysMemBar" class="system-progress-bar"></div></div>
						<div id="sysMemSub" class="system-metric-sub">`+t(phrases().SystemStatsMemoryDetecting, "Detecting memory usage")+`</div>
					</div>
					<div class="system-metric">
						<div class="system-metric-head"><span>`+t(phrases().SystemStatsNetwork, "Network")+`</span><strong id="sysNet">--</strong></div>
						<div id="sysNetSub" class="system-metric-sub">`+t(phrases().SystemStatsNetworkContainer, "RX / TX in the container network")+`</div>
					</div>
					<div class="system-metric">
						<div class="system-metric-head"><span>`+t(phrases().SystemStatsBlockIO, "Block I/O")+`</span><strong id="sysIO">--</strong></div>
						<div id="sysIOSub" class="system-metric-sub">`+t(phrases().SystemStatsIOCgroup, "Read / write via cgroup")+`</div>
					</div>
				</div>

				<div class="system-details-grid">
					<div><span>`+t(phrases().SystemStatsEnvironment, "Environment")+`</span><strong id="sysEnvironment">--</strong></div>
					<div><span>`+t(phrases().SystemStatsCPULimit, "CPU limit")+`</span><strong id="sysCpuLimit">--</strong></div>
					<div><span>`+t(phrases().SystemStatsPIDs, "PIDs")+`</span><strong id="sysPids">--</strong></div>
					<div><span>`+t(phrases().SystemStatsGoProcess, "Go process")+`</span><strong id="sysProcess">--</strong></div>
					<div><span>`+t(phrases().SystemStatsCPUThrottling, "CPU throttling")+`</span><strong id="sysThrottle">--</strong></div>
					<div><span>`+t(phrases().SystemStatsPressureAvg10, "Pressure avg10")+`</span><strong id="sysPressure">--</strong></div>
					<div><span>`+t(phrases().SystemStatsNetworkTotal, "Network total")+`</span><strong id="sysNetTotal">--</strong></div>
					<div><span>`+t(phrases().SystemStatsIOTotal, "I/O total")+`</span><strong id="sysIOTotal">--</strong></div>
				</div>
			</div>
		</div>

		<div class="card" id="endpoint-card">
			<div class="card-header">`+phrases().IPEndpointStatusTitle+`</div>
			<div class="card-content">
				<div id="endpoint-status" class="endpoint-status">
					<span class="endpoint-waiting">`+phrases().IPEndpointStatusWaiting+`</span>
				</div>
			</div>
		</div>
		<div class="card">
			<div class="card-header">⚙️ `+phrases().ConfigHeading+`</div>
			<div class="card-content">
				<div class="config-overview-grid">
					<div><strong>`+phrases().MaxLogLines+`:</strong> %d</div>
					<div><strong>`+phrases().MaxAPIRetries+`:</strong> %d</div>
					<div><strong>`+phrases().MaxConcurrent+`:</strong> %d</div>
					<div><strong>`+phrases().Interval+`:</strong> %ds</div>
				</div>
			</div>
		</div>
	</div><!-- end dashboard section -->
	`,
		statusClass,
		statusText,
		phrases().LastUpdate,
		time.Now().Format("15:04:05"),
		buildNotifierStatusHTML(),
		config.MaxLogLines,
		config.MaxAPIRetries,
		config.MaxConcurrent,
		config.Interval,
	)
}

func buildUsersSection() string {
	return `<div id="users-list" class="users-list-wrap">
		 <div class="users-list-loading">` + esc(phrases().UserLoading) + `</div>
	</div>
	<div class="add-domain-box">
		<div class="users-add-title">` + esc(phrases().UserNewTitle) + `</div>
		<input type="text" id="new-user-name" class="s-input mb-8" placeholder="` + esc(phrases().UserPlaceholderName) + `">
		<div class="input-with-action mb-8">
			<input type="password" id="new-user-pass" class="s-input" placeholder="` + esc(phrases().UserPlaceholderPass) + `">
			<button type="button" class="input-action-btn" data-click="togglePassword('new-user-pass', this)">👁️</button>
		</div>
		<select id="new-user-role" class="s-input mb-8">
			<option value="viewer">` + esc(phrases().UserRoleViewer) + `</option>
			<option value="editor">` + esc(phrases().UserRoleEditor) + `</option>
			<option value="admin">` + esc(phrases().UserRoleAdmin) + `</option>
		</select>
		<button class="s-btn s-btn-success-full" data-click="addUser()">` + esc(phrases().UserBtnCreate) + `</button>
	</div>`
}

func writeDashboardMetricsCard(
	w io.Writer,
	stats map[string]any,
	nicHTML, chartSVG, latencySVG string,
	isViewer bool,
) {
	resetBtn := `<button class="action-btn metrics-reset-btn" data-click="event.preventDefault();resetMetrics()">🗑️ ` + esc(phrases().MetricsResetBtn) + `</button>`
	if isViewer {
		resetBtn = ""
	}
	_, _ = fmt.Fprintf(
		w, `
	<div class="page-section" data-section="metrics">
		<div class="card" id="metrics-card">
			<div class="card-header card-header--space-between">
				📊 %s`+resetBtn+`
			</div>
			<div class="card-content">
				<!-- TOP STATS -->
				<div class="metrics-top-grid">
					<div>
						<strong>`+phrases().TotalRequests+`:</strong>
						<span id="mTotal">%v</span>
					</div>
					<div>
						<strong>`+phrases().SuccessRate+`:</strong>
						<span id="mSuccess" class="metric-success">%v</span>
					</div>
					<div>
						<strong>`+phrases().AvgLatency+`:</strong>
						<span id="mLatency">%v</span>
					</div>
					<div title="`+phrases().ClientErrors+` / `+phrases().ServerErrors+`">
						<strong>`+phrases().Errors+`:</strong>
						<span id="mErrors">%v / %v</span>
					</div>
				</div>

				<!-- LATENCY PERCENTILES -->
				<div class="latency-box">
					<div class="latency-box-label">
						`+phrases().MetricLatencyPercentile+`
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
						<span class="usage-limit-label">`+phrases().HourlyLimitEst+`</span>
						<span id="mUsage" class="usage-count">
							%v / %v `+phrases().RequestsLabel+`
						</span>
					</div>
					<div class="usage-track">
						<div id="mUsageBar" class="usage-bar" style="--usage-width:%v%%;--usage-color:%s;"></div>
					</div>
					<div class="usage-hint">
						`+phrases().UsageLast60Min+`
					</div>
				</div>

				<!-- BOTTOM GRID -->
				<div class="metrics-bottom-grid">
					<!-- HTTP METHODS -->
					<div class="http-methods-box">
						<div class="http-methods-label">
							`+phrases().MetricHTTPMethods+`
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
							`+phrases().MetricIPLatency+`
						</div>
						<div class="ip-latency-center">
							<div id="mIPLatency" class="ip-latency-value">
								%v
							</div>
							<div class="ip-latency-meta">
								`+phrases().MetricAvgFrom+`
								<span id="mIPCount">%v</span>
								`+phrases().ChecksLabel+`
							</div>
							<div class="ip-latency-meta">
								`+phrases().MetricLastCheck+`
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
		phrases().APIPerformance,

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

func writeDebugCard(w io.Writer) {
	_, _ = fmt.Fprint(w, `
	<div class="page-section" data-section="debug">
		<div class="card">
			<div class="card-header card-header--flex">
				🐞 `+phrases().DebugLogTitle+` <span class="debug-badge">`+phrases().DebugLogLive+`</span>
			</div>
			<div class="card-content">
				<div class="debug-toolbar">
					<input type="text" id="debug-filter" placeholder="`+phrases().DebugFilterPlaceholder+`"
						data-input="filterDebugLog(this.value)" class="debug-filter-input">
					<button data-click="clearDebugLog()" class="action-btn debug-clear-btn">`+phrases().DebugClearBtn+`</button>
					<label class="debug-autoscroll-label">
						<input type="checkbox" id="debug-autoscroll" checked> `+phrases().DebugAutoscroll+`
					</label>
				</div>
				<div id="debug-log-container" class="debug-log-box">
					<span class="debug-placeholder">`+phrases().DebugWaitingMsg+`</span>
				</div>
			</div>
		</div>
	</div>
	`)
}

func logEntryID(e LogEntry) string {
	h := sha256.Sum256([]byte(e.Timestamp + "|" + e.Action + "|" + e.Message))

	return hex.EncodeToString(h[:8])
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
					(%d `+phrases().EntriesLabel+`)
					%s
				</span>
			</div>
			<div class="card-content">
       			<div class="log-filters">
					<select id="logFilterSelect" class="log-filter-select" data-change="filterLogs(this.value)">
						<option value="all">`+phrases().FilterAll+`</option>
						<option value="ERR">`+phrases().FilterErrors+`</option>
						<option value="WARN">`+phrases().FilterWarnings+`</option>
						<option value="LOGIN">`+phrases().FilterLogin+`</option>
						<option value="LOGOUT">`+phrases().FilterLogout+`</option>
						<option value="LOGINFAILED">`+phrases().FilterLoginFailed+`</option>
						<option value="UPDATE">`+phrases().FilterUpdates+`</option>
						<option value="START">`+phrases().FilterStarts+`</option>
						<option value="STOP">`+phrases().FilterStop+`</option>
						<option value="CREATE">`+phrases().FilterCreated+`</option>
						<option value="CLEANUP">`+phrases().FilterCleanup+`</option>
						<option value="SKIP">`+phrases().FilterSkip+`</option>
						<option value="CONFIG">`+phrases().FilterConfig+`</option>
						<option value="INFO">`+phrases().FilterInfo+`</option>
					</select>
					<button class="filter-btn filter-btn--export" data-click="exportLogs('txt')">📄 TXT</button>
					<button class="filter-btn" data-click="exportLogs('json')">📋 JSON</button>
				</div>
				<div id="logContainer" class="log-container">
	`, esc(phrases().SystemEvents), entryCount, timeRangeHTML)

	for _, e := range logs {
		displayTime := e.Timestamp
		if t, err := time.Parse(time.RFC3339, e.Timestamp); err == nil {
			displayTime = t.Local().Format(statusTimestampLayoutwS)
		}
		actionUpper := strings.ToUpper(e.Action)
		icon := IconDefault
		if v, ok := actionIcons[actionUpper]; ok {
			icon = v
		}
		domainHTML := ""
		if e.Domain != "" {
			domainHTML = `<span class="log-entry-domain">` + esc(e.Domain) + `</span>`
		}
		copyText := displayTime
		if e.Domain != "" {
			copyText += " [" + e.Domain + "]"
		}
		copyText += " " + e.Message

		_, _ = fmt.Fprintf(
			w, `
				<div class="log-entry log-entry-row" data-action="%s" data-level="%s" data-copy="%s" data-log-id="%s">
					<span class="log-entry-icon">%s</span>
					<span class="log-entry-time">%s</span>
					<div class="log-entry-body">%s<span class="log-entry-message">%s</span></div>
					<button class="copy-btn log-copy-btn" data-click="copyLogEntry(this)" title="`+esc(phrases().CopyTitle)+`">📋</button>
					<button class="copy-btn log-delete-btn" data-click="deleteLogEntry(this)" title="`+esc(phrases().DeleteEntryTitle)+`">🗑️</button>
				</div>`,
			actionUpper, e.Level, esc(copyText), logEntryID(e),
			icon, displayTime, domainHTML, esc(e.Message),
		)
	}

	if len(logs) == 0 {
		_, _ = fmt.Fprintf(w, `<div class="log-empty">%s</div>`, esc(phrases().NoMoreEntries))
	}

	_, _ = fmt.Fprint(w, `
				</div>
			</div>
		</div>
	</div>
	`)
}

type dashboardDomainRow struct {
	Name    string
	History DomainHistory
}

func writeDomainsCard(w io.Writer, data map[string]any) {
	keys := domainKeysFromStatusData(data)
	configuredDomains, ipModes := configuredDomainMeta()
	rows := make([]dashboardDomainRow, 0, len(keys))

	var newestChange time.Time
	for _, domain := range keys {
		history, err := parseDomainHistory(data[domain])
		if err != nil {
			continue
		}

		rows = append(rows, dashboardDomainRow{
			Name:    domain,
			History: history,
		})

		if history.LastChanged == "" {
			continue
		}
		if changedAt, err := time.ParseInLocation(
			statusTimestampLayout,
			history.LastChanged,
			time.Local,
		); err == nil && changedAt.After(newestChange) {
			newestChange = changedAt
		}
	}

	_, _ = fmt.Fprint(w, `
	<div class="page-section" data-section="domains">
		<input type="text" class="search-box" id="domainSearch" inputmode="search" autocomplete="off"
			placeholder="`+phrases().DomainSearchPlaceholder+`" data-input="filterDomains(this.value)">
	`)

	_, _ = fmt.Fprint(w, `<div id="domainContainer">`)

	for _, row := range rows {
		writeSingleDomainCard(
			w,
			row.Name,
			row.History,
			configuredDomains,
			ipModes,
			newestChange,
		)
	}

	_, _ = fmt.Fprint(w, `
		</div> <!-- domainContainer -->
	</div> <!-- domains page-section -->
	`)
}

func writeSettingsSecuritySubpage(w io.Writer) {
	securitySection := buildSettingsSecuritySection()

	_, _ = fmt.Fprint(w, `
	<div class="page-section" data-section="settings-security">
		<div class="card card--no-cv">
			<div class="card-header">`+phrases().SettingsSecurity+`</div>
			<div class="card-content">
				`+securitySection+`
			</div>
		</div>
	</div>
	`)
}

func writeSettingsSystemSubpage(w io.Writer, c Config) {
	systemSection := buildSettingsSystemSection(c)

	_, _ = fmt.Fprint(w, `
	<div class="page-section" data-section="settings-system">
		<div class="card card--no-cv">
			<div class="card-header">`+phrases().SettingsSystem+`</div>
			<div class="card-content">
				`+systemSection+`
			</div>
		</div>
	</div>
	`)
}

func writeSettingsDomainsSubpage(w io.Writer) {
	domainsSection := buildSettingsDomainsSection()

	cfgMu.RLock()
	hasIPv64 := false
	for _, dc := range cfg.DomainConfigs {
		if dc.Provider == ProviderIPv64 {
			hasIPv64 = true
			break
		}
	}
	cfgMu.RUnlock()

	p := phrases()

	_, _ = fmt.Fprint(w, `
		<div class="page-section" data-section="settings-domains">
	`)

	if hasIPv64 {
		_, _ = fmt.Fprint(w, `
			<div class="card ipv64-mgmt-card">
				<div class="card-content">
					<div class="ipv64-mgmt-row">
						<div class="ipv64-mgmt-input-wrap">
							<label class="ipv64-mgmt-label" for="ipv64-domain-input">`+p.IPv64DomainFQDN+`</label>
							<input
								type="text"
								id="ipv64-domain-input"
								class="search-box ipv64-mgmt-input"
								autocomplete="off"
								placeholder="`+p.IPv64DomainPlaceholder+`">
						</div>

						<div class="ipv64-mgmt-input-wrap">
							<label class="ipv64-mgmt-label" for="ipv64-api-token-input">`+p.IPv64DomainAPITokenOptional+`</label>
							<div class="input-with-action">
								<input
									type="password"
									id="ipv64-api-token-input"
									class="search-box ipv64-mgmt-input"
									autocomplete="new-password"
									placeholder="`+p.IPv64DomainPlaceholderToken+`">

								<button
									type="button"
									class="input-action-btn"
									data-click="togglePassword('ipv64-api-token-input', this)">
									👁️
								</button>
							</div>
						</div>

						<button
							type="button"
							class="action-btn btn--add-domain"
							data-click="ipv64AddDomain()">
							➕ `+p.IPv64ActionAdd+`
						</button>

						<button
							type="button"
							class="action-btn btn--del-domain"
							data-click="ipv64DeleteDomain()">
							🗑️ `+p.IPv64ActionDelete+`
						</button>
					</div>

					<div id="ipv64-domain-result" class="ipv64-result"></div>
				</div>
			</div>
		`)
	}

	_, _ = fmt.Fprint(w, `
			<div class="card card--no-cv">
				<div class="card-header">`+p.SettingsDomains+`</div>
				<div class="card-content">
					`+domainsSection+`
				</div>
			</div>
		</div>
	`)
}

func writeSettingsNotifySubpage(w io.Writer, c Config) {
	notifySection := buildSettingsNotifySection(c)

	_, _ = fmt.Fprint(w, `
	<div class="page-section" data-section="settings-notify">
		<div class="card card--no-cv">
			<div class="card-header">`+phrases().SettingsNotify+`</div>
			<div class="card-content">
				`+notifySection+`
			</div>
		</div>
	</div>
	`)
}

func writeTOTPSection(w io.Writer, sess *Session, enabled bool) {
	if !enabled {
		_, _ = fmt.Fprint(w, `<div class="page-section" data-section="totp"></div>`)

		return
	}

	_, _ = fmt.Fprint(w, `
	<div class="page-section" data-section="totp">
		<div class="card totp-settings-card">
			<div class="card-header">`+phrases().NavTotpJS+`</div>
			<div class="card-content totp-settings-wrap" id="totp-settings-content">
				`+build2FASettingsFragmentForSession(sess, "", "")+`
			</div>
		</div>
	</div>
	`)
}

func writeUsersSection(w io.Writer, isAdmin bool) {
	if !isAdmin {
		_, _ = fmt.Fprint(w, `<div class="page-section" data-section="users"></div>`)

		return
	}
	_, _ = fmt.Fprint(w, `
	<div class="page-section" data-section="users">
		<div class="card">
			<div class="card-header">`+phrases().SettingsUserManagement+`</div>
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

func configuredDomainMeta() (map[string]struct{}, map[string]string) {
	configs := snapshotDomainConfigs()
	configured := make(map[string]struct{}, len(configs))
	ipModes := make(map[string]string, len(configs))

	for _, dc := range configs {
		key := strings.ToLower(strings.TrimSuffix(dc.FQDN, "."))
		configured[key] = struct{}{}
		if dc.IPMode != "" {
			ipModes[key] = dc.IPMode
		}
	}

	return configured, ipModes
}

func newestDomainChange(data map[string]any, keys []string) time.Time {
	var newestChange time.Time

	for _, k := range keys {
		dh, err := parseDomainHistory(data[k])
		if err != nil {
			continue
		}

		if dh.LastChanged == "" {
			continue
		}

		if t, err := time.ParseInLocation(
			statusTimestampLayout,
			dh.LastChanged,
			time.Local,
		); err == nil && t.After(newestChange) {
			newestChange = t
		}
	}

	return newestChange
}

func parseDomainHistory(v any) (DomainHistory, error) {
	var h DomainHistory

	b, err := json.Marshal(v)
	if err != nil {
		return h, fmt.Errorf("marshal domain history: %w", err)
	}

	if err := json.Unmarshal(b, &h); err != nil {
		return h, fmt.Errorf("unmarshal domain history: %w", err)
	}

	return h, nil
}

func writeSingleDomainCard(
	w io.Writer,
	domain string,
	h DomainHistory,
	configuredDomains map[string]struct{},
	ipModes map[string]string,
	newestChange time.Time,
) {
	latest := IPEntry{}
	if len(h.IPs) > 0 {
		latest = h.IPs[len(h.IPs)-1]
	}

	historyCount := 0
	if len(h.IPs) > 1 {
		historyCount = len(h.IPs) - 1
	}

	lastChangedUnixMS := int64(0)
	if changedAt, err := time.ParseInLocation(statusTimestampLayout, h.LastChanged, time.Local); err == nil {
		lastChangedUnixMS = changedAt.UnixMilli()
	}

	safeID := sanitizeIDWithHash(domain)
	domainKey := strings.ToLower(strings.TrimSuffix(domain, "."))
	_, isActive := configuredDomains[domainKey]
	isOrphan := !isActive

	dotClass, dotTitle, changedBadge := buildDomainStatusVisuals(h, safeID, newestChange)
	orphanStyle, orphanLabel, deleteBtn := buildOrphanDomainVisuals(isOrphan, domain)

	ipModeLabel := ""
	if mode := ipModes[domainKey]; mode != "" {
		ipModeLabel = " · " + mode
	}

	_, _ = fmt.Fprintf(
		w, `
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
							<button class="copy-btn" data-click="copyIP('%s')" title="`+esc(phrases().CopyTitle)+`">📋</button>
						</div>
						<div class="ip-display domain-ip-row-spaced">
							<span class="badge v6">IPv6</span>
							<span id="ip6-%s">%s</span>
							<button class="copy-btn" data-click="copyIP('%s')" title="`+esc(phrases().CopyTitle)+`">📋</button>
						</div>
					</div>
					<div class="domain-card-meta" data-last-changed="%s" data-last-changed-unix="%d" data-uptime-id="%s">
						<small>`+phrases().LastShort+` <span id="last-change-%s">%s</span></small>
						<small class="domain-uptime-small">⏱️ <span id="uptime-%s">—</span></small>
					</div>
				</div>
			</div>
			<div class="domain-history-box">
				<div class="domain-history-summary">`+esc(phrases().DomainHistorySummary)+`</div>
				<table class="domain-history-table">
					<thead class="domain-history-head">
						<tr>
							<th class="domain-history-th-time">`+esc(phrases().TableTime)+`</th>
							<th class="domain-history-th-ip">`+esc(phrases().TableIPs)+`</th>
						</tr>
					</thead>
					<tbody>`,
		orphanStyle,
		esc(domain),
		ipEntriesJSONAttr(h.IPs),
		safeID,
		dotClass,
		esc(dotTitle),
		esc(domain),
		esc(h.Provider+ipModeLabel),
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
		esc(h.LastChanged),
		lastChangedUnixMS,
		safeID,
		safeID,
		esc(latest.Time),
		safeID,
		historyCount,
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
	dotTitle := esc(phrases().DotTitleNoUpdate)
	changedBadge := `<span id="badge-` + safeID + `" class="changed-badge changed-badge--hidden">` + esc(phrases().BadgeChanged) + `</span>`

	if h.LastChanged == "" {
		return dotClass, dotTitle, changedBadge
	}

	t, err := time.ParseInLocation(statusTimestampLayout, h.LastChanged, time.Local)
	if err != nil {
		return dotClass, dotTitle, changedBadge
	}

	switch {
	case time.Since(t) < 15*time.Minute:
		dotClass = "domain-status-dot dot-ok dot-recent"
		dotTitle = esc(phrases().DotTitleChanged + h.LastChanged)
		changedBadge = `<span id="badge-` + safeID + `" class="changed-badge" data-changed-at="` + esc(h.LastChanged) + `" data-changed-unix="` + strconv.FormatInt(t.UnixMilli(), 10) + `">` + esc(phrases().BadgeChanged) + `</span>`
	case !newestChange.IsZero() && t.Before(newestChange.Add(-time.Minute)):
		dotClass = "domain-status-dot dot-warn"
		dotTitle = esc(phrases().DotTitleLast) + h.LastChanged + esc(phrases().DotTitleOther)
	default:
		dotClass = "domain-status-dot dot-ok"
		dotTitle = esc(phrases().DotTitleActive + h.LastChanged)
	}

	return dotClass, dotTitle, changedBadge
}

func buildOrphanDomainVisuals(isOrphan bool, domain string) (string, string, string) {
	if !isOrphan {
		return "", "", ""
	}
	orphanStyle := " domain-item--orphan"
	orphanLabel := `<span class="orphan-badge">` + esc(phrases().NotConfiguredLabel) + `</span>`

	deleteBtn := `<button class="action-btn btn-danger-soft" ` +
		`data-click="event.preventDefault();event.stopPropagation();` +
		`deleteDomain('` + jsString(domain) + `',this)">` +
		esc(phrases().RemoveBtn) + `</button>`

	return orphanStyle, orphanLabel, deleteBtn
}

func writeDomainHistoryRows(w io.Writer, h DomainHistory) {
	const visibleHistoryItems = 10

	start := len(h.IPs) - 2
	end := max(start-visibleHistoryItems+1, 0)

	for i := start; i >= end; i-- {
		e := h.IPs[i]

		v4 := "—"
		if e.IPv4 != "" {
			v4 = esc(e.IPv4)
		}

		v6 := "—"
		if e.IPv6 != "" {
			v6 = esc(e.IPv6)
		}

		_, _ = fmt.Fprintf(
			w, `
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
			esc(e.Time),
			v4,
			v6,
		)
	}
	if end > 0 {
		_, _ = fmt.Fprint(
			w,
			`<tr class="domain-history-more">
				<td colspan="2">
					`+fmt.Sprintf(phrases().HiddenEntriesFormat, end)+`
				</td>
			</tr>`,
		)
	}

	if len(h.IPs) < 2 {
		_, _ = fmt.Fprint(w, `<tr class="empty-history-row"><td colspan="2">`+phrases().NoMoreEntries+`</td></tr>`)
	}
}

func writeDashboardFooter(w http.ResponseWriter) {
	_, _ = fmt.Fprint(w, appFooterHTML())

	_, _ = fmt.Fprint(w, `
			</div><!-- end main-content -->
		</div><!-- end app-right -->
	</div><!-- end app-layout -->
	`)

	_, _ = fmt.Fprint(w, `
	<script src="/assets/i18n.js" defer></script>
	<script src="`+assetURL("/assets/dashboard.js", dashboardJSETag)+`" defer></script>
	</body>
	</html>
	`)
}

func appFooterHTML() string {
	return `
<footer class="dashboard-footer dashboard-footer--positioned">
	<div>
		<span>` + esc(fmt.Sprintf(phrases().FooterMadeWithByFormat, time.Now().Year())) + `</span>
		<span class="dashboard-footer-sep">|</span>
		<a href="https://github.com/CrazyUs3r/IONOS-DDNS"
		   target="_blank"
		   rel="noopener noreferrer"
		   class="dashboard-footer-link">CrazyUs3r</a>
	</div>
</footer>`
}

// ============================================================================
// DIAGNOSE / HEALTH CENTER
// ============================================================================

const (
	dashboardBackupApp     = "dyndns-dashboard"
	dashboardBackupVersion = 1
)

type dashboardBackup struct {
	Config    *Config                  `json:"config,omitempty"`
	Status    map[string]DomainHistory `json:"status,omitempty"`
	Metrics   map[string]any           `json:"metrics,omitempty"`
	App       string                   `json:"app"`
	CreatedAt string                   `json:"created_at"`
	Users     []DashboardUser          `json:"users,omitempty"`
	Logs      []LogEntry               `json:"logs,omitempty"`
	Version   int                      `json:"version"`
}

func writeBackupSection(w io.Writer, isAdmin bool) {
	if !isAdmin {
		_, _ = fmt.Fprint(w, `
		<div class="page-section" data-section="backup">
			<div class="card">
				<div class="card-header">💾 `+t(phrases().BackupTitle, "Backup & Restore")+`</div>
				<div class="card-content">
					<div class="backup-warning">
						🔒 `+t(phrases().BackupAdminOnly, "Backup & Restore is only available for admins.")+`
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
			<div class="card-header">💾 `+t(phrases().BackupTitle, "Backup & Restore")+`</div>
			<div class="card-content">
				<div class="backup-grid">
					<div class="backup-box">
						<h3>`+t(phrases().BackupCreateTitle, "Create backup")+`</h3>
						<p>`+t(phrases().BackupCreateDesc, "Exports config, status, users, logs and current metrics as JSON.")+`</p>
						<button class="action-btn" data-click="downloadFullBackup()">`+t(phrases().BackupDownloadBtn, "⬇️ Download backup")+`</button>
						<div class="backup-hint">
							`+t(phrases().BackupSecretsHint, "Warning: The backup contains secrets and password hashes. Store it safely.")+`
						</div>
					</div>

					<div class="backup-box">
						<h3>`+t(phrases().BackupRestoreTitle, "Restore backup")+`</h3>
						<p>`+t(phrases().BackupRestoreDesc, "Select a previously created backup and choose which areas should be restored.")+`</p>

						<input type="file" id="backup-file" class="search-box" accept="application/json,.json">

						<label class="inline-check">
							<input type="checkbox" id="restore-config" checked>
							`+t(phrases().BackupRestoreConfig, "Restore config")+`
						</label>

						<label class="inline-check">
							<input type="checkbox" id="restore-status" checked>
							`+t(phrases().BackupRestoreStatus, "Restore domain status / history")+`
						</label>

						<label class="inline-check">
							<input type="checkbox" id="restore-users">
							`+t(phrases().BackupRestoreUsers, "Restore users")+`
						</label>

						<button class="action-btn btn-danger-soft backup-restore-btn" data-click="restoreFullBackup()">
							`+t(phrases().BackupRestoreStartBtn, "♻️ Start restore")+`
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
			"error": t(phrases().BackupAdminRequired, "admin required"),
		})

		return false
	}

	return true
}

func cloneConfigForBackup() Config {
	return snapshotConfig()
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
		http.Error(w, esc(phrases().APIErrorMethodNotAllowed), http.StatusMethodNotAllowed)

		return
	}
	if !requireAdminAPI(w, r) {
		return
	}

	cfgCopy := cloneConfigForBackup()
	logs, _ := loadDashboardLogsFresh()

	backup := dashboardBackup{
		Version:   dashboardBackupVersion,
		App:       dashboardBackupApp,
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
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("Pragma", "no-cache")

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(backup); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}
}

func handleAPIBackupRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != MethodPOST {
		http.Error(w, esc(phrases().APIErrorMethodNotAllowed), http.StatusMethodNotAllowed)

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
		return backupRestoreRequest{}, http.StatusBadRequest, fmt.Errorf("%s", t(phrases().BackupNothingSelected, "nothing selected"))
	}

	file, _, err := r.FormFile("backup")
	if err != nil {
		return backupRestoreRequest{}, http.StatusBadRequest, fmt.Errorf("%s", t(phrases().BackupFileMissing, "backup file missing"))
	}
	defer func() {
		if err := file.Close(); err != nil {
			debugLog("DASHBOARD", "", fmt.Sprintf(phrases().ErrBodyClose+": %v", err))
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

	decoder := json.NewDecoder(io.LimitReader(file, 16<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&backup); err != nil {
		return dashboardBackup{}, fmt.Errorf(
			t(phrases().BackupInvalidJSONFormat, "invalid backup json: %w"),
			err,
		)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple JSON values")
		}

		return dashboardBackup{}, fmt.Errorf(
			t(phrases().BackupInvalidJSONFormat, "invalid backup json: %w"),
			err,
		)
	}

	if err := validateBackupEnvelope(backup); err != nil {
		return dashboardBackup{}, err
	}

	return backup, nil
}

func validateBackupEnvelope(backup dashboardBackup) error {
	if backup.App != dashboardBackupApp {
		return fmt.Errorf("backup belongs to unsupported app %q", backup.App)
	}
	if backup.Version != dashboardBackupVersion {
		return fmt.Errorf("unsupported backup version %d", backup.Version)
	}
	if strings.TrimSpace(backup.CreatedAt) == "" {
		return errors.New("backup creation time is missing")
	}
	if _, err := time.Parse(time.RFC3339, backup.CreatedAt); err != nil {
		return fmt.Errorf("invalid backup creation time: %w", err)
	}

	return nil
}

func validBackupPasswordHash(stored string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < 10_000 || iterations > 10_000_000 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil || len(salt) < 16 {
		return false
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[3])

	return err == nil && len(key) >= 16
}

func validBackupTOTPSecret(secret string) bool {
	secret = strings.ToUpper(strings.TrimSpace(secret))
	if secret == "" {
		return false
	}
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)

	return err == nil && len(decoded) >= 10
}

func validateBackupUsers(users []DashboardUser) error {
	if len(users) == 0 {
		return errors.New("backup contains no users")
	}
	if len(users) > 10_000 {
		return errors.New("backup contains too many users")
	}

	ids := make(map[string]struct{}, len(users))
	usernames := make(map[string]struct{}, len(users))
	admins := 0
	for index, user := range users {
		id := strings.TrimSpace(user.ID)
		username := strings.TrimSpace(user.Username)
		if id == "" {
			return fmt.Errorf("user %d has no id", index+1)
		}
		if _, exists := ids[id]; exists {
			return fmt.Errorf("duplicate user id %q", id)
		}
		ids[id] = struct{}{}

		if !validDashboardUsername(username) {
			return fmt.Errorf("invalid username %q", username)
		}
		usernameKey := strings.ToLower(username)
		if _, exists := usernames[usernameKey]; exists {
			return fmt.Errorf("duplicate username %q", username)
		}
		usernames[usernameKey] = struct{}{}

		if !isValidRole(user.Role) {
			return fmt.Errorf("invalid role for user %q", username)
		}
		if user.Role == RoleAdmin {
			admins++
		}
		if !validBackupPasswordHash(user.PasswordHash) {
			return fmt.Errorf("invalid password hash for user %q", username)
		}
		if user.TOTPEnabled && !validBackupTOTPSecret(user.TOTPSecret) {
			return fmt.Errorf("invalid TOTP secret for user %q", username)
		}
	}
	if admins == 0 {
		return errors.New("backup must contain at least one administrator")
	}

	return nil
}

func validateBackupStatus(status map[string]DomainHistory) error {
	if status == nil {
		return errors.New("backup contains no status")
	}
	if len(status) > 100_000 {
		return errors.New("backup status contains too many domains")
	}
	for domain := range status {
		if _, err := normalizeDNSName(domain); err != nil {
			return fmt.Errorf("invalid status domain %q", domain)
		}
	}

	return nil
}

func validateBackupRestoreRequest(req backupRestoreRequest) error {
	if err := validateBackupEnvelope(req.Backup); err != nil {
		return err
	}
	if req.Selection.Config {
		if req.Backup.Config == nil {
			return errors.New("backup contains no config")
		}
		if err := validateDomainConfigList(req.Backup.Config.DomainConfigs); err != nil {
			return fmt.Errorf("invalid backup config: %w", err)
		}
	}
	if req.Selection.Status {
		if err := validateBackupStatus(req.Backup.Status); err != nil {
			return err
		}
	}
	if req.Selection.Users {
		if err := validateBackupUsers(req.Backup.Users); err != nil {
			return err
		}
	}

	return nil
}

type backupRestoreSnapshot struct {
	Backup dashboardBackup
}

func captureBackupRestoreSnapshot(selection backupRestoreSelection) backupRestoreSnapshot {
	snapshot := dashboardBackup{
		Version:   dashboardBackupVersion,
		App:       dashboardBackupApp,
		CreatedAt: time.Now().Format(time.RFC3339),
	}
	if selection.Config {
		config := cloneConfigForBackup()
		snapshot.Config = &config
	}
	if selection.Status {
		snapshot.Status = readStatusBackup()
	}
	if selection.Users {
		snapshot.Users = loadUsers()
	}

	return backupRestoreSnapshot{Backup: snapshot}
}

func rollbackBackupRestore(snapshot backupRestoreSnapshot, restored []string) error {
	var rollbackErrors []string
	for _, r := range slices.Backward(restored) {
		var err error
		switch r {
		case "users":
			err = saveUsers(snapshot.Backup.Users)
			sessionStore.DeleteAll()
		case status:
			_, err = restoreBackupStatus(snapshot.Backup)
		case "config":
			_, err = restoreBackupConfig(snapshot.Backup)
		}
		if err != nil {
			rollbackErrors = append(rollbackErrors, r+": "+err.Error())
		}
	}
	if len(rollbackErrors) > 0 {
		return errors.New(strings.Join(rollbackErrors, "; "))
	}

	return nil
}

func restoreSelectedBackup(req backupRestoreRequest) ([]string, int, error) {
	backupRestoreMu.Lock()
	defer backupRestoreMu.Unlock()

	if err := validateBackupRestoreRequest(req); err != nil {
		return nil, http.StatusUnprocessableEntity, err
	}

	snapshot := captureBackupRestoreSnapshot(req.Selection)
	restored := make([]string, 0, 3)

	apply := func(name string, fn func() (int, error)) (int, error) {
		status, err := fn()
		if err == nil {
			restored = append(restored, name)

			return status, nil
		}
		if rollbackErr := rollbackBackupRestore(snapshot, restored); rollbackErr != nil {
			return http.StatusInternalServerError, fmt.Errorf("%w; rollback failed: %w", err, rollbackErr)
		}

		return status, err
	}

	if req.Selection.Config {
		if status, err := apply("config", func() (int, error) { return restoreBackupConfig(req.Backup) }); err != nil {
			return nil, status, err
		}
	}
	if req.Selection.Status {
		if status, err := apply("status", func() (int, error) { return restoreBackupStatus(req.Backup) }); err != nil {
			return nil, status, err
		}
	}
	if req.Selection.Users {
		if status, err := apply("users", func() (int, error) { return restoreBackupUsers(req.Backup) }); err != nil {
			return nil, status, err
		}
	}

	return restored, http.StatusOK, nil
}

func restoreBackupConfig(backup dashboardBackup) (int, error) {
	configUpdateMu.Lock()
	defer configUpdateMu.Unlock()

	if backup.Config == nil {
		return http.StatusBadRequest, fmt.Errorf("%s", t(phrases().BackupContainsNoConfig, "backup contains no config"))
	}

	oldCfg, err := applyBackupConfig(*backup.Config)
	if err != nil {
		return http.StatusUnprocessableEntity, err
	}

	if err := saveConfigToFile(); err != nil {
		restoreConfigInMemory(oldCfg)
		ResetHTTPClient()
		invalidateSecretReplacer()

		return http.StatusInternalServerError, fmt.Errorf(
			t(phrases().BackupConfigSaveFailedFormat, "config save failed: %w"),
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

	if err := validateDomainConfigList(
		cfg.DomainConfigs,
	); err != nil {
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
	config := snapshotConfig()
	setAtomicDebugFlags(config.DebugEnabled, config.DebugHTTPRaw)
	if config.MaxConcurrent > 0 {
		setWorkerConcurrencyLimit(config.MaxConcurrent)
	}

	ResetHTTPClient()
	invalidateSecretReplacer()

	go initNotifiers()

	forceNextUpdate.Store(true)
	lastCleanupNano.Store(0)
}

func restoreBackupStatus(backup dashboardBackup) (int, error) {
	if backup.Status == nil {
		return http.StatusBadRequest, fmt.Errorf(
			"%s",
			t(
				phrases().BackupContainsNoStatus,
				"backup contains no status",
			),
		)
	}

	statusMutex.Lock()

	err := writeStatusDomainsLocked(backup.Status)
	if err == nil {
		statusDomains = backup.Status
		statusPersistDirty = false
	}

	statusMutex.Unlock()

	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf(
			t(
				phrases().BackupStatusRestoreFailedFormat,
				"status restore failed: %w",
			),
			err,
		)
	}

	if err := updateDomainsCache(); err != nil {
		debugLog(
			"CACHE",
			"",
			fmt.Sprintf(
				t(
					phrases().ErrUpdateDomainsCache,
					"updateDomainsCache failed: %v",
				),
				err,
			),
		)
	}

	return http.StatusOK, nil
}

func restoreBackupUsers(backup dashboardBackup) (int, error) {
	if err := validateBackupUsers(backup.Users); err != nil {
		return http.StatusBadRequest, err
	}

	if err := saveUsers(backup.Users); err != nil {
		return http.StatusInternalServerError, fmt.Errorf(
			t(phrases().BackupUsersRestoreFailedFormat, "users restore failed: %w"),
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
			t(phrases().BackupRestoredLogFormat, "Backup restored: %s"),
			strings.Join(restored, ", "),
		),
	})
}

// ============================================================================
// DIAGNOSE / HEALTH CENTER
// ============================================================================

func writeDiagnoseSection(w io.Writer) {
	_, _ = fmt.Fprint(w, `
	<div class="page-section" data-section="diagnose">
		<div class="card">
			<div class="card-header card-header--space-between">
				<span>🩺 `+t(phrases().DiagnoseTitle, "Diagnose / Health Center")+`</span>
				<button class="action-btn topbar-action-btn" data-click="refreshDiagnosis()">`+t(phrases().DiagnoseRefreshBtn, "🔄 Refresh")+`</button>
			</div>
			<div class="card-content">
				<div id="diagnose-content" class="diag-loading">
					`+t(phrases().DiagnoseLoading, "Loading diagnosis...")+`
				</div>
			</div>
		</div>
	</div>
	`)
}

func handleAPIDiagnose(w http.ResponseWriter, r *http.Request) {
	if r.Method != MethodGET {
		http.Error(w, esc(phrases().APIErrorMethodNotAllowed), http.StatusMethodNotAllowed)

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
	Notifiers      map[string]bool
	Info           map[string]any
	Warnings       []string
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
		warnings = append(warnings, t(phrases().DiagnoseNoDomainsConfigured, "No domains configured."))
	}

	return warnings
}

func diagnoseSingleDomainWarnings(dc DomainConfig) []string {
	warnings := make([]string, 0)

	if strings.TrimSpace(dc.FQDN) == "" {
		warnings = append(warnings, t(phrases().DiagnoseDomainWithoutFQDN, "A domain without FQDN is configured."))
	}

	if dc.TTL > 0 && dc.TTL < 60 {
		warnings = append(warnings, fmt.Sprintf(
			t(phrases().DiagnoseTTLTooLowFormat, "%s: TTL is very low."),
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
		return t(phrases().DiagnoseUnknownDomain, "Unknown domain")
	}

	return fqdn
}

func providerCredentialWarning(dc DomainConfig) string {
	fqdn := diagnosisDomainName(dc)

	switch dc.Provider {
	case ProviderIONOS:
		if dc.APIPrefix == "" || dc.APISecret == "" {
			return fmt.Sprintf(
				t(phrases().DiagnoseIonosCredentialsIncompleteFormat, "%s: IONOS credentials incomplete."),
				fqdn,
			)
		}

	case ProviderCloudflare:
		if dc.CFToken == "" && (dc.CFEmail == "" || dc.CFSecret == "") {
			return fmt.Sprintf(
				t(phrases().DiagnoseCloudflareCredentialsIncompleteFormat, "%s: Cloudflare credentials incomplete."),
				fqdn,
			)
		}

	case ProviderIPv64:
		if dc.IPv64Token == "" {
			return fmt.Sprintf(
				t(phrases().DiagnoseIpv64TokenMissingFormat, "%s: IPv64 token missing."),
				fqdn,
			)
		}

	case ProviderFebas:
		if err := validateFebasUpdateURL(dc.FebasUpdateURL); err != nil {
			return fmt.Sprintf("%s: %v", fqdn, err)
		}

	case ProviderDNScale:
		if strings.TrimSpace(dc.APIKey) == "" {
			return fmt.Sprintf(
				t(phrases().DiagnoseDNScaleAPIKeyMissingFormat, "%s: DNScale API Key missing."),
				fqdn,
			)
		}

	case ProviderHetzner, ProviderHetznerCloud:
		if hetznerToken(&dc) == "" {
			return fmt.Sprintf(
				t(phrases().DiagnoseHetznerTokenMissingFormat, "%s: Hetzner token missing."),
				fqdn,
			)
		}
	}

	return ""
}

func diagnoseGlobalConfigWarnings(cfg Config) []string {
	warnings := make([]string, 0)

	if cfg.DryRun {
		warnings = append(warnings, t(phrases().DiagnoseDryRunActive, "Dry-run is active: DNS changes are not written."))
	}

	if cfg.DebugEnabled {
		warnings = append(warnings, t(phrases().DiagnoseDebugActive, "Debug mode is active."))
	}

	if cfg.DebugHTTPRaw {
		warnings = append(warnings, t(phrases().DiagnoseHTTPRawDebugActive, "HTTP raw debug is active. Sensitive data may appear in logs."))
	}

	if cfg.Interval > 0 && cfg.Interval < 60 {
		warnings = append(warnings, t(phrases().DiagnoseIntervalLow, "Update interval is very low."))
	}

	return warnings
}

func diagnoseNotifiers(cfg Config) map[string]bool {
	return map[string]bool{
		"telegram": cfg.Notifications.Telegram.Token != "" && cfg.Notifications.Telegram.ChatID != "",
		"gotify":   cfg.Notifications.Gotify.URL != "" && cfg.Notifications.Gotify.Token != "",
		"ntfy":     cfg.Notifications.Ntfy.URL != "" && cfg.Notifications.Ntfy.Topic != "",
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
		return starting, t(phrases().DiagnoseReasonSchedulerNotRun, "Scheduler has not run yet.")
	}

	if !lastOk.Load() {
		return unhealthy, t(phrases().DiagnoseReasonLastSchedulerFailed, "The last scheduler run failed.")
	}

	if len(warnings) > 0 || logWarnings > 0 {
		return "degraded", t(phrases().DiagnoseReasonWarningsButRunning, "There are warnings, but the service is running.")
	}

	return healthy, t(phrases().DiagnoseReasonAllGood, "Everything looks good.")
}

func formatDiagnosisTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}

	return t.Format(statusTimestampLayout)
}

func diagnosisFileInfos() []map[string]any {
	return []map[string]any{
		diagnoseFileInfo("config.json", configPath),
		diagnoseFileInfo("status/update.json", updatePath),
		diagnoseFileInfo("logs", logPath),
		diagnoseFileInfo("users.json", usersFilePath),
		diagnoseFileInfo("audit.json", auditLogFilePath()),
	}
}

func diagnoseFileInfo(name, path string) map[string]any {
	out := map[string]any{
		"name":   name,
		"exists": false,
	}

	if strings.TrimSpace(path) == "" {
		out["error"] = t(phrases().DiagnosePathEmpty, "path empty")

		return out
	}

	st, err := os.Stat(path)
	if err != nil {
		out["error"] = err.Error()

		return out
	}

	out["exists"] = true
	out["size"] = st.Size()
	out["modified"] = st.ModTime().Format(statusTimestampLayout)

	return out
}

// ============================================================================
// DNS PROPAGATION
// ============================================================================

type dnsResolverTarget struct {
	Name    string
	Address string
	System  bool
}

type dnsPropagationResult struct {
	Resolver   string   `json:"resolver"`
	Address    string   `json:"address,omitempty"`
	CNAME      string   `json:"cname,omitempty"`
	Error      string   `json:"error,omitempty"`
	IPv4       []string `json:"ipv4"`
	IPv6       []string `json:"ipv6"`
	DurationMS int64    `json:"duration_ms"`
	MatchIPv4  bool     `json:"match_ipv4"`
	MatchIPv6  bool     `json:"match_ipv6"`
}

func normalizeDNSName(raw string) (string, error) {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if len(name) == 0 || len(name) > 253 {
		return "", errors.New(t(phrases().DNSInvalidDomainName, "invalid domain name"))
	}
	for label := range strings.SplitSeq(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New(t(phrases().DNSInvalidDomainName, "invalid domain name"))
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' {
				return "", errors.New(t(phrases().DNSInvalidDomainName, "invalid domain name"))
			}
		}
	}

	return name, nil
}

func firstSystemNameserver() (string, error) {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return "", err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "nameserver") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		return normalizeDNSServer(fields[1])
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}

	return "", errors.New(t(phrases().DNSNoNameserverFound, "no nameserver found in /etc/resolv.conf"))
}

func dnsResolverTargets() []dnsResolverTarget {
	var targets []dnsResolverTarget
	seen := map[string]struct{}{}

	if addr, err := firstSystemNameserver(); err == nil {
		key := strings.ToLower(addr)
		seen[key] = struct{}{}
		targets = append(targets, dnsResolverTarget{
			Name:    fmt.Sprintf(t(phrases().DNSSystemResolverFormat, "System resolver (%s)"), addr),
			Address: addr,
		})
	} else {
		seen["system"] = struct{}{}
		targets = append(targets, dnsResolverTarget{Name: t(phrases().DNSSystemResolver, "System resolver"), System: true})
	}

	add := func(name, raw string) {
		address, err := normalizeDNSServer(raw)
		if err != nil {
			return
		}
		key := strings.ToLower(address)
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		targets = append(targets, dnsResolverTarget{Name: name, Address: address})
	}

	for _, server := range snapshotConfig().DNSServers {
		add("Configured: "+server, server)
		if len(targets) >= 5 {
			break
		}
	}
	add("Cloudflare", "1.1.1.1:53")
	add("Google", "8.8.8.8:53")
	if len(targets) > 7 {
		targets = targets[:7]
	}

	return targets
}

func stringSliceContains(values []string, wanted string) bool {
	if wanted == "" {
		return false
	}

	return slices.Contains(values, wanted)
}

func queryDNSResolver(ctx context.Context, target dnsResolverTarget, domain, expectedV4, expectedV6 string) dnsPropagationResult {
	started := time.Now()
	result := dnsPropagationResult{
		Resolver: target.Name,
		Address:  target.Address,
		IPv4:     []string{},
		IPv6:     []string{},
	}

	var resolver *net.Resolver

	if target.Address != "" {
		resolver = newResolverForDNSServer(target.Address)
	} else {
		resolver = net.DefaultResolver
	}

	ips, err := resolver.LookupIPAddr(ctx, domain)
	if err != nil {
		result.Error = err.Error()
	} else {
		for _, item := range ips {
			if item.IP == nil {
				continue
			}
			if item.IP.To4() != nil {
				result.IPv4 = append(result.IPv4, item.IP.String())
			} else {
				result.IPv6 = append(result.IPv6, item.IP.String())
			}
		}
		sort.Strings(result.IPv4)
		sort.Strings(result.IPv6)
	}

	if cname, cnameErr := resolver.LookupCNAME(ctx, domain); cnameErr == nil {
		result.CNAME = strings.TrimSuffix(cname, ".")
	}

	result.MatchIPv4 = stringSliceContains(result.IPv4, expectedV4)
	result.MatchIPv6 = stringSliceContains(result.IPv6, expectedV6)
	result.DurationMS = time.Since(started).Milliseconds()

	return result
}

func canRunDNSPropagation(r *http.Request) bool {
	if !authEnabled {
		return true
	}
	sess, ok := sessionFromRequest(r)

	return ok && (sess.Role == RoleAdmin || sess.Role == RoleEditor)
}

func handleAPIDNSPropagation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, esc(phrases().APIErrorMethodNotAllowed), http.StatusMethodNotAllowed)

		return
	}
	if !canRunDNSPropagation(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": esc(phrases().DNSAdminEditorRequired)})

		return
	}

	var req struct {
		Domain string `json:"domain"`
	}
	if err := decodeJSONBody(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": esc(phrases().APIErrorBadRequest)})

		return
	}
	domain, err := normalizeDNSName(req.Domain)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})

		return
	}

	expectedV4, expectedV6 := loadLastKnownIPs()
	targets := dnsResolverTargets()
	results := make([]dnsPropagationResult, len(targets))
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	for i, target := range targets {
		wg.Add(1)
		go func(index int, target dnsResolverTarget) {
			defer wg.Done()
			results[index] = queryDNSResolver(ctx, target, domain, expectedV4, expectedV6)
		}(i, target)
	}
	wg.Wait()

	writeJSON(w, http.StatusOK, map[string]any{
		"domain":        domain,
		"expected_ipv4": expectedV4,
		"expected_ipv6": expectedV6,
		"checked_at":    time.Now().UTC().Format(time.RFC3339),
		"results":       results,
	})
}

func writeAuditDNSSection(w io.Writer, isAdmin bool) {
	if !isAdmin {
		_, _ = fmt.Fprint(w, `<div class="page-section" data-section="audit"><div class="card"><div class="card-header">`+phrases().NavAuditJS+`</div><div class="card-content"><div class="backup-warning">🔒 `+phrases().AuditAdminOnly+`</div></div></div></div>`)

		return
	}

	var options strings.Builder
	for _, domain := range snapshotConfig().DomainConfigs {
		fqdn := strings.TrimSpace(domain.FQDN)
		if fqdn != "" {
			fmt.Fprintf(&options, `<option value="%s"></option>`, esc(fqdn))
		}
	}

	_, _ = fmt.Fprintf(w, `<div class="page-section" data-section="audit">
		<div class="audit-dns-grid">
			<div class="card audit-log-card audit-log-card-fixed">
				<div class="card-header card-header--space-between">
				<span>`+phrases().AuditLogTitle+` <span class="logs-summary-meta" id="audit-summary-meta"></span></span>
				<span class="audit-header-actions">
					<select id="audit-gen-select" class="log-filter-select" data-change="onAuditGenChange(this.value)" hidden></select>
					<button class="action-btn topbar-action-btn" data-click="refreshAuditLog()">`+phrases().AuditRefreshBtn+`</button>
				</span>
				</div>
				<div class="card-content"><div id="audit-log-content" class="audit-log-container audit-loading">`+phrases().AuditLoadingJS+`</div></div>
			</div>
			<div class="card card--no-cv dns-propagation-card">
				<div class="card-header">`+phrases().DNSPropagationTitle+`</div>
				<div class="card-content">
					<p class="audit-help">`+phrases().DNSPropagationHelp+`</p>
					<div class="dns-check-controls"><input id="dns-propagation-domain" class="search-box" list="dns-domain-list" placeholder="host.example.com"><datalist id="dns-domain-list">%s</datalist><button class="action-btn" data-click="runDNSPropagation()">`+phrases().DNSCheckBtn+`</button></div>
					<div id="dns-propagation-result" class="dns-propagation-result"></div>
				</div>
			</div>
		</div>
	</div>`, options.String())
}
