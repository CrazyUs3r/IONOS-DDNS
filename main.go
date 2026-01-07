package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	ActionStart   = "START"
	ActionStop    = "STOP"
	ActionUpdate  = "UPDATE"
	ActionCreate  = "CREATE"
	ActionCurrent = "CURRENT"
	ActionRetry   = "RETRY"
	ActionError   = "ERROR"
	ActionConfig  = "CONFIG"
	ActionZone    = "ZONE"
	ActionDryRun  = "DRY-RUN"
)

const DefaultMaxLogLines = 500

var actionClass = map[string]string{
	ActionStart:  "act-start",
	ActionStop:   "act-stop",
	ActionUpdate: "act-update",
	ActionCreate: "act-create",
	ActionRetry:  "act-retry",
	ActionError:  "act-error",
	ActionZone:   "act-error",
	ActionConfig: "act-error",
	ActionDryRun: "act-dryrun",
}

// ---------------- STRUKTUREN ----------------

type Phrases struct {
	Startup, Shutdown, NoZones, Update, Created, Current,
	DryRunWarn, ConfigError, DashTitle, StatusOk, StatusErr, LastUpdate,
	InfraHeading, ZoneLabel string
}

type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Action    string `json:"action"`
	Domain    string `json:"domain"`
	Message   string `json:"message"`
}

var languagePack = map[string]Phrases{
	"DE": {
		Startup: "Service gestartet", Shutdown: "Service beendet", NoZones: "keine Zone gefunden",
		Update: "Update", Created: "Neuanlage", Current: "ist aktuell",
		DryRunWarn: "⚠️ DRY-RUN MODUS AKTIV", ConfigError: "❌ API Credentials fehlen!",
		DashTitle: "DynDNS Dashboard", StatusOk: "System Online", StatusErr: "API Fehler", LastUpdate: "Letzter Check",
		InfraHeading: "Infrastruktur Übersicht", ZoneLabel: "Zone",
	},
	"EN": {
		Startup: "Service started", Shutdown: "Service stopped", NoZones: "no zone found",
		Update: "Update", Created: "Created", Current: "is up to date",
		DryRunWarn: "⚠️ DRY-RUN MODE ACTIVE", ConfigError: "❌ API Credentials missing!",
		DashTitle: "DynDNS Dashboard", StatusOk: "System Online", StatusErr: "API Error", LastUpdate: "Last Check",
		InfraHeading: "Infrastructure Overview", ZoneLabel: "Zone",
	},
}
var persistentActions = map[string]bool{
	"START":   true,
	"STOP":    true,
	"UPDATE":  true,
	"CREATE":  true,
	"ERROR":   true,
	"RETRY":   true,
	"CONFIG":  true,
	"ZONE":    true,
}

type IPEntry struct {
	Time string `json:"time"`
	IPv4 string `json:"ipv4,omitempty"`
	IPv6 string `json:"ipv6,omitempty"`
}

type DomainHistory struct {
	IPs      []IPEntry `json:"ips"`
	Provider string    `json:"provider"`
}

type Config struct {
	APIPrefix, APISecret, IPMode, IfaceName, HealthPort, LogDir, Lang string
	Domains                                                           []string
	Interval                                                          int
	DryRun                                                            bool
}

type Zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Record struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
}

var (
	cfg          Config
	T            Phrases
	logPath      string
	updatePath   string
	apiBaseURL   = "https://api.hosting.ionos.com/dns/v1/zones"
	lastOk       atomic.Bool
	logMutex     sync.Mutex
	statusMutex  sync.Mutex
	httpClient   = &http.Client{Timeout: 30 * time.Second}
	lastErrorMsg atomic.Value
)

// ---------------- LOGGING & ROTATION ----------------

func writeLog(level, action, domain, msg string) {
	logMutex.Lock()
	defer logMutex.Unlock()

	now := time.Now().Local()
	ts := now.Format("02.01.2006 15:04:05")

	if domain != "" {
		fmt.Printf("[%s] [%-4s] %-35s: %s\n", ts, level, domain, msg)
	} else {
		fmt.Printf("[%s] [%-4s] %s\n", ts, level, msg)
	}

	if !shouldPersist(level, action) {
		return
	}

	entry := LogEntry{
		Timestamp: now.Format("2006-01-02T15:04:05"),
		Level:     level,
		Action:    action,
		Domain:    domain,
		Message:   msg,
	}

	if js, err := json.Marshal(entry); err == nil {
		if f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
			defer f.Close()
			_, _ = f.Write(append(js, '\n'))
		}
	}
}

func rotateLogFile(path string, maxLines int) {
	logMutex.Lock()
	defer logMutex.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) <= maxLines {
		return
	}

	newLines := lines[len(lines)-maxLines:]
	output := strings.Join(newLines, "\n") + "\n"
	_ = os.WriteFile(path, []byte(output), 0644)
}

func shouldPersist(level, action string) bool {
	if level == "ERR" || level == "WARN" {
		return persistentActions[action]
	}

	switch action {
	case ActionStart, ActionStop, ActionUpdate, ActionCreate:
		return true
	}
	return false
}
func actionCSS(a string) string {
	if c, ok := actionClass[a]; ok {
		return c
	}
	return "act-default"
}
func printGroupedDomains() {
	fmt.Printf("\n🚀 Go-DynDNS [%s] (Mode: %s):\n", cfg.Lang, cfg.IPMode)
	groups := make(map[string][]string)
	for _, d := range cfg.Domains {
		parts := strings.Split(d, ".")
		if len(parts) >= 2 {
			main := strings.Join(parts[len(parts)-2:], ".")
			if d != main {
				prefix := strings.TrimSuffix(d, "."+main)
				groups[main] = append(groups[main], prefix)
			} else if _, ok := groups[main]; !ok {
				groups[main] = []string{}
			}
		}
	}
	var mainDomains []string
	for m := range groups {
		mainDomains = append(mainDomains, m)
	}
	sort.Strings(mainDomains)
	for _, main := range mainDomains {
		fmt.Printf("\n📦 %s\n", strings.ToUpper(main))
		subs := groups[main]
		sort.Strings(subs)
		if len(subs) == 0 {
			fmt.Printf("   ┗━━ (Root Domain)\n")
		} else {
			for i, sub := range subs {
				char := "┣"
				if i == len(subs)-1 {
					char = "┗"
				}
				fmt.Printf("   %s━━ %s\n", char, sub)
			}
		}
	}
	fmt.Println("\n" + strings.Repeat("-", 40))
}

func printInfrastructure(zones []Zone) {
	fmt.Println("\n" + T.InfraHeading)
	for _, z := range zones {
		data, _ := ionosAPI("GET", apiBaseURL+"/"+z.ID, nil)
		var detail struct{ Records []Record }
		_ = json.Unmarshal(data, &detail)

		fmt.Printf("\n🌍 %s: %s\n", T.ZoneLabel, z.Name)
		var relevant []Record
		for _, r := range detail.Records {
			if r.Type == "A" || r.Type == "AAAA" || r.Type == "CNAME" {
				relevant = append(relevant, r)
			}
		}
		sort.Slice(relevant, func(i, j int) bool { return relevant[i].Name < relevant[j].Name })
		for _, r := range relevant {
			fmt.Printf("   ┣━ %-35s [%-5s] -> %s\n", r.Name, r.Type, r.Content)
		}
	}
	fmt.Println("\n" + strings.Repeat("-", 40))
}

// ---------------- API & NETZWERK ----------------

func ionosAPI(method, url string, body interface{}) ([]byte, error) {
	var lastErr error

	for attempt := 0; attempt < 3; attempt++ {
		var bodyReader io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			bodyReader = bytes.NewBuffer(b)
		}

		req, _ := http.NewRequest(method, url, bodyReader)
		req.Header.Set("X-API-Key", cfg.APIPrefix+"."+cfg.APISecret)
		req.Header.Set("Content-Type", "application/json")

		res, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(time.Duration(attempt+1) * time.Second)
			continue
		}

		var respBody []byte
		func() {
			defer res.Body.Close()
			respBody, _ = io.ReadAll(res.Body)
		}()

		if res.StatusCode >= 300 {
			lastErr = fmt.Errorf("Status %d: %s", res.StatusCode, string(respBody))
			lastErrorMsg.Store(lastErr.Error())
			writeLog("ERR", ActionError, "", fmt.Sprintf("IONOS API Fehler: %v", lastErr))

			if res.StatusCode == 429 || res.StatusCode >= 500 {
				wait := time.Duration(math.Pow(2, float64(attempt+1))) * time.Second
				wait += time.Duration(rand.Intn(1000)) * time.Millisecond
				writeLog(
					"WARN",
					ActionRetry,
					"",
					fmt.Sprintf("API Limit/Fehler, Retry %d in %v", attempt+1, wait),
				)
				time.Sleep(wait)
				continue
			}

			// Permanenter Fehler (401, 403, 404, ...)
			return nil, lastErr
		}

		lastErrorMsg.Store("")
		return respBody, nil
	}

	return nil, fmt.Errorf("API fehlgeschlagen nach 3 Versuchen: %v", lastErr)
}

func getPublicIP(url string) string {
	resp, err := httpClient.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	body, _ := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(body))
}

func getIPv6() string {
	if cfg.IfaceName != "" {
		iface, err := net.InterfaceByName(cfg.IfaceName)
		if err == nil {
			addrs, _ := iface.Addrs()
			for _, a := range addrs {
				ipnet, ok := a.(*net.IPNet)
				if ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() == nil &&
					ipnet.IP.IsGlobalUnicast() && !ipnet.IP.IsLinkLocalUnicast() {
					return ipnet.IP.String()
				}
			}
		}
	}
	return getPublicIP("https://6.ident.me/")
}

// ---------------- LOGIK ----------------

func updateDNS(fqdn, recordType, newIP string, records []Record, zoneID string) bool {
	var existing *Record
	for i := range records {
		if records[i].Name == fqdn && records[i].Type == recordType {
			existing = &records[i]
			break
		}
	}
	if existing != nil && existing.Content == newIP {
		writeLog("INFO", ActionCurrent, fqdn, fmt.Sprintf("%-4s %s %s", recordType, newIP, T.Current))
		return false
	}
	if cfg.DryRun {
		writeLog("WARN", ActionDryRun, fqdn, fmt.Sprintf("Würde %s auf %s setzen", recordType, newIP))
		return true
	}
	method, url := "POST", apiBaseURL+"/"+zoneID+"/records"
	if existing != nil {
		method, url = "PUT", apiBaseURL+"/"+zoneID+"/records/"+existing.ID
	}

	payload := map[string]interface{}{"name": fqdn, "type": recordType, "content": newIP, "ttl": 60}
	_, err := ionosAPI(method, url, payload)
	if err == nil {
		writeLog("INFO", ActionUpdate, fqdn, fmt.Sprintf("%s -> %s", recordType, newIP))
		return true
	}
	return false
}

func runUpdate(firstRun bool) {
	data, err := ionosAPI("GET", apiBaseURL, nil)
	if err != nil {
		lastOk.Store(false)
		return
	}

	var zones []Zone
	if err := json.Unmarshal(data, &zones); err != nil {
		writeLog("ERR", ActionError, "", "Zone JSON ungültig")
		lastOk.Store(false)
		return
	}

	if firstRun {
		printGroupedDomains()
		printInfrastructure(zones)
	}

	allOk := true
	for _, fqdn := range cfg.Domains {
		var zone Zone
		for _, z := range zones {
			if strings.HasSuffix(fqdn, z.Name) {
				zone = z
				break
			}
		}
		if zone.ID == "" {
			writeLog("ERR", ActionZone, fqdn, T.NoZones)
			allOk = false
			continue
		}

		detailData, err := ionosAPI("GET", apiBaseURL+"/"+zone.ID, nil)
		if err != nil {
			allOk = false
			continue
		}
		var detail struct{ Records []Record }
		_ = json.Unmarshal(detailData, &detail)

		v4, v6 := "", ""
		v4Chg, v6Chg := false, false

		if cfg.IPMode != "IPV6" {
			v4 = getPublicIP("https://4.ident.me/")
			if v4 != "" {
				v4Chg = updateDNS(fqdn, "A", v4, detail.Records, zone.ID)
			}
		}
		if cfg.IPMode != "IPV4" {
			v6 = getIPv6()
			if v6 != "" {
				v6Chg = updateDNS(fqdn, "AAAA", v6, detail.Records, zone.ID)
			}
		}

		if (v4Chg || v6Chg) && !cfg.DryRun {
			updateStatusFile(fqdn, v4, v6, "IONOS")
		}
	}
	lastOk.Store(allOk)
}

func updateStatusFile(fqdn, ipv4, ipv6, provider string) {
	statusMutex.Lock()
	defer statusMutex.Unlock()

	domains := make(map[string]DomainHistory)
	if b, err := os.ReadFile(updatePath); err == nil {
		_ = json.Unmarshal(b, &domains)
	}

	h := domains[fqdn]
	h.Provider = provider
	newEntry := IPEntry{Time: time.Now().Local().Format("02.01.2006 15:04:05"), IPv4: ipv4, IPv6: ipv6}
	h.IPs = append(h.IPs, newEntry)
	if len(h.IPs) > 20 {
		h.IPs = h.IPs[len(h.IPs)-20:]
	}
	domains[fqdn] = h

	if js, err := json.MarshalIndent(domains, "", "  "); err == nil {
		tmp := updatePath + ".tmp"
		if errW := os.WriteFile(tmp, js, 0644); errW == nil {
			_ = os.Rename(tmp, updatePath)
		}
	}
}

// ---------------- DASHBOARD ----------------

func createMux() *http.ServeMux {
	mux := http.NewServeMux()

	// Health-Endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		if !lastOk.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Dashboard-Endpoint
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
            <meta http-equiv="refresh" content="60"> <title>`+html.EscapeString(T.DashTitle)+`</title>
			<style>
			/* ---------- Global ---------- */
			* {
				box-sizing: border-box;
			}
			
			:root {
				--bg: #0f172a;
				--card: #1e293b;
				--text: #f8fafc;
				--border: #334155;
			}
			
			body {
				font-family: system-ui, sans-serif;
				background: var(--bg);
				color: var(--text);
				padding: 10px;
				margin: 0;
				overflow-x: hidden;
			}
			
			.container {
				max-width: 800px;
				margin: 0 auto;
				overflow-x: hidden;
			}
			
			/* ---------- Status Banner ---------- */
			.status-banner {
				display: flex;
				flex-wrap: wrap;
				justify-content: center;
				gap: 8px;
				padding: 10px;
				border-radius: 12px;
				margin-bottom: 20px;
				font-weight: 600;
				font-size: 0.8rem;
				text-transform: uppercase;
				border: 1px solid rgba(255,255,255,0.1);
				position: relative;
				text-align: center;
				max-width: 100%;
				overflow: hidden;
			}
			
			.refresh-bar {
				position: absolute;
				bottom: 0;
				left: 0;
				height: 3px;
				background: rgba(255,255,255,0.3);
				width: 100%;
				animation: countdown 60s linear;
			}
			
			@keyframes countdown {
				from { width: 100%; }
				to   { width: 0%; }
			}
			
			.status-ok {
				background: rgba(34,197,94,0.15);
				color: #4ade80;
			}
			
			.status-error {
				background: rgba(239,68,68,0.15);
				color: #f87171;
			}
			
			/* ---------- Cards ---------- */
			.card {
				background: var(--card);
				padding: 15px;
				margin-bottom: 12px;
				border-radius: 12px;
				border: 1px solid var(--border);
				overflow-x: auto;
			}
			
			/* ---------- Tables ---------- */
			table {
				width: 100%;
				border-collapse: collapse;
				font-size: 0.85rem;
				table-layout: fixed;
			}
			
			td {
				padding: 10px 4px;
				border-bottom: 1px solid var(--border);
				vertical-align: top;
				max-width: 100%;
				overflow-wrap: anywhere;
			}
			
			/* ---------- Badges ---------- */
			.badge {
				padding: 3px 7px;
				border-radius: 4px;
				font-size: 0.7rem;
				color: #fff;
				font-weight: bold;
				min-width: 32px;
				text-align: center;
				display: inline-block;
				margin-right: 6px;
			}
			
			.v4 { background: #0ea5e9; }
			.v6 { background: #8b5cf6; }
			
			/* ---------- Text Handling ---------- */
			.ip-text,
			.log-entry,
			code {
				word-break: break-word;
				overflow-wrap: anywhere;
			}
			
			.ip-text {
				font-family: monospace;
				color: #cbd5e1;
			}
			
			.timestamp {
				color: #94a3b8;
				font-size: 0.75rem;
				white-space: nowrap;
			}
			
			/* ---------- Logs ---------- */
			.log-entry {
				font-size: 0.75rem;
				margin-bottom: 6px;
			}
			.log-entry.update { background: rgba(0, 255, 0, 0.05); color: #8f8; }
			.log-entry.error  { background: rgba(255, 0, 0, 0.1);  color: #f88; }
			.log-entry.info   { background: rgba(255, 255, 255, 0.05); }
			.log-container::-webkit-scrollbar {width: 6px;}
			.log-container::-webkit-scrollbar-thumb {background-color: rgba(255, 255, 255, 0.2); 
				border-radius: 10px;
			}
			.log-container::-webkit-scrollbar-track {background: transparent;
			}
			/* ---------- Code / API Errors ---------- */
			code {
				display: block;
				white-space: pre-wrap;
				max-width: 100%;
				font-size: 0.75rem;
			}
			
			/* ---------- Actions ---------- */
			.act-start  { color: #38bdf8; }
			.act-stop   { color: #94a3b8; }
			.act-update { color: #4ade80; }
			.act-create { color: #22d3ee; }
			.act-retry  { color: #facc15; }
			.act-error  { color: #f87171; }
			.act-dryrun { color: #c084fc; }
			.act-default{ color: #cbd5e1; }
			
			/* ---------- Mobile ---------- */
			@media (max-width: 480px) {
				td {
					display: block;
					width: 100%;
					padding: 5px 0;
				}
			
				.timestamp {
					display: block;
					margin-bottom: 4px;
				}
			}

			details.domain-card > summary {
				cursor: pointer;
				font-weight: 600;
				list-style: none;
			}

			details.domain-card > summary::-webkit-details-marker {
				display: none;
			}

			details.domain-card[open] > summary {
				margin-bottom: 8px;
			}

			.domain-card {
				max-height: 300px;
				overflow-y: auto;
			}
			</style>
		</head>
		<body>
		<div class="container">
		<h1>🌐 `+html.EscapeString(T.DashTitle)+`</h1>
        <div class="status-banner `+statusClass+`">
            `+statusText+` &bull; `+T.LastUpdate+`: `+time.Now().Format("15:04:05")+`
            <div class="refresh-bar"></div> </div>`)

		// API-Fehlerkarte
		if errStr, ok := lastErrorMsg.Load().(string); ok && errStr != "" {
			fmt.Fprintf(w, `<div class="card" style="border-color:#f87171;background:rgba(239,68,68,0.05)">
					<strong style="color:#f87171">⚠️ API Log:</strong><br><code style="font-size:0.75rem">%s</code></div>`, html.EscapeString(errStr))
		}

		// Event-Logs
		if len(logs) > 0 {
			fmt.Fprint(w, `
			<div class="card event-card">
				<div class="card-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
					<strong style="font-size: 1.1em;">🧾 System Events</strong>
					<span style="font-size: 0.85em; opacity: 0.5;">Verlauf</span>
				</div>
				<div class="log-container" style="max-height: 250px; overflow-y: auto; font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 13px; line-height: 1.4;">
			`)
			
			for _, e := range logs {
				displayTime := e.Timestamp
				if len(displayTime) >= 16 {
					// Umwandlung von 2026-01-01 14:30:00 zu 01.01.2026 14:30
					datePart := displayTime[8:10] + "." + displayTime[5:7] + "." + displayTime[0:4]
					timePart := displayTime[11:16]
					displayTime = datePart + " " + timePart
				}

				icon := "🔹" // Standard Icon (Info/Update)
				if e.Action == "error" || e.Action == "fail" {
					icon = "⚠️"
				} else if e.Action == "success" || e.Action == "added" {
					icon = "✅"
				}

				fmt.Fprintf(w, `
					<div class="log-entry %s" style="display: flex; flex-wrap: wrap; align-items: flex-start; padding: 8px 10px; border-radius: 6px; margin-bottom: 4px; gap: 4px 10px;">
						<div style="display: flex; align-items: center; flex-shrink: 0;">
							<span style="width: 25px; display: flex; justify-content: center; margin-right: 4px;">%s</span>
							<span style="color: #888; font-family: monospace; font-size: 0.9em; white-space: nowrap;">%s</span>
						</div>
						
						<div style="display: flex; flex-wrap: wrap; gap: 8px; flex: 1; min-width: 200px;">
							%s
							<span style="opacity: 0.95; word-break: break-word; font-size: 0.95em;">%s</span>
						</div>
					</div>`, 
					actionCSS(e.Action), 
					icon,
					displayTime,
					func() string { 
						if e.Domain == "" { return "" } 
						return `<span style="font-weight: 600; color: #64b5f6; white-space: nowrap;">` + html.EscapeString(e.Domain) + `</span>`
					}(),
					html.EscapeString(e.Message),
				)
			}
			fmt.Fprint(w, `</div></div>`)
		}

		// Domain-Status
		var keys []string
		for k := range data {
			if !strings.HasPrefix(k, "_") {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			var h DomainHistory
			b, _ := json.Marshal(data[k])
			_ = json.Unmarshal(b, &h)
			latest := IPEntry{}
			if len(h.IPs) > 0 {
				latest = h.IPs[len(h.IPs)-1]
			}
			fmt.Fprintf(w, `
			<details class="card domain-card">
				<summary>
					<div style="margin-bottom: 8px;">
						<strong>%s</strong> <i style="opacity: 0.8; font-size: 0.9em;">(%s)</i>
					</div>
					
					<div style="display: flex; justify-content: space-between; align-items: flex-start;">
						<div class="timestamp" style="display: flex; align-items: center;">%s</div>
						<div class="ip-text">
							<div><span class="badge v4">v4</span>%s</div>
							<div style="margin-top:4px"><span class="badge v6">v6</span>%s</div>
						</div>
					</div>
				</summary>
			<table>
			`,
				html.EscapeString(k),
				html.EscapeString(h.Provider),
				latest.Time,
				html.EscapeString(latest.IPv4),
				html.EscapeString(latest.IPv6),
			)
			for i := len(h.IPs) - 2; i >= 0; i-- {
				e := h.IPs[i]
				fmt.Fprintf(w, `<tr>
					<td><div class="timestamp">%s</div></td>
					<td class="ip-text">
						<div><span class="badge v4">v4</span>%s</div>
						<div style="margin-top:4px"><span class="badge v6">v6</span>%s</div>
					</td>
				</tr>`,
					html.EscapeString(e.Time),
					html.EscapeString(e.IPv4),
					html.EscapeString(e.IPv6),
				)
			}
			fmt.Fprint(w, `</table></details>`)
		}
		fmt.Fprint(w, `</div></body></html>`)
	})

	return mux
}

// ---------------- MAIN ----------------

func main() {
	rand.Seed(time.Now().UnixNano())
	lang := "DE"
	if strings.HasPrefix(strings.ToUpper(os.Getenv("LANG")), "EN") {
		lang = "EN"
	}
	T = languagePack[lang]

	d := []string{}
	for _, s := range strings.Split(os.Getenv("DOMAINS"), ",") {
		if t := strings.TrimSpace(strings.ToLower(s)); t != "" {
			d = append(d, t)
		}
	}
	iv := 300
	if i, err := strconv.Atoi(os.Getenv("INTERVAL")); err == nil && i >= 30 {
		iv = i
	}
	ld := os.Getenv("LOG_DIR")
	if ld == "" {
		ld = "/logs"
	}

	maxLogLines := DefaultMaxLogLines
	if s := strings.TrimSpace(os.Getenv("LOG_MAX_LINES")); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			maxLogLines = v
		} else {
			writeLog("WARN", ActionConfig, "", fmt.Sprintf("Ungültiger LOG_MAX_LINES Wert '%s', benutze Default %d", s, DefaultMaxLogLines))
		}
	}

	cfg = Config{
		APIPrefix:  os.Getenv("API_PREFIX"),
		APISecret:  os.Getenv("API_SECRET"),
		Domains:    d,
		Interval:   iv,
		IPMode:     strings.ToUpper(os.Getenv("IP_MODE")),
		IfaceName:  os.Getenv("INTERFACE"),
		HealthPort: os.Getenv("HEALTH_PORT"),
		DryRun:     os.Getenv("DRY_RUN") == "true",
		LogDir:     ld,
		Lang:       lang,
	}
	if cfg.HealthPort == "" {
		cfg.HealthPort = "8080"
	}

	_ = os.MkdirAll(cfg.LogDir, 0755)
	logPath = filepath.Join(cfg.LogDir, "dyndns.json")
	updatePath = filepath.Join(cfg.LogDir, "update.json")

	if cfg.APIPrefix == "" || cfg.APISecret == "" {
		writeLog("ERR", ActionConfig, "", T.ConfigError)
	}
	writeLog("INFO", ActionStart, "", "🚀 "+T.Startup)

	srv := &http.Server{Addr: ":" + cfg.HealthPort, Handler: createMux()}
	go func() { _ = srv.ListenAndServe() }()

	runUpdate(true)
	ticker := time.NewTicker(time.Duration(cfg.Interval) * time.Second)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			runUpdate(false)
			rotateLogFile(logPath, maxLogLines)
		case <-stop:
			writeLog("INFO", ActionStop, "", "🛑 "+T.Shutdown)
			ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
			_ = srv.Shutdown(ctx)
			return
		}
	}
}
