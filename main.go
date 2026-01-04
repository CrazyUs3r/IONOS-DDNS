package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ---------------- TRANSLATIONS ----------------

type Phrases struct {
	Startup      string
	Shutdown     string
	NoZones      string
	Update       string
	Created      string
	Current      string
	DryRunWarn   string
	InfraHeading string
	ConfigError  string
	ZoneLabel    string
}

var languagePack = map[string]Phrases{
	"DE": {
		Startup:      "Service gestartet",
		Shutdown:     "Service beendet",
		NoZones:      "keine Zone gefunden",
		Update:       "Update",
		Created:      "Neuanlage",
		Current:      "ist aktuell",
		DryRunWarn:   "⚠️ DRY-RUN MODUS AKTIV: Keine DNS-Änderungen.",
		InfraHeading: "📂 --- IONOS Infrastruktur Analyse ---",
		ConfigError:  "❌ API Credentials fehlen!",
		ZoneLabel:    "Zone",
	},
	"EN": {
		Startup:      "Service started",
		Shutdown:     "Service stopped",
		NoZones:      "no zone found",
		Update:       "Updating",
		Created:      "Creating",
		Current:      "is up to date",
		DryRunWarn:   "⚠️ DRY-RUN MODE ACTIVE: No DNS changes.",
		InfraHeading: "📂 --- IONOS Infrastructure Analysis ---",
		ConfigError:  "❌ API Credentials missing!",
		ZoneLabel:    "Zone",
	},
}

var T Phrases

// ---------------- CONFIG & GLOBAL ----------------

type Config struct {
	APIPrefix  string
	APISecret  string
	Domains    []string
	Interval   int
	IPMode     string
	IfaceName  string
	HealthPort string
	DebugMode  bool
	DryRun     bool
	Lang       string
}

var (
	cfg        Config
	logPath    = "/logs/dyndns.json"
	updatePath = "/logs/update.json"
	apiBaseURL = "https://api.hosting.ionos.com/dns/v1/zones"
	lastOk     = false
	histMutex  sync.Mutex
)

type Zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Record struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
}

type ZoneDetail struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Records []Record `json:"records"`
}

type IPEntry struct {
	Time string `json:"time"`
	IPv4 string `json:"ipv4,omitempty"`
	IPv6 string `json:"ipv6,omitempty"`
}

type DomainHistory struct {
	IPs []IPEntry `json:"ips"`
}

// ---------------- WEB SERVER (HEALTH & DASHBOARD) ----------------

func startHealthServer() {
	mux := http.NewServeMux()

	// 1. Docker Health Check
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if lastOk {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	})

	// 2. Web Dashboard Logik
	statusHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/status" {
			http.NotFound(w, r)
			return
		}

		fileData, err := os.ReadFile(updatePath)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Warte auf Daten..."))
			return
		}

		var tempMap map[string]DomainHistory
		json.Unmarshal(fileData, &tempMap)

		statusClass := "status-ok"
		statusText := "System Online"
		if !lastOk {
			statusClass = "status-error"
			statusText := "API Error"
			_ = statusText // Fix für ungenutzte Variable falls nötig
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// WICHTIG: Alle % im CSS müssen %% sein!
		fmt.Fprintf(w, `
		<!DOCTYPE html>
		<html lang="de">
		<head>
			<title>DynDNS Dashboard</title>
			<meta charset="utf-8">
			<meta name="viewport" content="width=device-width, initial-scale=1">
			<meta http-equiv="refresh" content="60">
			<style>
				body { font-family: -apple-system, system-ui, sans-serif; background: #0f172a; color: #f8fafc; padding: 20px; line-height: 1.5; }
				.container { max-width: 900px; margin: 0 auto; }
				.header-section { margin-bottom: 30px; border-bottom: 2px solid #1e293b; padding-bottom: 20px; }
				h1 { color: #38bdf8; margin: 0 0 15px 0; display: flex; align-items: center; gap: 12px; font-size: 1.8rem; }
				.health-banner { display: inline-flex; align-items: center; gap: 8px; padding: 8px 16px; border-radius: 20px; font-size: 0.85rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
				.status-ok { background: rgba(34, 197, 94, 0.15); color: #4ade80; border: 1px solid rgba(34, 197, 94, 0.3); }
				.status-error { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
				.pulse { width: 8px; height: 8px; border-radius: 50%%; background: currentColor; box-shadow: 0 0 8px currentColor; animation: pulse 2s infinite; }
				@keyframes pulse { 0%% { opacity: 1; } 50%% { opacity: 0.4; } 100%% { opacity: 1; } }
				.card { background: #1e293b; border-radius: 12px; padding: 20px; margin-bottom: 25px; box-shadow: 0 10px 15px -3px rgba(0,0,0,0.3); border: 1px solid #334155; }
				.domain-name { font-size: 1.25rem; font-weight: bold; color: #e2e8f0; margin-bottom: 15px; display: block; }
				table { width: 100%%; border-collapse: collapse; font-size: 0.9rem; }
				th { text-align: left; color: #38bdf8; background: #0f172a; padding: 12px; font-weight: 600; }
				td { padding: 12px; border-bottom: 1px solid #334155; vertical-align: top; }
				tr:last-child td { border-bottom: none; }
				.time { color: #94a3b8; font-family: monospace; white-space: nowrap; }
				.ip-row { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
				.ip { font-family: monospace; font-weight: 500; }
				.badge { font-size: 0.7rem; font-weight: bold; padding: 2px 6px; border-radius: 4px; color: white; min-width: 40px; text-align: center; }
				.badge-v4 { background: #0ea5e9; }
				.badge-v6 { background: #8b5cf6; }
			</style>
		</head>
		<body>
			<div class="container">
				<div class="header-section">
					<h1><span>🌐</span> IONOS DynDNS Status</h1>
					<div class="health-banner %s">
						<div class="pulse"></div>
						%s &bull; Letzter Check: %s
					</div>
				</div>
		`, statusClass, statusText, time.Now().Format("15:04:05"))

		keys := make([]string, 0, len(tempMap))
		for k := range tempMap { keys = append(keys, k) }
		sort.Strings(keys)

		for _, domain := range keys {
			fmt.Fprintf(w, "<div class='card'><span class='domain-name'>📦 %s</span>", domain)
			fmt.Fprintf(w, "<table><thead><tr><th>Zeitpunkt</th><th>IP Adressen</th></tr></thead><tbody>")
			
			ips := tempMap[domain].IPs
			for i := len(ips) - 1; i >= 0; i-- {
				entry := ips[i]
				t, _ := time.Parse(time.RFC3339, entry.Time)
				fmt.Fprintf(w, "<tr><td class='time'>%s</td><td>", t.Format("02.01.2006 15:04:05"))
				if entry.IPv4 != "" {
					fmt.Fprintf(w, "<div class='ip-row'><span class='badge badge-v4'>IPv4</span><span class='ip'>%s</span></div>", entry.IPv4)
				}
				if entry.IPv6 != "" {
					fmt.Fprintf(w, "<div class='ip-row'><span class='badge badge-v6'>IPv6</span><span class='ip'>%s</span></div>", entry.IPv6)
				}
				fmt.Fprintf(w, "</td></tr>")
			}
			fmt.Fprintf(w, "</tbody></table></div>")
		}
		fmt.Fprintf(w, "</div></body></html>")
	}

	mux.HandleFunc("/", statusHandler)
	mux.HandleFunc("/status", statusHandler)

	server := &http.Server{
		Addr: ":" + cfg.HealthPort,
		Handler: mux,
		ReadTimeout: 5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	_ = server.ListenAndServe()
}

// ---------------- INITIALIZATION ----------------

func loadConfig() Config {
	lang := strings.ToUpper(getEnv("LANG", "DE"))
	if _, ok := languagePack[lang]; ok {
		T = languagePack[lang]
	} else {
		T = languagePack["EN"]
	}

	dStr := os.Getenv("DOMAINS")
	rawDomains := strings.Split(dStr, ",")
	var cleaned []string
	for _, d := range rawDomains {
		t := strings.ToLower(strings.TrimSpace(d))
		if t != "" {
			cleaned = append(cleaned, t)
		}
	}
	sort.Strings(cleaned)

	return Config{
		APIPrefix:  os.Getenv("API_PREFIX"),
		APISecret:  os.Getenv("API_SECRET"),
		Domains:    cleaned,
		Interval:   getEnvInt("INTERVAL", 300),
		IPMode:     strings.ToUpper(getEnv("IP_MODE", "BOTH")),
		IfaceName:  getEnv("INTERFACE", "eth0"),
		HealthPort: getEnv("HEALTH_PORT", "8080"),
		DebugMode:  os.Getenv("DEBUG") == "true",
		DryRun:     os.Getenv("DRY_RUN") == "true",
		Lang:       lang,
	}
}

func main() {
	cfg = loadConfig()
	if cfg.APIPrefix == "" || cfg.APISecret == "" {
		log.Fatal(T.ConfigError)
	}

	go startHealthServer()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	printGroupedDomains()
	if cfg.DryRun {
		fmt.Println(T.DryRunWarn)
	}

	writeJsonLog("INFO", "startup", "", T.Startup)

	ticker := time.NewTicker(time.Duration(cfg.Interval) * time.Second)
	defer ticker.Stop()

	runUpdate(true)

	for {
		select {
		case <-stop:
			writeJsonLog("INFO", "shutdown", "", T.Shutdown)
			return
		case <-ticker.C:
			runUpdate(false)
		}
	}
}

// ---------------- CORE LOGIC ----------------

func runUpdate(firstRun bool) {
	zones, err := getZones()
	if err != nil {
		writeJsonLog("ERROR", "api_error", "", err.Error())
		lastOk = false
		return
	}
	lastOk = true

	if firstRun {
		printInfrastructure(zones)
	}

	var wg sync.WaitGroup
	for _, domain := range cfg.Domains {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			_ = processDomain(d, zones)
		}(domain)
	}
	wg.Wait()
}

func processDomain(fqdn string, zones []Zone) error {
	var targetZone Zone
	for _, z := range zones {
		if strings.HasSuffix(fqdn, z.Name) {
			targetZone = z
			break
		}
	}
	if targetZone.ID == "" {
		return fmt.Errorf(T.NoZones)
	}

	detail, err := getZoneDetails(targetZone.ID)
	if err != nil {
		return err
	}

	var curV4, curV6 string
	v4Changed, v6Changed := false, false

	if cfg.IPMode == "IPV4" || cfg.IPMode == "BOTH" {
		curV4 = getPublicIP("https://4.ident.me/")
		if curV4 != "" {
			v4Changed = updateDNS(fqdn, "A", curV4, detail.Records, targetZone.ID)
		}
	}
	if cfg.IPMode == "IPV6" || cfg.IPMode == "BOTH" {
		curV6 = getIPv6()
		if curV6 != "" {
			v6Changed = updateDNS(fqdn, "AAAA", curV6, detail.Records, targetZone.ID)
		}
	}

	if (v4Changed || v6Changed) && !cfg.DryRun {
		updateStatusFile(fqdn, curV4, curV6)
	}
	return nil
}

func updateDNS(fqdn, rType, currentIP string, records []Record, zoneID string) bool {
	var existing *Record
	for _, r := range records {
		if r.Name == fqdn && r.Type == rType {
			existing = &r
			break
		}
	}

	if existing != nil {
		if existing.Content != currentIP {
			msg := fmt.Sprintf("%s %s: %s -> %s", T.Update, rType, existing.Content, currentIP)
			fmt.Printf("🔄 %s: %s\n", fqdn, msg)
			if !cfg.DryRun {
				sendUpdate(zoneID, fqdn, rType, currentIP)
				writeJsonLog("INFO", "update", fqdn, msg)
			}
			return true
		}
		fmt.Printf("🆗 %s: %s %s (%s)\n", fqdn, rType, T.Current, currentIP)
		return false
	}

	msg := fmt.Sprintf("%s %s: %s", T.Created, rType, currentIP)
	fmt.Printf("🆕 %s: %s\n", fqdn, msg)
	if !cfg.DryRun {
		sendCreate(zoneID, fqdn, rType, currentIP)
		writeJsonLog("INFO", "create", fqdn, msg)
	}
	return true
}

func ionosAPI(method, url string, body interface{}) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyBytes, _ := json.Marshal(body)
		bodyReader = bytes.NewBuffer(bodyBytes)
	}
	req, _ := http.NewRequest(method, url, bodyReader)
	req.Header.Set("X-API-Key", fmt.Sprintf("%s.%s", cfg.APIPrefix, cfg.APISecret))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil { return nil, err }
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return data, nil
}

func sendUpdate(zoneID, fqdn, rType, ip string) {
	payload := []map[string]interface{}{{"name": fqdn, "type": rType, "content": ip, "ttl": 60}}
	_, _ = ionosAPI("PATCH", apiBaseURL+"/"+zoneID, payload)
}

func sendCreate(zoneID, fqdn, rType, ip string) {
	payload := []map[string]interface{}{{"name": fqdn, "type": rType, "content": ip, "ttl": 60}}
	_, _ = ionosAPI("POST", apiBaseURL+"/"+zoneID+"/records", payload)
}

func updateStatusFile(fqdn, ipv4, ipv6 string) {
	histMutex.Lock()
	defer histMutex.Unlock()

	fileData, err := os.ReadFile(updatePath)
	tempMap := make(map[string]DomainHistory)
	if err == nil {
		_ = json.Unmarshal(fileData, &tempMap)
	}

	history := tempMap[fqdn]

	if len(history.IPs) > 0 {
		lastEntry := history.IPs[len(history.IPs)-1]
		if lastEntry.IPv4 == ipv4 && lastEntry.IPv6 == ipv6 {
			return 
		}
	}

	history.IPs = append(history.IPs, IPEntry{
		Time: time.Now().Local().Format(time.RFC3339),
		IPv4: ipv4,
		IPv6: ipv6,
	})

	if len(history.IPs) > 30 {
		history.IPs = history.IPs[len(history.IPs)-30:]
	}
	tempMap[fqdn] = history

	newJson, _ := json.MarshalIndent(tempMap, "", "  ")
	_ = os.WriteFile(updatePath, newJson, 0644)
}

func writeJsonLog(level, action, domain, message string) {
	entry := map[string]string{
		"timestamp": time.Now().Local().Format(time.RFC3339),
		"level":     level,
		"action":    action,
		"domain":    domain,
		"message":   message,
	}
	jsonBytes, _ := json.Marshal(entry)
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		defer f.Close()
		_, _ = f.Write(append(jsonBytes, '\n'))
	}
}

func printGroupedDomains() {
	fmt.Printf("🚀 Go-DynDNS [%s] (%s):\n", cfg.Lang, cfg.IPMode)
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
	for m := range groups { mainDomains = append(mainDomains, m) }
	sort.Strings(mainDomains)
	for _, main := range mainDomains {
		fmt.Printf("\n📦 %s\n", strings.ToUpper(main))
		subs := groups[main]
		sort.Strings(subs)
		if len(subs) == 0 {
			fmt.Printf("   ┗━━ (Root Domain)\n")
		} else {
			for i, sub := range subs {
				char := "┣"; if i == len(subs)-1 { char = "┗" }
				fmt.Printf("   %s━━ %s\n", char, sub)
			}
		}
	}
	fmt.Println("\n" + strings.Repeat("-", 40))
}

func printInfrastructure(zones []Zone) {
	fmt.Println("\n" + T.InfraHeading)
	for _, z := range zones {
		detail, _ := getZoneDetails(z.ID)
		fmt.Printf("\n🌍 %s: %s\n", T.ZoneLabel, z.Name)
		var relevant []Record
		for _, r := range detail.Records {
			if r.Type == "A" || r.Type == "AAAA" || r.Type == "CNAME" { relevant = append(relevant, r) }
		}
		sort.Slice(relevant, func(i, j int) bool { return relevant[i].Name < relevant[j].Name })
		for _, r := range relevant {
			fmt.Printf("   ┣━ %-35s [%-5s] -> %s\n", r.Name, r.Type, r.Content)
		}
	}
	fmt.Println("\n" + strings.Repeat("-", 40))
}

func getZones() ([]Zone, error) {
	data, err := ionosAPI("GET", apiBaseURL, nil)
	if err != nil { return nil, err }
	var zones []Zone
	if strings.Contains(string(data), "\"items\"") {
		var wrapper struct { Items []Zone `json:"items"` }
		_ = json.Unmarshal(data, &wrapper)
		zones = wrapper.Items
	} else { _ = json.Unmarshal(data, &zones) }
	return zones, nil
}

func getZoneDetails(id string) (ZoneDetail, error) {
	data, _ := ionosAPI("GET", apiBaseURL+"/"+id, nil)
	var detail ZoneDetail
	_ = json.Unmarshal(data, &detail)
	return detail, nil
}

func getPublicIP(url string) string {
	resp, err := http.Get(url)
	if err != nil { return "" }
	defer resp.Body.Close()
	ip, _ := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(ip))
}

func getIPv6() string {
	iface, err := net.InterfaceByName(cfg.IfaceName)
	if err == nil {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() == nil && ipnet.IP.IsGlobalUnicast() {
				return ipnet.IP.String()
			}
		}
	}
	return getPublicIP("https://6.ident.me/")
}

func getEnvInt(key string, fallback int) int {
	var res int
	if _, err := fmt.Sscanf(os.Getenv(key), "%d", &res); err == nil { return res }
	return fallback
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" { return v }
	return fallback
}
