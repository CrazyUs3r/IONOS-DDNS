package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
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

// ---------------- STRUKTUREN ----------------

type Phrases struct {
	Startup, Shutdown, NoZones, Update, Created, Current,
	DryRunWarn, ConfigError, DashTitle, StatusOk, StatusErr, LastUpdate string
}

var languagePack = map[string]Phrases{
	"DE": {
		Startup: "Service gestartet", Shutdown: "Service beendet", NoZones: "keine Zone gefunden",
		Update: "Update", Created: "Neuanlage", Current: "ist aktuell",
		DryRunWarn: "⚠️ DRY-RUN MODUS AKTIV", ConfigError: "❌ API Credentials fehlen!",
		DashTitle: "DynDNS Dashboard", StatusOk: "System Online", StatusErr: "API Fehler", LastUpdate: "Letzter Check",
	},
	"EN": {
		Startup: "Service started", Shutdown: "Service stopped", NoZones: "no zone found",
		Update: "Update", Created: "Created", Current: "is up to date",
		DryRunWarn: "⚠️ DRY-RUN MODE ACTIVE", ConfigError: "❌ API Credentials missing!",
		DashTitle: "DynDNS Dashboard", StatusOk: "System Online", StatusErr: "API Error", LastUpdate: "Last Check",
	},
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
	cfg         Config
	T           Phrases
	logPath     string
	updatePath  string
	apiBaseURL  = "https://api.hosting.ionos.com/dns/v1/zones"
	lastOk      atomic.Bool
	logMutex    sync.Mutex
	statusMutex sync.Mutex
	httpClient  = &http.Client{Timeout: 30 * time.Second}
)

// ---------------- LOGGING & ANALYSE ----------------

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

	entry := map[string]string{
		"timestamp": now.Format("2006-01-02T15:04:05"),
		"level":     level, "action": action, "domain": domain, "message": msg,
	}
	
	if js, err := json.Marshal(entry); err == nil {
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			defer f.Close()
			_, _ = f.Write(append(js, '\n'))
		}
	}
}

func printInfraAnalysis(zones []Zone) {
	fmt.Println("\n📂 --- IONOS Infrastruktur Analyse ---")
	if len(zones) == 0 {
		fmt.Println("⚠️ Keine Zonen in diesem Account gefunden!")
	}
	for _, z := range zones {
		fmt.Printf("Zone: %s (ID: %s)\n", z.Name, z.ID)
		for _, d := range cfg.Domains {
			if strings.HasSuffix(d, z.Name) {
				fmt.Printf("   ┣━ Überwacht: %s\n", d)
			}
		}
	}
	fmt.Println("--------------------------------------\n")
}

func updateStatusFile(fqdn, ipv4, ipv6, provider string) {
	statusMutex.Lock()
	defer statusMutex.Unlock()

	domains := make(map[string]DomainHistory)
	if data, err := os.ReadFile(updatePath); err == nil {
		if errJ := json.Unmarshal(data, &domains); errJ != nil {
			writeLog("WARN", "JSON", fqdn, "Status-Datei korrupt, erstelle neu")
			domains = make(map[string]DomainHistory)
		}
	}

	h := domains[fqdn]
	h.Provider = provider
	if len(h.IPs) > 0 {
		last := h.IPs[len(h.IPs)-1]
		if last.IPv4 == ipv4 && last.IPv6 == ipv6 { return }
	}

	h.IPs = append(h.IPs, IPEntry{
		Time: time.Now().Local().Format("02.01.2006 15:04:05"), IPv4: ipv4, IPv6: ipv6,
	})
	if len(h.IPs) > 20 { h.IPs = h.IPs[len(h.IPs)-20:] }
	domains[fqdn] = h

	if js, err := json.MarshalIndent(domains, "", "  "); err == nil {
		tmpPath := updatePath + ".tmp"
		if errW := os.WriteFile(tmpPath, js, 0644); errW == nil {
			if errR := os.Rename(tmpPath, updatePath); errR != nil {
				writeLog("ERR", "FS", fqdn, "Fehler beim Umbenennen: "+errR.Error())
			}
		} else {
			writeLog("ERR", "FS", fqdn, "Fehler beim Schreiben: "+errW.Error())
		}
	}
}

// ---------------- DASHBOARD ----------------

func createMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if lastOk.Load() { w.WriteHeader(200); w.Write([]byte("OK")) } else { w.WriteHeader(503) }
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		statusMutex.Lock()
		domains := make(map[string]DomainHistory)
		if fileData, err := os.ReadFile(updatePath); err == nil { _ = json.Unmarshal(fileData, &domains) }
		statusMutex.Unlock()

		statusClass, statusText := "status-ok", T.StatusOk
		if !lastOk.Load() { 
			statusClass, statusText = "status-error", T.StatusErr 
		} else if cfg.DryRun { 
			statusClass = "status-dry" 
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// Wir haben genau 7 Platzhalter (%s) im String unten
		fmt.Fprintf(w, `<!DOCTYPE html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s</title>
<style>
body{font-family:-apple-system,system-ui,sans-serif;background:#0f172a;color:#f8fafc;padding:15px;margin:0;line-height:1.4}
.container{max-width:800px;margin:0 auto}
h1{font-size:1.4rem;color:#38bdf8;margin:15px 0;display:flex;align-items:center;gap:10px}
.status-banner{padding:8px 15px;border-radius:20px;display:inline-flex;align-items:center;gap:8px;margin-bottom:20px;font-weight:600;font-size:0.8rem;text-transform:uppercase}
.status-ok{background:rgba(34,197,94,0.15);color:#4ade80;border:1px solid rgba(34,197,94,0.3)}
.status-error{background:rgba(239,68,68,0.15);color:#f87171;border:1px solid rgba(239,68,68,0.3)}
.status-dry{background:rgba(251,191,24,0.15);color:#fbbf24;border:1px solid rgba(251,191,24,0.3)}
.card{background:#1e293b;padding:15px;margin-bottom:15px;border-radius:12px;border:1px solid #334155}
table{width:100%%;border-collapse:collapse;font-size:0.85rem}
td{padding:8px 4px;border-bottom:1px solid #334155}
.badge{padding:2px 6px;border-radius:4px;font-size:0.7rem;color:#fff;font-weight:bold;min-width:35px;text-align:center;display:inline-block;margin-right:5px}
.v4{background:#0ea5e9} .v6{background:#8b5cf6}
.dry{color:#fbbf24;font-size:0.8rem;font-weight:bold}
</style>
<script>
function updateClock() {
    const now = new Date();
    document.getElementById('live-clock').textContent = now.toLocaleTimeString('de-DE');
}
setInterval(updateClock, 1000);
window.onload = updateClock;
</script>
</head><body><div class="container">
<h1>🌐 %s %s</h1>
<div class="status-banner %s">
    <span id="live-clock">--:--:--</span> &bull; 
    %s &bull; 
    %s: %s
</div>`,
			T.DashTitle, // 1. Title
			T.DashTitle, // 2. H1 Text
			func() string { if cfg.DryRun { return "<span class='dry'>(DRY-RUN)</span>" }; return "" }(), // 3. DryRun Info
			statusClass, // 4. Banner CSS Klasse
			statusText,  // 5. Banner Status Text (System Online)
			T.LastUpdate, // 6. "Letzter Check" Label
			time.Now().Format("2006-01-02 15:04:05"), // 7. Zeitstempel
		)

		keys := make([]string, 0, len(domains))
		for k := range domains { keys = append(keys, k) }
		sort.Strings(keys)
		for _, name := range keys {
			h := domains[name]
			fmt.Fprintf(w, `<div class="card"><strong>%s</strong> <i>(%s)</i><table>`, name, h.Provider)
			for i := len(h.IPs) - 1; i >= 0; i-- {
				e := h.IPs[i]
				fmt.Fprintf(w, `<tr><td style="white-space:nowrap;color:#94a3b8">%s</td><td>`, e.Time)
				if e.IPv4 != "" { fmt.Fprintf(w, `<div><span class="badge v4">v4</span>%s</div>`, e.IPv4) }
				if e.IPv6 != "" { fmt.Fprintf(w, `<div><span class="badge v6">v6</span>%s</div>`, e.IPv6) }
				fmt.Fprintf(w, `</td></tr>`)
			}
			fmt.Fprintf(w, `</table></div>`)
		}
		if len(keys) == 0 { fmt.Fprintf(w, `<div class="card">Keine Daten vorhanden. Warte auf ersten Check...</div>`) }
		fmt.Fprintf(w, `</div></body></html>`)
	})
	return mux
}

// ---------------- API & NETZWERK ----------------

func getPublicIP(url string) string {
	for i := 0; i < 3; i++ {
		res, err := httpClient.Get(url)
		if err == nil {
			defer res.Body.Close()
			body, _ := io.ReadAll(res.Body)
			return strings.TrimSpace(string(body))
		}
		time.Sleep(time.Duration(1<<i) * time.Second)
	}
	return ""
}

func getIPv6() string {
	if cfg.IfaceName != "" {
		iface, err := net.InterfaceByName(cfg.IfaceName)
		if err == nil {
			addrs, _ := iface.Addrs()
			for _, a := range addrs {
				ipnet, ok := a.(*net.IPNet)
				if ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() == nil && ipnet.IP.IsGlobalUnicast() {
					return ipnet.IP.String()
				}
			}
		}
	}
	return getPublicIP("https://6.ident.me/")
}

// ---------------- API ----------------

func ionosAPI(method, url string, body interface{}) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		bodyReader = bytes.NewBuffer(b)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil { return nil, err }
	req.Header.Set("X-API-Key", cfg.APIPrefix+"."+cfg.APISecret)
	req.Header.Set("Content-Type", "application/json")
	res, err := httpClient.Do(req)
	if err != nil { return nil, err }
	defer res.Body.Close()
	respBody, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 300 {
		return nil, fmt.Errorf("Status %d: %s", res.StatusCode, string(respBody))
	}
	return respBody, nil
}

func syncDNS(zoneID, fqdn, rType, ip string, records []Record) (bool, error) {
	var existing *Record
	for _, r := range records {
		if r.Name == fqdn && r.Type == rType { existing = &r; break }
	}
	if existing != nil && existing.Content == ip {
		writeLog("INFO", T.Current, fqdn, fmt.Sprintf("🆗 %-4s %s", rType, T.Current))
		return false, nil
	}
	
	// KOMPATIBILITÄTS-ÄNDERUNG: Wir senden ein einzelnes Objekt statt eines Arrays
	payload := map[string]interface{}{
		"name": fqdn, 
		"type": rType, 
		"content": ip, 
		"ttl": 60,
	}

	method, url := "POST", apiBaseURL+"/"+zoneID+"/records"
	if existing != nil {
		method, url = "PUT", apiBaseURL+"/"+zoneID+"/records/"+existing.ID
	}

	_, err := ionosAPI(method, url, payload)
	if err == nil {
		writeLog("INFO", T.Update, fqdn, fmt.Sprintf("✅ %-4s -> %s", rType, ip))
		return true, nil
	}
	return false, err
}

// ---------------- UPDATE LOGIK ----------------

func runUpdate(firstRun bool) {
	if len(cfg.Domains) == 0 { return }
	data, err := ionosAPI("GET", apiBaseURL, nil)
	if err != nil { 
		writeLog("ERR", "API", "SYSTEM", "Konnte Zonen nicht abrufen: "+err.Error())
		lastOk.Store(false); return 
	}
	var zoneResponse []Zone
	if errJ := json.Unmarshal(data, &zoneResponse); errJ != nil {
		var wrapper struct{ Items []Zone `json:"items"` }
		_ = json.Unmarshal(data, &wrapper)
		zoneResponse = wrapper.Items
	}

	if firstRun { printInfraAnalysis(zoneResponse) }

	var wg sync.WaitGroup
	var hasError atomic.Bool

	for _, domain := range cfg.Domains {
		wg.Add(1)
		go func(fqdn string) {
			defer wg.Done()
			var zone Zone
			for _, z := range zoneResponse {
				if strings.HasSuffix(fqdn, z.Name) { zone = z; break }
			}
			if zone.ID == "" { 
				writeLog("ERR", "ZONE", fqdn, "Gehört zu keiner IONOS Zone!")
				hasError.Store(true); return 
			}

			detailData, errD := ionosAPI("GET", apiBaseURL+"/"+zone.ID, nil)
			if errD != nil { 
				writeLog("ERR", "API", fqdn, "Records konnten nicht geladen werden")
				hasError.Store(true); return 
			}
			var detail struct{ Records []Record `json:"records"` }
			_ = json.Unmarshal(detailData, &detail)

			v4, v6 := "", ""
			v4Chg, v6Chg := false, false

			if cfg.IPMode != "IPV6" {
				v4 = getPublicIP("https://4.ident.me/")
				if v4 != "" {
					chg, errS := syncDNS(zone.ID, fqdn, "A", v4, detail.Records)
					v4Chg = chg
					if errS != nil { hasError.Store(true) }
				}
			}
			if cfg.IPMode != "IPV4" {
				v6 = getIPv6()
				if v6 != "" {
					chg, errS := syncDNS(zone.ID, fqdn, "AAAA", v6, detail.Records)
					v6Chg = chg
					if errS != nil { hasError.Store(true) }
				}
			}
			if (v4 != "" || v6 != "") && (v4Chg || v6Chg || firstRun) {
				updateStatusFile(fqdn, v4, v6, "IONOS")
			}
		}(domain)
	}
	wg.Wait()
	lastOk.Store(!hasError.Load())
}

// ---------------- MAIN ----------------

func loadConfig() Config {
	lang := "DE"
	if strings.HasPrefix(strings.ToUpper(os.Getenv("LANG")), "EN") { lang = "EN" }
	T = languagePack[lang]
	var d []string
	for _, s := range strings.Split(os.Getenv("DOMAINS"), ",") {
		if t := strings.TrimSpace(strings.ToLower(s)); t != "" { d = append(d, t) }
	}
	iv := 300
	if i, err := strconv.Atoi(os.Getenv("INTERVAL")); err == nil && i >= 30 { iv = i }
	hp := os.Getenv("HEALTH_PORT"); if hp == "" { hp = "8080" }
	ld := os.Getenv("LOG_DIR"); if ld == "" { ld = "/logs" }
	return Config{
		APIPrefix: os.Getenv("API_PREFIX"), APISecret: os.Getenv("API_SECRET"),
		Domains: d, Interval: iv, IPMode: strings.ToUpper(os.Getenv("IP_MODE")),
		IfaceName: os.Getenv("INTERFACE"), HealthPort: hp, DryRun: os.Getenv("DRY_RUN") == "true",
		LogDir: ld, Lang: lang,
	}
}

func main() {
	cfg = loadConfig()
	_ = os.MkdirAll(cfg.LogDir, 0755)
	logPath = filepath.Join(cfg.LogDir, "dyndns.json")
	updatePath = filepath.Join(cfg.LogDir, "update.json")

	if cfg.APIPrefix == "" || cfg.APISecret == "" { log.Fatal(T.ConfigError) }
	writeLog("INFO", T.Startup, "", "🚀 "+T.Startup)

	srv := &http.Server{Addr: ":" + cfg.HealthPort, Handler: createMux()}
	serverErrors := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed { serverErrors <- err }
	}()

	runUpdate(true)
	ticker := time.NewTicker(time.Duration(cfg.Interval) * time.Second)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case err := <-serverErrors:
			log.Fatalf("❌ Serverfehler: %v", err)
		case <-ticker.C:
			runUpdate(false)
		case <-stop:
			writeLog("INFO", T.Shutdown, "", "🛑 "+T.Shutdown)
			ticker.Stop()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = srv.Shutdown(ctx)
			cancel() 
			return
		}
	}
}
