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
	"net/http/httputil"
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
  DefaultMaxLogLines = 500
	MaxAPIRetries      = 3
	MaxLogHistory      = 20
	APITimeout         = 25 * time.Second
) 

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
  LastChanged  string    `json:"last_changed"`
}

type Config struct {
    APIPrefix    string
    APISecret    string
    IPMode       string
    IfaceName    string
    HealthPort   string
    LogDir       string
    Lang         string
    Domains      []string
    DNSServers   []string
    Interval     int
    DryRun       bool
    DebugEnabled bool
    DebugHTTPRaw bool
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

type ZoneRecordCache struct {  
	sync.RWMutex  
	data map[string][]Record  
}

type APIError struct {  
	StatusCode int  
	Method     string  
	URL        string  
	Message    string  
	Retryable  bool  
	RetryAfter time.Duration  
}

type APIMetrics struct {  
	sync.Mutex  
	TotalRequests      int64  
	SuccessRequests    int64  
	FailedRequests     int64  
	RateLimitHits      int64  
	ServerErrors       int64  
	ClientErrors       int64  
	AverageLatency     time.Duration  
	LastError          string  
	LastErrorTimestamp time.Time  
	LastSuccessTimestamp time.Time
	RequestTimestamps    []time.Time
}

type SafeErrorMsg struct {
    sync.RWMutex
    msg string
}

var (
	cfg            Config
	T              Phrases
	logPath        string
	updatePath     string
	apiBaseURL     = "https://api.hosting.ionos.com/dns/v1/zones"
	lastOk         atomic.Bool
	logMutex       sync.Mutex
	statusMutex    sync.Mutex
	lastErrorMsg = &SafeErrorMsg{}
	httpClient     *http.Client
	clientOnce     sync.Once
  apiMetrics = &APIMetrics{}
)

func getHTTPClient() *http.Client {
	clientOnce.Do(func() {
		dnsList := cfg.DNSServers
		if len(dnsList) == 0 {
			dnsList = []string{"1.1.1.1:53", "8.8.8.8:53"}
		}
		dialer := &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
			Resolver: &net.Resolver{
				PreferGo: true, // Nutzt den stabilen Go-internen Resolver
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					var lastErr error
					
					for  i, dnsAddr := range dnsList {
						targetAddr := dnsAddr
						if !strings.Contains(targetAddr, ":") {
							targetAddr += ":53"
						}

						d := net.Dialer{
							Timeout: 3 * time.Second,
						}
						
						conn, err := d.DialContext(ctx, "udp", targetAddr)
						if err == nil {
							return conn, nil
						}
						
						lastErr = err
             if i == len(dnsList)-1 {
						    debugLog("DNS-FAILOVER", "", fmt.Sprintf("⚠️ Server %s nicht erreichbar: %v", targetAddr, err))
             }
					}
					
					return nil, fmt.Errorf("alle konfigurierten DNS-Server fehlgeschlagen: %w", lastErr)
				},
			},
		}

		httpClient = &http.Client{
			Timeout: 0, 
			Transport: &http.Transport{
				DialContext:           dialer.DialContext,
				MaxIdleConns:          10,
				MaxIdleConnsPerHost:   3,
				MaxConnsPerHost:       5,
				IdleConnTimeout:       60 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				DisableKeepAlives:     false,
				ForceAttemptHTTP2:     true, // Performance-Boost für IONOS API
			},
		}
		
		debugLog("SYSTEM", "", fmt.Sprintf("HTTP Client initialisiert mit %d DNS-Servern", len(dnsList)))
	})
	
	return httpClient
}


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
		if !os.IsNotExist(err) {  
			fmt.Printf("[WARN] Log-Rotation Fehler beim Lesen: %v\\n", err)  
		}  
		return  
	}  
  
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")  
  
	if len(lines) <= maxLines {  
		return  
	}

 
 newLines := lines[len(lines)-maxLines:]
 output := strings.Join(newLines, "\n") + "\n"
	  
	// ✅ Atomarer Swap: Erst temp-Datei schreiben, dann rename  
	tmpPath := path + ".tmp." + strconv.FormatInt(time.Now().UnixNano(), 10)  
	  
	if err := os.WriteFile(tmpPath, []byte(output), 0644); err != nil {  
		fmt.Printf("[WARN] Log-Rotation Schreibfehler: %v\\n", err)  
		return  
	}  
	  
	if err := os.Rename(tmpPath, path); err != nil {  
		fmt.Printf("[WARN] Log-Rotation Rename-Fehler: %v\\n", err)  
		_ = os.Remove(tmpPath) // Cleanup  
		return  
	}  
	  
	debugLog("MAINTENANCE", "", fmt.Sprintf("✅ Log rotiert: %d → %d Zeilen", len(lines), len(newLines)))  
}

func shouldPersist(level, action string) bool {
	if level == "ERR" || level == "WARN" || level == "DBG" {
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
	  
	if len(cfg.Domains) == 0 {  
		fmt.Println("\\n⚠️  Keine Domains konfiguriert!")  
		return  
	}  
	  
	groups := make(map[string][]string)  
	for _, d := range cfg.Domains {  
		if d == "" {  
			continue  
		}  
		  
		parts := strings.Split(d, ".")  
		if len(parts) < 2 {  
			fmt.Printf("\n⚠️  Ungültige Domain übersprungen: %s\n", d)  
			continue  
		}  
		  
		main := strings.Join(parts[len(parts)-2:], ".")  
		    
		if main == "" {  
			fmt.Printf("\n⚠️  Konnte Haupt-Domain nicht extrahieren: %s\n", d)  
			continue  
		}  
		  
		if d != main {  
			prefix := strings.TrimSuffix(d, "."+main)  
			groups[main] = append(groups[main], prefix)  
		} else if _, ok := groups[main]; !ok {  
			groups[main] = []string{}  
		}  
	}  
	  
	if len(groups) == 0 {  
		fmt.Println("\n⚠️  Keine gültigen Domains gefunden!")  
		return  
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
		data, _ := ionosAPI(context.Background(), "GET", apiBaseURL+"/"+z.ID, nil)
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

func ionosAPI(ctx context.Context, method, url string, body interface{}) ([]byte, error) {  
	var lastErr error  
  
	for attempt := 0; attempt < MaxAPIRetries; attempt++ {  
		start := time.Now() // Startzeit für Metriken (Latenz-Messung)
		debugLog("HTTP", "", fmt.Sprintf("🔄 Versuch %d/%d: %s %s", attempt+1, MaxAPIRetries, method, url))  
		  
		var bodyReader io.Reader  
		if body != nil {  
			bodyBytes, err := json.Marshal(body)  
			if err != nil {  
				return nil, fmt.Errorf("json marshal failed: %w", err)  
			}  
			bodyReader = bytes.NewBuffer(bodyBytes)  
			debugLog("HTTP", "", fmt.Sprintf("📤 Payload: %s", string(bodyBytes)))  
		}  
  
		reqCtx, cancel := context.WithTimeout(ctx, APITimeout)
  
		req, err := http.NewRequestWithContext(reqCtx, method, url, bodyReader)  
		if err != nil {  
			return nil, fmt.Errorf("request creation failed: %w", err)  
		}  
		  
		req.Header.Set("X-API-Key", cfg.APIPrefix+"."+cfg.APISecret)  
		req.Header.Set("Content-Type", "application/json")  
		req.Header.Set("Connection", "keep-alive")  
		req.Header.Set("User-Agent", "Go-DynDNS/2.0")  

		if cfg.DebugHTTPRaw {
			requestDump, _ := httputil.DumpRequestOut(req, true)
			debugLog("HTTP-RAW", "", "\n>>> REQUEST >>>\n"+string(requestDump))
		}

		res, err := getHTTPClient().Do(req)
    cancel()  
		duration := time.Since(start)

		if err != nil {  
			debugLog("HTTP", "", fmt.Sprintf("❌ Netzwerkfehler: %v | Dauer: %v", err, duration))  

			apiMetrics.RecordError(0, err, duration)
			
			lastErr = fmt.Errorf("network error: %w", err)  
			  
			wait := time.Duration(math.Pow(2, float64(attempt+1))) * time.Second  
			wait += time.Duration(rand.Intn(1000)) * time.Millisecond  
			  
			debugLog("HTTP", "", fmt.Sprintf("⏱️  Retry in %v", wait))  
			time.Sleep(wait)  
			continue  
		}
    	defer res.Body.Close()

		if cfg.DebugHTTPRaw {
    responseDump, err := httputil.DumpResponse(res, true)
    if err == nil {
        debugLog("HTTP-RAW", "", "\n<<< RESPONSE <<<\n"+string(responseDump))
    }
   }

		debugLog("HTTP", "", fmt.Sprintf("✅ Status: %d | Dauer: %v", res.StatusCode, duration))  
  
		respBody, err := io.ReadAll(res.Body)  
		  
		if err != nil {  
			// --- METRIK ERFASSEN (Body-Lesefehler) ---
			apiMetrics.RecordError(res.StatusCode, err, duration)
			
			debugLog("HTTP", "", fmt.Sprintf("❌ Body-Lesefehler: %v", err))  
			lastErr = fmt.Errorf("failed to read response body: %w", err)  
			
			wait := time.Duration(math.Pow(2, float64(attempt+1))) * time.Second  
			time.Sleep(wait)  
			continue  
		}  
  
		// Erfolg (2xx)  
		if res.StatusCode >= 200 && res.StatusCode < 300 {  
			// --- METRIK ERFASSEN (Erfolg) ---
			apiMetrics.RecordSuccess(duration)
			
			if errVal := lastErrorMsg.Get(); errVal != "" {
				if errStr := fmt.Sprint(errVal); errStr != "" {
					lastErrorMsg.Set("")
				}
       }
			debugLog("HTTP", "", fmt.Sprintf("✅ Erfolg: %d Bytes", len(respBody)))  
			return respBody, nil  
		}  
  
		// Fehler-Klassifizierung  
		apiErr := classifyAPIError(res.StatusCode, method, url, string(respBody))  
		
		// --- METRIK ERFASSEN (API-Fehler) ---
		apiMetrics.RecordError(res.StatusCode, apiErr, duration)
		
		// Kritische API-Fehler loggen
		if res.StatusCode == 401 || res.StatusCode == 403 {
			writeLog("ERR", ActionError, "", fmt.Sprintf("🚨 KRITISCHER API-FEHLER: %v", apiErr))
		}
		  
		debugLog("HTTP", "", fmt.Sprintf("⚠️  %s (Retryable: %v)", apiErr.Message, apiErr.Retryable))  
		lastErr = apiErr  
		lastErrorMsg.Set(sanitizeError(lastErr))  
  
		if !apiErr.IsRetryable() {  
			debugLog("HTTP", "", fmt.Sprintf("❌ Nicht-retryable Fehler: %s", apiErr.Message))  
			return nil, apiErr  
		}  
  
		if attempt >= MaxAPIRetries-1 {  
			debugLog("HTTP", "", fmt.Sprintf("❌ Maximale Versuche erreicht (%d)", MaxAPIRetries))  
			return nil, fmt.Errorf("maximale Versuche erreicht: %w", apiErr)  
		}  
  
		var wait time.Duration  
		if apiErr.RetryAfter > 0 {  
			wait = apiErr.RetryAfter  
		} else {  
			wait = time.Duration(math.Pow(2, float64(attempt+1))) * time.Second  
			wait += time.Duration(rand.Intn(1000)) * time.Millisecond  
			if res.StatusCode >= 500 {  
				wait = wait * 2  
			}  
		}  
		  
		debugLog("HTTP", "", fmt.Sprintf("🔄 Retry #%d in %v...", attempt+2, wait))  
		  
		select {  
		case <-time.After(wait):  
		case <-ctx.Done():  
			debugLog("HTTP", "", "❌ Context cancelled während Retry-Wait")  
			return nil, fmt.Errorf("context cancelled: %w", ctx.Err())  
		}  
	}  
	  
	return nil, fmt.Errorf("API fehlgeschlagen nach %d Versuchen: %w", MaxAPIRetries, lastErr)  
}


func getPublicIP(url string) (string, error) {
	debugLog("IP-CHECK", "", "🌐 Frage externe IP ab: "+url)
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		debugLog("IP-CHECK", "", fmt.Sprintf("❌ Request-Erstellung fehlgeschlagen: %v", err))
		return "", fmt.Errorf("request error: %w", err)
	}

	resp, err := getHTTPClient().Do(req)
	if err != nil {
		debugLog("IP-CHECK", "", fmt.Sprintf("❌ HTTP-Fehler: %v", err))
		return "", fmt.Errorf("http error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		debugLog("IP-CHECK", "", fmt.Sprintf("❌ Status Code: %d", resp.StatusCode))
		return "", fmt.Errorf("bad status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		debugLog("IP-CHECK", "", fmt.Sprintf("❌ Body-Lesefehler: %v", err))
		return "", fmt.Errorf("read error: %w", err)
	}
	
	ip := strings.TrimSpace(string(body))
	
	if net.ParseIP(ip) == nil {
		debugLog("IP-CHECK", "", fmt.Sprintf("❌ Ungültige IP: '%s'", ip))
		return "", fmt.Errorf("invalid ip: %s", ip)
	}
	
	debugLog("IP-CHECK", "", fmt.Sprintf("✅ Empfangene IP: %s", ip))
	return ip, nil
}

func getIPv6() (string, error) {
	if cfg.IfaceName != "" {
		debugLog("IP-CHECK", "", fmt.Sprintf("🔍 Prüfe Interface: %s", cfg.IfaceName))
		
		iface, err := net.InterfaceByName(cfg.IfaceName)
		if err != nil {
			debugLog("IP-CHECK", "", fmt.Sprintf("❌ Interface nicht gefunden: %v", err))
		} else {
			addrs, err := iface.Addrs()
			if err != nil {
				debugLog("IP-CHECK", "", fmt.Sprintf("❌ Adressen nicht lesbar: %v", err))
			} else {
				for _, a := range addrs {
					ipnet, ok := a.(*net.IPNet)
					if ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() == nil &&
						ipnet.IP.IsGlobalUnicast() && !ipnet.IP.IsLinkLocalUnicast() {
						debugLog("IP-CHECK", "", fmt.Sprintf("✅ IPv6 via Interface %s: %s", cfg.IfaceName, ipnet.IP.String()))
						return ipnet.IP.String(), nil
					}
				}
				debugLog("IP-CHECK", "", "⚠️  Keine IPv6 auf Interface, falle zurück auf externe Abfrage")
			}
		}
	}
	
	return getPublicIP("https://6.ident.me/")
}

// ---------------- LOGIK ----------------

func updateDNS(ctx context.Context, fqdn, recordType, newIP string, records []Record, zoneID string) (bool, error) {  
	var existing *Record  
	for i := range records {  
		if records[i].Name == fqdn && records[i].Type == recordType {  
			existing = &records[i]  
			debugLog("DNS-LOGIC", fqdn, fmt.Sprintf("📌 Gefundener Record: %s (ID: %s)", existing.Content, existing.ID))  
			break  
		}  
	}  
  
	if existing != nil && existing.Content == newIP {  
		debugLog("DNS-LOGIC", fqdn, fmt.Sprintf("✅ Record ist bereits aktuell: %s = %s", recordType, newIP))  
		writeLog("INFO", ActionCurrent, fqdn, fmt.Sprintf("✅ %-4s %s %s", recordType, newIP, T.Current))  
		return false, nil  
	}  
	  
	if existing == nil {  
		debugLog("DNS-LOGIC", fqdn, fmt.Sprintf("🆕 Kein bestehender %s Record gefunden. Plane Neuanlage.", recordType))  
	} else {  
		debugLog("DNS-LOGIC", fqdn, fmt.Sprintf("🔄 Record-Update erforderlich: %s -> %s", existing.Content, newIP))  
	}  
	  
	if cfg.DryRun {  
		writeLog("WARN", ActionDryRun, fqdn, fmt.Sprintf("Würde %s auf %s setzen", recordType, newIP))  
		return true, nil  
	}  
	  
	method, url := "POST", apiBaseURL+"/"+zoneID+"/records"  
	actionType := ActionCreate  
	if existing != nil {  
		method, url = "PUT", apiBaseURL+"/"+zoneID+"/records/"+existing.ID  
		actionType = ActionUpdate  
	}  
	  
	debugLog("DNS-LOGIC", fqdn, fmt.Sprintf("📡 API Call: %s %s", method, url))  
	  
	payload := map[string]interface{}{  
		"name":    fqdn,  
		"type":    recordType,  
		"content": newIP,  
		"ttl":     60,  
	}  
	  
	_, err := ionosAPI(ctx, method, url, payload)  
	  
	if err != nil {  
		// Spezifisches Error Handling  
		if apiErr, ok := err.(*APIError); ok {  
			switch apiErr.StatusCode {  
			case 401, 403:  
				writeLog("ERR", ActionError, fqdn, fmt.Sprintf("❌ %s: Berechtigung fehlt!", recordType))  
				return false, fmt.Errorf("authorization failed: %w", err)  
				  
			case 404:  
				writeLog("ERR", ActionZone, fqdn, fmt.Sprintf("❌ %s: Zone/Record nicht gefunden!", recordType))  
				return false, fmt.Errorf("resource not found: %w", err)  
				  
			case 422:  
				writeLog("ERR", ActionError, fqdn, fmt.Sprintf("❌ %s: Ungültige Daten (IP: %s)", recordType, newIP))  
				return false, fmt.Errorf("validation failed: %w", err)  
				  
			case 429:  
				writeLog("WARN", ActionRetry, fqdn, fmt.Sprintf("⏳ %s: Rate Limit, Retry läuft...", recordType))  
				// Error wird hochgereicht, Retry passiert in ionosAPI  
				return false, err  
				  
			default:  
				writeLog("ERR", ActionError, fqdn, fmt.Sprintf("❌ %s: API-Fehler %d", recordType, apiErr.StatusCode))  
				return false, err  
			}  
		}  
		  
		debugLog("DNS-LOGIC", fqdn, fmt.Sprintf("❌ Fehler: %v", err))  
		return false, err  
	}  
	  
	debugLog("DNS-LOGIC", fqdn, fmt.Sprintf("🔄 Erfolgreich: %s -> %s", recordType, newIP))  
	writeLog("INFO", actionType, fqdn, fmt.Sprintf("🔄 %s -> %s", recordType, newIP))  
	return true, nil  
}

func runUpdate(firstRun bool) {  
	debugLog("SCHEDULER", "", fmt.Sprintf("🚀 runUpdate() gestartet (parallel, firstRun=%v)", firstRun))  
	  
	ctx, cancel := context.WithTimeout(context.Background(), APITimeout*2) // Mehr Zeit für parallele Ops  
	defer cancel()  
	  
	// 1. GLOBALE IPs EINMALIG ERMITTELN  
	var currentIPv4, currentIPv6 string  
	var errV4, errV6 error  
  
	if cfg.IPMode != "IPV6" {  
		currentIPv4, errV4 = getPublicIP("https://4.ident.me/")  
		if errV4 != nil {  
			writeLog("ERR", ActionError, "", fmt.Sprintf("❌ Konnte IPv4 nicht ermitteln: %v", errV4))  
		}  
	}  
	if cfg.IPMode != "IPV4" {  
		currentIPv6, errV6 = getIPv6()  
		if errV6 != nil {  
			writeLog("ERR", ActionError, "", fmt.Sprintf("❌ Konnte IPv6 nicht ermitteln: %v", errV6))  
		}  
	}  
  
	// Abbrechen, wenn gar keine IP ermittelt werden konnte  
	if (cfg.IPMode == "IPV4" && errV4 != nil) ||   
	   (cfg.IPMode == "IPV6" && errV6 != nil) ||   
	   (cfg.IPMode == "BOTH" && errV4 != nil && errV6 != nil) {  
		lastOk.Store(false)  
		return  
	}  
  
	// 2. Zonen abrufen  
	data, err := ionosAPI(ctx, "GET", apiBaseURL, nil)  
	if err != nil {  
		lastOk.Store(false)  
		writeLog("ERR", ActionError, "", fmt.Sprintf("❌ Konnte Zonen nicht abrufen: %v", err))  
		return  
	}  
  
	var zones []Zone  
	if err := json.Unmarshal(data, &zones); err != nil {  
		lastOk.Store(false)  
		return  
	}  
  
	if firstRun {  
		printGroupedDomains()  
		printInfrastructure(zones)  
	}  
  
	// 3. Thread-Safe Cache erstellen  
	cache := NewZoneRecordCache()  
	  
	// Cache parallel befüllen  
	var cacheWg sync.WaitGroup  
	for _, z := range zones {  
		needed := false  
		for _, d := range cfg.Domains {  
			if strings.HasSuffix(d, z.Name) {  
				needed = true  
				break  
			}  
		}  
		if needed {  
			cacheWg.Add(1)  
			go func(zone Zone) {  
				defer cacheWg.Done()  
				  
				detailData, err := ionosAPI(ctx, "GET", apiBaseURL+"/"+zone.ID, nil)  
				if err == nil {  
					var detail struct{ Records []Record }  
					if json.Unmarshal(detailData, &detail) == nil {  
						cache.Set(zone.ID, detail.Records) // ✅ Thread-safe!  
					}  
				}  
			}(z)  
		}  
	}  
	cacheWg.Wait() // Warten bis Cache vollständig ist  
  
	// 4. PARALLELE UPDATES mit Context-Awareness  
	var wg sync.WaitGroup  
	sem := make(chan struct{}, 5)  
	var allOkAtomic atomic.Bool  
	allOkAtomic.Store(true)  
	var successCounter atomic.Int32  
  
	for _, fqdn := range cfg.Domains {  
		wg.Add(1)  
		go func(domain string) {  
			defer wg.Done()

			defer func() {
        			if r := recover(); r != nil {
            			writeLog("ERR", ActionError, domain, fmt.Sprintf("🔥 Panic abgefangen: %v", r))
        			}
			}()

			select {  
			case sem <- struct{}{}:  
				debugLog("WORKER", domain, "Slot belegt, starte Verarbeitung")  
			case <-ctx.Done():  
				debugLog("WORKER", domain, "Context abgebrochen, überspringe Domain")  
				allOkAtomic.Store(false)  
				return
			}  
			  
			defer func() {   
				debugLog("WORKER", domain, "Verarbeitung abgeschlossen, Slot freigegeben")  
				<-sem   
			}()  
  
			// Frühzeitige Context-Prüfung  
			if ctx.Err() != nil {  
				debugLog("WORKER", domain, "Context bereits abgelaufen")  
				allOkAtomic.Store(false)  
				return  
			}  
  
			// Zone für diese Domain finden  
			var zoneID string  
			for _, z := range zones {  
				if strings.HasSuffix(domain, z.Name) {  
					zoneID = z.ID  
					break  
				}  
			}  
			  
			if zoneID == "" {   
				debugLog("DNS-LOGIC", domain, "Abbruch: Keine passende Zone gefunden")  
				allOkAtomic.Store(false)  
				return   
			}  
  
			// ✅ Thread-safe Cache-Zugriff  
			records, exists := cache.Get(zoneID)  
			if !exists {  
				debugLog("DNS-LOGIC", domain, "Abbruch: Keine Records im Cache")  
				allOkAtomic.Store(false)  
				return  
			}  
  
			v4c, v6c := false, false  
  
			// IPv4 (A-Record)  
			if cfg.IPMode != "IPV6" && currentIPv4 != "" {  
				debugLog("DNS-LOGIC", domain, "Prüfe IPv4 (A-Record)...")  
				changed, err := updateDNS(ctx, domain, "A", currentIPv4, records, zoneID)  
				if err != nil {  
					// Bei kritischen Fehlern (401, 403, 404): Domain überspringen  
					if apiErr, ok := err.(*APIError); ok {  
						if apiErr.StatusCode == 401 || apiErr.StatusCode == 403 || apiErr.StatusCode == 404 {  
							debugLog("DNS-LOGIC", domain, "Kritischer Fehler, überspringe Domain")  
							allOkAtomic.Store(false)  
							return  
						}  
					}  
					// Andere Fehler: Loggen aber weitermachen  
					debugLog("DNS-LOGIC", domain, fmt.Sprintf("IPv4 Update fehlgeschlagen: %v", err))  
					allOkAtomic.Store(false)  
				}  
				v4c = changed  
			}  
			  
			// IPv6 (AAAA-Record)  
			if cfg.IPMode != "IPV4" && currentIPv6 != "" {  
				debugLog("DNS-LOGIC", domain, "Prüfe IPv6 (AAAA-Record)...")  
				changed, err := updateDNS(ctx, domain, "AAAA", currentIPv6, records, zoneID)  
				if err != nil {  
					// Gleiche Fehlerbehandlung wie bei IPv4  
					if apiErr, ok := err.(*APIError); ok {  
						if apiErr.StatusCode == 401 || apiErr.StatusCode == 403 || apiErr.StatusCode == 404 {  
							debugLog("DNS-LOGIC", domain, "Kritischer Fehler, überspringe Domain")  
							allOkAtomic.Store(false)  
							return  
						}  
					}  
					debugLog("DNS-LOGIC", domain, fmt.Sprintf("IPv6 Update fehlgeschlagen: %v", err))  
					allOkAtomic.Store(false)  
				}  
				v6c = changed  
			}  
  
			// Status-Update  
			if (v4c || v6c) && !cfg.DryRun {  
				debugLog("STATUS", domain, "Änderungen erkannt, schreibe update.json")  
				updateStatusFile(domain, currentIPv4, currentIPv6, "IONOS")  
				successCounter.Add(1)  
			} else {  
				debugLog("STATUS", domain, "Keine Änderungen notwendig")  
			}  
		}(fqdn)  
	}  
  
	wg.Wait()  
	lastOk.Store(allOkAtomic.Load())  
	debugLog("SCHEDULER", "", fmt.Sprintf("✅ runUpdate() beendet: %d Änderungen", successCounter.Load()))  
}

func updateStatusFile(fqdn, ipv4, ipv6, provider string) {
	statusMutex.Lock()
	defer statusMutex.Unlock()

	domains := make(map[string]DomainHistory)
	if b, err := os.ReadFile(updatePath); err == nil {
		if err := json.Unmarshal(b, &domains); err != nil {
			writeLog("WARN", ActionError, "", fmt.Sprintf("❌ Fehler beim Lesen von update.json: %v", err))
		}
	}

	h := domains[fqdn]
	h.Provider = provider
  h.LastChanged = time.Now().Local().Format("02.01.2006 15:04:05")
	newEntry := IPEntry{
		Time: time.Now().Local().Format("02.01.2006 15:04:05"),
		IPv4: ipv4,
		IPv6: ipv6,
	}
	h.IPs = append(h.IPs, newEntry)
	debugLog("STATUS-FILE", fqdn, fmt.Sprintf("Status-Datei aktualisiert: v4=%s, v6=%s", ipv4, ipv6))

	// Nur die letzten 20 Einträge behalten
	if len(h.IPs) > 20 {
		h.IPs = h.IPs[len(h.IPs)-20:]
	}
	domains[fqdn] = h

	js, err := json.MarshalIndent(domains, "", "  ")
	if err != nil {
		writeLog("ERR", ActionError, "", fmt.Sprintf("JSON Marshal Fehler: %v", err))
		return
	}

	tmp := updatePath + ".tmp"
	if err := os.WriteFile(tmp, js, 0644); err != nil {
		writeLog("ERR", ActionError, "", fmt.Sprintf("Fehler beim Schreiben: %v", err))
		return
	}

	if err := os.Rename(tmp, updatePath); err != nil {
		writeLog("ERR", ActionError, "", fmt.Sprintf("Fehler beim Umbenennen: %v", err))
		_ = os.Remove(tmp) // Cleanup
	}
}

// ---------------- DASHBOARD ----------------

func createMux() *http.ServeMux {  
	mux := http.NewServeMux()  
  
	// Erweiterter Health-Endpoint mit API-Status  
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {  
		if !lastOk.Load() {  
			debugLog("HEALTH", "", "Health-Check failed: System not OK")  
			  
			stats := apiMetrics.GetStats()  
			w.Header().Set("Content-Type", "application/json")  
			w.WriteHeader(http.StatusServiceUnavailable)  
			  
			response := map[string]interface{}{  
				"status":      "unhealthy",  
				"api_metrics": stats,  
			}  
			json.NewEncoder(w).Encode(response)  
			return  
		}  
		  
		debugLog("HEALTH", "", "Health-Check OK")  
		  
		// Detaillierte Statistiken im Query-Parameter  
		if r.URL.Query().Get("detailed") == "true" {  
			stats := apiMetrics.GetStats()  
			w.Header().Set("Content-Type", "application/json")  
			w.WriteHeader(http.StatusOK)  
			  
			response := map[string]interface{}{  
				"status":      "healthy",  
				"api_metrics": stats,  
			}  
			json.NewEncoder(w).Encode(response)  
			return  
		}  
		  
		w.WriteHeader(http.StatusOK)  
		w.Write([]byte("OK"))  
	})  
  
	// Neuer Metrics-Endpoint  
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {  
		stats := apiMetrics.GetStats()  
		w.Header().Set("Content-Type", "application/json")  
		json.NewEncoder(w).Encode(stats)  
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
			/* ---------- Metrics ---------- */
			.metrics-grid {
    			display: grid; 
    			grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); 
    			gap: 15px; 
    			margin-top: 10px;
			}
			.metric-item {
    			background: rgba(255,255,255,0.05);
    			padding: 10px;
    			border-radius: 8px;
    			text-align: center;
			}
			.metric-value {
    			display: block;
    			font-size: 1.2rem;
    			font-weight: bold;
    			color: #4ade80;
			}
			.metric-label {
    			font-size: 0.7rem;
    			color: #94a3b8;
    			text-transform: uppercase;
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
		if errStr := lastErrorMsg.Get(); errStr != "" {
			    fmt.Fprintf(w, `<div class="card" style="border-color:#f87171;background:rgba(239,68,68,0.05)">
					    <strong style="color:#f87171">⚠️ API Log:</strong><br><code style="font-size:0.75rem">%s</code></div>`, html.EscapeString(errStr))
		    }

    stats := apiMetrics.GetStats()
    fmt.Fprintf(w, `
    <div class="card">
        <strong>📊 API Performance</strong>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; font-size: 0.8rem; margin-top: 10px; border-bottom: 1px solid var(--border); padding-bottom: 10px; margin-bottom: 10px;">
            <div>Requests (Total): %v</div>
            <div>Erfolgsrate: <span style="color:#4ade80">%v</span></div>
            <div>Letzter Erfolg: <span style="color:#38bdf8">%v</span></div>
            <div>Ø Latenz: %v</div>
            <div>Fehler (4xx/5xx): %v / %v</div>
        </div>
        
        <div>
            <div style="display: flex; justify-content: space-between; font-size: 0.7rem; color: #94a3b8; margin-bottom: 4px;">
                <span>STÜNDLICHES LIMIT (EST.)</span>
                <span>%v / 1200 Requests</span>
            </div>
            <div style="width: 100%%; background: #334155; height: 8px; border-radius: 4px; overflow: hidden;">
                <div style="width: %s%%; height: 100%%; background: %s; transition: width 0.5s ease;"></div>
            </div>
            <div style="font-size: 0.65rem; color: #64748b; margin-top: 4px;">Basierend auf Requests der letzten 60 Minuten</div>
        </div>
    </div>`, 
    stats["total_requests"], stats["success_rate"], stats["last_success_time"], stats["avg_latency"], 
    stats["client_errors"], stats["server_errors"], stats["usage_count"], stats["usage_percent"], stats["usage_color"])

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



//-----------------Helfer----------------
func debugLog(action, domain, msg string) {
	if cfg.DebugEnabled {
		writeLog("DBG", action, domain, msg)
	}
}

func logHTTPClientStats() {
	if !cfg.DebugEnabled {
		return
	}

	client := getHTTPClient()
	transport := client.Transport.(*http.Transport)
	debugLog("HTTP-STATS", "", fmt.Sprintf(
		"MaxIdleConns=%d, MaxIdleConnsPerHost=%d, IdleConnTimeout=%v",
		transport.MaxIdleConns,
		transport.MaxIdleConnsPerHost,
		transport.IdleConnTimeout,
	))

  prefix := cfg.APIPrefix
  if len(prefix) > 5 {
      prefix = prefix[:5]
  }

	debugLog("CONFIG", "", "========== KONFIGURATION ==========")
	debugLog("CONFIG", "", fmt.Sprintf("API Prefix: %s***", prefix))
	debugLog("CONFIG", "", fmt.Sprintf("Domains:      %v", cfg.Domains))
	debugLog("CONFIG", "", fmt.Sprintf("Interval:     %ds", cfg.Interval))
	debugLog("CONFIG", "", fmt.Sprintf("IP Mode:      %s", cfg.IPMode))
	debugLog("CONFIG", "", fmt.Sprintf("Interface:    %s", cfg.IfaceName))
	debugLog("CONFIG", "", fmt.Sprintf("Health Port:  %s", cfg.HealthPort))
	debugLog("CONFIG", "", fmt.Sprintf("Dry Run:      %v", cfg.DryRun))
	debugLog("CONFIG", "", fmt.Sprintf("Log Dir:      %s", cfg.LogDir))
	debugLog("CONFIG", "", fmt.Sprintf("Language:     %s", cfg.Lang))
	debugLog("CONFIG", "", "===================================")
}

func NewZoneRecordCache() *ZoneRecordCache {  
	return &ZoneRecordCache{  
		data: make(map[string][]Record),  
	}  
}  
  
func (c *ZoneRecordCache) Set(zoneID string, records []Record) {  
	c.Lock()  
	defer c.Unlock()  
	c.data[zoneID] = records  
}  
  
func (c *ZoneRecordCache) Get(zoneID string) ([]Record, bool) {  
	c.RLock()  
	defer c.RUnlock()  
	records, exists := c.data[zoneID]  
	return records, exists  
}

func (e *APIError) Error() string {  
	return fmt.Sprintf("API Error [%s %s]: Status %d - %s", e.Method, e.URL, e.StatusCode, e.Message)  
}  
  
func (e *APIError) IsRetryable() bool {  
	return e.Retryable  
}  
  
// Klassifiziert API-Fehler und entscheidet über Retry-Strategie  
func classifyAPIError(statusCode int, method, url, responseBody string) *APIError {  
	apiErr := &APIError{  
		StatusCode: statusCode,  
		Method:     method,  
		URL:        url,  
		Message:    responseBody,  
		Retryable:  false,  
		RetryAfter: 0,  
	}  
  
	switch statusCode {  
	// 2xx - Erfolg (sollte hier nicht ankommen)  
	case 200, 201, 204:  
		return nil  
  
	// 4xx - Client Errors  
	case 400:  
		apiErr.Message = "Bad Request - Ungültige Anfrage (Payload prüfen)"  
		apiErr.Retryable = false  
		  
	case 401:  
		apiErr.Message = "Unauthorized - API-Key ungültig oder abgelaufen"  
		apiErr.Retryable = false  
		writeLog("ERR", ActionConfig, "", "❌ API-Authentifizierung fehlgeschlagen! API-Key prüfen!")  
		  
	case 403:  
		apiErr.Message = "Forbidden - Keine Berechtigung für diese Zone/Record"  
		apiErr.Retryable = false  
		  
	case 404:  
		apiErr.Message = "Not Found - Zone oder Record existiert nicht"  
		apiErr.Retryable = false  
		  
	case 422:  
		apiErr.Message = "Unprocessable Entity - Validierungsfehler (TTL, IP-Format, etc.)"  
		apiErr.Retryable = false  
		  
	case 429:  
		// IONOS Rate Limit: 429 kommt, aber ist nicht dokumentiert wie oft  
		apiErr.Message = "Rate Limit überschritten"  
		apiErr.Retryable = true  
		apiErr.RetryAfter = 60 * time.Second // Konservativ: 1 Minute warten  
		writeLog("WARN", ActionRetry, "", "⚠️ IONOS Rate Limit! Warte 60s...")  
  
	// 5xx - Server Errors (immer retry)  
	case 500:  
		apiErr.Message = "Internal Server Error - IONOS API Problem"  
		apiErr.Retryable = true  
		  
	case 502:  
		apiErr.Message = "Bad Gateway - IONOS Gateway Problem"  
		apiErr.Retryable = true  
		  
	case 503:  
		apiErr.Message = "Service Unavailable - IONOS temporär nicht erreichbar"  
		apiErr.Retryable = true  
		apiErr.RetryAfter = 30 * time.Second  
		  
	case 504:  
		apiErr.Message = "Gateway Timeout - IONOS antwortet nicht"  
		apiErr.Retryable = true  
		  
	default:  
		if statusCode >= 500 {  
			apiErr.Message = fmt.Sprintf("Server Error %d", statusCode)  
			apiErr.Retryable = true  
		} else {  
			apiErr.Message = fmt.Sprintf("Client Error %d", statusCode)  
			apiErr.Retryable = false  
		}  
	}  
  
	return apiErr  
}

func (m *APIMetrics) RecordSuccess(duration time.Duration) {  
	m.Lock()  
	defer m.Unlock()  
	m.TotalRequests++  
	m.SuccessRequests++  
	now := time.Now()
	m.LastSuccessTimestamp = now
	m.RequestTimestamps = append(m.RequestTimestamps, now)
	m.updateLatency(duration)  
}  
  
func (m *APIMetrics) RecordError(statusCode int, err error, duration time.Duration) {  
	m.Lock()  
	defer m.Unlock()  
	m.TotalRequests++  
	m.FailedRequests++  
	now := time.Now()
	m.LastError = err.Error()  
	m.LastErrorTimestamp = now
	m.RequestTimestamps = append(m.RequestTimestamps, now)
	m.updateLatency(duration)  
	  
	switch {  
	case statusCode == 429:  
		m.RateLimitHits++  
	case statusCode >= 500:  
		m.ServerErrors++  
	case statusCode >= 400:  
		m.ClientErrors++  
	}  
}
  
func (m *APIMetrics) updateLatency(duration time.Duration) {  
	// Gleitender Durchschnitt (einfache Variante)  
	if m.AverageLatency == 0 {  
		m.AverageLatency = duration  
	} else {  
		m.AverageLatency = (m.AverageLatency*9 + duration) / 10  
	}  
}  
  
func (m *APIMetrics) GetStats() map[string]interface{} {  
	m.Lock()  
	defer m.Unlock()  
	
	// Rollierendes Fenster: Nur Requests der letzten 60 Min zählen
	now := time.Now()
	threshold := now.Add(-1 * time.Hour)
	var valid []time.Time
	for _, t := range m.RequestTimestamps {
		if t.After(threshold) {
			valid = append(valid, t)
		}
	}
	m.RequestTimestamps = valid
	currentCount := len(m.RequestTimestamps)
	
	limit := 1200.0
	percent := (float64(currentCount) / limit) * 100
	if percent > 100 { percent = 100 }

	successRate := 0.0  
	if m.TotalRequests > 0 {  
		successRate = float64(m.SuccessRequests) / float64(m.TotalRequests) * 100  
	}  
	  
	return map[string]interface{}{  
		"total_requests":     m.TotalRequests,  
		"success_rate":       fmt.Sprintf("%.2f%%", successRate),  
		"avg_latency":        m.AverageLatency.String(),  
		"server_errors":      m.ServerErrors,  
		"client_errors":      m.ClientErrors,  
		"last_success_time":  m.LastSuccessTimestamp.Format("15:04:05"),
		"usage_count":        currentCount,
		"usage_percent":      fmt.Sprintf("%.1f", percent),
		"usage_color":        m.getUsageColor(percent),
	}  
}

func (m *APIMetrics) getUsageColor(p float64) string {
	if p > 90 { return "#f87171" } // Rot
	if p > 70 { return "#facc15" } // Gelb
	return "#4ade80"               // Grün
}

func sanitizeError(err error) string {  
	if err == nil {  
		return ""  
	}  
	msg := err.Error()  
	  
	// API-Secret entfernen  
	if cfg.APISecret != "" {  
		msg = strings.ReplaceAll(msg, cfg.APISecret, "***SECRET***")  
	}  
	  
	// API-Prefix entfernen (falls vollständig im Error)  
	if cfg.APIPrefix != "" {  
		msg = strings.ReplaceAll(msg, cfg.APIPrefix, "***PREFIX***")  
	}  
	  
	// Vollständigen API-Key entfernen  
	fullKey := cfg.APIPrefix + "." + cfg.APISecret  
	msg = strings.ReplaceAll(msg, fullKey, "***API-KEY***")  
	  
	return msg  
}

func validateConfig() error {  
	var errs []string  
	  
	// API Credentials  
	if cfg.APIPrefix == "" {  
		errs = append(errs, "API_PREFIX fehlt")  
	}  
	if cfg.APISecret == "" {  
		errs = append(errs, "API_SECRET fehlt")  
	}  
	  
	// Domains  
	if len(cfg.Domains) == 0 {  
		errs = append(errs, "Keine Domains konfiguriert")  
	}  
	  
	// Port-Validierung  
	port, err := strconv.Atoi(cfg.HealthPort)  
	if err != nil || port < 1 || port > 65535 {  
		writeLog("WARN", ActionConfig, "", fmt.Sprintf("Ungültiger Port '%s', nutze 8080", cfg.HealthPort))  
		cfg.HealthPort = "8080"  
	}  
	  
	// Interval  
	if cfg.Interval < 60 {
    	if cfg.Interval < 30 {
        	writeLog("WARN", ActionConfig, "", "Intervall zu klein, setze auf 60s")
        	cfg.Interval = 60
    	} else if len(cfg.Domains) > 10 {
        	writeLog("WARN", ActionConfig, "", "⚠️ Kurzes Intervall + viele Domains = Rate-Limit-Risiko!")
    	}
	}
	  
	// IP-Mode  
	validModes := map[string]bool{"IPV4": true, "IPV6": true, "BOTH": true}  
	if !validModes[cfg.IPMode] {  
		writeLog("WARN", ActionConfig, "", fmt.Sprintf("Ungültiger IP_MODE '%s', nutze BOTH", cfg.IPMode))  
		cfg.IPMode = "BOTH"  
	}  
	  
	if len(errs) > 0 {  
		return fmt.Errorf("Config-Fehler: %s", strings.Join(errs, ", "))  
	} 
	  
	return nil  
}

func (s *SafeErrorMsg) Set(msg string) {
    s.Lock()
    defer s.Unlock()
    s.msg = msg
}

func (s *SafeErrorMsg) Get() string {
    s.RLock()
    defer s.RUnlock()
    return s.msg
}

// ---------------- MAIN ----------------

func main() {
	defer func() {
        if r := recover(); r != nil {
            fmt.Printf("[FATAL] Main-Panic: %v\n", r)
            os.Exit(1)
        }
	}()
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

  dnsEnv := os.Getenv("DNS_SERVERS")
  var dnsList []string
  if dnsEnv != "" {
      parts := strings.Split(dnsEnv, ",")
      for _, p := range parts {
          trimmed := strings.TrimSpace(p)
          if trimmed != "" {
              dnsList = append(dnsList, trimmed)
          }
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
        DNSServers:   dnsList,
        DebugEnabled: os.Getenv("DEBUG") == "true",
        DebugHTTPRaw: os.Getenv("DEBUG_HTTP_RAW") == "true",
    }

    if cfg.IPMode == "" {
	    cfg.IPMode = "BOTH"
    }

    if cfg.DebugEnabled {
        writeLog("DBG", "CONFIG", "", fmt.Sprintf("Debug-Modus aktiv. Intervall: %ds, Mode: %s", cfg.Interval, cfg.IPMode))
        writeLog("DBG", "CONFIG", "", fmt.Sprintf("Geladene Domains: %v", cfg.Domains))
    }

  logHTTPClientStats() 

	if cfg.HealthPort == "" {
		cfg.HealthPort = "8080"
	}

	_ = os.MkdirAll(cfg.LogDir, 0755)
	logPath = filepath.Join(cfg.LogDir, "dyndns.json")
	updatePath = filepath.Join(cfg.LogDir, "update.json")

	if cfg.APIPrefix == "" || cfg.APISecret == "" {
		writeLog("ERR", ActionConfig, "", T.ConfigError)
	}

	if err := validateConfig(); err != nil {  
		writeLog("ERR", ActionConfig, "", fmt.Sprintf("❌ %v", err))  
		os.Exit(1)  
	}

	writeLog("INFO", ActionStart, "", "🚀 "+T.Startup)

	srv := &http.Server{Addr: ":" + cfg.HealthPort, Handler: createMux()}

	go func() {
     debugLog("SYSTEM", "", "Starte HTTP-Server Routine...")
		writeLog("INFO", "SERVER", "", fmt.Sprintf("Dashboard gestartet auf Port %s", cfg.HealthPort))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			writeLog("ERR", ActionError, "", fmt.Sprintf("Server Fehler: %v", err))
		}
	}()

	runUpdate(true)
	ticker := time.NewTicker(time.Duration(cfg.Interval) * time.Second)
	defer ticker.Stop()
	
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
       debugLog("SCHEDULER", "", "Intervall erreicht, starte runUpdate(false)")
			runUpdate(false)
			limit := maxLogLines
			if cfg.Interval > 300 {
				limit = 1000
			}
       debugLog("MAINTENANCE", "", "Starte Log-Rotation...")
			rotateLogFile(logPath, limit)
			
		case sig := <-stop:
       debugLog("SYSTEM", "", fmt.Sprintf("Shutdown Signal empfangen: %v", sig))
			writeLog("INFO", ActionStop, "", fmt.Sprintf("🛑 %s (Signal: %v)", T.Shutdown, sig))
			ticker.Stop()

			if httpClient != nil {
            httpClient.CloseIdleConnections()
            debugLog("SYSTEM", "", "HTTP Verbindungen getrennt")
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			
       debugLog("SYSTEM", "", "Server wird heruntergefahren...")
			if err := srv.Shutdown(ctx); err != nil {
				writeLog("WARN", ActionError, "", fmt.Sprintf("Server Shutdown Fehler: %v", err))
			} else {
         debugLog("SYSTEM", "", "Server erfolgreich heruntergefahren")
       }
			return
		}
	}
}
