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
	"syscall"
	"time"
)

// ---------------- CONFIG & ENV ----------------
var (
	apiPrefix  = os.Getenv("API_PREFIX")
	apiSecret  = os.Getenv("API_SECRET")
	domains    = strings.Split(os.Getenv("DOMAINS"), ",")
	interval   = getEnvInt("INTERVAL", 300)
	ipMode     = strings.ToUpper(os.Getenv("IP_MODE"))
	ifaceName  = os.Getenv("INTERFACE")
	healthPort = os.Getenv("HEALTH_PORT")
  debugMode = os.Getenv("DEBUG") == "true"
	
	logPath    = "/logs/dyndns.json"
	updatePath = "/logs/update.json"
	
	apiBaseURL = "https://api.hosting.ionos.com/dns/v1/zones"
	lastOk     = false
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

// Strukturen für update.json (Version 2 mit kombinierten Einträgen)
type IPEntry struct {
	Time string `json:"time"`
	IPv4 string `json:"ipv4,omitempty"`
	IPv6 string `json:"ipv6,omitempty"`
}

type DomainHistory struct {
	IPs []IPEntry `json:"ips"`
}

var historyMap = make(map[string]DomainHistory)

// ---------------- LOGGING & STATUS ----------------

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
		f.Write(append(jsonBytes, '\n'))
	}
}

// updateStatusFile fügt einen kombinierten Eintrag hinzu und begrenzt auf 30
func updateStatusFile(fqdn, ipv4, ipv6 string) {
	fileData, err := os.ReadFile(updatePath)
	if err == nil {
		json.Unmarshal(fileData, &historyMap)
	}

	newEntry := IPEntry{
		Time: time.Now().Local().Format(time.RFC3339),
		IPv4: ipv4,
		IPv6: ipv6,
	}

	history := historyMap[fqdn]
	history.IPs = append(history.IPs, newEntry)

	// LIMIT: Nur die letzten 30 Einträge behalten
	if len(history.IPs) > 30 {
		history.IPs = history.IPs[len(history.IPs)-30:]
	}

	historyMap[fqdn] = history
	newJson, _ := json.MarshalIndent(historyMap, "", "  ")
	os.WriteFile(updatePath, newJson, 0644)
}

func startHealthServer() {
	if healthPort == "" { healthPort = "8080" }
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if lastOk {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("ERROR"))
		}
	})
	log.Fatal(http.ListenAndServe(":"+healthPort, nil))
}

// ---------------- MAIN LOGIC ----------------

func main() {
	if apiPrefix == "" || apiSecret == "" {
		log.Fatal("❌ API Credentials fehlen!")
	}
	if ifaceName == "" { ifaceName = "eth0" }
	if ipMode == "" { ipMode = "BOTH" }

	var cleanedDomains []string
	for _, d := range domains {
		trimmed := strings.TrimSpace(d)
		if trimmed != "" {
			cleanedDomains = append(cleanedDomains, trimmed)
		}
	}
	sort.Strings(cleanedDomains)
	domains = cleanedDomains

	go startHealthServer()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	printGroupedDomains()

	writeJsonLog("INFO", "startup", "", "Service gestartet")

	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	firstRun := true
	for {
		err := runUpdate(firstRun)
		lastOk = (err == nil)
		firstRun = false

		select {
		case <-stop:
			writeJsonLog("INFO", "shutdown", "", "Service beendet")
			return
		case <-ticker.C:
			continue
		}
	}
}

func printGroupedDomains() {
	fmt.Printf("🚀 Go-DynDNS gestartet (%s) für:\n", ipMode)
	
	groups := make(map[string][]string)
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		parts := strings.Split(d, ".")
		
		if len(parts) >= 2 {
			main := strings.Join(parts[len(parts)-2:], ".")
			if d != main {
				prefix := strings.TrimSuffix(d, "."+main)
				groups[main] = append(groups[main], prefix)
			} else {
				if _, für := groups[main]; !für {
					groups[main] = []string{}
				}
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
		sort.Strings(subs) // Subdomains innerhalb der Gruppe sortieren

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

func runUpdate(firstRun bool) error {
	zones, err := getZones()
	if err != nil { 
		writeJsonLog("ERROR", "api_error", "", err.Error())
		return err 
	}
	if firstRun { printInfrastructure(zones) }

	allSuccessful := true
	for _, domain := range domains {
		domain = strings.TrimSpace(strings.ToLower(domain))
		if domain == "" { continue }
		if err := processDomain(domain, zones); err != nil {
			log.Printf("❌ Fehler bei %s: %v", domain, err)
			allSuccessful = false
		}
	}
	if !allSuccessful { return fmt.Errorf("updates failed") }
	return nil
}

func processDomain(fqdn string, zones []Zone) error {
	var targetZone Zone
	for _, z := range zones {
		if strings.HasSuffix(fqdn, z.Name) {
			targetZone = z
			break
		}
	}
	if targetZone.ID == "" { return fmt.Errorf("keine Zone gefunden") }

	detail, err := getZoneDetails(targetZone.ID)
	if err != nil { return err }

	var currentIPv4, currentIPv6 string
	var changed bool

	// IPv4 Check
	if ipMode == "IPV4" || ipMode == "BOTH" {
		currentIPv4 = getPublicIP("https://4.ident.me/")
		if currentIPv4 != "" {
			if updateDNS(fqdn, "A", currentIPv4, detail.Records, targetZone.ID) {
				changed = true
			}
		}
	}

	// IPv6 Check
	if ipMode == "IPV6" || ipMode == "BOTH" {
		currentIPv6 = getIPv6()
		if currentIPv6 != "" {
			if updateDNS(fqdn, "AAAA", currentIPv6, detail.Records, targetZone.ID) {
				changed = true
			}
		}
	}

	// Wenn sich mindestens einer der beiden geändert hat -> kombinierten Eintrag schreiben
	if changed {
		updateStatusFile(fqdn, currentIPv4, currentIPv6)
	}

	return nil
}

// updateDNS gibt true zurück, wenn ein Update oder eine Neuanlage stattfand
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
			msg := fmt.Sprintf("Update %s: %s -> %s", rType, existing.Content, currentIP)
			fmt.Printf("🔄 %s\n", msg)
			sendUpdate(zoneID, fqdn, rType, currentIP)
			writeJsonLog("INFO", "update", fqdn, msg)
			return true
		}
		fmt.Printf("🆗 %-4s für %-30s ist aktuell.\n", rType, fqdn)
		return false
	}
	
	fmt.Printf("🆕 Erstelle %s für %s: %s\n", rType, fqdn, currentIP)
	sendCreate(zoneID, fqdn, rType, currentIP)
	writeJsonLog("INFO", "create", fqdn, "Record neu angelegt")
	return true
}

// ---------------- API & NET HELPERS ----------------

func getIPv6() string {
	iface, err := net.InterfaceByName(ifaceName)
	if err == nil {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() == nil {
				if ipnet.IP.IsGlobalUnicast() { return ipnet.IP.String() }
			}
		}
	}
	return getPublicIP("https://6.ident.me/")
}

func ionosAPI(method, url string, body interface{}) ([]byte, error) {
	var bodyReader io.Reader
	var bodyBytes []byte
	if body != nil {
		bodyBytes, _ = json.Marshal(body)
		bodyReader = bytes.NewBuffer(bodyBytes)
	}

	if debugMode {
		fmt.Printf("🔍 DEBUG: %s %s | Body: %s\n", method, url, string(bodyBytes))
	}

	req, _ := http.NewRequest(method, url, bodyReader)
	req.Header.Set("X-API-Key", fmt.Sprintf("%s.%s", apiPrefix, apiSecret))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		if debugMode { fmt.Printf("⚠️ DEBUG-ERR: %v\n", err) }
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	
	if debugMode {
		fmt.Printf("📥 DEBUG-RES: Status %d | Response: %s\n", resp.StatusCode, string(data))
	}

	return data, err
}


func getZones() ([]Zone, error) {
	data, err := ionosAPI("GET", apiBaseURL, nil)
	if err != nil { return nil, err }
	var zones []Zone
	if strings.Contains(string(data), "\"items\"") {
		var wrapper struct { Items []Zone `json:"items"` }
		json.Unmarshal(data, &wrapper)
		zones = wrapper.Items
	} else { json.Unmarshal(data, &zones) }
	sort.Slice(zones, func(i, j int) bool { return zones[i].Name < zones[j].Name })
	return zones, nil
}

func getZoneDetails(zoneID string) (ZoneDetail, error) {
	data, err := ionosAPI("GET", apiBaseURL+"/"+zoneID, nil)
	var detail ZoneDetail
	if err != nil { return detail, err }
	json.Unmarshal(data, &detail)
	return detail, nil
}

func getPublicIP(url string) string {
	resp, err := http.Get(url)
	if err != nil { return "" }
	defer resp.Body.Close()
	ip, _ := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(ip))
}

func sendUpdate(zoneID, fqdn, rType, ip string) {
	payload := []map[string]interface{}{{"name": fqdn, "type": rType, "content": ip, "ttl": 60}}
	ionosAPI("PATCH", apiBaseURL+"/"+zoneID, payload)
}

func sendCreate(zoneID, fqdn, rType, ip string) {
	payload := []map[string]interface{}{{"name": fqdn, "type": rType, "content": ip, "ttl": 60}}
	ionosAPI("POST", apiBaseURL+"/"+zoneID+"/records", payload)
}

func printInfrastructure(zones []Zone) {
	fmt.Println("\n📂 --- IONOS Infrastruktur Analyse (Go) ---")
	for _, z := range zones {
		detail, _ := getZoneDetails(z.ID)
		fmt.Printf("\n🌍 Zone: %s\n", z.Name)
		relevant := []Record{}
		for _, r := range detail.Records {
			if r.Type == "A" || r.Type == "AAAA" || r.Type == "CNAME" { relevant = append(relevant, r) }
		}
		sort.Slice(relevant, func(i, j int) bool { return relevant[i].Name < relevant[j].Name })
		for _, r := range relevant { fmt.Printf("   ┣━ %-35s [%-5s] -> %s\n", r.Name, r.Type, r.Content) }
	}
	fmt.Println("\n--------------------------------------------\n")
}

func getEnvInt(key string, fallback int) int {
	if val := os.Getenv(key); val != "" {
		var res int
		fmt.Sscanf(val, "%d", &res)
		return res
	}
	return fallback
}
