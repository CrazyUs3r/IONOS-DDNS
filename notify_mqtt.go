// Package main
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"maps"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

type mqttNotifier struct {
	client             mqtt.Client
	discoveryID        string
	domainsTopic       string
	commandResultTopic string
	stateTopic         string
	clientID           string
	commandPrefix      string
	availabilityTopic  string
	discoveryPrefix    string
	baseTopic          string
	topic              string
	mu                 sync.RWMutex
	closed             atomic.Bool
	qos                byte
	discovery          bool
	retain             bool
	connected          bool
}

// ============================================================================.
func (m *mqttNotifier) Name() string { return "Mqtt" }

func (m *mqttNotifier) isConnected() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.connected
}

func (m *mqttNotifier) setConnected(v bool) {
	m.mu.Lock()
	m.connected = v
	m.mu.Unlock()
}

func newMQTTNotifier(
	broker string,
	clientID string,
	username string,
	password string,
	topic string,
	qos byte,
	retain bool,
	caFile string,
	discovery bool,
	discoveryPrefix string,
) *mqttNotifier {
	if strings.TrimSpace(clientID) == "" {
		clientID = "go-dyndns"
	}
	if strings.TrimSpace(discoveryPrefix) == "" {
		discoveryPrefix = "homeassistant"
	}
	if strings.TrimSpace(topic) == "" {
		topic = "go-dyndns/events"
	}

	eventTopic := strings.TrimRight(strings.TrimSpace(topic), "/")
	baseTopic := deriveMQTTBaseTopic(eventTopic)
	discoveryID := mqttObjectID(clientID)

	n := &mqttNotifier{
		topic:              eventTopic,
		qos:                qos,
		retain:             retain,
		discovery:          discovery,
		discoveryPrefix:    strings.TrimRight(discoveryPrefix, "/"),
		discoveryID:        discoveryID,
		stateTopic:         baseTopic + "/state",
		clientID:           clientID,
		baseTopic:          baseTopic,
		domainsTopic:       baseTopic + "/domains",
		availabilityTopic:  baseTopic + "/availability",
		commandPrefix:      baseTopic + "/command",
		commandResultTopic: baseTopic + "/command/result",
	}

	opts := mqtt.NewClientOptions()
	opts.AddBroker(broker)
	opts.SetClientID(runtimeMQTTClientID(clientID))
	opts.SetCleanSession(true)
	opts.SetOrderMatters(false)

	if username != "" {
		opts.SetUsername(username)
	}
	if password != "" {
		opts.SetPassword(password)
	}

	opts.SetAutoReconnect(true)
	opts.SetConnectRetry(true)
	opts.SetConnectRetryInterval(3 * time.Second)
	opts.SetMaxReconnectInterval(30 * time.Second)
	opts.SetConnectTimeout(5 * time.Second)
	opts.SetWriteTimeout(5 * time.Second)
	opts.SetKeepAlive(30 * time.Second)
	opts.SetPingTimeout(5 * time.Second)
	opts.SetWill(n.availabilityTopic, "offline", 1, true)
	opts.SetDefaultPublishHandler(func(_ mqtt.Client, _ mqtt.Message) {})

	if caFile != "" {
		certPool := x509.NewCertPool()
		ca, err := os.ReadFile(caFile)
		switch {
		case err != nil:
			log(LogContext{
				Level:   LogError,
				Action:  ActionError,
				Message: fmt.Sprintf(phrases().MqttCAFileReadError, err),
			})
		case !certPool.AppendCertsFromPEM(ca):
			log(LogContext{
				Level:   LogError,
				Action:  ActionError,
				Message: phrases().MqttCAFileInvalid,
			})
		default:
			opts.SetTLSConfig(&tls.Config{
				RootCAs:    certPool,
				MinVersion: tls.VersionTLS12,
			})
		}
	}

	opts.OnConnect = func(c mqtt.Client) {
		if n.closed.Load() {
			c.Disconnect(0)

			return
		}
		n.setConnected(true)
		log(LogContext{
			Level:   LogInfo,
			Action:  ActionConfig,
			Message: phrases().MqttConnected,
		})
		go n.afterConnect(c)
	}

	opts.OnConnectionLost = func(_ mqtt.Client, err error) {
		n.setConnected(false)
		if n.closed.Load() {
			return
		}
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: fmt.Sprintf(phrases().MqttConnectionLost, err),
		})
	}

	client := mqtt.NewClient(opts)
	n.client = client

	log(LogContext{
		Level:   LogInfo,
		Action:  ActionConfig,
		Message: fmt.Sprintf(phrases().MqttConnecting, broker),
	})

	token := client.Connect()
	if !token.WaitTimeout(6 * time.Second) {
		log(LogContext{
			Level:   LogWarn,
			Action:  ActionConfig,
			Message: phrases().MqttInitialConnectionPending,
		})

		return n
	}
	if err := token.Error(); err != nil {
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: fmt.Sprintf(phrases().MqttConnectFailed, err),
		})
	}

	return n
}

func (m *mqttNotifier) afterConnect(client mqtt.Client) {
	if m.closed.Load() {
		return
	}

	filters := map[string]byte{
		m.commandPrefix + "/update":   1,
		m.commandPrefix + "/refresh":  1,
		m.commandPrefix + "/status":   1,
		m.discoveryPrefix + "/status": 0,
	}

	token := client.SubscribeMultiple(filters, m.handleInbound)
	if !token.WaitTimeout(3 * time.Second) {
		log(LogContext{Level: LogError, Action: ActionError, Message: phrases().MqttSubscribeTimeout})
	} else if err := token.Error(); err != nil {
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: fmt.Sprintf(phrases().MqttSubscribeFailed, err),
		})
	}

	if m.closed.Load() {
		return
	}
	_ = m.publishRawWithClient(client, m.availabilityTopic, 1, true, []byte("online"))

	if m.closed.Load() {
		return
	}
	if m.discovery {
		if err := m.publishDiscovery(client); err != nil {
			log(LogContext{
				Level:   LogError,
				Action:  ActionError,
				Message: fmt.Sprintf(phrases().MqttDiscoveryError, err),
			})
		}
	}

	if m.closed.Load() {
		return
	}
	if err := m.publishSnapshot(client); err != nil {
		debugLog("MQTT", "", fmt.Sprintf(phrases().MqttStatePublishFailed, err))
	}
	if err := m.publishDomainStates(client); err != nil {
		debugLog("MQTT", "", fmt.Sprintf(phrases().MqttDomainStatePublishFailed, err))
	}
}

func (m *mqttNotifier) handleInbound(client mqtt.Client, message mqtt.Message) {
	if m.closed.Load() {
		return
	}
	topic := message.Topic()
	payload := append([]byte(nil), message.Payload()...)
	retained := message.Retained()

	go func() {
		if topic == m.discoveryPrefix+"/status" {
			if strings.EqualFold(strings.TrimSpace(string(payload)), "online") {
				if m.discovery {
					_ = m.publishDiscovery(client)
				}
				_ = m.publishSnapshot(client)
				_ = m.publishDomainStates(client)
			}

			return
		}

		if strings.HasPrefix(topic, m.commandPrefix+"/") {
			m.handleCommand(client, topic, payload, retained)
		}
	}()
}

func (m *mqttNotifier) Send(msg NotifyMessage) error {
	if m.closed.Load() {
		return errors.New(phrases().MqttNotConnected)
	}
	if !m.isConnected() {
		return errors.New(phrases().MqttNotConnected)
	}

	payload := map[string]any{
		"action":    msg.Action,
		"domain":    msg.Domain,
		"message":   msg.Message,
		"level":     msg.Level,
		"emoji":     notifyIcon(msg),
		"timestamp": time.Now().Format(statusTimestampLayout),
		"source":    ManagedComment,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	logMQTTPublish(m.topic, m.qos, m.retain, data)
	if err := m.publishRawWithClient(m.client, m.topic, m.qos, m.retain, data); err != nil {
		return err
	}

	switch msg.Action {
	case ActionStart, ActionStop, ActionUpdate, ActionCreate, ActionError,
		ActionRetry, ActionConfig, ActionCleanup, ActionServer:
		_ = m.publishSnapshot(m.client)
	}

	return nil
}

func (m *mqttNotifier) Close() {
	if !m.closed.CompareAndSwap(false, true) {
		return
	}
	if m.client != nil {
		if m.client.IsConnectionOpen() {
			_ = m.publishRawWithClient(m.client, m.availabilityTopic, 1, true, []byte("offline"))
		}
		m.client.Disconnect(500)
	}
	m.setConnected(false)
}

// ============================================================================.
func (m *mqttNotifier) publishSnapshot(client mqtt.Client) error {
	cfgMu.RLock()
	ipMode := cfg.IPMode
	domainCount := len(cfg.DomainConfigs)
	interval := cfg.Interval
	dryRun := cfg.DryRun
	cfgMu.RUnlock()

	serviceStatus := "online"
	if !schedulerRanOnce.Load() {
		serviceStatus = starting
	} else if !lastOk.Load() {
		serviceStatus = "error"
	}

	payload := map[string]any{
		"status":             serviceStatus,
		"healthy":            schedulerRanOnce.Load() && lastOk.Load(),
		"scheduler_started":  schedulerRanOnce.Load(),
		"update_in_progress": updateInProgress.Load(),
		"last_error":         lastErrorMsg.Get(),
		"ip_mode":            ipMode,
		"domain_count":       domainCount,
		"interval_seconds":   interval,
		"dry_run":            dryRun,
		"uptime_seconds":     int64(time.Since(startTime).Seconds()),
		"version":            Version,
		"build_date":         BuildDate,
		"vcs_ref":            VCSRef,
		"metrics":            apiMetrics.GetStats(),
		"timestamp":          time.Now().Format(statusTimestampLayout),
		"source":             ManagedComment,
	}

	return m.publishJSONWithClient(client, m.stateTopic, payload)
}

func (m *mqttNotifier) publishDomainStates(client mqtt.Client) error {
	statusData := make(map[string]DomainHistory)
	statusMutex.Lock()
	if updatePath != "" {
		if b, err := os.ReadFile(updatePath); err == nil {
			_ = json.Unmarshal(b, &statusData)
		}
	}
	statusMutex.Unlock()

	cfgMu.RLock()
	configured := make(map[string]string, len(cfg.DomainConfigs))
	for _, dc := range cfg.DomainConfigs {
		configured[dc.FQDN] = string(dc.Provider)
	}
	cfgMu.RUnlock()

	allDomains := make(map[string]struct{}, len(statusData)+len(configured))
	for domain := range statusData {
		allDomains[domain] = struct{}{}
	}
	for domain := range configured {
		allDomains[domain] = struct{}{}
	}

	domains := make([]string, 0, len(allDomains))
	for domain := range allDomains {
		domains = append(domains, domain)
	}
	sort.Strings(domains)

	aggregate := make(map[string]any, len(domains))
	for _, domain := range domains {
		history := statusData[domain]
		provider := history.Provider
		if provider == "" {
			provider = configured[domain]
		}

		var latest IPEntry
		if len(history.IPs) > 0 {
			latest = history.IPs[len(history.IPs)-1]
		}

		state := map[string]any{
			"domain":       domain,
			"provider":     provider,
			"ipv4":         latest.IPv4,
			"ipv6":         latest.IPv6,
			"sample_time":  latest.Time,
			"last_changed": history.LastChanged,
			"timestamp":    time.Now().Format(statusTimestampLayout),
		}
		aggregate[domain] = state

		domainID := mqttDomainID(domain)
		stateTopic := fmt.Sprintf("%s/domain/%s/state", m.baseTopic, domainID)
		if err := m.publishJSONWithClient(client, stateTopic, state); err != nil {
			return err
		}
		if m.discovery {
			if err := m.publishDomainDiscovery(client, domain, domainID, stateTopic); err != nil {
				return err
			}
		}
	}

	return m.publishJSONWithClient(client, m.domainsTopic, map[string]any{
		"count":     len(domains),
		"domains":   aggregate,
		"timestamp": time.Now().Format(statusTimestampLayout),
	})
}

// ============================================================================.
type mqttCommandRequest struct {
	RequestID string `json:"request_id"`
}

func (m *mqttNotifier) handleCommand(client mqtt.Client, topic string, payload []byte, retained bool) {
	command := strings.TrimPrefix(topic, m.commandPrefix+"/")
	requestID := mqttRequestID(payload)

	if retained {
		m.publishCommandResult(client, command, requestID, false, "rejected", phrases().MqttCmdRetainedIgnored)

		return
	}
	if len(payload) > 4096 {
		m.publishCommandResult(client, command, requestID, false, "rejected", phrases().MqttCmdPayloadTooLarge)

		return
	}

	switch command {
	case "update":
		if !validMQTTButtonPayload(payload, "UPDATE") {
			m.publishCommandResult(client, command, requestID, false, "rejected", phrases().MqttCmdInvalidUpdatePayload)

			return
		}
		if !updateInProgress.CompareAndSwap(false, true) {
			m.publishCommandResult(client, command, requestID, false, "busy", phrases().MqttCmdUpdateAlreadyRunning)

			return
		}

		m.publishCommandResult(client, command, requestID, true, "running", phrases().MqttCmdManualUpdateStarted)
		_ = m.publishSnapshot(client)

		go func() {
			defer updateInProgress.Store(false)
			debugLog("NOTIFY", "", phrases().MqttManualUpdateTriggered)
			forceNextUpdate.Store(true)
			runClaimedUpdate(false)

			status := "completed"
			message := phrases().MqttCmdManualUpdateCompleted
			accepted := true
			if !lastOk.Load() {
				status = "failed"
				message = phrases().MqttCmdManualUpdateFailed
				accepted = false
			}
			m.publishCommandResult(client, command, requestID, accepted, status, message)
			_ = m.publishSnapshot(client)
			_ = m.publishDomainStates(client)
		}()

	case "refresh", "status":
		if !validMQTTButtonPayload(payload, "REFRESH") {
			m.publishCommandResult(client, command, requestID, false, "rejected", phrases().MqttCmdInvalidRefreshPayload)

			return
		}
		if m.discovery {
			_ = m.publishDiscovery(client)
		}
		stateErr := m.publishSnapshot(client)
		domainErr := m.publishDomainStates(client)
		if stateErr != nil || domainErr != nil {
			m.publishCommandResult(client, command, requestID, false, "failed", phrases().MqttCmdStateRefreshFailed)

			return
		}
		m.publishCommandResult(client, command, requestID, true, "completed", phrases().MqttCmdStateRepublished)

	default:
		m.publishCommandResult(client, command, requestID, false, "rejected", phrases().MqttCmdUnknown)
	}
}

func (m *mqttNotifier) publishCommandResult(
	client mqtt.Client,
	command string,
	requestID string,
	accepted bool,
	status string,
	message string,
) {
	_ = m.publishJSONWithClient(client, m.commandResultTopic, map[string]any{
		"command":    command,
		"request_id": requestID,
		"accepted":   accepted,
		"status":     status,
		"message":    message,
		"timestamp":  time.Now().Format(statusTimestampLayout),
	})
}

func mqttRequestID(payload []byte) string {
	trimmed := strings.TrimSpace(string(payload))
	if !strings.HasPrefix(trimmed, "{") {
		return ""
	}
	var request mqttCommandRequest
	if json.Unmarshal(payload, &request) != nil {
		return ""
	}
	if len(request.RequestID) > 128 {
		return request.RequestID[:128]
	}

	return request.RequestID
}

func validMQTTButtonPayload(payload []byte, command string) bool {
	value := strings.TrimSpace(string(payload))
	if value == "" || strings.HasPrefix(value, "{") {
		return true
	}
	value = strings.ToUpper(value)

	return value == "PRESS" || value == "ON" || value == command
}

// ============================================================================.
func (m *mqttNotifier) publishDiscovery(client mqtt.Client) error {
	entities := []struct {
		payload   map[string]any
		component string
		objectID  string
	}{
		{
			component: "sensor",
			objectID:  m.discoveryID + "_ip",
			payload: m.discoveryEntity(phrases().MqttDiscoveryLastEvent, m.discoveryID+"_ip", map[string]any{
				"state_topic":           m.topic,
				"value_template":        "{{ value_json.message }}",
				"json_attributes_topic": m.topic,
				"icon":                  "mdi:message-alert-outline",
			}),
		},
		{
			component: "sensor",
			objectID:  m.discoveryID + "_status",
			payload: m.discoveryEntity(phrases().MqttDiscoveryStatus, m.discoveryID+"_status", map[string]any{
				"state_topic":    m.stateTopic,
				"value_template": "{{ value_json.status }}",
				"icon":           "mdi:dns",
			}),
		},
		{
			component: "binary_sensor",
			objectID:  m.discoveryID + "_health",
			payload: m.discoveryEntity(phrases().MqttDiscoveryHealth, m.discoveryID+"_health", map[string]any{
				"state_topic":    m.stateTopic,
				"value_template": "{{ 'ON' if value_json.healthy else 'OFF' }}",
				"payload_on":     "ON",
				"payload_off":    "OFF",
				"icon":           "mdi:heart-pulse",
			}),
		},
		{
			component: "binary_sensor",
			objectID:  m.discoveryID + "_update_running",
			payload: m.discoveryEntity(phrases().MqttDiscoveryUpdateRunning, m.discoveryID+"_update_running", map[string]any{
				"state_topic":    m.stateTopic,
				"value_template": "{{ 'ON' if value_json.update_in_progress else 'OFF' }}",
				"payload_on":     "ON",
				"payload_off":    "OFF",
				"icon":           "mdi:update",
			}),
		},
		{
			component: "sensor",
			objectID:  m.discoveryID + "_domains",
			payload: m.discoveryEntity(phrases().MqttDiscoveryDomains, m.discoveryID+"_domains", map[string]any{
				"state_topic":           m.stateTopic,
				"value_template":        "{{ value_json.domain_count }}",
				"json_attributes_topic": m.domainsTopic,
				"icon":                  "mdi:web",
			}),
		},
		{
			component: "sensor",
			objectID:  m.discoveryID + "_requests",
			payload: m.discoveryEntity(phrases().MqttDiscoveryRequests, m.discoveryID+"_requests", map[string]any{
				"state_topic":    m.stateTopic,
				"value_template": "{{ value_json.metrics.total_requests }}",
				"icon":           "mdi:counter",
			}),
		},
		{
			component: "sensor",
			objectID:  m.discoveryID + "_success_rate",
			payload: m.discoveryEntity(phrases().MqttDiscoverySuccessRate, m.discoveryID+"_success_rate", map[string]any{
				"state_topic":    m.stateTopic,
				"value_template": "{{ value_json.metrics.success_rate }}",
				"icon":           "mdi:percent",
			}),
		},
		{
			component: "sensor",
			objectID:  m.discoveryID + "_latency",
			payload: m.discoveryEntity(phrases().MqttDiscoveryAverageLatency, m.discoveryID+"_latency", map[string]any{
				"state_topic":    m.stateTopic,
				"value_template": "{{ value_json.metrics.avg_latency }}",
				"icon":           "mdi:timer-outline",
			}),
		},
		{
			component: "sensor",
			objectID:  m.discoveryID + "_uptime",
			payload: m.discoveryEntity(phrases().MqttDiscoveryUptime, m.discoveryID+"_uptime", map[string]any{
				"state_topic":         m.stateTopic,
				"value_template":      "{{ value_json.uptime_seconds }}",
				"device_class":        "duration",
				"unit_of_measurement": "s",
				"state_class":         "measurement",
			}),
		},
		{
			component: "sensor",
			objectID:  m.discoveryID + "_command_result",
			payload: m.discoveryEntity(phrases().MqttDiscoveryLastCommand, m.discoveryID+"_command_result", map[string]any{
				"state_topic":           m.commandResultTopic,
				"value_template":        "{{ value_json.status }}",
				"json_attributes_topic": m.commandResultTopic,
				"icon":                  "mdi:console-line",
				"entity_category":       "diagnostic",
			}),
		},
		{
			component: "button",
			objectID:  m.discoveryID + "_update",
			payload: m.discoveryEntity(phrases().MqttDiscoveryUpdateNow, m.discoveryID+"_update", map[string]any{
				"command_topic":   m.commandPrefix + "/update",
				"payload_press":   "PRESS",
				"retain":          false,
				"icon":            "mdi:update",
				"entity_category": "config",
			}),
		},
		{
			component: "button",
			objectID:  m.discoveryID + "_refresh",
			payload: m.discoveryEntity(phrases().MqttDiscoveryRefreshState, m.discoveryID+"_refresh", map[string]any{
				"command_topic":   m.commandPrefix + "/refresh",
				"payload_press":   "PRESS",
				"retain":          false,
				"icon":            "mdi:refresh",
				"entity_category": "config",
			}),
		},
	}

	for _, entity := range entities {
		if err := m.publishDiscoveryEntity(client, entity.component, entity.objectID, entity.payload); err != nil {
			return err
		}
	}

	log(LogContext{
		Level:   LogInfo,
		Action:  ActionConfig,
		Message: phrases().MqttDiscoveryPublished,
	})

	return nil
}

func (m *mqttNotifier) publishDomainDiscovery(
	client mqtt.Client,
	domain string,
	domainID string,
	stateTopic string,
) error {
	for _, family := range []struct {
		name string
		key  string
		icon string
	}{
		{name: phrases().MqttDiscoveryIPv4, key: "ipv4", icon: "mdi:ip-network"},
		{name: phrases().MqttDiscoveryIPv6, key: "ipv6", icon: "mdi:ip-network-outline"},
	} {
		objectID := fmt.Sprintf("%s_%s_%s", m.discoveryID, domainID, family.key)
		payload := m.discoveryEntity(domain+" "+family.name, objectID, map[string]any{
			"state_topic":           stateTopic,
			"value_template":        fmt.Sprintf("{{ value_json.%s }}", family.key),
			"json_attributes_topic": stateTopic,
			"icon":                  family.icon,
		})
		if err := m.publishDiscoveryEntity(client, "sensor", objectID, payload); err != nil {
			return err
		}
	}

	return nil
}

func (m *mqttNotifier) discoveryEntity(name, uniqueID string, extra map[string]any) map[string]any {
	payload := map[string]any{
		"name":                  name,
		"unique_id":             uniqueID,
		"availability_topic":    m.availabilityTopic,
		"payload_available":     "online",
		"payload_not_available": "offline",
		"device": map[string]any{
			"name":         "Go DynDNS",
			"identifiers":  []string{m.clientID},
			"manufacturer": "custom",
			"model":        "Go-DynDNS-Service",
			"sw_version":   Version,
		},
		"origin": map[string]any{
			"name":       "go-dyndns",
			"sw_version": Version,
		},
	}
	maps.Copy(payload, extra)

	return payload
}

func (m *mqttNotifier) publishDiscoveryEntity(
	client mqtt.Client,
	component string,
	objectID string,
	payload map[string]any,
) error {
	configTopic := fmt.Sprintf("%s/%s/%s/config", m.discoveryPrefix, component, mqttObjectID(objectID))

	return m.publishJSONWithClient(client, configTopic, payload)
}

// ============================================================================.
func (m *mqttNotifier) publishJSONWithClient(
	client mqtt.Client,
	topic string,
	payload any,
) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	return m.publishRawWithClient(client, topic, 1, true, data)
}

func (m *mqttNotifier) publishRawWithClient(
	client mqtt.Client,
	topic string,
	qos byte,
	retain bool,
	payload []byte,
) error {
	if client == nil || !client.IsConnectionOpen() {
		return errors.New(phrases().MqttNotConnected)
	}

	token := client.Publish(topic, qos, retain, payload)
	if !token.WaitTimeout(3 * time.Second) {
		return fmt.Errorf(phrases().MqttPublishTimeout, topic)
	}

	return token.Error()
}

// ============================================================================.
func deriveMQTTBaseTopic(eventTopic string) string {
	base := strings.TrimRight(eventTopic, "/")
	for _, suffix := range []string{"/events", "/event", "/notifications"} {
		if before, ok := strings.CutSuffix(base, suffix); ok {
			base = before

			break
		}
	}
	if base == "" {
		return "go-dyndns"
	}

	return base
}

func runtimeMQTTClientID(clientID string) string {
	base := mqttObjectID(clientID)
	if len(base) > 13 {
		base = base[:13]
	}

	h := fnv.New32a()
	_, _ = fmt.Fprintf(h, "%s:%d:%d", base, os.Getpid(), time.Now().UnixNano())

	return fmt.Sprintf("%s-%08x", base, h.Sum32())
}

func mqttObjectID(value string) string {
	value = strings.TrimSpace(value)
	var b strings.Builder
	b.Grow(len(value))
	lastUnderscore := false
	for _, r := range value {
		valid := (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_'
		if valid {
			b.WriteRune(r)
			lastUnderscore = false

			continue
		}
		if !lastUnderscore {
			b.WriteByte('_')
			lastUnderscore = true
		}
	}
	result := strings.Trim(b.String(), "_-")
	if result == "" {
		return "go_dyndns"
	}

	return result
}

func mqttDomainID(domain string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(strings.ToLower(domain)))
	base := mqttObjectID(strings.ReplaceAll(domain, ".", "_"))
	if len(base) > 40 {
		base = base[:40]
	}

	return fmt.Sprintf("%s_%08x", base, h.Sum32())
}
