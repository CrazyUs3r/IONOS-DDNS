// Package main
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

type mqttNotifier struct {
	client          mqtt.Client
	topic           string
	qos             byte
	retain          bool
	discovery       bool
	discoveryPrefix string
	stateTopic      string
	clientID        string
	connected       bool
	discoverySent   bool
	mu              sync.RWMutex
}

// ============================================================================
// MQTT NOTIFIER
// ============================================================================
func (m *mqttNotifier) Name() string {
	return "mqtt"
}

func (m *mqttNotifier) isConnected() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.connected
}

func (m *mqttNotifier) setConnected(v bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connected = v
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
	if clientID == "" {
		clientID = "go-dyndns"
	}

	if discoveryPrefix == "" {
		discoveryPrefix = "homeassistant"
	}

	n := &mqttNotifier{
		topic:           topic,
		qos:             qos,
		retain:          retain,
		discovery:       discovery,
		discoveryPrefix: discoveryPrefix,
		stateTopic:      topic,
		clientID:        clientID,
	}

	opts := mqtt.NewClientOptions()
	opts.AddBroker(broker)

	opts.SetClientID(fmt.Sprintf("%s-%d", clientID, time.Now().UnixNano()))

	opts.SetUsername(username)
	opts.SetPassword(password)

	opts.SetAutoReconnect(true)
	opts.SetConnectRetry(true)
	opts.SetConnectRetryInterval(3 * time.Second)

	opts.SetConnectTimeout(5 * time.Second)
	opts.SetKeepAlive(30 * time.Second)
	opts.SetPingTimeout(5 * time.Second)

	if caFile != "" {
		certpool := x509.NewCertPool()
		ca, err := os.ReadFile(caFile)
		if err == nil && certpool.AppendCertsFromPEM(ca) {
			opts.SetTLSConfig(&tls.Config{
				RootCAs:    certpool,
				MinVersion: tls.VersionTLS12,
			})
		}
	}

	opts.OnConnect = func(c mqtt.Client) {
		n.setConnected(true)

		log(LogContext{
			Level:   LogInfo,
			Action:  ActionConfig,
			Message: "MQTT connected",
		})

		time.Sleep(200 * time.Millisecond)

		if n.discovery && !n.discoverySent {
			if err := n.publishDiscovery(c); err != nil {
				log(LogContext{
					Level:   LogError,
					Action:  ActionError,
					Message: fmt.Sprintf("MQTT discovery error: %v", err),
				})
			} else {
				n.discoverySent = true
				log(LogContext{
					Level:   LogInfo,
					Action:  ActionConfig,
					Message: "MQTT discovery published",
				})
			}
		}
	}

	opts.OnConnectionLost = func(_ mqtt.Client, err error) {
		n.setConnected(false)

		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: fmt.Sprintf("MQTT connection lost: %v", err),
		})
	}

	client := mqtt.NewClient(opts)
	n.client = client

	log(LogContext{
		Level:   LogInfo,
		Action:  ActionConfig,
		Message: fmt.Sprintf("MQTT connecting to %s", broker),
	})

	token := client.Connect()
	if token.Wait() && token.Error() != nil {
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: fmt.Sprintf("MQTT connect failed: %v", token.Error()),
		})
		return n
	}

	return n
}

func (m *mqttNotifier) Send(msg NotifyMessage) error {
	if !m.isConnected() {
		return fmt.Errorf("mqtt not connected")
	}

	payload := map[string]interface{}{
		"action":    msg.Action,
		"domain":    msg.Domain,
		"message":   msg.Message,
		"level":     msg.Level,
		"emoji":     levelEmoji(msg.Level),
		"timestamp": time.Now().Format("02.01.2006 15:04:05"),
		"source":    ManagedComment,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	logMQTTPublish(m.topic, m.qos, m.retain, data)

	token := m.client.Publish(m.topic, m.qos, m.retain, data)

	if m.qos > 0 {
		if ok := token.WaitTimeout(3 * time.Second); !ok {
			return fmt.Errorf("mqtt publish timeout")
		}
		if token.Error() != nil {
			return token.Error()
		}
	}

	return nil
}

func (m *mqttNotifier) publishDiscovery(client mqtt.Client) error {
	configTopic := fmt.Sprintf("%s/sensor/%s_ip/config",
		m.discoveryPrefix,
		m.clientID,
	)

	payload := map[string]interface{}{
		"name":                  "Go DynDNS",
		"unique_id":             fmt.Sprintf("%s_ip", m.clientID),
		"state_topic":           m.stateTopic,
		"value_template":        "{{ value_json.message }}",
		"json_attributes_topic": m.stateTopic,
		"icon":                  "mdi:dns",
		"device": map[string]interface{}{
			"name":         "Go DynDNS",
			"identifiers":  []string{m.clientID},
			"manufacturer": "custom",
			"model":        "Go-DynDNS-Service",
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	token := client.Publish(configTopic, 1, true, data)

	if ok := token.WaitTimeout(3 * time.Second); !ok {
		return fmt.Errorf("discovery timeout")
	}
	if token.Error() != nil {
		return token.Error()
	}

	return nil
}
