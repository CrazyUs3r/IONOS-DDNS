// Package main
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
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
}

// ============================================================================
// MQTT NOTIFIER
// ============================================================================
func (m *mqttNotifier) Name() string {
	return "mqtt"
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

	if broker == "" {
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: "MQTT broker is empty",
		})
		return n
	}

	opts := mqtt.NewClientOptions()
	opts.AddBroker(broker)
	opts.SetClientID(clientID)

	if username != "" {
		opts.SetUsername(username)
		opts.SetPassword(password)
	}

	opts.SetAutoReconnect(true)
	opts.SetConnectTimeout(5 * time.Second)
	opts.SetConnectRetry(true)
	opts.SetConnectRetryInterval(5 * time.Second)

	opts.OnConnect = func(c mqtt.Client) {
		log(LogContext{
			Level:   LogInfo,
			Action:  ActionConfig,
			Message: "MQTT connected",
		})

		if n.discovery {
			if err := n.publishDiscovery(c); err != nil {
				log(LogContext{
					Level:   LogError,
					Action:  ActionError,
					Message: fmt.Sprintf("MQTT discovery publish error: %v", err),
				})
			}
		}
	}

	opts.OnConnectionLost = func(_ mqtt.Client, err error) {
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: fmt.Sprintf("MQTT connection lost: %v", err),
		})
	}

	if caFile != "" {
		certpool := x509.NewCertPool()

		ca, err := os.ReadFile(caFile)
		if err != nil {
			log(LogContext{
				Level:   LogError,
				Action:  ActionError,
				Message: fmt.Sprintf("MQTT CA file read error: %v", err),
			})
		} else if ok := certpool.AppendCertsFromPEM(ca); !ok {
			log(LogContext{
				Level:   LogError,
				Action:  ActionError,
				Message: "MQTT CA file contains no valid certificates",
			})
		} else {
			opts.SetTLSConfig(&tls.Config{
				RootCAs:    certpool,
				MinVersion: tls.VersionTLS12,
			})
		}
	}

	client := mqtt.NewClient(opts)
	n.client = client

	log(LogContext{
		Level:   LogInfo,
		Action:  ActionConfig,
		Message: fmt.Sprintf("MQTT connecting to %s", broker),
	})

	go func() {
		token := client.Connect()
		if token.Wait() && token.Error() != nil {
			log(LogContext{
				Level:   LogError,
				Action:  ActionError,
				Message: fmt.Sprintf("MQTT background connect error: %v", token.Error()),
			})
		}
	}()
	return n
}

func (m *mqttNotifier) Send(msg NotifyMessage) error {
	if m.client == nil || !m.client.IsConnected() {
		return fmt.Errorf("mqtt client not connected")
	}

	payload := map[string]interface{}{
		"action":    msg.Action,
		"domain":    msg.Domain,
		"message":   msg.Message,
		"level":     msg.Level,
		"timestamp": time.Now().Unix(),
		"source":    ManagedComment,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	logMQTTPublish(m.topic, m.qos, m.retain, data)

	token := m.client.Publish(m.topic, m.qos, m.retain, data)

	if !token.WaitTimeout(5 * time.Second) {
		return fmt.Errorf("mqtt publish timeout")
	}

	return token.Error()
}

func (m *mqttNotifier) publishDiscovery(client mqtt.Client) error {
	configTopic := fmt.Sprintf("%s/sensor/%s_ip/config", m.discoveryPrefix, m.clientID)

	payload := map[string]interface{}{
		"name":                  "Go DynDNS IP",
		"unique_id":             fmt.Sprintf("%s_ip", m.clientID),
		"state_topic":           m.stateTopic,
		"value_template":        "{{ value_json.message }}",
		"json_attributes_topic": m.stateTopic,
		"device": map[string]interface{}{
			"name":         "Go DynDNS",
			"identifiers":  []string{m.clientID},
			"manufacturer": "custom",
			"model":        "dyndns-notifier",
		},
		"icon": "mdi:wan",
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	logMQTTPublish(configTopic, 1, true, data)

	token := client.Publish(configTopic, 1, true, data)

	if !token.WaitTimeout(5 * time.Second) {
		return fmt.Errorf("mqtt discovery publish timeout")
	}

	return token.Error()
}
