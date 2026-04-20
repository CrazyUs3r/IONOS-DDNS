// Package main
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// ============================================================================
// WEBHOOK NOTIFIER
// ============================================================================
type webhookNotifier struct {
	url    string
	secret string
}

func newWebhookNotifier(url, secret string) *webhookNotifier {
	return &webhookNotifier{url: url, secret: secret}
}

func (w *webhookNotifier) Name() string { return "Webhook" }

func (w *webhookNotifier) Send(msg NotifyMessage) error {
	return w.doSend(msg)
}

func (w *webhookNotifier) SendSync(msg NotifyMessage) error {
	return w.doSend(msg)
}

func (w *webhookNotifier) doSend(msg NotifyMessage) error {
	payload := map[string]interface{}{
		"action":    msg.Action,
		"domain":    msg.Domain,
		"message":   msg.Message,
		"level":     levelToString(msg.Level),
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("webhook marshal: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", ManagedComment)
	if w.secret != "" {
		req.Header.Set("X-Webhook-Secret", w.secret)
	}

	resp, err := getHTTPClient().Do(req)
	if err != nil {
		return fmt.Errorf("webhook send: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook HTTP %d", resp.StatusCode)
	}
	return nil
}
