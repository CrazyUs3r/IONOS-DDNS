// Package main
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// ============================================================================.
type webhookNotifier struct {
	ctx    context.Context
	cancel context.CancelFunc
	url    string
	secret string
}

func newWebhookNotifier(url, secret string) *webhookNotifier {
	ctx, cancel := context.WithCancel(notificationParentContext())

	return &webhookNotifier{url: url, secret: secret, ctx: ctx, cancel: cancel}
}

func (w *webhookNotifier) Name() string { return "Webhook" }

func (w *webhookNotifier) Close() { w.cancel() }

func (w *webhookNotifier) Send(msg NotifyMessage) error {
	return w.doSend(msg)
}

func (w *webhookNotifier) SendSync(msg NotifyMessage) error {
	return w.doSend(msg)
}

func webhookSignature(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)

	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func (w *webhookNotifier) doSend(msg NotifyMessage) error {
	payload := map[string]any{
		"action":    msg.Action,
		"domain":    msg.Domain,
		"message":   msg.Message,
		"level":     levelToString(msg.Level),
		"timestamp": time.Now().Format(time.RFC3339),
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("webhook marshal: %w", err)
	}

	const maxAttempts = 3
	wait := 5 * time.Second

	for attempt := range maxAttempts {
		err := w.trySend(data)
		if err == nil {
			return nil
		}

		if attempt == maxAttempts-1 {
			return err
		}

		debugLog("NOTIFY", "", fmt.Sprintf("⌛ Webhook retry %d/%d: %v", attempt+1, maxAttempts, err))
		timer := time.NewTimer(wait)
		select {
		case <-w.ctx.Done():
			stopNotifyTimer(timer)

			return err
		case <-timer.C:
		}
		wait *= 2
	}

	return nil
}

func (w *webhookNotifier) trySend(data []byte) error {
	ctx, cancel := context.WithTimeout(w.ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, MethodPOST, w.url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", ManagedComment)
	if w.secret != "" {
		req.Header.Set("X-Hub-Signature-256", webhookSignature(w.secret, data))
	}

	resp, err := getHTTPClient().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return nil
}
