// Package main
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ============================================================================
// GOTIFY NOTIFIER
// ============================================================================
type gotifyNotifier struct {
	url   string
	token string
}

func newGotifyNotifier(url, token string) *gotifyNotifier {
	url = strings.TrimRight(url, "/")
	return &gotifyNotifier{url: url, token: token}
}

func (g *gotifyNotifier) Name() string { return "Gotify" }

func (g *gotifyNotifier) Send(msg NotifyMessage) error {
	title, body := formatGotifyMessage(msg)

	payload := map[string]interface{}{
		"title":    title,
		"message":  body,
		"priority": gotifyPriority(msg.Level),
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	endpoint := fmt.Sprintf("%s/message?token=%s", g.url, g.token)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", ManagedComment)

	resp, err := getHTTPClient().Do(req)
	if err != nil {
		return fmt.Errorf("send: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("gotify HTTP %d: %s", resp.StatusCode, string(b))
	}

	return nil
}

func formatGotifyMessage(msg NotifyMessage) (title, body string) {
	icon := levelEmoji(msg.Level)

	switch msg.Action {
	case ActionUpdate:
		icon = "🔄"
	case ActionCreate:
		icon = "🆕"
	case ActionStart:
		icon = "🚀"
	case ActionStop:
		icon = "🛑"
	case ActionCleanup:
		icon = "🧹"
	}

	title = fmt.Sprintf("%s Go-DynDNS · %s", icon, msg.Action)

	var sb strings.Builder
	if msg.Domain != "" {
		sb.WriteString(fmt.Sprintf("Domain: %s\n", msg.Domain))
	}
	sb.WriteString(msg.Message)
	sb.WriteString(fmt.Sprintf("\n%s", time.Now().Local().Format("02.01.2006 15:04:05")))

	return title, sb.String()
}

func gotifyPriority(level LogLevel) int {
	switch level {
	case LogError:
		return 8
	case LogWarn:
		return 5
	default:
		return 3
	}
}
