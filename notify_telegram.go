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
// TELEGRAM NOTIFIER
// ============================================================================
type telegramNotifier struct {
	token  string
	chatID string
}

func newTelegramNotifier(token, chatID string) *telegramNotifier {
	return &telegramNotifier{token: token, chatID: chatID}
}

func (t *telegramNotifier) Name() string { return "Telegram" }

func (t *telegramNotifier) Send(msg NotifyMessage) error {
	text := formatTelegramMessage(msg)

	payload := map[string]interface{}{
		"chat_id":    t.chatID,
		"text":       text,
		"parse_mode": "HTML",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.token)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
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

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("telegram HTTP %d: %s", resp.StatusCode, string(b))
	}

	var result struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if !result.OK {
		return fmt.Errorf("telegram error: %s", result.Description)
	}

	return nil
}

func formatTelegramMessage(msg NotifyMessage) string {
	var sb strings.Builder

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

	fmt.Fprintf(&sb, "<b>%s Go-DynDNS</b>\n", icon)

	if msg.Domain != "" {
		fmt.Fprintf(&sb, "🌐 <code>%s</code>\n", msg.Domain)
	}

	fmt.Fprintf(&sb, "📋 <b>%s</b>\n", msg.Action)
	fmt.Fprintf(&sb, "💬 %s\n", msg.Message)
	fmt.Fprintf(&sb, "🕒 <i>%s</i>", time.Now().Local().Format("02.01.2006 15:04:05"))

	return sb.String()
}
