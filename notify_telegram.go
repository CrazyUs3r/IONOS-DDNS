// Package main
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// TELEGRAM NOTIFIER
// ============================================================================
func newTelegramNotifier(token, chatID string) *telegramNotifier {
	return &telegramNotifier{
		token:       token,
		chatID:      chatID,
		instanceTag: generateInstanceTag(),
	}
}

func (t *telegramNotifier) Name() string { return "Telegram" }

// ============================================================================
// SEND (outbound notifications)
// ============================================================================
func (t *telegramNotifier) Send(msg NotifyMessage) error {
	text := formatTelegramMessage(msg, t.instanceTag)
	return t.sendText(t.chatID, text, nil)
}

func (t *telegramNotifier) sendText(chatID, text string, kb *tgInlineKeyboard) error {
	payload := map[string]interface{}{
		"chat_id":    chatID,
		"text":       text,
		"parse_mode": "HTML",
	}
	if kb != nil {
		payload["reply_markup"] = kb
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

func (t *telegramNotifier) deleteMessage(chatID int64, messageID int) {
	payload := map[string]interface{}{
		"chat_id":    chatID,
		"message_id": messageID,
	}
	body, _ := json.Marshal(payload)
	url := fmt.Sprintf("https://api.telegram.org/bot%s/deleteMessage", t.token)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", ManagedComment)
	resp, err := getHTTPClient().Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

func (t *telegramNotifier) answerCallback(callbackID string) {
	payload := map[string]interface{}{"callback_query_id": callbackID}
	body, _ := json.Marshal(payload)
	url := fmt.Sprintf("https://api.telegram.org/bot%s/answerCallbackQuery", t.token)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := getHTTPClient().Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

// ============================================================================
// POLLING LOOP
// ============================================================================
func (t *telegramNotifier) StartPolling() {
	t.pollOnce.Do(func() {
		go t.pollingLoop()
	})
}

func (t *telegramNotifier) pollingLoop() {
	debugLog("NOTIFY", "", "📡 Telegram Bot Polling gestartet")
	go t.registerCommands()

	for {
		select {
		case <-shutdownCtx.Done():
			debugLog("NOTIFY", "", "📡 Telegram Polling gestoppt")
			return
		default:
		}

		updates, err := t.getUpdates(int(t.lastOffset.Load()) + 1)
		if err != nil {
			debugLog("NOTIFY", "", fmt.Sprintf("⚠️ Telegram getUpdates Fehler: %v", err))
			select {
			case <-shutdownCtx.Done():
				return
			case <-time.After(10 * time.Second):
			}
			continue
		}

		for _, u := range updates {
			if int32(u.UpdateID) > t.lastOffset.Load() {
				t.lastOffset.Store(int32(u.UpdateID))
			}
			u := u
			if u.CallbackQuery != nil {
				go t.handleCallback(u.CallbackQuery)
				continue
			}
			if u.Message != nil {
				go t.handleCommand(u.Message)
			}
		}

		select {
		case <-shutdownCtx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func (t *telegramNotifier) getUpdates(offset int) ([]tgUpdateFull, error) {
	url := fmt.Sprintf(
		`https://api.telegram.org/bot%s/getUpdates?offset=%d&timeout=30&allowed_updates=["message","callback_query"]`,
		t.token, offset,
	)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ManagedComment)

	resp, err := getHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var result struct {
		OK     bool           `json:"ok"`
		Result []tgUpdateFull `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	if !result.OK {
		return nil, fmt.Errorf("telegram getUpdates not OK")
	}

	return result.Result, nil
}

func (t *telegramNotifier) registerCommands() {
	commands := []map[string]string{
		{"command": "start", "description": "Hauptmenü anzeigen"},
		{"command": "status", "description": "System-Status & IPs"},
		{"command": "metrics", "description": "API-Metriken anzeigen"},
		{"command": "domains", "description": "Alle Domains & IPs auflisten"},
		{"command": "update", "description": "Manuelles DNS-Update starten"},
		{"command": "health", "description": "Health-Check abfragen"},
		{"command": "help", "description": "Alle Befehle anzeigen"},
	}
	payload := map[string]interface{}{"commands": commands}
	body, _ := json.Marshal(payload)
	url := fmt.Sprintf("https://api.telegram.org/bot%s/setMyCommands", t.token)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", ManagedComment)
	resp, err := getHTTPClient().Do(req)
	if err != nil {
		debugLog("NOTIFY", "", fmt.Sprintf("⚠️ setMyCommands fehlgeschlagen: %v", err))
		return
	}
	_ = resp.Body.Close()
	debugLog("NOTIFY", "", "✅ Telegram Bot-Commands registriert")
}

// ============================================================================
// AUTH
// ============================================================================
func (t *telegramNotifier) isAuthorized(chatID string) bool {
	return strings.TrimSpace(chatID) == strings.TrimSpace(t.chatID)
}

func chatIDStr(id int64) string {
	return fmt.Sprintf("%d", id)
}

// ============================================================================
// COMMAND HANDLER
// ============================================================================
func (t *telegramNotifier) handleCommand(msg *tgMessage) {
	chatID := chatIDStr(msg.Chat.ID)
	if !t.isAuthorized(chatID) {
		debugLog("NOTIFY", "", fmt.Sprintf("⛔ Telegram: Unberechtigter Zugriff von chat %s", chatID))
		return
	}

	text := strings.TrimSpace(msg.Text)
	if idx := strings.Index(text, "@"); idx > 0 && strings.HasPrefix(text, "/") {
		text = text[:idx]
	}
	cmd := strings.ToLower(text)

	switch cmd {
	case "/start", "/help":
		t.sendMainMenu(chatID)
	case "/status":
		t.sendStatus(chatID)
	case "/metrics":
		t.sendMetrics(chatID)
	case "/domains":
		t.sendDomains(chatID)
	case "/update":
		t.triggerUpdate(chatID)
	case "/health":
		t.sendHealth(chatID)
	default:
		if strings.HasPrefix(cmd, "/") {
			_ = t.sendText(chatID, "❓ Unbekannter Befehl. Tippe /help für alle Befehle.", nil)
		}
	}
}

// ============================================================================
// CALLBACK HANDLER
// ============================================================================
func (t *telegramNotifier) handleCallback(cb *tgCallbackQuery) {
	chatID := chatIDStr(cb.Message.Chat.ID)
	t.answerCallback(cb.ID)
	if !t.isAuthorized(chatID) {
		return
	}

	switch cb.Data {
	case "menu":
		t.sendMainMenu(chatID)
	case "status":
		t.sendStatus(chatID)
	case "metrics":
		t.sendMetrics(chatID)
	case "domains":
		t.sendDomains(chatID)
	case "update":
		t.triggerUpdate(chatID)
	case "health":
		t.sendHealth(chatID)
	case "close":
		t.deleteMessage(cb.Message.Chat.ID, cb.Message.MessageID)
	}
}

// ============================================================================
// KEYBOARDS
// ============================================================================
func mainKeyboard() *tgInlineKeyboard {
	return &tgInlineKeyboard{
		InlineKeyboard: [][]tgInlineButton{
			{
				{Text: "📊 Status", CallbackData: "status"},
				{Text: "📈 Metriken", CallbackData: "metrics"},
			},
			{
				{Text: "🌐 Domains", CallbackData: "domains"},
				{Text: "❤️ Health", CallbackData: "health"},
			},
			{
				{Text: "🔄 Update starten", CallbackData: "update"},
			},
			{
				{Text: "✖ Schließen", CallbackData: "close"},
			},
		},
	}
}

func backKeyboard() *tgInlineKeyboard {
	return &tgInlineKeyboard{
		InlineKeyboard: [][]tgInlineButton{
			{
				{Text: "🏠 Menü", CallbackData: "menu"},
				{Text: "🔄 Update", CallbackData: "update"},
			},
			{
				{Text: "✖ Schließen", CallbackData: "close"},
			},
		},
	}
}

// ============================================================================
// VIEWS
// ============================================================================
func (t *telegramNotifier) sendMainMenu(chatID string) {
	text := fmt.Sprintf(
		"<b>🌐 Go-DynDNS</b>  <code>%s</code>\n\nWas möchtest du tun?",
		t.instanceTag,
	)
	_ = t.sendText(chatID, text, mainKeyboard())
}

func (t *telegramNotifier) sendStatus(chatID string) {
	stats := apiMetrics.GetStats()

	status := "✅ Online"
	if !lastOk.Load() {
		status = "❌ Fehler"
	}
	if !schedulerRanOnce.Load() {
		status = "⏳ Startet..."
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "<b>📊 System Status</b>  <code>%s</code>\n\n", t.instanceTag)
	fmt.Fprintf(&sb, "🔸 Status:      <b>%s</b>\n", status)
	fmt.Fprintf(&sb, "🔸 IP-Modus:    <code>%s</code>\n", cfg.IPMode)
	fmt.Fprintf(&sb, "🔸 Domains:     <code>%d</code>\n", len(cfg.DomainConfigs))
	fmt.Fprintf(&sb, "🔸 Intervall:   <code>%ds</code>\n", cfg.Interval)
	fmt.Fprintf(&sb, "🔸 Dry-Run:     <code>%v</code>\n", cfg.DryRun)
	fmt.Fprintf(&sb, "🔸 Anfragen:    <code>%v</code>\n", stats["total_requests"])
	fmt.Fprintf(&sb, "🔸 Erfolgsrate: <code>%v</code>\n", stats["success_rate"])
	fmt.Fprintf(&sb, "🔸 Ø Latenz:    <code>%v</code>\n", stats["avg_latency"])
	fmt.Fprintf(&sb, "🔸 Letzter OK:  <code>%v</code>\n", stats["last_success_time"])
	fmt.Fprintf(&sb, "\n🕒 <i>%s</i>", time.Now().Local().Format("02.01.2006 15:04:05"))

	_ = t.sendText(chatID, sb.String(), backKeyboard())
}

func (t *telegramNotifier) sendMetrics(chatID string) {
	stats := apiMetrics.GetStats()

	var sb strings.Builder
	fmt.Fprintf(&sb, "<b>📈 API Metriken</b>  <code>%s</code>\n\n", t.instanceTag)

	fmt.Fprintf(&sb, "<b>Requests</b>\n")
	fmt.Fprintf(&sb, "  Gesamt:      <code>%v</code>\n", stats["total_requests"])
	fmt.Fprintf(&sb, "  Erfolgsrate: <code>%v</code>\n", stats["success_rate"])
	fmt.Fprintf(&sb, "  Client-Err:  <code>%v</code>\n", stats["client_errors"])
	fmt.Fprintf(&sb, "  Server-Err:  <code>%v</code>\n", stats["server_errors"])

	fmt.Fprintf(&sb, "\n<b>Latenz</b>\n")
	fmt.Fprintf(&sb, "  Ø:   <code>%v</code>\n", stats["avg_latency"])
	fmt.Fprintf(&sb, "  P50: <code>%v</code>\n", stats["p50_latency"])
	fmt.Fprintf(&sb, "  P85: <code>%v</code>\n", stats["p85_latency"])
	fmt.Fprintf(&sb, "  P99: <code>%v</code>\n", stats["p99_latency"])

	fmt.Fprintf(&sb, "\n<b>IP-Check</b>\n")
	fmt.Fprintf(&sb, "  Ø:       <code>%v</code>\n", stats["ip_latency_avg"])
	fmt.Fprintf(&sb, "  Checks:  <code>%v</code>\n", stats["ip_latency_count"])
	fmt.Fprintf(&sb, "  Letzter: <code>%v</code>\n", stats["last_ip_check"])

	fmt.Fprintf(&sb, "\n<b>Stunden-Limit</b>\n")
	fmt.Fprintf(&sb, "  Genutzt: <code>%v / %v</code>\n", stats["usage_count"], stats["hourly_limit"])
	fmt.Fprintf(&sb, "  Auslast: <code>%v%%</code>\n", stats["usage_percent"])

	fmt.Fprintf(&sb, "\n<b>Heute (HTTP)</b>\n")
	fmt.Fprintf(&sb, "  GET: <code>%v</code>  POST: <code>%v</code>  PUT: <code>%v</code>  DEL: <code>%v</code>",
		stats["daily_get"], stats["daily_post"], stats["daily_put"], stats["daily_delete"])
	if v, ok := stats["daily_nic"]; ok {
		fmt.Fprintf(&sb, "  NIC: <code>%v</code>", v)
	}
	fmt.Fprintf(&sb, "\n\n🕒 <i>%s</i>", time.Now().Local().Format("02.01.2006 15:04:05"))

	_ = t.sendText(chatID, sb.String(), backKeyboard())
}

func (t *telegramNotifier) sendDomains(chatID string) {
	var sb strings.Builder
	fmt.Fprintf(&sb, "<b>🌐 Domains</b>  <code>%s</code>\n\n", t.instanceTag)

	if len(cfg.DomainConfigs) == 0 {
		sb.WriteString("Keine Domains konfiguriert.")
	} else {
		for _, dc := range cfg.DomainConfigs {
			fmt.Fprintf(&sb, "🔹 <code>%s</code>  <i>(%s)</i>\n", dc.FQDN, dc.Provider)
		}
	}

	statusMutex.Lock()
	statusData := make(map[string]DomainHistory)
	if b, err := os.ReadFile(updatePath); err == nil {
		_ = json.Unmarshal(b, &statusData)
	}
	statusMutex.Unlock()

	if len(statusData) > 0 {
		sb.WriteString("\n<b>Aktuelle IPs</b>\n")
		for domain, h := range statusData {
			if len(h.IPs) == 0 {
				continue
			}
			latest := h.IPs[len(h.IPs)-1]
			fmt.Fprintf(&sb, "\n🌐 <code>%s</code>\n", domain)
			if latest.IPv4 != "" {
				fmt.Fprintf(&sb, "  v4: <code>%s</code>\n", latest.IPv4)
			}
			if latest.IPv6 != "" {
				fmt.Fprintf(&sb, "  v6: <code>%s</code>\n", latest.IPv6)
			}
			fmt.Fprintf(&sb, "  🕒 <i>%s</i>\n", latest.Time)
		}
	}

	fmt.Fprintf(&sb, "\n🕒 <i>%s</i>", time.Now().Local().Format("02.01.2006 15:04:05"))
	_ = t.sendText(chatID, sb.String(), backKeyboard())
}

func (t *telegramNotifier) sendHealth(chatID string) {
	var sb strings.Builder
	fmt.Fprintf(&sb, "<b>❤️ Health-Check</b>  <code>%s</code>\n\n", t.instanceTag)

	switch {
	case !schedulerRanOnce.Load():
		fmt.Fprintf(&sb, "⏳ Status: <b>Startet...</b>\n")
		sb.WriteString("Wartet auf ersten Scheduler-Lauf.\n")
	case lastOk.Load():
		fmt.Fprintf(&sb, "✅ Status: <b>Healthy</b>\n")
	default:
		fmt.Fprintf(&sb, "❌ Status: <b>Unhealthy</b>\n")
		if lastErr := lastErrorMsg.Get(); lastErr != "" {
			fmt.Fprintf(&sb, "Fehler: <code>%s</code>\n", lastErr)
		}
	}

	stats := apiMetrics.GetStats()
	fmt.Fprintf(&sb, "\n🔸 Erfolgsrate: <code>%v</code>\n", stats["success_rate"])
	fmt.Fprintf(&sb, "🔸 Ø Latenz:    <code>%v</code>\n", stats["avg_latency"])
	fmt.Fprintf(&sb, "🔸 Letzter OK:  <code>%v</code>\n", stats["last_success_time"])
	fmt.Fprintf(&sb, "\n🕒 <i>%s</i>", time.Now().Local().Format("02.01.2006 15:04:05"))

	_ = t.sendText(chatID, sb.String(), backKeyboard())
}

func (t *telegramNotifier) triggerUpdate(chatID string) {
	if !updateInProgress.CompareAndSwap(false, true) {
		_ = t.sendText(chatID, "ℹ️ Ein Update läuft bereits. Bitte kurz warten.", backKeyboard())
		return
	}

	_ = t.sendText(chatID, "🔄 <b>Manuelles Update wird gestartet...</b>", backKeyboard())

	go func() {
		defer updateInProgress.Store(false)
		debugLog("NOTIFY", "", "📡 Telegram: Manuelles Update ausgelöst")
		forceNextUpdate.Store(true)
		runUpdate(false)
		_ = t.sendText(chatID,
			fmt.Sprintf("✅ Update abgeschlossen.\n🕒 <i>%s</i>",
				time.Now().Local().Format("02.01.2006 15:04:05")),
			backKeyboard())
	}()
}

// ============================================================================
// TELEGRAM SEND
// ============================================================================
var instanceEmojis = []string{
	"🔵", "🟢", "🟡", "🟠", "🔴", "🟣", "⚫", "⚪",
	"🐶", "🐱", "🦊", "🐻", "🐼", "🐨", "🐯", "🦁",
	"🚀", "🌍", "⚡", "🔥", "❄️", "🌊", "🌈", "☀️",
}

func generateInstanceTag() string {
	pool := instanceEmojis
	a := pool[rand.Intn(len(pool))]
	b := pool[rand.Intn(len(pool))]
	if a == b {
		b = pool[rand.Intn(len(pool))]
	}
	return a + b
}

func formatTelegramMessage(msg NotifyMessage, instanceTag string) string {
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

	var sb strings.Builder
	fmt.Fprintf(&sb, "<b>%s Go-DynDNS</b>  <code>%s</code>\n", icon, instanceTag)
	if msg.Domain != "" {
		fmt.Fprintf(&sb, "🌐 <code>%s</code>\n", msg.Domain)
	}
	fmt.Fprintf(&sb, "📋 <b>%s</b>\n", msg.Action)
	fmt.Fprintf(&sb, "💬 %s\n", msg.Message)
	fmt.Fprintf(&sb, "🕒 <i>%s</i>", time.Now().Local().Format("02.01.2006 15:04:05"))
	return sb.String()
}