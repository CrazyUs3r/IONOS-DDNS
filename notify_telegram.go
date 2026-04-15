// Package main
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// ============================================================================
// TELEGRAM NOTIFIER
// ============================================================================
func newTelegramNotifier(token, chatID string) *telegramNotifier {
	ctx, cancel := context.WithCancel(shutdownCtx)
	t := &telegramNotifier{
		token:       token,
		chatID:      chatID,
		instanceTag: generateInstanceTag(),
		sendQueue:   make(chan tgQueuedMsg, tgQueueSize),
		pollCtx:     ctx,
		pollCancel:  cancel,
	}
	go t.drainQueue()
	return t
}

func (t *telegramNotifier) getPollClient() *http.Client {
	t.pollClientOnce.Do(func() {
		t.pollClient = newTelegramPollClient()
	})
	return t.pollClient
}

func newTelegramPollClient() *http.Client {
	return &http.Client{
		Timeout: 45 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
			MaxIdleConns:        5,
			MaxIdleConnsPerHost: 2,
			MaxConnsPerHost:     3,
			IdleConnTimeout:     90 * time.Second,
			ForceAttemptHTTP2:   true,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
	}
}

func (t *telegramNotifier) Name() string { return "Telegram" }

// ============================================================================
// SEND (outbound notifications) — uses shared getHTTPClient()
// ============================================================================
func (t *telegramNotifier) Send(msg NotifyMessage) error {
	text := formatTelegramMessage(msg, t.instanceTag)
	t.enqueue(t.chatID, text, nil)
	return nil
}

func (t *telegramNotifier) SendSync(msg NotifyMessage) error {
	text := formatTelegramMessage(msg, t.instanceTag)
	return t.sendTextWithRetry(t.chatID, text, nil)
}

func (t *telegramNotifier) enqueue(chatID, text string, kb *tgInlineKeyboard) {
	msg := tgQueuedMsg{
		chatID:   chatID,
		text:     text,
		kb:       kb,
		enqueued: time.Now(),
	}
	select {
	case t.sendQueue <- msg:
	default:
		select {
		case dropped := <-t.sendQueue:
			debugLog("NOTIFY", "", fmt.Sprintf(
				T.TgQueueFull,
				time.Since(dropped.enqueued).Round(time.Second),
			))
		default:
		}
		select {
		case t.sendQueue <- msg:
		default:
			debugLog("NOTIFY", "", T.TgQueuePushFailed)
		}
	}
}

func (t *telegramNotifier) drainQueue() {
	ticker := time.NewTicker(tgSendInterval)
	defer ticker.Stop()

	for {
		select {
		case <-t.pollCtx.Done():
			deadline := time.After(10 * time.Second)
			for {
				select {
				case msg := <-t.sendQueue:
					if time.Since(msg.enqueued) < tgQueueMaxAge {
						_ = t.sendTextWithRetry(msg.chatID, msg.text, msg.kb)
					}
				case <-deadline:
					return
				}
			}

		case <-ticker.C:
			select {
			case msg := <-t.sendQueue:
				if time.Since(msg.enqueued) > tgQueueMaxAge {
					debugLog("NOTIFY", "", fmt.Sprintf(
						T.TgMsgDiscarded,
						time.Since(msg.enqueued).Round(time.Second),
					))
					continue
				}
				if err := t.sendTextWithRetry(msg.chatID, msg.text, msg.kb); err != nil {
					debugLog("NOTIFY", "", fmt.Sprintf(T.TgSendFailed, err))
				}
			default:

			}
		}
	}
}

func (t *telegramNotifier) sendTextWithRetry(chatID, text string, kb *tgInlineKeyboard) error {
	const maxRetries = 3
	wait := 5 * time.Second

	for attempt := 0; attempt < maxRetries; attempt++ {
		err := t.sendText(chatID, text, kb)
		if err == nil {
			return nil
		}
		if strings.Contains(err.Error(), "429") {
			debugLog("NOTIFY", "", fmt.Sprintf(
				T.TgRateLimit,
				wait, attempt+1, maxRetries,
			))
			select {
			case <-t.pollCtx.Done():
				return err
			case <-time.After(wait):
			}
			wait *= 2
			continue
		}
		return err
	}
	return errors.New(T.TgMaxRetries)
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
		return fmt.Errorf(T.TgHTTPError, resp.StatusCode, string(b))
	}

	var result struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if !result.OK {
		return fmt.Errorf(T.TgSendError, result.Description)
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

func (t *telegramNotifier) StopPolling() {
	t.pollCancel()
}

func (t *telegramNotifier) pollingLoop() {
	debugLog("NOTIFY", "", T.TgPollingStarted)
	defer t.deleteWebhook()
	go t.registerCommands()

	for {
		select {
		case <-t.pollCtx.Done():
			debugLog("NOTIFY", "", T.TgPollingStopped)
			return
		default:
		}

		updates, err := t.getUpdates(int(t.lastOffset.Load()) + 1)
		if err != nil {
			debugLog("NOTIFY", "", fmt.Sprintf(T.TgGetUpdatesFailed, err))
			select {
			case <-t.pollCtx.Done():
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
		case <-t.pollCtx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func (t *telegramNotifier) getUpdates(offset int) ([]tgUpdateFull, error) {
	url := fmt.Sprintf(
		"https://api.telegram.org/bot%s/getUpdates?offset=%d&timeout=30",
		t.token, offset,
	)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ManagedComment)

	resp, err := t.getPollClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var result struct {
		OK          bool           `json:"ok"`
		Result      []tgUpdateFull `json:"result"`
		Description string         `json:"description"`
		ErrorCode   int            `json:"error_code"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	if !result.OK {
		return nil, fmt.Errorf(T.TgGetUpdatesNotOk, result.ErrorCode, result.Description)
	}

	return result.Result, nil
}

func (t *telegramNotifier) registerCommands() {
	commands := []map[string]string{
		{"command": "start", "description": T.TgCmdStart},
		{"command": "status", "description": T.TgCmdStatus},
		{"command": "metrics", "description": T.TgCmdMetrics},
		{"command": "domains", "description": T.TgCmdDomains},
		{"command": "update", "description": T.TgCmdUpdate},
		{"command": "health", "description": T.TgCmdHealth},
		{"command": "help", "description": T.TgCmdHelp},
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
		debugLog("NOTIFY", "", fmt.Sprintf(T.TgSetCmdsFailed, err))
		return
	}
	_ = resp.Body.Close()
	debugLog("NOTIFY", "", T.TgBotCmdsReg)
}

func (t *telegramNotifier) deleteWebhook() {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/deleteWebhook?drop_pending_updates=false", t.token)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		debugLog("NOTIFY", "", fmt.Sprintf(T.TgWebhookDeleteRequestError, err))
		return
	}
	req.Header.Set("User-Agent", ManagedComment)
	resp, err := t.getPollClient().Do(req)
	if err != nil {
		debugLog("NOTIFY", "", fmt.Sprintf(T.TgWebhookDeleteFailed, err))
		return
	}
	_ = resp.Body.Close()
	debugLog("NOTIFY", "", T.TgWebhookUnregistered)
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
		debugLog("NOTIFY", "", fmt.Sprintf(T.TgUnauthAccess, chatID))
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
			t.enqueue(chatID, T.TgUnknownCommand, nil)
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
				{Text: T.TgBtnStatus, CallbackData: "status"},
				{Text: T.TgBtnMetrics, CallbackData: "metrics"},
			},
			{
				{Text: T.TgBtnDomains, CallbackData: "domains"},
				{Text: T.TgBtnHealth, CallbackData: "health"},
			},
			{
				{Text: T.TgBtnUpdate, CallbackData: "update"},
			},
			{
				{Text: T.TgBtnClose, CallbackData: "close"},
			},
		},
	}
}

func backKeyboard() *tgInlineKeyboard {
	return &tgInlineKeyboard{
		InlineKeyboard: [][]tgInlineButton{
			{
				{Text: T.TgBtnMenu, CallbackData: "menu"},
				{Text: T.TgBtnUpdate, CallbackData: "update"},
			},
			{
				{Text: T.TgBtnClose, CallbackData: "close"},
			},
		},
	}
}

// ============================================================================
// VIEWS
// ============================================================================
func (t *telegramNotifier) sendMainMenu(chatID string) {
	text := fmt.Sprintf(
		"<b>🌐 Go-DynDNS</b>  <code>%s</code>\n\n"+T.TgMenuPrompt,
		t.instanceTag,
	)
	t.enqueue(chatID, text, mainKeyboard())
}

func (t *telegramNotifier) sendStatus(chatID string) {
	stats := apiMetrics.GetStats()

	status := T.TgStatusOnline
	if !lastOk.Load() {
		status = T.TgStatusError
	}
	if !schedulerRanOnce.Load() {
		status = T.TgStatusStarting
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "<b>%s</b>  <code>%s</code>\n\n", T.TgStatusHeading, t.instanceTag)
	fmt.Fprintf(&sb, "🔸 %s      <b>%s</b>\n", T.TgStatusLabelStatus, status)
	fmt.Fprintf(&sb, "🔸 %s    <code>%s</code>\n", T.TgStatusLabelIPMode, cfg.IPMode)
	fmt.Fprintf(&sb, "🔸 %s     <code>%d</code>\n", T.TgStatusLabelDomains, len(cfg.DomainConfigs))
	fmt.Fprintf(&sb, "🔸 %s   <code>%ds</code>\n", T.TgStatusLabelInterval, cfg.Interval)
	fmt.Fprintf(&sb, "🔸 %s     <code>%v</code>\n", T.TgStatusLabelDryRun, cfg.DryRun)
	fmt.Fprintf(&sb, "🔸 %s    <code>%v</code>\n", T.TgStatusLabelRequests, stats["total_requests"])
	fmt.Fprintf(&sb, "🔸 %s: <code>%v</code>\n", T.TgStatusLabelSuccessRate, stats["success_rate"])
	fmt.Fprintf(&sb, "🔸 %s    <code>%v</code>\n", T.TgStatusLabelLatency, stats["avg_latency"])
	fmt.Fprintf(&sb, "🔸 %s  <code>%v</code>\n", T.TgStatusLabelLastOk, stats["last_success_time"])
	fmt.Fprintf(&sb, "\n🕒 <i>%s</i>", time.Now().Local().Format("02.01.2006 15:04:05"))

	t.enqueue(chatID, sb.String(), backKeyboard())
}

func (t *telegramNotifier) sendMetrics(chatID string) {
	stats := apiMetrics.GetStats()

	var sb strings.Builder
	fmt.Fprintf(&sb, "<b>%s</b>  <code>%s</code>\n\n", T.TgMetricsHeading, t.instanceTag)

	fmt.Fprintf(&sb, "<b>%s</b>\n", T.TgMetricsRequests)
	fmt.Fprintf(&sb, "  %s <code>%v</code>\n", T.TgMetricsTotal, stats["total_requests"])
	fmt.Fprintf(&sb, "  %s <code>%v</code>\n", T.TgMetricsSuccessRate, stats["success_rate"])
	fmt.Fprintf(&sb, "  %s  <code>%v</code>\n", T.TgMetricsClientErr, stats["client_errors"])
	fmt.Fprintf(&sb, "  %s  <code>%v</code>\n", T.TgMetricsServerErr, stats["server_errors"])

	fmt.Fprintf(&sb, "\n<b>%s</b>\n", T.TgMetricsLatency)
	fmt.Fprintf(&sb, "  Ø:   <code>%v</code>\n", stats["avg_latency"])
	fmt.Fprintf(&sb, "  P50: <code>%v</code>\n", stats["p50_latency"])
	fmt.Fprintf(&sb, "  P85: <code>%v</code>\n", stats["p85_latency"])
	fmt.Fprintf(&sb, "  P99: <code>%v</code>\n", stats["p99_latency"])

	fmt.Fprintf(&sb, "\n<b>%s</b>\n", T.TgMetricsIPCheck)
	fmt.Fprintf(&sb, "  Ø:       <code>%v</code>\n", stats["ip_latency_avg"])
	fmt.Fprintf(&sb, "  %s  <code>%v</code>\n", T.TgMetricsChecks, stats["ip_latency_count"])
	fmt.Fprintf(&sb, "  %s: <code>%v</code>\n", T.TgMetricsLast, stats["last_ip_check"])

	fmt.Fprintf(&sb, "\n<b>%s</b>\n", T.TgMetricsHourlyLimit)
	fmt.Fprintf(&sb, "  %s <code>%v / %v</code>\n", T.TgMetricsUsed, stats["usage_count"], stats["hourly_limit"])
	fmt.Fprintf(&sb, "  %s <code>%v%%</code>\n", T.TgMetricsLoad, stats["usage_percent"])

	fmt.Fprintf(&sb, "\n<b>%s</b>\n", T.TgMetricsTodayHTTP)
	fmt.Fprintf(&sb, "  GET: <code>%v</code>  POST: <code>%v</code>  PUT: <code>%v</code>  DEL: <code>%v</code>",
		stats["daily_get"], stats["daily_post"], stats["daily_put"], stats["daily_delete"])
	if v, ok := stats["daily_nic"]; ok {
		fmt.Fprintf(&sb, "  NIC: <code>%v</code>", v)
	}
	fmt.Fprintf(&sb, "\n\n🕒 <i>%s</i>", time.Now().Local().Format("02.01.2006 15:04:05"))

	t.enqueue(chatID, sb.String(), backKeyboard())
}

func (t *telegramNotifier) sendDomains(chatID string) {
	var sb strings.Builder
	fmt.Fprintf(&sb, "<b>%s</b>  <code>%s</code>\n\n", T.TgDomainsHeading, t.instanceTag)

	if len(cfg.DomainConfigs) == 0 {
		sb.WriteString(T.NoDomainsConfigured)
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
		fmt.Fprintf(&sb, "\n<b>%s</b>\n", T.TgDomainsCurrentIPs)
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
	t.enqueue(chatID, sb.String(), backKeyboard())
}

func (t *telegramNotifier) sendHealth(chatID string) {
	var sb strings.Builder
	fmt.Fprintf(&sb, "<b>%s</b>  <code>%s</code>\n\n", T.TgHealthHeading, t.instanceTag)

	switch {
	case !schedulerRanOnce.Load():
		fmt.Fprintf(&sb, "%s\n", T.TgHealthStarting)
		fmt.Fprintf(&sb, "%s\n", T.TgHealthWaitingDetail)
	case lastOk.Load():
		fmt.Fprintf(&sb, "%s\n", T.TgHealthHealthy)
	default:
		fmt.Fprintf(&sb, "%s\n", T.TgHealthUnhealthy)
		if lastErr := lastErrorMsg.Get(); lastErr != "" {
			fmt.Fprintf(&sb, "%s <code>%s</code>\n", T.TgHealthErrorLabel, lastErr)
		}
	}

	stats := apiMetrics.GetStats()
	fmt.Fprintf(&sb, "\n🔸 %s <code>%v</code>\n", T.TgStatusLabelSuccessRate, stats["success_rate"])
	fmt.Fprintf(&sb, "🔸 %s    <code>%v</code>\n", T.TgStatusLabelLatency, stats["avg_latency"])
	fmt.Fprintf(&sb, "🔸 %s  <code>%v</code>\n", T.TgStatusLabelLastOk, stats["last_success_time"])
	fmt.Fprintf(&sb, "\n🕒 <i>%s</i>", time.Now().Local().Format("02.01.2006 15:04:05"))

	t.enqueue(chatID, sb.String(), backKeyboard())
}

func (t *telegramNotifier) triggerUpdate(chatID string) {
	if !updateInProgress.CompareAndSwap(false, true) {
		t.enqueue(chatID, T.TgUpdateAlreadyRunning, backKeyboard())
		return
	}
	t.enqueue(chatID, T.TgUpdateStarting, backKeyboard())
	go func() {
		defer updateInProgress.Store(false)
		debugLog("NOTIFY", "", T.NotifyTelegramManualUpdate)
		forceNextUpdate.Store(true)
		runUpdate(false)
		t.enqueue(chatID,
			fmt.Sprintf(T.TgUpdateDone+"\n🕒 <i>%s</i>",
				time.Now().Local().Format("02.01.2006 15:04:05")),
			backKeyboard())
	}()
}

// ============================================================================
// HELPERS
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
