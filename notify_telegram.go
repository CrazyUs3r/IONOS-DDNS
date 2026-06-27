// Package main
package main

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// TELEGRAM TYPES
// ============================================================================
type tgMessage struct {
	MessageID int    `json:"message_id"`
	Text      string `json:"text"`
	Chat      tgChat `json:"chat"`
	From      tgUser `json:"from"`
	Date      int64  `json:"date"`
}

type tgChat struct {
	ID int64 `json:"id"`
}

type tgUser struct {
	ID        int64  `json:"id"`
	FirstName string `json:"first_name"`
	Username  string `json:"username"`
}

type tgInlineKeyboard struct {
	InlineKeyboard [][]tgInlineButton `json:"inline_keyboard"`
}

type tgInlineButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data"`
}

type tgCallbackQuery struct {
	ID      string    `json:"id"`
	From    tgUser    `json:"from"`
	Message tgMessage `json:"message"`
	Data    string    `json:"data"`
}

type tgUpdateFull struct {
	UpdateID      int64            `json:"update_id"`
	Message       *tgMessage       `json:"message,omitempty"`
	CallbackQuery *tgCallbackQuery `json:"callback_query,omitempty"`
}
type telegramNotifier struct {
	token          string
	chatID         string
	instanceTag    string
	pollOnce       sync.Once
	pollClientOnce sync.Once
	pollClient     *http.Client
	lastOffset     atomic.Int64
	sendQueue      chan tgQueuedMsg
	pollCtx        context.Context
	pollCancel     context.CancelFunc
	wg             sync.WaitGroup
}

type tgQueuedMsg struct {
	chatID   string
	text     string
	kb       *tgInlineKeyboard
	enqueued time.Time
}

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
	t.wg.Go(func() {
		t.drainQueue()
	})
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
				phrases().TgQueueFull,
				time.Since(dropped.enqueued).Round(time.Second),
			))
		default:
		}
		select {
		case t.sendQueue <- msg:
		default:
			debugLog("NOTIFY", "", phrases().TgQueuePushFailed)
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
				default:
					return
				}
			}

		case <-ticker.C:
			select {
			case msg := <-t.sendQueue:
				if time.Since(msg.enqueued) > tgQueueMaxAge {
					debugLog("NOTIFY", "", fmt.Sprintf(
						phrases().TgMsgDiscarded,
						time.Since(msg.enqueued).Round(time.Second),
					))
					continue
				}
				if err := t.sendTextWithRetry(msg.chatID, msg.text, msg.kb); err != nil {
					debugLog("NOTIFY", "", fmt.Sprintf(phrases().TgSendFailed, err))
				}
			default:

			}
		}
	}
}

func (t *telegramNotifier) sendTextWithRetry(chatID, text string, kb *tgInlineKeyboard) error {
	const maxRetries = 3
	wait := 5 * time.Second

	for attempt := range maxRetries {
		err := t.sendText(chatID, text, kb)
		if err == nil {
			return nil
		}
		if strings.Contains(err.Error(), "429") {
			debugLog("NOTIFY", "", fmt.Sprintf(
				phrases().TgRateLimit,
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
	return errors.New(phrases().TgMaxRetries)
}

func (t *telegramNotifier) sendText(chatID, text string, kb *tgInlineKeyboard) error {
	payload := map[string]any{
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
	ctx, cancel := context.WithTimeout(t.pollCtx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, MethodPOST, url, bytes.NewReader(body))
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
		return fmt.Errorf(phrases().TgHTTPError, resp.StatusCode, string(b))
	}

	var result struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if !result.OK {
		return fmt.Errorf(phrases().TgSendError, result.Description)
	}

	return nil
}

func (t *telegramNotifier) deleteMessage(chatID int64, messageID int) {
	payload := map[string]any{
		"chat_id":    chatID,
		"message_id": messageID,
	}
	body, _ := json.Marshal(payload)
	url := fmt.Sprintf("https://api.telegram.org/bot%s/deleteMessage", t.token)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, MethodPOST, url, bytes.NewReader(body))
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
	payload := map[string]any{"callback_query_id": callbackID}
	body, _ := json.Marshal(payload)
	url := fmt.Sprintf("https://api.telegram.org/bot%s/answerCallbackQuery", t.token)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, MethodPOST, url, bytes.NewReader(body))
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
		t.wg.Go(func() {
			t.pollingLoop()
		})
	})
}

func (t *telegramNotifier) StopPolling() {
	t.pollCancel()
	t.wg.Wait()
}

func (t *telegramNotifier) pollingLoop() {
	debugLog("NOTIFY", "", phrases().TgPollingStarted)
	go t.deleteWebhook()
	go t.registerCommands()

	for {
		select {
		case <-t.pollCtx.Done():
			debugLog("NOTIFY", "", phrases().TgPollingStopped)
			return
		default:
		}

		updates, err := t.getUpdates(int(t.lastOffset.Load()) + 1)
		if err != nil {
			debugLog("NOTIFY", "", fmt.Sprintf(phrases().TgGetUpdatesFailed, err))
			select {
			case <-t.pollCtx.Done():
				return
			case <-time.After(10 * time.Second):
			}
			continue
		}

		for _, u := range updates {
			if u.UpdateID > t.lastOffset.Load() {
				t.lastOffset.Store(u.UpdateID)
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
	ctx, cancel := context.WithTimeout(t.pollCtx, 40*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, MethodGET, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ManagedComment)

	logHTTPRequest(req)

	start := time.Now()
	resp, err := t.getPollClient().Do(req)
	duration := time.Since(start)

	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	logHTTPResponse(resp, duration)

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
		return nil, fmt.Errorf(phrases().TgGetUpdatesNotOk, result.ErrorCode, result.Description)
	}

	return result.Result, nil
}

func (t *telegramNotifier) registerCommands() {
	commands := []map[string]string{
		{"command": "start", "description": phrases().TgCmdStart},
		{"command": "status", "description": phrases().TgCmdStatus},
		{"command": "metrics", "description": phrases().TgCmdMetrics},
		{"command": "domains", "description": phrases().TgCmdDomains},
		{"command": "update", "description": phrases().TgCmdUpdate},
		{"command": "health", "description": phrases().TgCmdHealth},
		{"command": "help", "description": phrases().TgCmdHelp},
	}
	payload := map[string]any{"commands": commands}
	body, _ := json.Marshal(payload)
	url := fmt.Sprintf("https://api.telegram.org/bot%s/setMyCommands", t.token)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, MethodPOST, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", ManagedComment)
	resp, err := getHTTPClient().Do(req)
	if err != nil {
		debugLog("NOTIFY", "", fmt.Sprintf(phrases().TgSetCmdsFailed, err))
		return
	}
	_ = resp.Body.Close()
	debugLog("NOTIFY", "", phrases().TgBotCmdsReg)
}

func (t *telegramNotifier) deleteWebhook() {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/deleteWebhook?drop_pending_updates=false", t.token)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, MethodGET, url, nil)
	if err != nil {
		debugLog("NOTIFY", "", fmt.Sprintf(phrases().TgWebhookDeleteRequestError, err))
		return
	}
	req.Header.Set("User-Agent", ManagedComment)
	resp, err := t.getPollClient().Do(req)
	if err != nil {
		debugLog("NOTIFY", "", fmt.Sprintf(phrases().TgWebhookDeleteFailed, err))
		return
	}
	_ = resp.Body.Close()
	debugLog("NOTIFY", "", phrases().TgWebhookUnregistered)
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
		debugLog("NOTIFY", "", fmt.Sprintf(phrases().TgUnauthAccess, chatID))
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
			t.enqueue(chatID, phrases().TgUnknownCommand, nil)
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
				{Text: phrases().TgBtnStatus, CallbackData: "status"},
				{Text: phrases().TgBtnMetrics, CallbackData: "metrics"},
			},
			{
				{Text: phrases().TgBtnDomains, CallbackData: "domains"},
				{Text: phrases().TgBtnHealth, CallbackData: "health"},
			},
			{
				{Text: phrases().TgBtnUpdate, CallbackData: "update"},
			},
			{
				{Text: phrases().TgBtnClose, CallbackData: "close"},
			},
		},
	}
}

func backKeyboard() *tgInlineKeyboard {
	return &tgInlineKeyboard{
		InlineKeyboard: [][]tgInlineButton{
			{
				{Text: phrases().TgBtnMenu, CallbackData: "menu"},
				{Text: phrases().TgBtnUpdate, CallbackData: "update"},
			},
			{
				{Text: phrases().TgBtnClose, CallbackData: "close"},
			},
		},
	}
}

// ============================================================================
// VIEWS
// ============================================================================
func (t *telegramNotifier) sendMainMenu(chatID string) {
	text := fmt.Sprintf(
		"<b>🌐 Go-DynDNS</b>  <code>%s</code>\n\n"+phrases().TgMenuPrompt,
		t.instanceTag,
	)
	t.enqueue(chatID, text, mainKeyboard())
}

func (t *telegramNotifier) sendStatus(chatID string) {
	cfgMu.RLock()
	ipMode := cfg.IPMode
	domainCount := len(cfg.DomainConfigs)
	interval := cfg.Interval
	dryRun := cfg.DryRun
	cfgMu.RUnlock()

	stats := apiMetrics.GetStats()

	status := phrases().TgStatusOnline
	if !lastOk.Load() {
		status = phrases().TgStatusError
	}
	if !schedulerRanOnce.Load() {
		status = phrases().TgStatusStarting
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "<b>%s</b>  <code>%s</code>\n\n", phrases().TgStatusHeading, t.instanceTag)
	fmt.Fprintf(&sb, "🔸 %s      <b>%s</b>\n", phrases().TgStatusLabelStatus, status)
	fmt.Fprintf(&sb, "🔸 %s    <code>%s</code>\n", phrases().TgStatusLabelIPMode, ipMode)
	fmt.Fprintf(&sb, "🔸 %s     <code>%d</code>\n", phrases().TgStatusLabelDomains, domainCount)
	fmt.Fprintf(&sb, "🔸 %s   <code>%ds</code>\n", phrases().TgStatusLabelInterval, interval)
	fmt.Fprintf(&sb, "🔸 %s     <code>%v</code>\n", phrases().TgStatusLabelDryRun, dryRun)
	fmt.Fprintf(&sb, "🔸 %s    <code>%v</code>\n", phrases().TgStatusLabelRequests, stats["total_requests"])
	fmt.Fprintf(&sb, "🔸 %s: <code>%v</code>\n", phrases().TgStatusLabelSuccessRate, stats["success_rate"])
	fmt.Fprintf(&sb, "🔸 %s    <code>%v</code>\n", phrases().TgStatusLabelLatency, stats["avg_latency"])
	fmt.Fprintf(&sb, "🔸 %s  <code>%v</code>\n", phrases().TgStatusLabelLastOk, stats["last_success_time"])
	fmt.Fprintf(&sb, "\n🕒 <i>%s</i>", time.Now().Format(statusTimestampLayout))

	t.enqueue(chatID, sb.String(), backKeyboard())
}

func (t *telegramNotifier) sendMetrics(chatID string) {
	stats := apiMetrics.GetStats()

	var sb strings.Builder
	fmt.Fprintf(&sb, "<b>%s</b>  <code>%s</code>\n\n", phrases().TgMetricsHeading, t.instanceTag)

	fmt.Fprintf(&sb, "<b>%s</b>\n", phrases().TgMetricsRequests)
	fmt.Fprintf(&sb, "  %s <code>%v</code>\n", phrases().TgMetricsTotal, stats["total_requests"])
	fmt.Fprintf(&sb, "  %s <code>%v</code>\n", phrases().TgMetricsSuccessRate, stats["success_rate"])
	fmt.Fprintf(&sb, "  %s  <code>%v</code>\n", phrases().TgMetricsClientErr, stats["client_errors"])
	fmt.Fprintf(&sb, "  %s  <code>%v</code>\n", phrases().TgMetricsServerErr, stats["server_errors"])

	fmt.Fprintf(&sb, "\n<b>%s</b>\n", phrases().TgMetricsLatency)
	fmt.Fprintf(&sb, "  Ø:   <code>%v</code>\n", stats["avg_latency"])
	fmt.Fprintf(&sb, "  P50: <code>%v</code>\n", stats["p50_latency"])
	fmt.Fprintf(&sb, "  P85: <code>%v</code>\n", stats["p85_latency"])
	fmt.Fprintf(&sb, "  P99: <code>%v</code>\n", stats["p99_latency"])

	fmt.Fprintf(&sb, "\n<b>%s</b>\n", phrases().TgMetricsIPCheck)
	fmt.Fprintf(&sb, "  Ø:       <code>%v</code>\n", stats["ip_latency_avg"])
	fmt.Fprintf(&sb, "  %s  <code>%v</code>\n", phrases().TgMetricsChecks, stats["ip_latency_count"])
	fmt.Fprintf(&sb, "  %s: <code>%v</code>\n", phrases().TgMetricsLast, stats["last_ip_check"])

	fmt.Fprintf(&sb, "\n<b>%s</b>\n", phrases().TgMetricsHourlyLimit)
	fmt.Fprintf(&sb, "  %s <code>%v / %v</code>\n", phrases().TgMetricsUsed, stats["usage_count"], stats["hourly_limit"])
	fmt.Fprintf(&sb, "  %s <code>%v%%</code>\n", phrases().TgMetricsLoad, stats["usage_percent"])

	fmt.Fprintf(&sb, "\n<b>%s</b>\n", phrases().TgMetricsTodayHTTP)
	fmt.Fprintf(&sb, "  GET: <code>%v</code>  POST: <code>%v</code>  PUT: <code>%v</code>  DEL: <code>%v</code>",
		stats["daily_get"], stats["daily_post"], stats["daily_put"], stats["daily_delete"])
	if v, ok := stats["daily_nic"]; ok {
		fmt.Fprintf(&sb, "  NIC: <code>%v</code>", v)
	}
	fmt.Fprintf(&sb, "\n\n🕒 <i>%s</i>", time.Now().Format(statusTimestampLayout))

	t.enqueue(chatID, sb.String(), backKeyboard())
}

func (t *telegramNotifier) sendDomains(chatID string) {
	cfgMu.RLock()
	domainConfigs := make([]DomainConfig, len(cfg.DomainConfigs))
	copy(domainConfigs, cfg.DomainConfigs)
	cfgMu.RUnlock()
	var sb strings.Builder
	fmt.Fprintf(&sb, "<b>%s</b>  <code>%s</code>\n\n", phrases().TgDomainsHeading, t.instanceTag)

	if len(domainConfigs) == 0 {
		sb.WriteString(phrases().NoDomainsConfigured)
	} else {
		for _, dc := range domainConfigs {
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
		fmt.Fprintf(&sb, "\n<b>%s</b>\n", phrases().TgDomainsCurrentIPs)
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

	fmt.Fprintf(&sb, "\n🕒 <i>%s</i>", time.Now().Format(statusTimestampLayout))
	t.enqueue(chatID, sb.String(), backKeyboard())
}

func (t *telegramNotifier) sendHealth(chatID string) {
	var sb strings.Builder
	fmt.Fprintf(&sb, "<b>%s</b>  <code>%s</code>\n\n", phrases().TgHealthHeading, t.instanceTag)

	switch {
	case !schedulerRanOnce.Load():
		fmt.Fprintf(&sb, "%s\n", phrases().TgHealthStarting)
		fmt.Fprintf(&sb, "%s\n", phrases().TgHealthWaitingDetail)
	case lastOk.Load():
		fmt.Fprintf(&sb, "%s\n", phrases().TgHealthHealthy)
	default:
		fmt.Fprintf(&sb, "%s\n", phrases().TgHealthUnhealthy)
		if lastErr := lastErrorMsg.Get(); lastErr != "" {
			fmt.Fprintf(&sb, "%s <code>%s</code>\n", phrases().TgHealthErrorLabel, lastErr)
		}
	}

	stats := apiMetrics.GetStats()
	fmt.Fprintf(&sb, "\n🔸 %s <code>%v</code>\n", phrases().TgStatusLabelSuccessRate, stats["success_rate"])
	fmt.Fprintf(&sb, "🔸 %s    <code>%v</code>\n", phrases().TgStatusLabelLatency, stats["avg_latency"])
	fmt.Fprintf(&sb, "🔸 %s  <code>%v</code>\n", phrases().TgStatusLabelLastOk, stats["last_success_time"])
	fmt.Fprintf(&sb, "\n🕒 <i>%s</i>", time.Now().Format(statusTimestampLayout))

	t.enqueue(chatID, sb.String(), backKeyboard())
}

func (t *telegramNotifier) triggerUpdate(chatID string) {
	if !updateInProgress.CompareAndSwap(false, true) {
		t.enqueue(chatID, phrases().TgUpdateAlreadyRunning, backKeyboard())
		return
	}
	t.enqueue(chatID, phrases().TgUpdateStarting, backKeyboard())
	go func() {
		defer updateInProgress.Store(false)
		debugLog("NOTIFY", "", phrases().NotifyTelegramManualUpdate)
		forceNextUpdate.Store(true)
		runClaimedUpdate(false)
		t.enqueue(chatID,
			fmt.Sprintf(phrases().TgUpdateDone+"\n🕒 <i>%s</i>",
				time.Now().Format(statusTimestampLayout)),
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

func secureRandInt(limit int) (int, error) {
	n, err := crand.Int(crand.Reader, big.NewInt(int64(limit)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}

func generateInstanceTag() string {
	pool := instanceEmojis
	if len(pool) < 2 {
		return ""
	}

	aIdx, err := secureRandInt(len(pool))
	if err != nil {
		return pool[0] + pool[1]
	}

	bIdx, err := secureRandInt(len(pool))
	if err != nil {
		return pool[0] + pool[1]
	}

	for aIdx == bIdx {
		bIdx, err = secureRandInt(len(pool))
		if err != nil {
			return pool[0] + pool[1]
		}
	}

	return pool[aIdx] + pool[bIdx]
}

func formatTelegramMessage(msg NotifyMessage, instanceTag string) string {
	icon := notifyIcon(msg)

	var sb strings.Builder
	fmt.Fprintf(&sb, "<b>%s Go-DynDNS</b>  <code>%s</code>\n", icon, instanceTag)
	if msg.Domain != "" {
		fmt.Fprintf(&sb, "🌐 <code>%s</code>\n", msg.Domain)
	}
	fmt.Fprintf(&sb, "📋 <b>%s</b>\n", msg.Action)
	fmt.Fprintf(&sb, "💬 %s\n", msg.Message)
	fmt.Fprintf(&sb, "🕒 <i>%s</i>", time.Now().Format(statusTimestampLayout))
	return sb.String()
}
