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
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// TELEGRAM TYPES
// ============================================================================

type tgMessage struct {
	From      tgUser `json:"from"`
	Text      string `json:"text"`
	MessageID int    `json:"message_id"`
	Chat      tgChat `json:"chat"`
	Date      int64  `json:"date"`
}

type tgChat struct {
	ID int64 `json:"id"`
}

type tgUser struct {
	FirstName string `json:"first_name"`
	Username  string `json:"username"`
	ID        int64  `json:"id"`
}

type tgInlineKeyboard struct {
	InlineKeyboard [][]tgInlineButton `json:"inline_keyboard"`
}

type tgInlineButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data"`
}

type tgCallbackQuery struct {
	From    tgUser    `json:"from"`
	ID      string    `json:"id"`
	Data    string    `json:"data"`
	Message tgMessage `json:"message"`
}

type tgUpdateFull struct {
	Message       *tgMessage       `json:"message,omitempty"`
	CallbackQuery *tgCallbackQuery `json:"callback_query,omitempty"`
	UpdateID      int64            `json:"update_id"`
}
type telegramNotifier struct {
	pollCtx        context.Context
	pollClient     *http.Client
	sendQueue      chan tgQueuedMsg
	pollCancel     context.CancelFunc
	token          string
	instanceTag    string
	chatIDs        []string
	wg             sync.WaitGroup
	lastOffset     atomic.Int64
	pollOnce       sync.Once
	pollClientOnce sync.Once
}

type tgQueuedMsg struct {
	enqueued time.Time
	kb       *tgInlineKeyboard
	chatID   string
	text     string
}

// ============================================================================
// TELEGRAM NOTIFIER
// ============================================================================

func newTelegramNotifier(token, chatIDs string) *telegramNotifier {
	ctx, cancel := context.WithCancel(shutdownCtx)
	t := &telegramNotifier{
		token:       token,
		chatIDs:     parseTelegramChatIDs(chatIDs),
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
	select {
	case <-t.pollCtx.Done():
		return t.pollCtx.Err()
	default:
	}

	text := formatTelegramMessage(msg, t.instanceTag)
	for _, chatID := range t.chatIDs {
		t.enqueue(chatID, text, nil)
	}

	return nil
}

func (t *telegramNotifier) SendSync(msg NotifyMessage) error {
	text := formatTelegramMessage(msg, t.instanceTag)
	var errs []error
	for _, chatID := range t.chatIDs {
		if err := t.sendTextWithRetry(chatID, text, nil); err != nil {
			errs = append(errs, fmt.Errorf("chat %s: %w", chatID, err))
		}
	}

	return errors.Join(errs...)
}

func (t *telegramNotifier) enqueue(chatID, text string, kb *tgInlineKeyboard) {
	select {
	case <-t.pollCtx.Done():
		return
	default:
	}

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
			return

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
	const maxAttempts = 3
	wait := 5 * time.Second

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		lastErr = t.sendText(chatID, text, kb)
		if lastErr == nil {
			return nil
		}
		if !strings.Contains(lastErr.Error(), "429") || attempt == maxAttempts {
			break
		}

		debugLog("NOTIFY", "", fmt.Sprintf(
			phrases().TgRateLimit,
			wait, attempt, maxAttempts-1,
		))
		timer := time.NewTimer(wait)
		select {
		case <-t.pollCtx.Done():
			stopNotifyTimer(timer)

			return lastErr
		case <-timer.C:
		}
		wait *= 2
	}

	if lastErr != nil {
		return fmt.Errorf("%s: %w", phrases().TgMaxRetries, lastErr)
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
		Description string `json:"description"`
		OK          bool   `json:"ok"`
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

	body, err := json.Marshal(payload)
	if err != nil {
		debugLog("NOTIFY", "", fmt.Sprintf("marshal deleteMessage payload: %v", err))

		return
	}

	url := fmt.Sprintf(
		"https://api.telegram.org/bot%s/deleteMessage",
		t.token,
	)

	ctx, cancel := context.WithTimeout(t.pollCtx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(
		ctx,
		MethodPOST,
		url,
		bytes.NewReader(body),
	)
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
	payload := struct {
		CallbackQueryID string `json:"callback_query_id"`
	}{
		CallbackQueryID: callbackID,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		debugLog("NOTIFY", "", fmt.Sprintf("marshal callback response: %v", err))

		return
	}

	url := fmt.Sprintf(
		"https://api.telegram.org/bot%s/answerCallbackQuery",
		t.token,
	)

	ctx, cancel := context.WithTimeout(t.pollCtx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(
		ctx,
		MethodPOST,
		url,
		bytes.NewReader(body),
	)
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
	if t.pollClient != nil {
		t.pollClient.CloseIdleConnections()
	}
}

func (t *telegramNotifier) Close() { t.StopPolling() }

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

	req, err := http.NewRequestWithContext(ctx, MethodGET, url, http.NoBody)
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
		Description string         `json:"description"`
		Result      []tgUpdateFull `json:"result"`
		ErrorCode   int            `json:"error_code"`
		OK          bool           `json:"ok"`
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
	type telegramCommand struct {
		Command     string `json:"command"`
		Description string `json:"description"`
	}

	payload := struct {
		Commands []telegramCommand `json:"commands"`
	}{
		Commands: []telegramCommand{
			{Command: "start", Description: phrases().TgCmdStart},
			{Command: "status", Description: phrases().TgCmdStatus},
			{Command: "metrics", Description: phrases().TgCmdMetrics},
			{Command: "domains", Description: phrases().TgCmdDomains},
			{Command: "update", Description: phrases().TgCmdUpdate},
			{Command: "health", Description: phrases().TgCmdHealth},
			{Command: "help", Description: phrases().TgCmdHelp},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		debugLog("NOTIFY", "", fmt.Sprintf("marshal bot commands: %v", err))

		return
	}

	url := fmt.Sprintf(
		"https://api.telegram.org/bot%s/setMyCommands",
		t.token,
	)

	ctx, cancel := context.WithTimeout(t.pollCtx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(
		ctx,
		MethodPOST,
		url,
		bytes.NewReader(body),
	)
	if err != nil {
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", ManagedComment)

	resp, err := getHTTPClient().Do(req)
	if err != nil {
		debugLog(
			"NOTIFY",
			"",
			fmt.Sprintf(phrases().TgSetCmdsFailed, err),
		)

		return
	}

	_ = resp.Body.Close()
	debugLog("NOTIFY", "", phrases().TgBotCmdsReg)
}

func (t *telegramNotifier) deleteWebhook() {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/deleteWebhook?drop_pending_updates=false", t.token)
	ctx, cancel := context.WithTimeout(t.pollCtx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, MethodGET, url, http.NoBody)
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

func parseTelegramChatIDs(value string) []string {
	seen := make(map[string]struct{})
	chatIDs := make([]string, 0)

	for raw := range strings.SplitSeq(value, ",") {
		chatID := strings.TrimSpace(raw)
		if chatID == "" {
			continue
		}
		if _, exists := seen[chatID]; exists {
			continue
		}
		seen[chatID] = struct{}{}
		chatIDs = append(chatIDs, chatID)
	}

	return chatIDs
}

func (t *telegramNotifier) isAuthorized(chatID string) bool {
	chatID = strings.TrimSpace(chatID)

	return slices.Contains(t.chatIDs, chatID)
}

func chatIDStr(id int64) string {
	return strconv.FormatInt(id, 10)
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
			fmt.Fprintf(&sb, "🔹 <code>%s</code>  <i>(%s)</i>\n", esc(dc.FQDN), esc(string(dc.Provider)))
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
			fmt.Fprintf(&sb, "\n🌐 <code>%s</code>\n", esc(domain))
			if latest.IPv4 != "" {
				fmt.Fprintf(&sb, "  v4: <code>%s</code>\n", esc(latest.IPv4))
			}
			if latest.IPv6 != "" {
				fmt.Fprintf(&sb, "  v6: <code>%s</code>\n", esc(latest.IPv6))
			}
			fmt.Fprintf(&sb, "  🕒 <i>%s</i>\n", esc(latest.Time))
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
			fmt.Fprintf(&sb, "%s <code>%s</code>\n", phrases().TgHealthErrorLabel, esc(lastErr))
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
	fmt.Fprintf(&sb, "<b>%s Go-DynDNS</b>  <code>%s</code>\n", icon, esc(instanceTag))
	if msg.Domain != "" {
		fmt.Fprintf(&sb, "🌐 <code>%s</code>\n", esc(msg.Domain))
	}
	fmt.Fprintf(&sb, "📋 <b>%s</b>\n", esc(msg.Action))
	fmt.Fprintf(&sb, "💬 %s\n", esc(msg.Message))
	fmt.Fprintf(&sb, "🕒 <i>%s</i>", time.Now().Format(statusTimestampLayout))

	return sb.String()
}
