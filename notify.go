// Package main
package main

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// INIT
// ============================================================================
func initNotifiers() {
	notifyCfg = notifyConfig{
		events:    make(map[NotifyEvent]struct{}),
		notifiers: []Notifier{},
		limiter:   newNotifyRateLimiter(1.0, 5),
	}

	for _, raw := range cfg.Notifications.Events {
		e := NotifyEvent(strings.ToUpper(strings.TrimSpace(raw)))
		notifyCfg.events[e] = struct{}{}
	}

	if cfg.Notifications.Telegram.Token != "" && cfg.Notifications.Telegram.ChatID != "" {
		tg := newTelegramNotifier(cfg.Notifications.Telegram.Token, cfg.Notifications.Telegram.ChatID)
		notifyCfg.notifiers = append(notifyCfg.notifiers, tg)
		tg.StartPolling()
		debugLog("NOTIFY", "", "✅ Telegram aktiv")
	}

	if cfg.Notifications.Gotify.URL != "" && cfg.Notifications.Gotify.Token != "" {
		notifyCfg.notifiers = append(notifyCfg.notifiers,
			newGotifyNotifier(cfg.Notifications.Gotify.URL, cfg.Notifications.Gotify.Token))
		debugLog("NOTIFY", "", "✅ Gotify aktiv")
	}
}

// ============================================================================
// DISPATCH — async (normal log path)
// ============================================================================
func notify(ctx LogContext) {
	if len(notifyCfg.notifiers) == 0 {
		return
	}

	event := NotifyEvent(strings.ToUpper(ctx.Action))
	if _, ok := notifyCfg.events[event]; !ok {
		return
	}

	if !notifyCfg.limiter.allow() {
		debugLog("NOTIFY", "", "⚠️ Rate limit reached, notification dropped")
		return
	}

	nm := buildNotifyMessage(ctx)

	for _, n := range notifyCfg.notifiers {
		n := n
		go func() {
			if err := n.Send(nm); err != nil {
				fmt.Printf("[WARN] Notify %s fehlgeschlagen: %v\n", n.Name(), err)
			}
		}()
	}
}

func notifySync(ctx LogContext) {
	if len(notifyCfg.notifiers) == 0 {
		return
	}

	event := NotifyEvent(strings.ToUpper(ctx.Action))
	if _, ok := notifyCfg.events[event]; !ok {
		return
	}

	nm := buildNotifyMessage(ctx)

	var wg sync.WaitGroup
	for _, n := range notifyCfg.notifiers {
		n := n
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := n.Send(nm); err != nil {
				fmt.Printf("[WARN] Notify %s fehlgeschlagen: %v\n", n.Name(), err)
			}
		}()
	}
	wg.Wait()
}

func buildNotifyMessage(ctx LogContext) NotifyMessage {
	msg := ctx.Message
	if ctx.Error != nil {
		msg = fmt.Sprintf("%s: %v", ctx.Message, ctx.Error)
	}
	return NotifyMessage{
		Action:  ctx.Action,
		Domain:  ctx.Domain,
		Message: msg,
		Level:   ctx.Level,
	}
}

func newNotifyRateLimiter(perSecond float64, burst int) *notifyRateLimiter {
	return &notifyRateLimiter{
		tokens:   burst,
		maxBurst: burst,
		lastFill: time.Now(),
		perSec:   perSecond,
	}
}

func (r *notifyRateLimiter) allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(r.lastFill).Seconds()
	r.lastFill = now

	r.tokens += int(elapsed * r.perSec)
	if r.tokens > r.maxBurst {
		r.tokens = r.maxBurst
	}
	if r.tokens <= 0 {
		return false
	}
	r.tokens--
	return true
}

// ============================================================================
// HELPERS
// ============================================================================
func levelEmoji(level LogLevel) string {
	switch level {
	case LogError:
		return "❌"
	case LogWarn:
		return "⚠️"
	default:
		return "ℹ️"
	}
}
