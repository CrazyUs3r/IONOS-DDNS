// Package main
package main

import (
	"fmt"
	"strings"
	"sync"
)

// ============================================================================
// INIT
// ============================================================================
func initNotifiers() {
	notifyCfg = notifyConfig{
		events:    make(map[NotifyEvent]struct{}),
		notifiers: []Notifier{},
	}

	for _, raw := range cfg.Notifications.Events {
		e := NotifyEvent(strings.ToUpper(strings.TrimSpace(raw)))
		notifyCfg.events[e] = struct{}{}
	}

	if cfg.Notifications.Telegram.Token != "" && cfg.Notifications.Telegram.ChatID != "" {
		tg := newTelegramNotifier(cfg.Notifications.Telegram.Token, cfg.Notifications.Telegram.ChatID)
		notifyCfg.notifiers = append(notifyCfg.notifiers, tg)
		tg.StartPolling()
		debugLog("NOTIFY", "", T.NotifyTelegramActive)
		log(LogContext{
			Level:   LogInfo,
			Action:  ActionConfig,
			Message: t(T.NotifyTelegramActive, "✅ Telegram active"),
		})
	}

	if cfg.Notifications.Gotify.URL != "" && cfg.Notifications.Gotify.Token != "" {
		notifyCfg.notifiers = append(notifyCfg.notifiers, newGotifyNotifier(cfg.Notifications.Gotify.URL, cfg.Notifications.Gotify.Token))
		debugLog("NOTIFY", "", T.NotifyGotifyActive)
		log(LogContext{
			Level:   LogInfo,
			Action:  ActionConfig,
			Message: t(T.NotifyGotifyActive, "✅ Gotify active"),
		})
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

	nm := buildNotifyMessage(ctx)

	for _, n := range notifyCfg.notifiers {
		n := n
		go func() {
			if err := n.Send(nm); err != nil {
				debugLog("NOTIFY", "", fmt.Sprintf(T.NotifyFailed, n.Name(), err))
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

	type syncSender interface {
		SendSync(msg NotifyMessage) error
	}

	var wg sync.WaitGroup
	for _, n := range notifyCfg.notifiers {
		n := n
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			var err error
			if s, ok := n.(syncSender); ok {
				err = s.SendSync(nm)
			} else {
				err = n.Send(nm)
			}

			if err != nil {
				debugLog("NOTIFY", "", fmt.Sprintf(T.NotifyFailed, n.Name(), err))
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