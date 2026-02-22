// Package main
package main

import (
	"fmt"
	"strings"
)

// ============================================================================
// NOTIFICATION
// ============================================================================

type NotifyEvent string

const (
	NotifyOnUpdate  NotifyEvent = "UPDATE"
	NotifyOnCreate  NotifyEvent = "CREATE"
	NotifyOnError   NotifyEvent = "ERROR"
	NotifyOnStart   NotifyEvent = "START"
	NotifyOnStop    NotifyEvent = "STOP"
	NotifyOnCleanup NotifyEvent = "CLEANUP"
)

type Notifier interface {
	Name() string
	Send(msg NotifyMessage) error
}

type NotifyMessage struct {
	Action  string
	Domain  string
	Message string
	Level   LogLevel
}

type notifyConfig struct {
	notifiers []Notifier
	events map[NotifyEvent]struct{}
}

var notifyCfg notifyConfig

// ============================================================================
// INIT
// ============================================================================

//	Telegram: TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID
//	Gotify:   GOTIFY_URL + GOTIFY_TOKEN
//	Events:   NOTIFY_ON (Default: UPDATE,CREATE,ERROR)
func initNotifiers() {
	notifyCfg = notifyConfig{
		events: make(map[NotifyEvent]struct{}),
	}

	// ── Events konfigurieren ────────────────────────────────────────────────
	notifyOn := getEnvOrDefault("NOTIFY_ON", "UPDATE,CREATE,ERROR")
	for _, raw := range strings.Split(notifyOn, ",") {
		e := NotifyEvent(strings.ToUpper(strings.TrimSpace(raw)))
		switch e {
		case NotifyOnUpdate, NotifyOnCreate, NotifyOnError,
			NotifyOnStart, NotifyOnStop, NotifyOnCleanup:
			notifyCfg.events[e] = struct{}{}
		default:
			debugLog("NOTIFY", "", fmt.Sprintf("⚠️ Unbekanntes NOTIFY_ON Event: %s", e))
		}
	}

	// ── Telegram ────────────────────────────────────────────────────────────
	tgToken := getEnvOrDefault("TELEGRAM_BOT_TOKEN", "")
	tgChat := getEnvOrDefault("TELEGRAM_CHAT_ID", "")
	if tgToken != "" && tgChat != "" {
		notifyCfg.notifiers = append(notifyCfg.notifiers, newTelegramNotifier(tgToken, tgChat))
		debugLog("NOTIFY", "", "✅ Telegram Notifier aktiviert")
	}

	// ── Gotify ──────────────────────────────────────────────────────────────
	gotifyURL := getEnvOrDefault("GOTIFY_URL", "")
	gotifyToken := getEnvOrDefault("GOTIFY_TOKEN", "")
	if gotifyURL != "" && gotifyToken != "" {
		notifyCfg.notifiers = append(notifyCfg.notifiers, newGotifyNotifier(gotifyURL, gotifyToken))
		debugLog("NOTIFY", "", "✅ Gotify Notifier aktiviert")
	}

	if len(notifyCfg.notifiers) == 0 {
		debugLog("NOTIFY", "", "ℹ️ Keine Notifier konfiguriert")
	} else {
		debugLog("NOTIFY", "", fmt.Sprintf("📣 %d Notifier aktiv, Events: %s",
			len(notifyCfg.notifiers), notifyOn))
	}
}

// ============================================================================
// DISPATCH
// ============================================================================
func notify(ctx LogContext) {
	if len(notifyCfg.notifiers) == 0 {
		return
	}

	event := NotifyEvent(strings.ToUpper(ctx.Action))
	if _, ok := notifyCfg.events[event]; !ok {
		return
	}

	msg := ctx.Message
	if ctx.Error != nil {
		msg = fmt.Sprintf("%s: %v", ctx.Message, ctx.Error)
	}

	nm := NotifyMessage{
		Action:  ctx.Action,
		Domain:  ctx.Domain,
		Message: msg,
		Level:   ctx.Level,
	}

	for _, n := range notifyCfg.notifiers {
		n := n
		go func() {
			if err := n.Send(nm); err != nil {
				fmt.Printf("[WARN] Notify %s fehlgeschlagen: %v\n", n.Name(), err)
			}
		}()
	}
}

// ============================================================================
// HELPERS
// ============================================================================
func getEnvOrDefault(key, def string) string {
	if v := strings.TrimSpace(envGet(key)); v != "" {
		return v
	}
	return def
}

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
