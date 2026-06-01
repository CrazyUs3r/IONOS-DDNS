// Package main
package main

import (
	"fmt"
	"sync"
)

// ============================================================================
// NOTIFICATION
// ============================================================================
type NotifyEvent string

const (
	NotifyOnUpdate  NotifyEvent = NotifyEvent(ActionUpdate)
	NotifyOnCreate  NotifyEvent = NotifyEvent(ActionCreate)
	NotifyOnCurrent NotifyEvent = NotifyEvent(ActionCurrent)
	NotifyOnRetry   NotifyEvent = NotifyEvent(ActionRetry)
	NotifyOnError   NotifyEvent = NotifyEvent(ActionError)
	NotifyOnStart   NotifyEvent = NotifyEvent(ActionStart)
	NotifyOnStop    NotifyEvent = NotifyEvent(ActionStop)
	NotifyOnConfig  NotifyEvent = NotifyEvent(ActionConfig)
	NotifyOnZone    NotifyEvent = NotifyEvent(ActionZone)
	NotifyOnDryRun  NotifyEvent = NotifyEvent(ActionDryRun)
	NotifyOnCleanup NotifyEvent = NotifyEvent(ActionCleanup)
	NotifyOnSkip    NotifyEvent = NotifyEvent(ActionSkip)
	NotifyOnAPI     NotifyEvent = NotifyEvent(ActionAPI)
	NotifyOnServer  NotifyEvent = NotifyEvent(ActionServer)
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
	events    map[NotifyEvent]struct{}
}

// ============================================================================
// INIT
// ============================================================================
func initNotifiers() {
	notifyCfgMu.RLock()
	oldNotifiers := notifyCfg.notifiers
	notifyCfgMu.RUnlock()

	for _, n := range oldNotifiers {
		if tg, ok := n.(*telegramNotifier); ok {
			tg.StopPolling()
		}
	}

	newCfg := notifyConfig{
		events:    make(map[NotifyEvent]struct{}),
		notifiers: []Notifier{},
	}

	for _, raw := range cfg.Notifications.Events {
		newCfg.events[normalizeNotifyEvent(raw)] = struct{}{}
	}

	if cfg.Notifications.Telegram.Token != "" && cfg.Notifications.Telegram.ChatID != "" {
		tg := newTelegramNotifier(cfg.Notifications.Telegram.Token, cfg.Notifications.Telegram.ChatID)
		newCfg.notifiers = append(newCfg.notifiers, tg)
		tg.StartPolling()
		debugLog("NOTIFY", "", fmt.Sprintf("%s %s", T.NotifyTelegramActive, cfg.Notifications.Telegram.ChatID))
		log(LogContext{
			Level:   LogInfo,
			Action:  ActionConfig,
			Message: t(T.NotifyTelegramActive, "✅ Telegram active"),
		})
	}

	if cfg.Notifications.Gotify.URL != "" && cfg.Notifications.Gotify.Token != "" {
		newCfg.notifiers = append(newCfg.notifiers, newGotifyNotifier(cfg.Notifications.Gotify.URL, cfg.Notifications.Gotify.Token))
		debugLog("NOTIFY", "", fmt.Sprintf("%s %s", T.NotifyGotifyActive, cfg.Notifications.Gotify.URL))
		log(LogContext{
			Level:   LogInfo,
			Action:  ActionConfig,
			Message: t(T.NotifyGotifyActive, "✅ Gotify active"),
		})
	}

	if cfg.Notifications.Webhook.URL != "" {
		newCfg.notifiers = append(newCfg.notifiers,
			newWebhookNotifier(cfg.Notifications.Webhook.URL, cfg.Notifications.Webhook.Secret))
		debugLog("NOTIFY", "", fmt.Sprintf("%s %s", T.NotifyWebhookActive, cfg.Notifications.Webhook.URL))
		log(LogContext{
			Level:   LogInfo,
			Action:  ActionConfig,
			Message: t(T.NotifyWebhookActive, "✅ Webhook active"),
		})
	}

	if cfg.Notifications.MQTTConfig.Broker != "" && cfg.Notifications.MQTTConfig.Topic != "" {
		newCfg.notifiers = append(newCfg.notifiers, newMQTTNotifier(
			cfg.Notifications.MQTTConfig.Broker,
			cfg.Notifications.MQTTConfig.ClientID,
			cfg.Notifications.MQTTConfig.Username,
			cfg.Notifications.MQTTConfig.Password,
			cfg.Notifications.MQTTConfig.Topic,
			cfg.Notifications.MQTTConfig.QoS,
			cfg.Notifications.MQTTConfig.Retain,
			cfg.Notifications.MQTTConfig.CAFile,
			cfg.Notifications.MQTTConfig.Discovery,
			cfg.Notifications.MQTTConfig.DiscoveryPrefix,
		))
		debugLog("NOTIFY", "", fmt.Sprintf("%s %s", T.NotifyMqttActive, cfg.Notifications.MQTTConfig.Broker))
		log(LogContext{
			Level:   LogInfo,
			Action:  ActionConfig,
			Message: t(T.NotifyMqttActive, "✅ MQTT active"),
		})
	}

	if cfg.Notifications.Email.Host != "" && cfg.Notifications.Email.To != "" {
		newCfg.notifiers = append(newCfg.notifiers, newEmailNotifier(
			cfg.Notifications.Email.Host,
			cfg.Notifications.Email.Port,
			cfg.Notifications.Email.Username,
			cfg.Notifications.Email.Password,
			cfg.Notifications.Email.From,
			cfg.Notifications.Email.To,
			cfg.Notifications.Email.SubjectPrefix,
			cfg.Notifications.Email.TLSMode,
		))
		debugLog("NOTIFY", "", fmt.Sprintf("%s %s", T.NotifyEmailActive, cfg.Notifications.Email.To))
		log(LogContext{
			Level:   LogInfo,
			Action:  ActionConfig,
			Message: t(T.NotifyEmailActive, "✅ Email (SMTP) active"),
		})
	}

	notifyCfgMu.Lock()
	notifyCfg = newCfg
	notifyCfgMu.Unlock()
}

// ============================================================================
// DISPATCH — async (normal log path)
// ============================================================================
func notify(ctx LogContext) {
	notifyCfgMu.RLock()
	notifiers := notifyCfg.notifiers
	events := notifyCfg.events
	notifyCfgMu.RUnlock()
	if len(notifiers) == 0 {
		return
	}

	event := normalizeNotifyEvent(ctx.Action)
	if _, ok := events[event]; !ok {
		return
	}

	nm := buildNotifyMessage(ctx)

	for _, n := range notifiers {
		go func() {
			if err := n.Send(nm); err != nil {
				debugLog("NOTIFY", "", fmt.Sprintf(T.NotifyFailed, n.Name(), err))
			}
		}()
	}
}

func notifySync(ctx LogContext) {
	notifyCfgMu.RLock()
	notifiers := notifyCfg.notifiers
	events := notifyCfg.events
	notifyCfgMu.RUnlock()

	if len(notifiers) == 0 {
		return
	}

	event := normalizeNotifyEvent(ctx.Action)
	if _, ok := events[event]; !ok {
		return
	}

	nm := buildNotifyMessage(ctx)

	type syncSender interface {
		SendSync(msg NotifyMessage) error
	}

	var wg sync.WaitGroup
	for _, n := range notifiers {
		wg.Go(func() {
			var err error
			if s, ok := n.(syncSender); ok {
				err = s.SendSync(nm)
			} else {
				err = n.Send(nm)
			}

			if err != nil {
				debugLog("NOTIFY", "", fmt.Sprintf(T.NotifyFailed, n.Name(), err))
			}
		})
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
func normalizeNotifyEvent(action string) NotifyEvent {
	return NotifyEvent(action)
}

func notifyIcon(msg NotifyMessage) string {
	if icon, ok := actionIcons[string(normalizeNotifyEvent(msg.Action))]; ok {
		return icon
	}

	switch msg.Level {
	case LogError:
		return IconError
	case LogWarn:
		return IconWarn
	default:
		return IconInfo
	}
}
