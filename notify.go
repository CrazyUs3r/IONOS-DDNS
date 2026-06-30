// Package main
package main

import (
	"context"
	"fmt"
	"sync"
	"time"
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
	NotifyInfo      NotifyEvent = NotifyEvent(ActionInfo)
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

var notifierInitMu sync.Mutex

type notifyConfig struct {
	notifiers []Notifier
	events    map[NotifyEvent]struct{}
}

// ============================================================================
// INIT
// ============================================================================
func initNotifiers() {
	notifierInitMu.Lock()
	defer notifierInitMu.Unlock()

	if shutdownCtx != nil && shutdownCtx.Err() != nil {
		return
	}

	newCfg := buildNotifyConfig(snapshotNotifierConfig())
	notifyCfgMu.Lock()
	oldNotifiers := append([]Notifier(nil), notifyCfg.notifiers...)
	notifyCfg = newCfg
	notifyCfgMu.Unlock()
	closeNotifierList(oldNotifiers)
}

func buildNotifyConfig(config Config) notifyConfig {
	newCfg := notifyConfig{
		events:    make(map[NotifyEvent]struct{}),
		notifiers: []Notifier{},
	}
	for _, raw := range config.Notifications.Events {
		newCfg.events[normalizeNotifyEvent(raw)] = struct{}{}
	}
	if !config.Notifications.Enabled {
		return newCfg
	}

	appendTelegramNotifier(&newCfg, config)
	appendGotifyNotifier(&newCfg, config)
	appendWebhookNotifier(&newCfg, config)
	appendNtfyNotifier(&newCfg, config)
	appendMQTTNotifier(&newCfg, config)
	appendEmailNotifier(&newCfg, config)
	return newCfg
}

func appendTelegramNotifier(target *notifyConfig, config Config) {
	telegram := config.Notifications.Telegram
	if telegram.Token == "" || telegram.ChatID == "" {
		return
	}
	tg := newTelegramNotifier(telegram.Token, telegram.ChatID)
	target.notifiers = append(target.notifiers, tg)
	tg.StartPolling()
	debugLog("NOTIFY", "", fmt.Sprintf("%s %s", phrases().NotifyTelegramActive, telegram.ChatID))
	log(LogContext{Level: LogInfo, Action: ActionConfig, Message: t(phrases().NotifyTelegramActive, "✅ Telegram active")})
}

func appendGotifyNotifier(target *notifyConfig, config Config) {
	gotify := config.Notifications.Gotify
	if gotify.URL == "" || gotify.Token == "" {
		return
	}
	target.notifiers = append(target.notifiers, newGotifyNotifier(gotify.URL, gotify.Token))
	debugLog("NOTIFY", "", fmt.Sprintf("%s %s", phrases().NotifyGotifyActive, gotify.URL))
	log(LogContext{Level: LogInfo, Action: ActionConfig, Message: t(phrases().NotifyGotifyActive, "✅ Gotify active")})
}

func appendWebhookNotifier(target *notifyConfig, config Config) {
	webhook := config.Notifications.Webhook
	if webhook.URL == "" {
		return
	}
	target.notifiers = append(target.notifiers, newWebhookNotifier(webhook.URL, webhook.Secret))
	debugLog("NOTIFY", "", fmt.Sprintf("%s %s", phrases().NotifyWebhookActive, webhook.URL))
	log(LogContext{Level: LogInfo, Action: ActionConfig, Message: t(phrases().NotifyWebhookActive, "✅ Webhook active")})
}

func appendNtfyNotifier(target *notifyConfig, config Config) {
	ntfy := config.Notifications.Ntfy
	if ntfy.URL == "" || ntfy.Topic == "" {
		return
	}
	target.notifiers = append(target.notifiers, newNtfyNotifier(ntfy.URL, ntfy.Topic, ntfy.Token))
	debugLog("NOTIFY", "", fmt.Sprintf("%s %s", phrases().NotifyNtfyActive, ntfy.URL))
	log(LogContext{Level: LogInfo, Action: ActionConfig, Message: t(phrases().NotifyNtfyActive, "✅ Ntfy active")})
}

func appendMQTTNotifier(target *notifyConfig, config Config) {
	mqtt := config.Notifications.MQTTConfig
	if mqtt.Broker == "" || mqtt.Topic == "" {
		return
	}
	target.notifiers = append(target.notifiers, newMQTTNotifier(
		mqtt.Broker,
		mqtt.ClientID,
		mqtt.Username,
		mqtt.Password,
		mqtt.Topic,
		mqtt.QoS,
		mqtt.Retain,
		mqtt.CAFile,
		mqtt.Discovery,
		mqtt.DiscoveryPrefix,
	))
	debugLog("NOTIFY", "", fmt.Sprintf("%s %s", phrases().NotifyMqttActive, mqtt.Broker))
	log(LogContext{Level: LogInfo, Action: ActionConfig, Message: t(phrases().NotifyMqttActive, "✅ MQTT active")})
}

func appendEmailNotifier(target *notifyConfig, config Config) {
	email := config.Notifications.Email
	if email.Host == "" || email.To == "" {
		return
	}
	target.notifiers = append(target.notifiers, newEmailNotifier(
		email.Host,
		email.Port,
		email.Username,
		email.Password,
		email.From,
		email.To,
		email.SubjectPrefix,
		email.TLSMode,
	))
	debugLog("NOTIFY", "", fmt.Sprintf("%s %s", phrases().NotifyEmailActive, email.To))
	log(LogContext{Level: LogInfo, Action: ActionConfig, Message: t(phrases().NotifyEmailActive, "✅ Email (SMTP) active")})
}

func notificationParentContext() context.Context {
	if shutdownCtx != nil {
		return shutdownCtx
	}
	return context.Background()
}

func stopNotifyTimer(timer *time.Timer) {
	if timer == nil || timer.Stop() {
		return
	}
	select {
	case <-timer.C:
	default:
	}
}

func notificationCredentialsConfigured(config Config) bool {
	return (config.Notifications.Telegram.Token != "" && config.Notifications.Telegram.ChatID != "") ||
		(config.Notifications.Gotify.URL != "" && config.Notifications.Gotify.Token != "") ||
		(config.Notifications.Ntfy.URL != "" && config.Notifications.Ntfy.Topic != "") ||
		config.Notifications.Webhook.URL != "" ||
		(config.Notifications.MQTTConfig.Broker != "" && config.Notifications.MQTTConfig.Topic != "") ||
		(config.Notifications.Email.Host != "" && config.Notifications.Email.To != "")
}

func snapshotNotifierConfig() Config {
	cfgMu.RLock()
	config := cfg
	config.Notifications.Events = append([]string(nil), cfg.Notifications.Events...)
	cfgMu.RUnlock()
	return config
}

type notifierCloser interface {
	Close()
}

func closeNotifierList(notifiers []Notifier) {
	for _, notifier := range notifiers {
		if closer, ok := notifier.(notifierCloser); ok {
			closer.Close()
		}
	}
}

func closeNotifiers() {
	notifierInitMu.Lock()
	defer notifierInitMu.Unlock()

	notifyCfgMu.Lock()
	oldNotifiers := append([]Notifier(nil), notifyCfg.notifiers...)
	notifyCfg = notifyConfig{events: make(map[NotifyEvent]struct{})}
	notifyCfgMu.Unlock()
	closeNotifierList(oldNotifiers)
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
				debugLog("NOTIFY", "", fmt.Sprintf(phrases().NotifyFailed, n.Name(), err))
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
				debugLog("NOTIFY", "", fmt.Sprintf(phrases().NotifyFailed, n.Name(), err))
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
	msg = sanitizeText(msg)
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
