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
// GOTIFY NOTIFIER
// ============================================================================
type gotifyNotifier struct {
	url       string
	token     string
	sendQueue chan gotifyQueuedMsg
}

type gotifyQueuedMsg struct {
	title    string
	body     string
	priority int
	enqueued time.Time
}

func newGotifyNotifier(url, token string) *gotifyNotifier {
	g := &gotifyNotifier{
		url:       strings.TrimRight(url, "/"),
		token:     token,
		sendQueue: make(chan gotifyQueuedMsg, gotifyQueueSize),
	}
	go g.drainQueue()
	return g
}

func (g *gotifyNotifier) Name() string { return "Gotify" }

func (g *gotifyNotifier) Send(msg NotifyMessage) error {
	title, body := formatGotifyMessage(msg)
	qm := gotifyQueuedMsg{
		title:    title,
		body:     body,
		priority: gotifyPriority(msg.Level),
		enqueued: time.Now(),
	}
	select {
	case g.sendQueue <- qm:
	default:
		select {
		case dropped := <-g.sendQueue:
			debugLog("NOTIFY", "", fmt.Sprintf(
				"⚠️ Gotify Queue voll – älteste Nachricht verworfen (Alter: %v)",
				time.Since(dropped.enqueued).Round(time.Second),
			))
		default:
		}
		select {
		case g.sendQueue <- qm:
		default:
		}
	}
	return nil
}

func (g *gotifyNotifier) SendSync(msg NotifyMessage) error {
	title, body := formatGotifyMessage(msg)
	return g.sendWithRetry(gotifyQueuedMsg{
		title:    title,
		body:     body,
		priority: gotifyPriority(msg.Level),
		enqueued: time.Now(),
	})
}

func (g *gotifyNotifier) drainQueue() {
	ticker := time.NewTicker(gotifySendDelay)
	defer ticker.Stop()

	for {
		select {
		case <-shutdownCtx.Done():
			deadline := time.After(10 * time.Second)
			for {
				select {
				case msg := <-g.sendQueue:
					if time.Since(msg.enqueued) < gotifyQueueMaxAge {
						_ = g.sendWithRetry(msg)
					}
				case <-deadline:
					return
				}
			}

		case <-ticker.C:
			select {
			case msg := <-g.sendQueue:
				if time.Since(msg.enqueued) > gotifyQueueMaxAge {
					debugLog("NOTIFY", "", fmt.Sprintf(
						"⚠️ Gotify Nachricht verworfen (zu alt: %v)",
						time.Since(msg.enqueued).Round(time.Second),
					))
					continue
				}
				if err := g.sendWithRetry(msg); err != nil {
					debugLog("NOTIFY", "", fmt.Sprintf("⚠️ Gotify Send fehlgeschlagen: %v", err))
				}
			default:
			}
		}
	}
}

func (g *gotifyNotifier) sendWithRetry(msg gotifyQueuedMsg) error {
	const maxRetries = 3
	wait := 5 * time.Second

	payload := map[string]interface{}{
		"title":    msg.title,
		"message":  msg.body,
		"priority": msg.priority,
	}

	for attempt := 0; attempt < maxRetries; attempt++ {
		err := g.doSend(payload)
		if err == nil {
			return nil
		}
		debugLog("NOTIFY", "", fmt.Sprintf(
			"⌛ Gotify Retry %d/%d nach Fehler: %v (warte %v)",
			attempt+1, maxRetries, err, wait,
		))
		select {
		case <-shutdownCtx.Done():
			return err
		case <-time.After(wait):
		}
		wait *= 2
	}
	return fmt.Errorf("gotify: max retries erreicht")
}

func (g *gotifyNotifier) doSend(payload map[string]interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	endpoint := fmt.Sprintf("%s/message?token=%s", g.url, g.token)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
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

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("gotify HTTP %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

func formatGotifyMessage(msg NotifyMessage) (title, body string) {
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

	title = fmt.Sprintf("%s Go-DynDNS · %s", icon, msg.Action)

	var sb strings.Builder
	if msg.Domain != "" {
		fmt.Fprintf(&sb, "Domain: %s\n", msg.Domain)
	}
	sb.WriteString(msg.Message)
	fmt.Fprintf(&sb, "\n%s", time.Now().Local().Format("02.01.2006 15:04:05"))

	return title, sb.String()
}

func gotifyPriority(level LogLevel) int {
	switch level {
	case LogError:
		return 8
	case LogWarn:
		return 5
	default:
		return 3
	}
}