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
	"sync"
	"time"
)

// ============================================================================
// GOTIFY TYPES
// ============================================================================
type gotifyNotifier struct {
	ctx       context.Context
	sendQueue chan gotifyQueuedMsg
	cancel    context.CancelFunc
	url       string
	token     string
	wg        sync.WaitGroup
}

type gotifyQueuedMsg struct {
	enqueued time.Time
	title    string
	body     string
	priority int
}

// ============================================================================
// GOTIFY NOTIFIER
// ============================================================================
func newGotifyNotifier(url, token string) *gotifyNotifier {
	ctx, cancel := context.WithCancel(notificationParentContext())
	g := &gotifyNotifier{
		url:       strings.TrimRight(strings.TrimSpace(url), "/"),
		token:     strings.TrimSpace(token),
		sendQueue: make(chan gotifyQueuedMsg, gotifyQueueSize),
		ctx:       ctx,
		cancel:    cancel,
	}
	g.wg.Go(func() {
		g.drainQueue()
	})
	return g
}

func (g *gotifyNotifier) Name() string { return "Gotify" }

func (g *gotifyNotifier) Close() {
	g.cancel()
	g.wg.Wait()
}

func (g *gotifyNotifier) Send(msg NotifyMessage) error {
	select {
	case <-g.ctx.Done():
		return g.ctx.Err()
	default:
	}

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
				t(phrases().GotifyQueueFull, "⚠️ Gotify Queue voll – älteste Nachricht verworfen (Alter: %v)"),
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
		case <-g.ctx.Done():
			return

		case <-ticker.C:
			select {
			case msg := <-g.sendQueue:
				if time.Since(msg.enqueued) > gotifyQueueMaxAge {
					debugLog("NOTIFY", "", fmt.Sprintf(
						t(phrases().GotifyMsgDiscarded, "⚠️ Gotify Nachricht verworfen (zu alt: %v)"),
						time.Since(msg.enqueued).Round(time.Second),
					))
					continue
				}
				if err := g.sendWithRetry(msg); err != nil {
					debugLog("NOTIFY", "", fmt.Sprintf(
						t(phrases().GotifySendFailed, "⚠️ Gotify Send fehlgeschlagen: %v"),
						err,
					))
				}
			default:
			}
		}
	}
}

func (g *gotifyNotifier) sendWithRetry(msg gotifyQueuedMsg) error {
	const maxAttempts = 3
	wait := 5 * time.Second

	payload := map[string]any{
		"title":    msg.title,
		"message":  msg.body,
		"priority": msg.priority,
	}

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		lastErr = g.doSend(payload)
		if lastErr == nil {
			return nil
		}
		if attempt == maxAttempts {
			break
		}

		debugLog("NOTIFY", "", fmt.Sprintf(
			t(phrases().GotifyRetry, "⌛ Gotify Retry %d/%d nach Fehler: %v (warte %v)"),
			attempt, maxAttempts-1, lastErr, wait,
		))
		timer := time.NewTimer(wait)
		select {
		case <-g.ctx.Done():
			stopNotifyTimer(timer)
			return lastErr
		case <-timer.C:
		}
		wait *= 2
	}

	return fmt.Errorf("gotify: max retries reached: %w", lastErr)
}

func (g *gotifyNotifier) doSend(payload map[string]any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	endpoint := fmt.Sprintf("%s/message?token=%s", g.url, g.token)
	ctx, cancel := context.WithTimeout(g.ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, MethodPOST, endpoint, bytes.NewReader(data))
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
	icon := notifyIcon(msg)

	title = fmt.Sprintf("%s Go-DynDNS · %s", icon, msg.Action)

	var sb strings.Builder
	if msg.Domain != "" {
		fmt.Fprintf(&sb, "Domain: %s\n", msg.Domain)
	}
	sb.WriteString(msg.Message)
	fmt.Fprintf(&sb, "\n%s", time.Now().Format(statusTimestampLayout))

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
