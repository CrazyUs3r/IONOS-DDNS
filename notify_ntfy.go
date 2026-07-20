// Package main
package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ============================================================================.
type ntfyNotifier struct {
	ctx       context.Context
	sendQueue chan ntfyQueuedMsg
	cancel    context.CancelFunc
	url       string
	topic     string
	token     string
	wg        sync.WaitGroup
}

func (n *ntfyNotifier) Name() string {
	return "ntfy"
}

func (n *ntfyNotifier) Close() {
	n.cancel()
	n.wg.Wait()
}

type ntfyQueuedMsg struct {
	enqueued time.Time
	title    string
	message  string
	domain   string
	priority string
}

// ============================================================================.
func newNtfyNotifier(url, topic, token string) *ntfyNotifier {
	ctx, cancel := context.WithCancel(notificationParentContext())
	n := &ntfyNotifier{
		url:       strings.TrimRight(strings.TrimSpace(url), "/"),
		topic:     strings.Trim(strings.TrimSpace(topic), "/"),
		token:     strings.TrimSpace(token),
		sendQueue: make(chan ntfyQueuedMsg, ntfyQueueSize),
		ctx:       ctx,
		cancel:    cancel,
	}

	n.wg.Go(func() {
		n.drainQueue()
	})

	return n
}

func (n *ntfyNotifier) Send(msg NotifyMessage) error {
	select {
	case <-n.ctx.Done():
		return n.ctx.Err()
	default:
	}

	icon := notifyIcon(msg)
	qm := ntfyQueuedMsg{
		title:    fmt.Sprintf("%s Go-DynDNS · %s", icon, msg.Action),
		message:  msg.Message,
		domain:   msg.Domain,
		priority: ntfyPriority(msg.Level),
		enqueued: time.Now(),
	}

	select {
	case n.sendQueue <- qm:
	default:
		var discardedAge time.Duration

		select {
		case discarded := <-n.sendQueue:
			discardedAge = time.Since(discarded.enqueued)
		default:
		}

		debugLog("NOTIFY", "", fmt.Sprintf(
			t(
				phrases().NtfyQueueFull,
				"⚠️ ntfy-Warteschlange voll – älteste Nachricht verworfen (Alter: %v)",
			),
			discardedAge,
		))

		select {
		case n.sendQueue <- qm:
		default:
		}
	}

	return nil
}

func (n *ntfyNotifier) drainQueue() {
	ticker := time.NewTicker(ntfySendDelay)
	defer ticker.Stop()

	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			select {
			case msg := <-n.sendQueue:
				age := time.Since(msg.enqueued)
				if age > ntfyQueueMaxAge {
					debugLog("NOTIFY", "", fmt.Sprintf(
						t(
							phrases().NtfyMsgDiscarded,
							"⚠️ ntfy-Nachricht verworfen (zu alt: %v)",
						),
						age,
					))

					continue
				}
				if err := n.sendWithRetry(msg); err != nil {
					debugLog("NOTIFY", "", fmt.Sprintf(
						t(
							phrases().NtfySendFailed,
							"⚠️ ntfy-Versand fehlgeschlagen: %v",
						),
						err,
					))
				}
			default:
			}
		}
	}
}

func (n *ntfyNotifier) sendWithRetry(msg ntfyQueuedMsg) error {
	const maxAttempts = 3
	wait := 5 * time.Second

	var lastErr error

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		lastErr = n.doSend(msg)
		if lastErr == nil {
			return nil
		}

		if attempt == maxAttempts {
			break
		}

		debugLog("NOTIFY", "", fmt.Sprintf(
			t(phrases().NtfyRetry, "⌛ ntfy: Wiederholung %d/%d nach Fehler: %v (warte %v)"),
			attempt, maxAttempts-1, lastErr, wait,
		))

		timer := time.NewTimer(wait)
		select {
		case <-n.ctx.Done():
			stopNotifyTimer(timer)

			return lastErr
		case <-timer.C:
		}

		wait *= 2
	}

	return fmt.Errorf(t(phrases().NtfyMaxAttemptsReached, "ntfy: Maximale Anzahl an Versuchen erreicht: %w"), lastErr)
}

func (n *ntfyNotifier) doSend(msg ntfyQueuedMsg) error {
	endpoint := fmt.Sprintf("%s/%s", n.url, n.topic)

	ctx, cancel := context.WithTimeout(n.ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(
		ctx,
		MethodPOST,
		endpoint,
		strings.NewReader(msg.message),
	)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}

	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	req.Header.Set("User-Agent", ManagedComment)
	req.Header.Set("Title", msg.title)

	if msg.domain != "" {
		req.Header.Set("Tags", msg.domain)
	}
	if msg.priority != "" {
		req.Header.Set("Priority", msg.priority)
	}
	if n.token != "" {
		req.Header.Set("Authorization", "Bearer "+n.token)
	}

	resp, err := getHTTPClient().Do(req)
	if err != nil {
		return fmt.Errorf("send: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))

		return fmt.Errorf(
			"ntfy HTTP %d: %s",
			resp.StatusCode,
			strings.TrimSpace(string(body)),
		)
	}

	return nil
}

func ntfyPriority(level LogLevel) string {
	switch level {
	case LogError:
		return "5"
	case LogWarn:
		return "4"
	default:
		return "3"
	}
}
