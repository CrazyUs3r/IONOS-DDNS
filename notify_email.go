// Package main
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strings"
	"sync"
	"time"
)

const (
	emailQueueSize        = 32
	emailQueueMaxAge      = 10 * time.Minute
	emailSendInterval     = 1 * time.Second
	emailDialTimeout      = 15 * time.Second
	emailOperationTimeout = 30 * time.Second
)

type emailNotifier struct {
	host          string
	port          int
	username      string
	password      string
	from          string
	to            []string
	subjectPrefix string
	tlsMode       string // "starttls" | "tls" | "plain"
	sendQueue     chan emailMsg
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
}

type emailMsg struct {
	subject  string
	body     string
	enqueued time.Time
}

// ============================================================================
// CONSTRUCTOR
// ============================================================================

func newEmailNotifier(host string, port int, username, password, from, toRaw, subjectPrefix, tlsMode string) *emailNotifier {
	host = strings.TrimSpace(host)
	from = strings.TrimSpace(from)
	subjectPrefix = sanitizeEmailHeader(subjectPrefix)
	tlsMode = strings.ToLower(strings.TrimSpace(tlsMode))
	if tlsMode != emailTLSModeTLS && tlsMode != emailTLSModePlain && tlsMode != emailTLSModeStartTLS {
		tlsMode = emailTLSModeTLS
	}
	if port < 1 || port > 65535 {
		if tlsMode == emailTLSModeTLS {
			port = 465
		} else {
			port = 587
		}
	}

	if subjectPrefix == "" {
		subjectPrefix = "[DynDNS]"
	}
	if tlsMode == "" {
		tlsMode = emailTLSModeStartTLS
	}

	recipients := make([]string, 0)
	for addr := range strings.SplitSeq(toRaw, ",") {
		addr = strings.TrimSpace(addr)
		if addr != "" {
			recipients = append(recipients, addr)
		}
	}

	ctx, cancel := context.WithCancel(notificationParentContext())
	n := &emailNotifier{
		host:          host,
		port:          port,
		username:      username,
		password:      password,
		from:          from,
		to:            recipients,
		subjectPrefix: subjectPrefix,
		tlsMode:       tlsMode,
		sendQueue:     make(chan emailMsg, emailQueueSize),
		ctx:           ctx,
		cancel:        cancel,
	}
	n.wg.Go(func() {
		n.drainQueue()
	})
	return n
}

func (e *emailNotifier) Name() string { return "Email" }

func (e *emailNotifier) Close() {
	e.cancel()
	e.wg.Wait()
}

// ============================================================================
// SEND
// ============================================================================

func (e *emailNotifier) Send(msg NotifyMessage) error {
	select {
	case <-e.ctx.Done():
		return e.ctx.Err()
	default:
	}

	subject, body := formatEmailMessage(msg, e.subjectPrefix)
	em := emailMsg{subject: subject, body: body, enqueued: time.Now()}

	select {
	case e.sendQueue <- em:
	default:
		select {
		case dropped := <-e.sendQueue:
			debugLog("NOTIFY", "", fmt.Sprintf(
				"⚠️ Email queue full – oldest message dropped (age: %v)",
				time.Since(dropped.enqueued).Round(time.Second),
			))
		default:
		}
		select {
		case e.sendQueue <- em:
		default:
		}
	}
	return nil
}

func (e *emailNotifier) SendSync(msg NotifyMessage) error {
	subject, body := formatEmailMessage(msg, e.subjectPrefix)
	return e.doSend(emailMsg{subject: subject, body: body})
}

// ============================================================================
// QUEUE DRAIN
// ============================================================================

func (e *emailNotifier) drainQueue() {
	ticker := time.NewTicker(emailSendInterval)
	defer ticker.Stop()

	for {
		select {
		case <-e.ctx.Done():
			return

		case <-ticker.C:
			select {
			case msg := <-e.sendQueue:
				if time.Since(msg.enqueued) > emailQueueMaxAge {
					debugLog("NOTIFY", "", fmt.Sprintf(
						"⚠️ Email message discarded (too old: %v)",
						time.Since(msg.enqueued).Round(time.Second),
					))
					continue
				}
				if err := e.doSend(msg); err != nil {
					debugLog("NOTIFY", "", fmt.Sprintf("⚠️ Email send failed: %v", err))
					log(LogContext{
						Level:    LogError,
						Category: "NOTIFY",
						Action:   ActionError,
						Message:  "Email (SMTP) error",
						Error:    err,
					})
				}
			default:
			}
		}
	}
}

// ============================================================================
// SMTP SEND
// ============================================================================

func (e *emailNotifier) doSend(msg emailMsg) error {
	if len(e.to) == 0 {
		return errors.New("email: no recipients configured")
	}

	rawMsg := e.buildRawMessage(msg.subject, msg.body)

	addr := fmt.Sprintf("%s:%d", e.host, e.port)

	switch e.tlsMode {
	case emailTLSModeTLS:
		return e.sendTLS(addr, rawMsg)
	case emailTLSModePlain:
		return e.sendPlain(addr, rawMsg)
	default:
		return e.sendStartTLS(addr, rawMsg)
	}
}

func (e *emailNotifier) sendStartTLS(addr string, msg []byte) error {
	conn, err := net.DialTimeout(ProtocolTCP, addr, emailDialTimeout)
	if err != nil {
		return fmt.Errorf("email dial: %w", err)
	}
	if err := conn.SetDeadline(time.Now().Add(emailOperationTimeout)); err != nil {
		_ = conn.Close()
		return fmt.Errorf("email deadline: %w", err)
	}

	client, err := smtp.NewClient(conn, e.host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("email client: %w", err)
	}
	defer func() { _ = client.Quit() }()

	tlsCfg := &tls.Config{ServerName: e.host, MinVersion: tls.VersionTLS12}
	if err := client.StartTLS(tlsCfg); err != nil {
		return fmt.Errorf("email starttls: %w", err)
	}

	if e.username != "" {
		auth := smtp.PlainAuth("", e.username, e.password, e.host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("email auth: %w", err)
		}
	}

	return e.smtpSend(client, msg)
}

func (e *emailNotifier) sendTLS(addr string, msg []byte) error {
	tlsCfg := &tls.Config{ServerName: e.host, MinVersion: tls.VersionTLS12}
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: emailDialTimeout},
		ProtocolTCP, addr, tlsCfg,
	)
	if err != nil {
		return fmt.Errorf("email tls dial: %w", err)
	}
	if err := conn.SetDeadline(time.Now().Add(emailOperationTimeout)); err != nil {
		_ = conn.Close()
		return fmt.Errorf("email tls deadline: %w", err)
	}

	client, err := smtp.NewClient(conn, e.host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("email tls client: %w", err)
	}
	defer func() { _ = client.Quit() }()

	if e.username != "" {
		auth := smtp.PlainAuth("", e.username, e.password, e.host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("email tls auth: %w", err)
		}
	}

	return e.smtpSend(client, msg)
}

func (e *emailNotifier) sendPlain(addr string, msg []byte) error {
	conn, err := net.DialTimeout(ProtocolTCP, addr, emailDialTimeout)
	if err != nil {
		return fmt.Errorf("email plain dial: %w", err)
	}
	if err := conn.SetDeadline(time.Now().Add(emailOperationTimeout)); err != nil {
		_ = conn.Close()
		return fmt.Errorf("email plain deadline: %w", err)
	}

	client, err := smtp.NewClient(conn, e.host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("email plain client: %w", err)
	}
	defer func() { _ = client.Quit() }()

	if e.username != "" {
		auth := smtp.PlainAuth("", e.username, e.password, e.host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("email plain auth: %w", err)
		}
	}

	return e.smtpSend(client, msg)
}

func (e *emailNotifier) smtpSend(client *smtp.Client, msg []byte) error {
	if err := client.Mail(e.from); err != nil {
		return fmt.Errorf("email MAIL FROM: %w", err)
	}
	for _, rcpt := range e.to {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("email RCPT TO %s: %w", rcpt, err)
		}
	}
	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("email DATA: %w", err)
	}
	if _, err := wc.Write(msg); err != nil {
		_ = wc.Close()
		return fmt.Errorf("email write: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("email DATA close: %w", err)
	}
	return nil
}

// ============================================================================
// MESSAGE FORMATTING
// ============================================================================

func (e *emailNotifier) buildRawMessage(subject, body string) []byte {
	toHeader := sanitizeEmailHeader(strings.Join(e.to, ", "))
	fromHeader := sanitizeEmailHeader(e.from)
	subject = sanitizeEmailHeader(subject)
	now := time.Now().Format("Mon, 02 Jan 2006 15:04:05 -0700")

	var sb strings.Builder
	fmt.Fprintf(&sb, "From: %s\r\n", fromHeader)
	fmt.Fprintf(&sb, "To: %s\r\n", toHeader)
	fmt.Fprintf(&sb, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", subject))
	fmt.Fprintf(&sb, "Date: %s\r\n", now)
	fmt.Fprintf(&sb, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&sb, "Content-Type: text/plain; charset=UTF-8\r\n")
	fmt.Fprintf(&sb, "\r\n")
	fmt.Fprintf(&sb, "%s\r\n", body)
	return []byte(sb.String())
}

func sanitizeEmailHeader(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	return strings.TrimSpace(value)
}

func formatEmailMessage(msg NotifyMessage, prefix string) (subject, body string) {
	icon := notifyIcon(msg)

	subject = fmt.Sprintf("%s %s %s", prefix, icon, msg.Action)
	if msg.Domain != "" {
		subject += " – " + msg.Domain
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "Go-DynDNS Notification\n")
	fmt.Fprintf(&sb, "======================\n\n")
	fmt.Fprintf(&sb, "Event:   %s %s\n", icon, msg.Action)
	if msg.Domain != "" {
		fmt.Fprintf(&sb, "Domain:  %s\n", msg.Domain)
	}
	fmt.Fprintf(&sb, "Message: %s\n", msg.Message)
	fmt.Fprintf(&sb, "Time:    %s\n", time.Now().Format(statusTimestampLayout))
	fmt.Fprintf(&sb, "\n--\nSent by Go-DynDNS\n")

	return subject, sb.String()
}
