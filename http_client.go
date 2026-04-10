// Package main
package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// ============================================================================
// HTTP TRACE / TIMINGS (DNS, CONNECT, TLS, TTFB, REUSE)
// ============================================================================
func (t *httpTimings) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			t.gotConn = time.Now().Local()
			t.connReused = info.Reused
			t.connWasIdle = info.WasIdle
			t.connIdleTime = info.IdleTime
		},
		DNSStart: func(httptrace.DNSStartInfo) {
			t.dnsStart = time.Now().Local()
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			t.dnsDone = time.Now().Local()
			t.dnsErr = info.Err
		},
		ConnectStart: func(network, addr string) {
			if t.connectStart.IsZero() {
				t.connectStart = time.Now().Local()
				t.connectNet = network
				t.connectAddr = addr
			}
		},
		ConnectDone: func(_, _ string, err error) {
			if t.connectDone.IsZero() {
				t.connectDone = time.Now().Local()
				t.connectErr = err
			}
		},
		TLSHandshakeStart: func() {
			t.tlsStart = time.Now().Local()
		},
		TLSHandshakeDone: func(cs tls.ConnectionState, err error) {
			t.tlsDone = time.Now().Local()
			t.tlsState = &cs
			t.tlsErr = err
		},
		WroteRequest: func(httptrace.WroteRequestInfo) {
			t.wroteRequest = time.Now().Local()
		},

		GotFirstResponseByte: func() {
			t.firstByte = time.Now().Local()
		},
	}
}

func fmtDur(a, b time.Time) string {
	if a.IsZero() || b.IsZero() || b.Before(a) {
		return "-"
	}
	return b.Sub(a).String()
}

func (t *httpTimings) String() string {
	total := "-"
	if !t.start.IsZero() && !t.end.IsZero() && !t.end.Before(t.start) {
		total = t.end.Sub(t.start).String()
	}

	parts := []string{
		"total=" + total,
		"dns=" + fmtDur(t.dnsStart, t.dnsDone),
		"connect=" + fmtDur(t.connectStart, t.connectDone),
		"tls=" + fmtDur(t.tlsStart, t.tlsDone),
		"ttfb=" + fmtDur(t.wroteRequest, t.firstByte),
	}

	if !t.gotConn.IsZero() {
		parts = append(parts,
			fmt.Sprintf("reused=%t", t.connReused),
			fmt.Sprintf("idle=%t", t.connWasIdle),
		)
		if t.connWasIdle {
			parts = append(parts, "idleTime="+t.connIdleTime.String())
		}
	}

	if t.connectAddr != "" {
		parts = append(parts, "dial="+t.connectNet+":"+t.connectAddr)
	}

	if t.dnsErr != nil {
		parts = append(parts, "dnsErr="+t.dnsErr.Error())
	}
	if t.connectErr != nil {
		parts = append(parts, "connectErr="+t.connectErr.Error())
	}
	if t.tlsErr != nil {
		parts = append(parts, "tlsErr="+t.tlsErr.Error())
	}

	return strings.Join(parts, " | ")
}

// ============================================================================
// HTTP CLIENT & TRANSPORT
// ============================================================================
func (t *loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var timings *httpTimings
	if cfg.DebugHTTPRaw {
		timings = &httpTimings{start: time.Now().Local()}
		ctx := httptrace.WithClientTrace(req.Context(), timings.trace())
		req = req.Clone(ctx)
	}

	if cfg.DebugHTTPRaw {
		logReq := req.Clone(req.Context())

		if req.GetBody != nil {
			if rc, err := req.GetBody(); err == nil {
				logReq.Body = rc
				defer func() {
					if closeErr := rc.Close(); closeErr != nil {
						debugLog("HTTP-RAW", "", fmt.Sprintf("Failed to close cloned body: %v", closeErr))
					}
				}()
			}
		}

		if apiKey := logReq.Header.Get("X-API-Key"); apiKey != "" {
			parts := strings.Split(apiKey, ".")
			if len(parts) == 2 {
				p0 := parts[0]
				p1 := parts[1]

				head := p0
				if len(head) > 5 {
					head = head[:5]
				}

				tail := p1
				if len(tail) > 5 {
					tail = tail[len(tail)-5:]
				}

				logReq.Header.Set("X-API-Key", head+"***."+"***"+tail)
			} else {
				logReq.Header.Set("X-API-Key", "***MASKED***")
			}
		}

		if auth := logReq.Header.Get("Authorization"); auth != "" {
			if strings.HasPrefix(auth, "Bearer ") {
				logReq.Header.Set("Authorization", "Bearer ***MASKED***")
			}
		}

		requestDump, _ := httputil.DumpRequestOut(logReq, true)
		debugLog("HTTP-RAW", "", "\n>>> REQUEST >>>\n"+string(requestDump))
	}

	start := time.Now().Local()
	resp, err := t.base.RoundTrip(req)
	duration := time.Since(start)

	if timings != nil {
		timings.end = time.Now().Local()
		msg := timings.String()
		if replacer := getSecretReplacer(); replacer != nil {
			msg = replacer.Replace(msg)
		}
		debugLog("HTTP-TIMING", "", fmt.Sprintf("%s %s → %s", req.Method, req.URL.String(), msg))
	}

	if err != nil {
		return nil, err
	}

	if cfg.DebugHTTPRaw && resp != nil {
		var bodyBytes []byte
		if resp.Body != nil {
			bodyBytes, _ = io.ReadAll(resp.Body)
			closeErr := resp.Body.Close()
			if closeErr != nil {
				debugLog("HTTP-RAW", "", fmt.Sprintf("Failed to close response body: %v", closeErr))
			}
			resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		bodyStr := string(bodyBytes)
		if replacer := getSecretReplacer(); replacer != nil {
			bodyStr = replacer.Replace(bodyStr)
		}

		var prettyJSON bytes.Buffer
		if err := json.Indent(&prettyJSON, []byte(bodyStr), "", "  "); err == nil {
			bodyStr = prettyJSON.String()
		}

		maxDebugLen := 5000
		if len(bodyStr) > maxDebugLen {
			totalLen := len(bodyStr)
			bodyStr = bodyStr[:maxDebugLen] + fmt.Sprintf("\n... (%d bytes truncated for debug log)", totalLen-maxDebugLen)
		}

		debugLog("HTTP-RAW", "", fmt.Sprintf("\n<<< RESPONSE (%.2fs) <<<\nStatus: %s\nBody:\n%s\n",
			duration.Seconds(),
			resp.Status,
			bodyStr))
	}
	return resp, nil
}

func ResetHTTPClient() {
	clientMu.Lock()
	defer clientMu.Unlock()
	httpClient = nil
	clientDNSKey = ""
}

func dnsKey(servers []string) string {
	return strings.Join(servers, ",")
}

func getHTTPClient() *http.Client {
	currentKey := dnsKey(cfg.DNSServers)

	// Schneller Pfad: DNS unverändert
	clientMu.RLock()
	if httpClient != nil && clientDNSKey == currentKey {
		c := httpClient
		clientMu.RUnlock()
		return c
	}
	clientMu.RUnlock()

	// Langsamer Pfad: neu bauen
	clientMu.Lock()
	defer clientMu.Unlock()

	// Double-check nach Lock
	if httpClient != nil && clientDNSKey == currentKey {
		return httpClient
	}

	httpClient = buildHTTPClient(cfg.DNSServers)
	clientDNSKey = currentKey
	return httpClient
}

func buildHTTPClient(dnsList []string) *http.Client {
	if len(dnsList) == 0 {
		dnsList = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	domainCount := len(cfg.DomainConfigs)
	maxIdleConns := HTTPMaxIdleConns
	maxIdleConnsPerHost := HTTPMaxIdleConnsHost
	maxConnsPerHost := HTTPMaxConnsHost

	if domainCount > 20 {
		multiplier := (domainCount / 20) + 1
		maxIdleConns *= multiplier
		maxIdleConnsPerHost *= multiplier
		maxConnsPerHost *= multiplier

		debugLog("HTTP", "", fmt.Sprintf(
			"🔧 %s %d Domains → MaxConns=%d, IdlePerHost=%d",
			T.HTTPPool, domainCount, maxConnsPerHost, maxIdleConnsPerHost,
		))
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var lastErr error
			startIndex := int(atomic.LoadInt32(&lastSuccessfulDNS))

			for i := 0; i < len(dnsList); i++ {
				if err := ctx.Err(); err != nil {
					return nil, err
				}

				idx := (startIndex + i) % len(dnsList)
				targetAddr := dnsList[idx]
				if !strings.Contains(targetAddr, ":") {
					targetAddr += ":53"
				}

				d := net.Dialer{Timeout: 5 * time.Second}

				conn, err := d.DialContext(ctx, "udp", targetAddr)
				if err != nil {
					conn, err = d.DialContext(ctx, "tcp", targetAddr)
				}

				if err == nil {
					if idx != startIndex {
						atomic.StoreInt32(&lastSuccessfulDNS, int32(idx))
					}
					return conn, nil
				}

				lastErr = err
				debugLog("DNS-FAILOVER", "", fmt.Sprintf("❌ DNS %s fehlgeschlagen: %v", targetAddr, err))
			}

			return nil, fmt.Errorf("alle DNS-Server fehlgeschlagen: %w", lastErr)
		},
	}

	dnsTTL := time.Duration(cfg.Interval)*time.Second + 30*time.Second
	if dnsTTL < 60*time.Second {
		dnsTTL = 60 * time.Second
	}
	if dnsTTL > 10*time.Minute {
		dnsTTL = 10 * time.Minute
	}
	cache := newDNSCache(resolver, dnsTTL)

	baseDialer := &net.Dialer{
		Timeout:       DNSResolverTimeout,
		KeepAlive:     DNSKeepalive,
		DualStack:     true,
		FallbackDelay: 250 * time.Millisecond,
	}

	cachedDialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return baseDialer.DialContext(ctx, network, addr)
		}

		if ip := net.ParseIP(host); ip != nil {
			return baseDialer.DialContext(ctx, network, addr)
		}

		addrs, err := cache.getIPAddrs(ctx, host)
		if err != nil {
			return nil, err
		}

		var lastErr error
		for _, ipAddr := range addrs {
			target := net.JoinHostPort(ipAddr.IP.String(), port)
			conn, dErr := baseDialer.DialContext(ctx, network, target)
			if dErr == nil {
				return conn, nil
			}
			lastErr = dErr
		}
		cache.invalidate(host)
		return nil, fmt.Errorf("dial failed for %s (ips=%d): %w", addr, len(addrs), lastErr)
	}

	baseTransport := &http.Transport{
		DialContext:           cachedDialContext,
		MaxIdleConns:          maxIdleConns,
		MaxIdleConnsPerHost:   maxIdleConnsPerHost,
		MaxConnsPerHost:       maxConnsPerHost,
		IdleConnTimeout:       HTTPIdleConnTimeout,
		TLSHandshakeTimeout:   HTTPTLSTimeout,
		ResponseHeaderTimeout: HTTPResponseTimeout,
		ExpectContinueTimeout: HTTPExpectTimeout,
		DisableKeepAlives:     false,
		ForceAttemptHTTP2:     true,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			ClientSessionCache: tls.NewLRUClientSessionCache(32),
		},
	}

	httpClient = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &loggingTransport{
			base: baseTransport,
		},
	}

	debugLog("SYSTEM", "", fmt.Sprintf(T.HTTPClientInitialized, len(dnsList)))
	return &http.Client{ /* ... */ }
}

// ============================================================================
// SANITIZATION
// ============================================================================
func getSecretReplacer() *strings.Replacer {
	secretReplacerOnce.Do(func() {
		replacements := []string{}

		for _, dc := range cfg.DomainConfigs {
			switch dc.Provider {
			case ProviderIONOS:
				if dc.APIPrefix != "" && dc.APISecret != "" {
					fullKey := dc.APIPrefix + "." + dc.APISecret
					replacements = append(replacements, fullKey, "***API-KEY***")
				}
				if dc.APISecret != "" {
					replacements = append(replacements, dc.APISecret, "***SECRET***")
				}
				if dc.APIPrefix != "" {
					replacements = append(replacements, dc.APIPrefix, "***PREFIX***")
				}

			case ProviderCloudflare:
				if dc.CFToken != "" {
					replacements = append(replacements, dc.CFToken, "***CF-TOKEN***")
				}
				if dc.CFSecret != "" {
					replacements = append(replacements, dc.CFSecret, "***CF-SECRET***")
				}

			case ProviderIPv64:
				if dc.IPv64Token != "" {
					replacements = append(replacements, dc.IPv64Token, "***IPV64-TOKEN***")
				}
			}
		}

		if len(replacements) > 0 {
			secretReplacer = strings.NewReplacer(replacements...)
		} else {
			secretReplacer = strings.NewReplacer("dummy_secret_placeholder", "none")
		}
	})

	return secretReplacer
}

func sanitizeError(err error) string {
	if err == nil {
		return ""
	}

	msg := err.Error()

	if replacer := getSecretReplacer(); replacer != nil {
		msg = replacer.Replace(msg)
	}

	return msg
}

func sanitizeID(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "x"
	}

	var b strings.Builder
	b.Grow(len(s))

	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune(r)
		case r == '.':
			b.WriteByte('-')
		default:
		}
	}
	out := b.String()
	if out == "" {
		return "x"
	}
	return out
}

func sanitizeIDWithHash(s string) string {
	base := sanitizeID(s)
	sum := sha1.Sum([]byte(s))
	sfx := hex.EncodeToString(sum[:])[:8]
	if base == "" || base == "x" {
		return "d-" + sfx
	}
	return base + "-" + sfx
}

// ============================================================================
// DNS CACHE (TTL cache + in-flight dedupe)
// ============================================================================
func newDNSCache(r *net.Resolver, ttl time.Duration) *dnsCache {
	return &dnsCache{
		ttl:      ttl,
		entries:  make(map[string]dnsCacheEntry),
		inflight: make(map[string]*dnsInFlight),
		resolver: r,
	}
}

func (c *dnsCache) getIPAddrs(ctx context.Context, host string) ([]net.IPAddr, error) {
	now := time.Now().Local()

	c.mu.Lock()
	if e, ok := c.entries[host]; ok && now.Before(e.expiry) && len(e.ips) > 0 {
		out := make([]net.IPAddr, len(e.ips))
		copy(out, e.ips)
		c.mu.Unlock()
		return out, nil
	}

	if inf, ok := c.inflight[host]; ok {
		done := inf.done
		c.mu.Unlock()

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-done:
			if inf.err != nil {
				return nil, inf.err
			}
			out := make([]net.IPAddr, len(inf.addrs))
			copy(out, inf.addrs)
			return out, nil
		}
	}

	inf := &dnsInFlight{done: make(chan struct{})}
	c.inflight[host] = inf
	c.mu.Unlock()

	addrs, err := c.lookupWithTrace(ctx, host)

	c.mu.Lock()
	inf.addrs = addrs
	inf.err = err
	close(inf.done)
	delete(c.inflight, host)

	if err == nil && len(addrs) > 0 {
		c.entries[host] = dnsCacheEntry{
			ips:    addrs,
			expiry: now.Add(c.ttl),
		}
	}
	c.mu.Unlock()

	return addrs, err
}

func (c *dnsCache) lookupWithTrace(ctx context.Context, host string) ([]net.IPAddr, error) {
	if tr := httptrace.ContextClientTrace(ctx); tr != nil && tr.DNSStart != nil {
		tr.DNSStart(httptrace.DNSStartInfo{Host: host})
	}

	addrs, err := c.resolver.LookupIPAddr(ctx, host)

	if tr := httptrace.ContextClientTrace(ctx); tr != nil && tr.DNSDone != nil {
		tr.DNSDone(httptrace.DNSDoneInfo{Addrs: addrs, Err: err})
	}

	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("dns: keine IPs für host=%s", host)
	}
	return addrs, nil
}

func (c *dnsCache) invalidate(host string) {
	c.mu.Lock()
	delete(c.entries, host)
	c.mu.Unlock()
}

// ============================================================================
// TRUST_PROXY - Forwarded-For
// ============================================================================
func getClientIP(r *http.Request) string {
	trustProxy := true

	if v := strings.TrimSpace(os.Getenv("TRUST_PROXY")); v != "" {
		trustProxy = strings.ToLower(v) != "false"
	}

	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			ips := strings.Split(xff, ",")
			if len(ips) > 0 {
				return strings.TrimSpace(ips[0])
			}
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return xri
		}
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func validateTriggerToken(r *http.Request) bool {
	token := r.Header.Get(TriggerTokenHeader)

	expectedToken := os.Getenv("TRIGGER_TOKEN")
	if expectedToken == "" {
		return true
	}

	return token == expectedToken
}
