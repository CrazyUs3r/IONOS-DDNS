// Package main
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
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
	"sync"
	"time"
)

// ============================================================================
// DNS CACHE
// ============================================================================
type dnsCache struct {
	ttl      time.Duration
	mu       sync.Mutex
	entries  map[string]dnsCacheEntry
	inflight map[string]*dnsInFlight
	resolver *net.Resolver
}

type dnsCacheEntry struct {
	ips    []net.IPAddr
	expiry time.Time
}

type dnsInFlight struct {
	done  chan struct{}
	addrs []net.IPAddr
	err   error
}

type bodyReadCloser struct {
	io.Reader
	io.Closer
}

// ============================================================================
// HTTP TRACE / TIMINGS (DNS, CONNECT, TLS, TTFB, REUSE)
// ============================================================================
type httpTimings struct {
	start        time.Time
	end          time.Time
	gotConn      time.Time
	connReused   bool
	connWasIdle  bool
	connIdleTime time.Duration
	dnsStart     time.Time
	dnsDone      time.Time
	dnsErr       error
	connectStart time.Time
	connectDone  time.Time
	connectNet   string
	connectAddr  string
	connectErr   error
	tlsStart     time.Time
	tlsDone      time.Time
	tlsState     *tls.ConnectionState
	tlsErr       error
	wroteRequest time.Time
	firstByte    time.Time
}

// ============================================================================
// HTTP TRACE / TIMINGS (DNS, CONNECT, TLS, TTFB, REUSE)
// ============================================================================
func (t *httpTimings) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			t.gotConn = time.Now()
			t.connReused = info.Reused
			t.connWasIdle = info.WasIdle
			t.connIdleTime = info.IdleTime
		},
		DNSStart: func(httptrace.DNSStartInfo) {
			t.dnsStart = time.Now()
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			t.dnsDone = time.Now()
			t.dnsErr = info.Err
		},
		ConnectStart: func(network, addr string) {
			if t.connectStart.IsZero() {
				t.connectStart = time.Now()
				t.connectNet = network
				t.connectAddr = addr
			}
		},
		ConnectDone: func(_, _ string, err error) {
			if t.connectDone.IsZero() {
				t.connectDone = time.Now()
				t.connectErr = err
			}
		},
		TLSHandshakeStart: func() {
			t.tlsStart = time.Now()
		},
		TLSHandshakeDone: func(cs tls.ConnectionState, err error) {
			t.tlsDone = time.Now()
			t.tlsState = &cs
			t.tlsErr = err
		},
		WroteRequest: func(httptrace.WroteRequestInfo) {
			t.wroteRequest = time.Now()
		},

		GotFirstResponseByte: func() {
			t.firstByte = time.Now()
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
	req, timings := prepareHTTPTracing(req)

	if cfg.DebugHTTPRaw {
		logHTTPRequest(req)
	}

	start := time.Now()
	resp, err := t.base.RoundTrip(req)
	duration := time.Since(start)

	logHTTPTimings(req, timings)

	if err != nil {
		return nil, err
	}

	if cfg.DebugHTTPRaw && resp != nil {
		logHTTPResponse(resp, duration)
	}

	return resp, nil
}

func prepareHTTPTracing(req *http.Request) (*http.Request, *httpTimings) {
	if !cfg.DebugHTTPRaw {
		return req, nil
	}

	timings := &httpTimings{start: time.Now()}
	ctx := httptrace.WithClientTrace(req.Context(), timings.trace())

	return req.Clone(ctx), timings
}

func logHTTPTimings(req *http.Request, timings *httpTimings) {
	if timings == nil {
		return
	}

	timings.end = time.Now()
	msg := timings.String()

	if replacer := getSecretReplacer(); replacer != nil {
		msg = replacer.Replace(msg)
	}

	debugLog("HTTP-TIMING", "", fmt.Sprintf("%s %s → %s", req.Method, req.URL.String(), msg))
}

func cloneRequestForLogging(req *http.Request) (*http.Request, func()) {
	logReq := req.Clone(req.Context())

	if req.GetBody == nil {
		logReq.Body = nil
		return logReq, func() {}
	}

	rc, err := req.GetBody()
	if err != nil {
		logReq.Body = nil
		return logReq, func() {}
	}

	logReq.Body = rc
	return logReq, func() {
		if closeErr := rc.Close(); closeErr != nil {
			debugLog("HTTP-RAW", "", fmt.Sprintf("Failed to close cloned body: %v", closeErr))
		}
	}
}

func maskSensitiveRequestHeaders(req *http.Request) {
	maskAPIKeyHeader(req.Header)
	maskAuthorizationHeader(req.Header)
}

func maskAPIKeyHeader(header http.Header) {
	apiKey := header.Get("X-API-Key")
	if apiKey == "" {
		return
	}

	parts := strings.Split(apiKey, ".")
	if len(parts) != 2 {
		header.Set("X-API-Key", "***MASKED***")
		return
	}

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

	header.Set("X-API-Key", head+"***."+"***"+tail)
}

func maskAuthorizationHeader(header http.Header) {
	auth := header.Get("Authorization")
	if auth == "" {
		return
	}

	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		header.Set("Authorization", "Bearer ***MASKED***")
		return
	}

	header.Set("Authorization", "***MASKED***")
}

func logHTTPRequest(req *http.Request) {
	if !cfg.DebugHTTPRaw {
		return
	}

	logReq, cleanup := cloneRequestForLogging(req)
	defer cleanup()

	maskSensitiveRequestHeaders(logReq)

	requestDump, _ := httputil.DumpRequestOut(logReq, true)
	debugLog("HTTP-RAW", "", "\n>>> REQUEST >>>\n"+string(requestDump))
}

func logHTTPResponse(resp *http.Response, duration time.Duration) {
	if !cfg.DebugHTTPRaw {
		return
	}

	bodyBytes, truncated := peekAndRestoreResponseBody(resp, 5000)
	bodyStr := sanitizeHTTPDebugBody(string(bodyBytes))
	bodyStr = prettyPrintHTTPDebugJSON(bodyStr)
	if truncated {
		bodyStr += "\n... (response body truncated for debug log)"
	}

	debugLog(
		"HTTP-RAW",
		"",
		fmt.Sprintf(
			"\n<<< RESPONSE (%.2fs) <<<\nStatus: %s\nBody:\n%s\n",
			duration.Seconds(),
			resp.Status,
			bodyStr,
		),
	)
}

func peekAndRestoreResponseBody(resp *http.Response, maxBytes int) ([]byte, bool) {
	if resp == nil || resp.Body == nil || maxBytes <= 0 {
		return nil, false
	}

	original := resp.Body
	peeked, err := io.ReadAll(io.LimitReader(original, int64(maxBytes+1)))
	if err != nil {
		resp.Body = original
		debugLog("HTTP-RAW", "", fmt.Sprintf("Failed to peek response body: %v", err))
		return nil, false
	}

	truncated := len(peeked) > maxBytes
	logBytes := peeked
	if truncated {
		logBytes = peeked[:maxBytes]
		resp.Body = &bodyReadCloser{
			Reader: io.MultiReader(bytes.NewReader(peeked), original),
			Closer: original,
		}
		return logBytes, true
	}

	if err := original.Close(); err != nil {
		debugLog("HTTP-RAW", "", fmt.Sprintf("Failed to close response body: %v", err))
	}

	resp.Body = io.NopCloser(bytes.NewReader(peeked))
	return logBytes, false
}

func logMQTTPublish(topic string, qos byte, retain bool, payload []byte) {
	if !cfg.DebugHTTPRaw {
		return
	}

	body := sanitizeHTTPDebugBody(string(payload))
	body = prettyPrintHTTPDebugJSON(body)
	body = truncateHTTPDebugBody(body, 5000)

	debugLog(
		"MQTT-RAW",
		"",
		fmt.Sprintf(
			"\n>>> PUBLISH >>>\nTopic: %s\nQoS: %d\nRetain: %t\nPayload:\n%s\n",
			topic,
			qos,
			retain,
			body,
		),
	)
}

func sanitizeHTTPDebugBody(body string) string {
	if replacer := getSecretReplacer(); replacer != nil {
		return replacer.Replace(body)
	}
	return body
}

func prettyPrintHTTPDebugJSON(body string) string {
	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, []byte(body), "", "  "); err == nil {
		return prettyJSON.String()
	}
	return body
}

func truncateHTTPDebugBody(body string, maxLen int) string {
	if len(body) <= maxLen {
		return body
	}

	totalLen := len(body)
	return body[:maxLen] + fmt.Sprintf("\n... (%d bytes truncated for debug log)", totalLen-maxLen)
}

func ResetHTTPClient() {
	clientMu.Lock()
	defer clientMu.Unlock()
	httpClient = nil
	clientDNSKey = ""
}

func invalidateSecretReplacer() {
	secretReplacerMu.Lock()
	secretReplacer = nil
	secretReplacerMu.Unlock()
}

func dnsKey(servers []string) string {
	return strings.Join(servers, ",")
}

func getHTTPClient() *http.Client {
	cfgMu.RLock()
	dnsServers := make([]string, len(cfg.DNSServers))
	copy(dnsServers, cfg.DNSServers)
	domainCount := len(cfg.DomainConfigs)
	cfgMu.RUnlock()

	dnsServers = normalizeDNSServers(dnsServers)
	currentKey := fmt.Sprintf("%s|domains=%d", dnsKey(dnsServers), domainCount)

	clientMu.RLock()
	if httpClient != nil && clientDNSKey == currentKey {
		c := httpClient
		clientMu.RUnlock()
		return c
	}
	clientMu.RUnlock()

	clientMu.Lock()
	defer clientMu.Unlock()

	if httpClient != nil && clientDNSKey == currentKey {
		return httpClient
	}

	httpClient = buildHTTPClient(dnsServers)
	clientDNSKey = currentKey
	return httpClient
}

func buildHTTPClient(dnsList []string) *http.Client {
	dnsList = normalizeDNSServers(dnsList)
	domainCount := len(snapshotDomainConfigs())
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

	dnsList = normalizeDNSServers(dnsList)
	resolver := newFailoverResolver(dnsList)

	dnsTTL := min(max(time.Duration(cfg.Interval)*time.Second+30*time.Second, 60*time.Second), 10*time.Minute)
	cache := newDNSCache(resolver, dnsTTL)

	baseDialer := &net.Dialer{
		Timeout:       DNSResolverTimeout,
		KeepAlive:     DNSKeepalive,
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

		addrs = filterIPAddrsForNetwork(prioritizeIPAddrs(addrs), network)
		if len(addrs) == 0 {
			return nil, fmt.Errorf("dns: keine passende IP für host=%s network=%s", host, network)
		}

		conn, err := dialResolvedAddrs(ctx, baseDialer, network, addr, port, addrs)
		if err == nil {
			return conn, nil
		}

		cache.invalidate(host)
		return nil, err
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

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &loggingTransport{
			base: baseTransport,
		},
	}

	debugLog("SYSTEM", "", fmt.Sprintf(T.HTTPClientInitialized, len(dnsList), strings.Join(dnsList, ", ")))
	return client
}

func normalizeDNSServers(servers []string) []string {
	if len(servers) == 0 {
		servers = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}

	out := make([]string, 0, len(servers))
	seen := make(map[string]struct{}, len(servers))
	for _, serverList := range servers {
		for _, server := range splitDNSServerList(serverList) {
			server = normalizeDNSServer(server)
			if server == "" {
				continue
			}
			if _, ok := seen[server]; ok {
				continue
			}
			seen[server] = struct{}{}
			out = append(out, server)
		}
	}

	if len(out) == 0 {
		return []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	return out
}

func splitDNSServerList(serverList string) []string {
	serverList = strings.TrimSpace(serverList)
	if serverList == "" {
		return nil
	}

	parts := strings.FieldsFunc(serverList, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})

	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func normalizeDNSServer(server string) string {
	server = strings.TrimSpace(server)
	if server == "" {
		return ""
	}

	if host, port, err := net.SplitHostPort(server); err == nil {
		if port == "" {
			port = "53"
		}
		return net.JoinHostPort(strings.Trim(host, "[]"), port)
	}

	trimmed := strings.Trim(server, "[]")
	if ip := net.ParseIP(trimmed); ip != nil {
		return net.JoinHostPort(ip.String(), "53")
	}

	if !strings.Contains(server, ":") {
		return net.JoinHostPort(server, "53")
	}

	return server
}

func newFailoverResolver(dnsList []string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			if network == "" {
				network = "udp"
			}

			var lastErr error
			startIndex := int(lastSuccessfulDNS.Load())
			if len(dnsList) > 0 {
				startIndex %= len(dnsList)
			}

			for i := range dnsList {
				if err := ctx.Err(); err != nil {
					return nil, err
				}

				idx := (startIndex + i) % len(dnsList)
				targetAddr := dnsList[idx]
				d := net.Dialer{Timeout: dnsLookupTimeout(), KeepAlive: DNSKeepalive}

				conn, err := d.DialContext(ctx, network, targetAddr)
				if err != nil && strings.HasPrefix(network, "udp") {
					conn, err = d.DialContext(ctx, "tcp", targetAddr)
				}

				if err == nil {
					if idx != startIndex {
						lastSuccessfulDNS.Store(int64(idx))
					}
					return conn, nil
				}

				lastErr = err
				debugLog("DNS-FAILOVER", "", fmt.Sprintf("❌ DNS %s via %s fehlgeschlagen: %v", targetAddr, network, err))
			}

			return nil, fmt.Errorf("alle DNS-Server fehlgeschlagen: %w", lastErr)
		},
	}
}

func dnsLookupTimeout() time.Duration {
	if DNSResolverTimeout > 0 {
		return DNSResolverTimeout
	}
	return 5 * time.Second
}

type dialResult struct {
	conn net.Conn
	err  error
	addr string
}

func dialResolvedAddrs(ctx context.Context, d *net.Dialer, network, originalAddr, port string, addrs []net.IPAddr) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan dialResult, len(addrs))
	started := 0
	fallbackDelay := d.FallbackDelay
	if fallbackDelay <= 0 {
		fallbackDelay = 250 * time.Millisecond
	}

	for i, ipAddr := range addrs {
		if ipAddr.IP == nil {
			continue
		}

		target := net.JoinHostPort(ipAddr.IP.String(), port)
		started++

		go func(i int, target string) {
			if i > 0 {
				timer := time.NewTimer(time.Duration(i) * fallbackDelay)
				defer timer.Stop()
				select {
				case <-ctx.Done():
					results <- dialResult{err: ctx.Err(), addr: target}
					return
				case <-timer.C:
				}
			}

			conn, err := d.DialContext(ctx, network, target)
			results <- dialResult{conn: conn, err: err, addr: target}
		}(i, target)
	}

	if started == 0 {
		return nil, fmt.Errorf("dial failed for %s: keine IPs", originalAddr)
	}

	var lastErr error
	for i := 0; i < started; i++ {
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, ctx.Err()
		case result := <-results:
			if result.err == nil {
				cancel()
				go closeLateDialResults(results, started-i-1)
				return result.conn, nil
			}
			lastErr = result.err
			debugLog("HTTP-DIAL", "", fmt.Sprintf("Dial %s fehlgeschlagen: %v", result.addr, result.err))
		}
	}

	return nil, fmt.Errorf("dial failed for %s (ips=%d): %w", originalAddr, len(addrs), lastErr)
}

func closeLateDialResults(results <-chan dialResult, count int) {
	for range count {
		result := <-results
		if result.conn != nil {
			_ = result.conn.Close()
		}
	}
}

func filterIPAddrsForNetwork(addrs []net.IPAddr, network string) []net.IPAddr {
	if network != "tcp4" && network != "tcp6" {
		return addrs
	}

	out := make([]net.IPAddr, 0, len(addrs))
	for _, addr := range addrs {
		if addr.IP == nil {
			continue
		}
		if network == "tcp4" && addr.IP.To4() != nil {
			out = append(out, addr)
		}
		if network == "tcp6" && addr.IP.To4() == nil {
			out = append(out, addr)
		}
	}
	return out
}

func prioritizeIPAddrs(addrs []net.IPAddr) []net.IPAddr {
	v4 := make([]net.IPAddr, 0, len(addrs))
	v6 := make([]net.IPAddr, 0, len(addrs))
	for _, addr := range addrs {
		if addr.IP == nil {
			continue
		}
		if addr.IP.To4() != nil {
			v4 = append(v4, addr)
		} else {
			v6 = append(v6, addr)
		}
	}

	out := make([]net.IPAddr, 0, len(v4)+len(v6))
	for len(v4) > 0 || len(v6) > 0 {
		if len(v6) > 0 {
			out = append(out, v6[0])
			v6 = v6[1:]
		}
		if len(v4) > 0 {
			out = append(out, v4[0])
			v4 = v4[1:]
		}
	}
	return out
}

// ============================================================================
// SANITIZATION
// ============================================================================
func getSecretReplacer() *strings.Replacer {
	secretReplacerMu.RLock()
	r := secretReplacer
	secretReplacerMu.RUnlock()
	if r != nil {
		return r
	}
	secretReplacerMu.Lock()
	defer secretReplacerMu.Unlock()
	if secretReplacer == nil { // double-checked
		secretReplacer = buildSecretReplacer(snapshotDomainConfigs())
	}
	return secretReplacer
}

func buildSecretReplacer(domainConfigs []DomainConfig) *strings.Replacer {
	replacements := buildSecretReplacements(domainConfigs)

	if len(replacements) == 0 {
		return strings.NewReplacer("dummy_secret_placeholder", "none")
	}

	return strings.NewReplacer(replacements...)
}

func buildSecretReplacements(domainConfigs []DomainConfig) []string {
	replacements := []string{}

	for _, dc := range domainConfigs {
		replacements = appendProviderReplacements(replacements, dc)
	}

	return replacements
}

func appendProviderReplacements(replacements []string, dc DomainConfig) []string {
	switch dc.Provider {
	case ProviderIONOS:
		return appendIONOSReplacements(replacements, dc)

	case ProviderCloudflare:
		return appendCloudflareReplacements(replacements, dc)

	case ProviderIPv64:
		return appendIPv64Replacements(replacements, dc)

	case ProviderHetzner, ProviderHetznerCloud:
		return appendHetznerReplacements(replacements, dc)

	default:
		return replacements
	}
}

func appendIONOSReplacements(replacements []string, dc DomainConfig) []string {
	if dc.APIPrefix != "" && dc.APISecret != "" {
		replacements = append(replacements, dc.APIPrefix+"."+dc.APISecret, "***API-KEY***")
	}

	replacements = appendIfNotEmpty(replacements, dc.APISecret, "***SECRET***")
	replacements = appendIfNotEmpty(replacements, dc.APIPrefix, "***PREFIX***")

	return replacements
}

func appendCloudflareReplacements(replacements []string, dc DomainConfig) []string {
	replacements = appendIfNotEmpty(replacements, dc.CFToken, "***CF-TOKEN***")
	replacements = appendIfNotEmpty(replacements, dc.CFSecret, "***CF-SECRET***")

	return replacements
}

func appendIPv64Replacements(replacements []string, dc DomainConfig) []string {
	return appendIfNotEmpty(replacements, dc.IPv64Token, "***IPV64-TOKEN***")
}

func appendHetznerReplacements(replacements []string, dc DomainConfig) []string {
	replacements = appendIfNotEmpty(replacements, dc.APISecret, "***HETZNER-TOKEN***")
	replacements = appendIfNotEmpty(replacements, dc.APIPrefix, "***HETZNER-TOKEN***")

	return replacements
}

func appendIfNotEmpty(replacements []string, value, replacement string) []string {
	if value == "" {
		return replacements
	}

	return append(replacements, value, replacement)
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

var sanitizeIDCache sync.Map // string → string

func sanitizeIDWithHash(s string) string {
	if cached, ok := sanitizeIDCache.Load(s); ok {
		return cached.(string)
	}
	base := sanitizeID(s)
	sum := sha256.Sum256([]byte(s))
	sfx := hex.EncodeToString(sum[:])[:8]
	var result string
	if base == "" || base == "x" {
		result = "d-" + sfx
	} else {
		result = base + "-" + sfx
	}
	sanitizeIDCache.Store(s, result)
	return result
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
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return nil, fmt.Errorf("dns: leerer host")
	}

	now := time.Now()

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

	lookupCtx, cancel := context.WithTimeout(ctx, dnsLookupTimeout())
	defer cancel()

	addrs, err := c.lookupWithTrace(lookupCtx, host)

	c.mu.Lock()
	inf.addrs = addrs
	inf.err = err
	close(inf.done)
	delete(c.inflight, host)

	if err == nil && len(addrs) > 0 {
		c.entries[host] = dnsCacheEntry{
			ips:    addrs,
			expiry: time.Now().Add(c.ttl),
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
	return prioritizeIPAddrs(addrs), nil
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
		trustProxy = strings.ToLower(v) != constFalse
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

var triggerToken = os.Getenv("TRIGGER_TOKEN")

func validateTriggerToken(r *http.Request) bool {
	token := r.Header.Get(TriggerTokenHeader)

	if triggerToken == "" {
		return true
	}

	return subtle.ConstantTimeCompare([]byte(token), []byte(triggerToken)) == 1
}
