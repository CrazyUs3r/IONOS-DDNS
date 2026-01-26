package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync/atomic"
	"time"
)

// ============================================================================
// HTTP CLIENT & TRANSPORT
// ============================================================================

func (t *loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if cfg.DebugHTTPRaw {
		logReq := req.Clone(req.Context())
		if req.GetBody != nil {
			if rc, err := req.GetBody(); err == nil {
				logReq.Body = rc
			}
		}

		if apiKey := logReq.Header.Get("X-API-Key"); apiKey != "" {
			parts := strings.Split(apiKey, ".")
			if len(parts) == 2 {
				logReq.Header.Set("X-API-Key", parts[0][:5]+"***."+"***"+parts[1][len(parts[1])-5:])
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

	start := time.Now()
	resp, err := t.base.RoundTrip(req)
	duration := time.Since(start)

	if err != nil {
		return nil, err
	}

	if cfg.DebugHTTPRaw && resp != nil {
		var bodyBytes []byte
		if resp.Body != nil {
			bodyBytes, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
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

func getHTTPClient() *http.Client {
	clientOnce.Do(func() {
		dnsList := cfg.DNSServers
		if len(dnsList) == 0 {
			dnsList = []string{"1.1.1.1:53", "8.8.8.8:53"}
		}

		domainCount := len(cfg.DomainConfigs)
		maxIdleConns := HTTPMaxIdleConns
		maxIdleConnsPerHost := HTTPMaxIdleConnsHost
		maxConnsPerHost := HTTPMaxConnsHost

		// Bei vielen Domains: Pool vergrößern
		if domainCount > 20 {
			multiplier := (domainCount / 20) + 1
			maxIdleConns *= multiplier
			maxIdleConnsPerHost *= multiplier
			maxConnsPerHost *= multiplier

			debugLog("HTTP", "", fmt.Sprintf(
				"🔧 HTTP Pool erweitert: %d Domains → MaxConns=%d, IdlePerHost=%d",
				domainCount, maxConnsPerHost, maxIdleConnsPerHost,
			))
		}

		dialer := &net.Dialer{
			Timeout:   DNSResolverTimeout,
			KeepAlive: DNSKeepalive,
			Resolver: &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					var lastErr error
					startIndex := int(atomic.LoadInt32(&lastSuccessfulDNS))

					for i := 0; i < len(dnsList); i++ {
						idx := (startIndex + i) % len(dnsList)
						dnsAddr := dnsList[idx]
						targetAddr := dnsAddr
						if !strings.Contains(targetAddr, ":") {
							targetAddr += ":53"
						}

						d := net.Dialer{Timeout: 5 * time.Second}
						conn, err := d.DialContext(ctx, "udp", targetAddr)

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
			},
		}

		baseTransport := &http.Transport{
			DialContext:           dialer.DialContext,
			MaxIdleConns:          maxIdleConns,
			MaxIdleConnsPerHost:   maxIdleConnsPerHost,
			MaxConnsPerHost:       maxConnsPerHost,
			IdleConnTimeout:       HTTPIdleConnTimeout,
			TLSHandshakeTimeout:   HTTPTLSTimeout,
			ResponseHeaderTimeout: HTTPResponseTimeout,
			ExpectContinueTimeout: HTTPExpectTimeout,
			DisableKeepAlives:     false,
			ForceAttemptHTTP2:     true,
		}

		httpClient = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &loggingTransport{
				base: baseTransport,
			},
		}

		debugLog("SYSTEM", "", fmt.Sprintf(T.HttpClientInitialized, len(dnsList)))
	})

	return httpClient
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
