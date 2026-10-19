// Package main
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// HTTP Requests and IP Validation
// ============================================================================

func fetchIPResponse(ctx context.Context, url string) (string, int, time.Duration, error) {
	debugLog(logCategoryIPCheck, "", "🌐 "+url)

	req, err := http.NewRequestWithContext(ctx, MethodGET, url, http.NoBody)
	if err != nil {
		debugLog(logCategoryIPCheck, "", fmt.Sprintf("❌ %s: %v", phrases().RequestCreationFailed, err))

		return "", 0, 0, fmt.Errorf("%s: %w", t(phrases().ErrRequestCreate, "request create failed"), err)
	}

	start := time.Now()
	resp, err := getHTTPClient().Do(req)
	duration := time.Since(start)
	if err != nil {
		debugLog(logCategoryIPCheck, "", fmt.Sprintf("❌ %s: %v", phrases().HTTPError, err))

		return "", 0, duration, fmt.Errorf("%s: %w", t(phrases().ErrNetworkError, "network error"), err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			log(LogContext{
				Level:   LogError,
				Action:  ActionError,
				Message: fmt.Sprintf(t(phrases().FailedCloseResponseBody, "Failed to close response body: %v"), cerr),
			})
		}
	}()

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("%s: %d", phrases().BadStatusCode, resp.StatusCode)
		debugLog(logCategoryIPCheck, "", "❌ "+err.Error())

		return "", resp.StatusCode, duration, err
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, IPCheckBodyMaxBytes+1))
	if err != nil {
		debugLog(logCategoryIPCheck, "", fmt.Sprintf("❌ %s: %v", phrases().BodyReadError, err))

		return "", resp.StatusCode, duration, fmt.Errorf("%s: %w", t(phrases().ErrBodyRead, "body read failed"), err)
	}

	if int64(len(body)) > IPCheckBodyMaxBytes {
		return "", resp.StatusCode, duration, errors.New("IP response exceeds maximum size")
	}

	return strings.TrimSpace(string(body)), resp.StatusCode, duration, nil
}

func validatePublicIP(ipStr string, want IPVersion) (string, error) {
	ip, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil {
		return "", fmt.Errorf(phrases().InvalidIPDetected, ipStr)
	}

	ip = ip.Unmap().WithZone("")

	switch want {
	case IPV4:
		if !ip.Is4() {
			return "", fmt.Errorf(phrases().ExpectedIPv4ButGot, ipStr)
		}

	case IPV6:
		if !ip.Is6() {
			return "", fmt.Errorf(phrases().ExpectedIPv6ButGot, ipStr)
		}

	default:
		return "", fmt.Errorf("unsupported IP version: %v", want)
	}

	if !ip.IsGlobalUnicast() ||
		ip.IsPrivate() ||
		ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() {
		return "", fmt.Errorf("non-public IP detected: %s", ip)
	}

	return ip.String(), nil
}

func getPublicIP(ctx context.Context, url string, want IPVersion) (string, error) {
	ipStr, statusCode, duration, err := fetchIPResponse(ctx, url)
	if err != nil {
		apiMetrics.RecordError("IP", MethodGET, statusCode, err, duration)
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: fmt.Sprintf("%s: %d %v", phrases().IPCheckFailed, statusCode, err),
		})
		debugLog(logCategoryIPCheck, "", "❌ "+err.Error())

		return "", err
	}

	validatedIP, err := validatePublicIP(ipStr, want)
	if err != nil {
		apiMetrics.RecordError("IP", MethodGET, statusCode, err, duration)
		log(LogContext{
			Level:   LogError,
			Action:  ActionError,
			Message: fmt.Sprintf("%s: %d %v", phrases().IPCheckFailed, statusCode, err),
		})
		debugLog(logCategoryIPCheck, "", "❌ "+err.Error())

		return "", err
	}

	debugLog(logCategoryIPCheck, "", fmt.Sprintf("✅ %s: %s | %s: %v", phrases().ReceivedIP, validatedIP, phrases().AvgLatency, duration))
	ipLog(fmt.Sprintf(phrases().PublicIPDetectedVia, want, url, validatedIP, phrases().AvgLatency, duration))

	apiMetrics.RecordSuccess("IP", MethodGET, duration)
	apiMetrics.RecordIPLatency(duration)

	return validatedIP, nil
}

func getPublicIPFromAny(parent context.Context, urls []string, want IPVersion) (string, error) {
	if len(urls) == 0 {
		return "", errors.New(phrases().NoIPEndpointsConfigured)
	}

	var lastErr error
	attempted := 0
	failed := 0
	lastURL := ""

	for _, rawURL := range urls {
		if err := parent.Err(); err != nil {
			return "", err
		}

		u := strings.TrimSpace(rawURL)
		if u == "" {
			continue
		}

		attempted++
		lastURL = u

		ctx, cancel := context.WithTimeout(parent, IPCheckTimeout)
		ip, err := getPublicIP(ctx, u, want)
		cancel()

		if err == nil {
			broadcastUpdate("ip_check_result", map[string]any{
				"url":  u,
				"ok":   true,
				"want": strconv.Itoa(int(want)),
			})

			return ip, nil
		}

		if parent.Err() != nil {
			return "", parent.Err()
		}

		failed++
		lastErr = err

		broadcastUpdate("ip_check_result", map[string]any{
			"url":  u,
			"ok":   false,
			"want": strconv.Itoa(int(want)),
		})

		debugLog(logCategoryIPCheck, "",
			fmt.Sprintf(phrases().FallbackFailed, u, err))
	}

	if attempted == 0 {
		return "", errors.New(phrases().NoIPEndpointsConfigured)
	}
	if lastErr == nil {
		lastErr = errors.New(phrases().NoIPEndpointsConfigured)
	}

	return "", fmt.Errorf(
		"%s (attempted=%d failed=%d last=%s): %w",
		phrases().AllIPEndpointsFailed,
		attempted,
		failed,
		lastURL,
		lastErr,
	)
}

// ============================================================================
// IP Detection and Fallback Handling
// ============================================================================

func getIPv6(ctx context.Context, ifaceName string) (string, error) {
	if ifaceName != "" {
		if ip, err := getIPv6FromInterface(ctx, ifaceName); err == nil {
			return ip, nil
		}
	}
	ipLog(phrases().IPv6PublicFallback)
	debugLog(logCategoryIPCheck, "", phrases().IPv6FallbackEndpoints)

	return getPublicIPFromAny(ctx, activeIPv6Endpoints(), IPV6)
}

func fetchCurrentIPs(ctx context.Context) (ipv4, ipv6 string, err error) {
	cfgMu.RLock()
	ipMode := cfg.IPMode
	ifaceName := cfg.IfaceName
	cfgMu.RUnlock()

	var errV4, errV6 error
	var resV4, resV6 string
	var wg sync.WaitGroup

	if ipMode != IPModeV6 {
		ipLog("🔎 " + phrases().CheckingIPv4 + " ...")
		wg.Go(func() {
			resV4, errV4 = getPublicIPFromAny(ctx, activeIPv4Endpoints(), IPV4)
			if errV4 != nil {
				noteIPCheckFailure(IPV4, errV4)

				return
			}
			noteIPCheckSuccess(IPV4)
		})
	}

	if ipMode != IPModeV4 {
		ipLog("🔎 " + phrases().CheckingIPv6 + " ...")
		wg.Go(func() {
			resV6, errV6 = getIPv6(ctx, ifaceName)
			if errV6 != nil {
				noteIPCheckFailure(IPV6, errV6)

				return
			}
			noteIPCheckSuccess(IPV6)
		})
	}

	wg.Wait()

	return finalizeFetchedIPs(ipMode, resV4, resV6, errV4, errV6)
}

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "localhost"
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() && !ipNet.IP.IsLinkLocalUnicast() {
			if ipNet.IP.To4() != nil {
				return ipNet.IP.String()
			}
		}
	}

	return "localhost"
}

// ============================================================================
// IP Detection Result Processing
// ============================================================================

func finalizeFetchedIPs(ipMode, ipv4, ipv6 string, errV4, errV6 error) (string, string, error) {
	switch ipMode {
	case IPModeV4:
		return finalizeIPv4Only(ipv4, errV4)
	case IPModeV6:
		return finalizeIPv6Only(ipv6, errV6)
	default:
		// IPModeBoth und unbekannte Modi: fetchCurrentIPs hat beide
		// Versionen abgefragt, daher gleich behandeln.
		return finalizeBothIPs(ipv4, ipv6, errV4, errV6)
	}
}

func finalizeIPv4Only(ipv4 string, errV4 error) (string, string, error) {
	if errV4 != nil {
		return "", "", fmt.Errorf("%s: %w", phrases().IPv4RequiredButFailed, errV4)
	}
	if ipv4 != "" {
		ipLog(fmt.Sprintf(phrases().IPv4Current, ipv4))
	}

	return ipv4, "", nil
}

func finalizeIPv6Only(ipv6 string, errV6 error) (string, string, error) {
	if errV6 != nil {
		return "", "", fmt.Errorf("%s: %w", phrases().IPv6RequiredButFailed, errV6)
	}
	if ipv6 != "" {
		ipLog(fmt.Sprintf(phrases().IPv6Current, ipv6))
	}

	return "", ipv6, nil
}

func finalizeBothIPs(ipv4, ipv6 string, errV4, errV6 error) (string, string, error) {
	if errV4 != nil && errV6 != nil {
		return "", "", fmt.Errorf("%s: v4=%w, v6=%w", phrases().BothIPVersionsFailed, errV4, errV6)
	}
	if ipv4 != "" {
		ipLog(fmt.Sprintf(phrases().IPv4Current, ipv4))
	}
	if ipv6 != "" {
		ipLog(fmt.Sprintf(phrases().IPv6Current, ipv6))
	}

	return ipv4, ipv6, nil
}

// ============================================================================
// IP Endpoints and IPv6 Address Validation
// ============================================================================

func activeIPv4Endpoints() []string {
	cfgMu.RLock()
	eps := append([]string(nil), cfg.IPv4Endpoints...)
	cfgMu.RUnlock()

	if len(eps) > 0 {
		return eps
	}

	return append([]string(nil), DefaultIPv4Endpoints...)
}

func activeIPv6Endpoints() []string {
	cfgMu.RLock()
	eps := append([]string(nil), cfg.IPv6Endpoints...)
	cfgMu.RUnlock()

	if len(eps) > 0 {
		return eps
	}

	return append([]string(nil), DefaultIPv6Endpoints...)
}

func isUsableGlobalIPv6(ip net.IP) bool {
	ip = ip.To16()
	if ip == nil || ip.To4() != nil {
		return false
	}

	if !ip.IsGlobalUnicast() {
		return false
	}

	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
		return false
	}

	if ip[0]&0xfe == 0xfc {
		return false
	}

	if ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0d && ip[3] == 0xb8 {
		return false
	}

	return true
}
