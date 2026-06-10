//go:build darwin

// Package main
package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// IP DETECTION
// ============================================================================
func fetchIPResponse(ctx context.Context, url string) (string, int, time.Duration, error) {
	debugLog("IP-CHECK", "", "🌐 "+url)

	req, err := http.NewRequestWithContext(ctx, MethodGET, url, nil)
	if err != nil {
		debugLog("IP-CHECK", "", fmt.Sprintf("❌ %s: %v", T.RequestCreationFailed, err))
		return "", 0, 0, fmt.Errorf("%s: %w", t(T.ErrRequestCreate, "request create failed"), err)
	}

	start := time.Now()
	resp, err := getHTTPClient().Do(req)
	duration := time.Since(start)
	if err != nil {
		debugLog("IP-CHECK", "", fmt.Sprintf("❌ %s: %v", T.HTTPError, err))
		return "", 0, duration, fmt.Errorf("%s: %w", t(T.ErrNetworkError, "network error"), err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			log(LogContext{
				Level:   LogError,
				Action:  ActionError,
				Message: fmt.Sprintf(t(T.FailedCloseResponseBody, "Failed to close response body: %v"), cerr),
			})
		}
	}()

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("%s: %d", T.BadStatusCode, resp.StatusCode)
		debugLog("IP-CHECK", "", "❌ "+err.Error())
		return "", resp.StatusCode, duration, err
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, IPCheckBodyMaxBytes))
	if err != nil {
		debugLog("IP-CHECK", "", fmt.Sprintf("❌ %s: %v", T.BodyReadError, err))
		return "", resp.StatusCode, duration, fmt.Errorf("%s: %w", t(T.ErrBodyRead, "body read failed"), err)
	}

	return strings.TrimSpace(string(body)), resp.StatusCode, duration, nil
}

func validatePublicIP(ipStr string, want IPVersion) (string, error) {
	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		return "", fmt.Errorf(T.InvalidIPDetected, ipStr)
	}

	switch want {
	case IPV4:
		if parsed.To4() == nil {
			return "", fmt.Errorf(T.ExpectedIPv4ButGot, ipStr)
		}
	case IPV6:
		if parsed.To4() != nil {
			return "", fmt.Errorf(T.ExpectedIPv6ButGot, ipStr)
		}
	}

	return ipStr, nil
}

func getPublicIP(ctx context.Context, url string, want IPVersion) (string, error) {
	ipStr, statusCode, duration, err := fetchIPResponse(ctx, url)
	if err != nil {
		apiMetrics.RecordError("IP", statusCode, err, duration)
		return "", err
	}

	validatedIP, err := validatePublicIP(ipStr, want)
	if err != nil {
		apiMetrics.RecordError("IP", statusCode, err, duration)
		debugLog("IP-CHECK", "", "❌ "+err.Error())
		return "", err
	}

	debugLog("IP-CHECK", "", fmt.Sprintf("✅ %s: %s | %s: %v", T.ReceivedIP, validatedIP, T.AvgLatency, duration))
	ipLog(fmt.Sprintf(T.PublicIPDetectedVia, want, url, validatedIP, T.AvgLatency, duration))

	apiMetrics.RecordSuccess("IP", duration)
	apiMetrics.RecordIPLatency(duration)

	return validatedIP, nil
}

func getPublicIPFromAny(parent context.Context, urls []string, want IPVersion) (string, error) {
	if len(urls) == 0 {
		return "", errors.New(T.NoIPEndpointsConfigured)
	}

	var lastErr error

	for _, rawURL := range urls {
		u := strings.TrimSpace(rawURL)
		if u == "" {
			continue
		}

		ctx, cancel := context.WithTimeout(parent, IPCheckTimeout)
		ip, err := getPublicIP(ctx, u, want)
		cancel()

		if err == nil {
			broadcastUpdate("ip_check_result", map[string]any{
				"url":  u,
				"ok":   true,
				"want": fmt.Sprintf("%d", int(want)),
			})
			return ip, nil
		}

		broadcastUpdate("ip_check_result", map[string]any{
			"url":  u,
			"ok":   false,
			"want": fmt.Sprintf("%d", int(want)),
		})
		lastErr = err
		debugLog("IP-CHECK", "", fmt.Sprintf(T.FallbackFailed, u, err))
	}

	if lastErr == nil {
		lastErr = errors.New(T.NoIPEndpointsConfigured)
	}

	return "", fmt.Errorf("%s: %w", T.AllIPEndpointsFailed, lastErr)
}

type darwinIPv6Candidate struct {
	ip         net.IP
	source     string
	flags      string
	temporary  bool
	deprecated bool
}

type darwinIPv6ScanResult struct {
	candidate *darwinIPv6Candidate
	sawGlobal bool
}

func getIPv6FromInterface(ifaceName string) (string, error) {
	debugLog("IP-CHECK", "", fmt.Sprintf("🔍 %s: %s", T.CheckingInterface, ifaceName))

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		debugLog("IP-CHECK", "", fmt.Sprintf("❌ %s: %v", T.InterfaceNotFound, err))
		return "", err
	}

	if scan, err := getDarwinIPv6FromIfconfig(ifaceName); err == nil {
		if scan.candidate != nil {
			return selectIPv6FromInterface(ifaceName, scan.candidate)
		}

		if scan.sawGlobal {
			debugLog("IP-CHECK", "", "⚠️  "+T.NoIPv6OnInterface)
			return "", errors.New(T.NoIPv6OnInterface)
		}
	} else {
		debugLog("IP-CHECK", "", fmt.Sprintf("⚠️ ifconfig IPv6 lookup failed, falling back to net.Interface.Addrs: %v", err))
	}

	addrs, err := iface.Addrs()
	if err != nil {
		debugLog("IP-CHECK", "", fmt.Sprintf("❌ %s: %v", T.AddressesNotReadable, err))
		return "", err
	}

	for _, addr := range addrs {
		ip := ipFromNetAddr(addr)
		if !isUsableGlobalIPv6(ip) {
			continue
		}

		return selectIPv6FromInterface(ifaceName, &darwinIPv6Candidate{
			ip:     ip,
			source: "net.Interface.Addrs",
			flags:  "unknown",
		})
	}

	debugLog("IP-CHECK", "", "⚠️  "+T.NoIPv6OnInterface)
	return "", errors.New(T.NoIPv6OnInterface)
}

func getDarwinIPv6FromIfconfig(ifaceName string) (darwinIPv6ScanResult, error) {
	out, err := exec.Command("/sbin/ifconfig", ifaceName).CombinedOutput()
	if err != nil {
		out, err = exec.Command("ifconfig", ifaceName).CombinedOutput()
		if err != nil {
			return darwinIPv6ScanResult{}, err
		}
	}

	return parseDarwinIfconfigIPv6(out), nil
}

func parseDarwinIfconfigIPv6(out []byte) darwinIPv6ScanResult {
	var fallbackTemporary *darwinIPv6Candidate
	var fallbackDeprecated *darwinIPv6Candidate
	result := darwinIPv6ScanResult{}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "inet6" {
			continue
		}

		ip := parseDarwinInet6Field(fields[1])
		if !isUsableGlobalIPv6(ip) {
			continue
		}

		result.sawGlobal = true

		if hasDarwinIPv6Flag(fields, "tentative", "duplicated", "duplicate", "dadfailed", "detached", "invalid") {
			ipLog(fmt.Sprintf("⚠️ SKIP invalid IPv6: %s", ip.String()))
			continue
		}

		candidate := &darwinIPv6Candidate{
			ip:         ip,
			source:     "ifconfig",
			flags:      strings.Join(fields[2:], " "),
			temporary:  hasDarwinIPv6Flag(fields, "temporary"),
			deprecated: hasDarwinIPv6Flag(fields, "deprecated"),
		}

		if candidate.deprecated {
			ipLog(fmt.Sprintf("⚠️ SKIP deprecated/expired IPv6: %s", ip.String()))
			if fallbackDeprecated == nil {
				fallbackDeprecated = candidate
			}
			continue
		}

		if candidate.temporary {
			if fallbackTemporary == nil {
				fallbackTemporary = candidate
			}
			continue
		}

		result.candidate = candidate
		return result
	}

	if fallbackTemporary != nil {
		result.candidate = fallbackTemporary
		return result
	}

	if fallbackDeprecated != nil {
		result.candidate = fallbackDeprecated
		return result
	}

	return result
}

func parseDarwinInet6Field(raw string) net.IP {
	ipStr := strings.TrimSpace(raw)
	if i := strings.IndexByte(ipStr, '%'); i >= 0 {
		ipStr = ipStr[:i]
	}
	return net.ParseIP(ipStr)
}

func hasDarwinIPv6Flag(fields []string, flags ...string) bool {
	wanted := make(map[string]struct{}, len(flags))
	for _, flag := range flags {
		wanted[strings.ToLower(strings.TrimSpace(flag))] = struct{}{}
	}

	for _, field := range fields {
		key := strings.Trim(strings.ToLower(field), ",;[]()")
		if _, ok := wanted[key]; ok {
			return true
		}
	}

	return false
}

func ipFromNetAddr(addr net.Addr) net.IP {
	switch v := addr.(type) {
	case *net.IPNet:
		return v.IP
	case *net.IPAddr:
		return v.IP
	default:
		ipPart := addr.String()
		if i := strings.IndexByte(ipPart, '/'); i >= 0 {
			ipPart = ipPart[:i]
		}
		if i := strings.IndexByte(ipPart, '%'); i >= 0 {
			ipPart = ipPart[:i]
		}
		return net.ParseIP(ipPart)
	}
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

func selectIPv6FromInterface(ifaceName string, candidate *darwinIPv6Candidate) (string, error) {
	ipLog(fmt.Sprintf(
		"%s | source=%s flags=%s temporary=%t deprecated=%t",
		fmt.Sprintf(T.IPv6ViaInterface, ifaceName, candidate.ip.String()),
		candidate.source,
		candidate.flags,
		candidate.temporary,
		candidate.deprecated,
	))

	return candidate.ip.String(), nil
}

func getIPv6(ctx context.Context, ifaceName string) (string, error) {
	if ifaceName != "" {
		if ip, err := getIPv6FromInterface(ifaceName); err == nil {
			return ip, nil
		}
	}
	ipLog(T.IPv6PublicFallback)
	debugLog("IP-CHECK", "", T.IPv6FallbackEndpoints)
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
		ipLog("🔎 " + T.CheckingIPv4 + " ...")
		wg.Go(func() {
			resV4, errV4 = getPublicIPFromAny(ctx, activeIPv4Endpoints(), IPV4)
			if errV4 != nil {
				log(LogContext{
					Level:   LogError,
					Action:  ActionError,
					Message: T.IPv4CheckFailed,
					Error:   errV4,
				})
			}
		})
	}

	if ipMode != IPModeV4 {
		ipLog("🔎 " + T.CheckingIPv6 + " ...")
		wg.Go(func() {
			resV6, errV6 = getIPv6(ctx, ifaceName)
			if errV6 != nil {
				log(LogContext{
					Level:   LogError,
					Action:  ActionError,
					Message: T.IPv6CheckFailed,
					Error:   errV6,
				})
			}
		})
	}

	wg.Wait()

	return finalizeFetchedIPs(ipMode, resV4, resV6, errV4, errV6)
}

func finalizeFetchedIPs(ipMode, ipv4, ipv6 string, errV4, errV6 error) (string, string, error) {
	switch ipMode {
	case IPModeV4:
		return finalizeIPv4Only(ipv4, errV4)
	case IPModeV6:
		return finalizeIPv6Only(ipv6, errV6)
	case IPModeBoth:
		return finalizeBothIPs(ipv4, ipv6, errV4, errV6)
	default:
		logFetchedIPs(ipv4, ipv6)
		return ipv4, ipv6, nil
	}
}

func finalizeIPv4Only(ipv4 string, errV4 error) (string, string, error) {
	if errV4 != nil {
		return "", "", fmt.Errorf("%s: %w", T.IPv4RequiredButFailed, errV4)
	}
	if ipv4 != "" {
		ipLog(fmt.Sprintf(T.IPv4Current, ipv4))
	}
	return ipv4, "", nil
}

func finalizeIPv6Only(ipv6 string, errV6 error) (string, string, error) {
	if errV6 != nil {
		return "", "", fmt.Errorf("%s: %w", T.IPv6RequiredButFailed, errV6)
	}
	if ipv6 != "" {
		ipLog(fmt.Sprintf(T.IPv6Current, ipv6))
	}
	return "", ipv6, nil
}

func finalizeBothIPs(ipv4, ipv6 string, errV4, errV6 error) (string, string, error) {
	if errV4 != nil && errV6 != nil {
		return "", "", fmt.Errorf("%s: v4=%v, v6=%v", T.BothIPVersionsFailed, errV4, errV6)
	}
	logFetchedIPs(ipv4, ipv6)
	return ipv4, ipv6, nil
}

func logFetchedIPs(ipv4, ipv6 string) {
	if ipv4 != "" {
		ipLog(fmt.Sprintf(T.IPv4Current, ipv4))
	}
	if ipv6 != "" {
		ipLog(fmt.Sprintf(T.IPv6Current, ipv6))
	}
}

func activeIPv4Endpoints() []string {
	cfgMu.RLock()
	eps := cfg.IPv4Endpoints
	cfgMu.RUnlock()
	if len(eps) > 0 {
		return eps
	}
	return DefaultIPv4Endpoints
}

func activeIPv6Endpoints() []string {
	cfgMu.RLock()
	eps := cfg.IPv6Endpoints
	cfgMu.RUnlock()
	if len(eps) > 0 {
		return eps
	}
	return DefaultIPv6Endpoints
}

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "localhost"
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				return ipNet.IP.String()
			}
		}
	}
	return "localhost"
}
