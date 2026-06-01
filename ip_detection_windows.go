//go:build windows

// Package main
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ============================================================================
// IP DETECTION
// ============================================================================
func fetchIPResponse(ctx context.Context, url string) (string, int, time.Duration, error) {
	debugLog("IP-CHECK", "", "🌐 "+url)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
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

func getIPv6FromInterface(ifaceName string) (string, error) {
	debugLog("IP-CHECK", "", fmt.Sprintf("🔍 %s: %s", T.CheckingInterface, ifaceName))

	var ifaceIndex uint64
	hasIfaceIndex := false

	if iface, err := net.InterfaceByName(ifaceName); err == nil {
		if iface.Index < 0 {
			err := fmt.Errorf("invalid negative interface index: %d", iface.Index)
			debugLog("IP-CHECK", "", fmt.Sprintf("❌ invalid interface index for %s: %v", ifaceName, err))
			return "", err
		}

		ifaceIndex = uint64(iface.Index)
		hasIfaceIndex = true
	}

	adapters, buf, err := getWindowsIPv6Adapters()
	_ = buf
	if err != nil {
		debugLog("IP-CHECK", "", fmt.Sprintf("❌ %s: %v", T.AddressesNotReadable, err))
		return "", err
	}

	matchedInterface := false

	for adapter := adapters; adapter != nil; adapter = adapter.Next {
		if !windowsAdapterMatchesInterface(adapter, ifaceName, ifaceIndex, hasIfaceIndex) {
			continue
		}

		matchedInterface = true

		for addr := adapter.FirstUnicastAddress; addr != nil; addr = addr.Next {
			ip := addr.Address.IP()
			if ip == nil {
				continue
			}

			ipLog(fmt.Sprintf(
				"ADDR: %s dad_state=%d preferred_lft=%d valid_lft=%d flags=%#x",
				ip.String(), addr.DadState, addr.PreferredLifetime, addr.ValidLifetime, addr.Flags,
			))

			if !isUsableGlobalIPv6(ip) {
				continue
			}

			if isInvalidWindowsIPv6Addr(addr) {
				ipLog(fmt.Sprintf("⚠️ SKIP invalid IPv6: %s", ip.String()))
				continue
			}

			if isDeprecatedWindowsIPv6Addr(addr) {
				ipLog(fmt.Sprintf("⚠️ SKIP deprecated/expired IPv6: %s", ip.String()))
				continue
			}

			return selectIPv6FromInterface(ifaceName, ip)
		}
	}

	if !matchedInterface {
		err := fmt.Errorf("%s: %s", T.InterfaceNotFound, ifaceName)
		debugLog("IP-CHECK", "", "❌ "+err.Error())
		return "", err
	}

	debugLog("IP-CHECK", "", "⚠️  "+T.NoIPv6OnInterface)
	return "", errors.New(T.NoIPv6OnInterface)
}

func getWindowsIPv6Adapters() (*windows.IpAdapterAddresses, []byte, error) {
	size := uint32(15 * 1024)
	flags := uint32(
		windows.GAA_FLAG_INCLUDE_ALL_INTERFACES |
			windows.GAA_FLAG_SKIP_ANYCAST |
			windows.GAA_FLAG_SKIP_MULTICAST |
			windows.GAA_FLAG_SKIP_DNS_SERVER,
	)

	for range 3 {
		buf := make([]byte, size)
		adapter := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))

		err := windows.GetAdaptersAddresses(windows.AF_INET6, flags, 0, adapter, &size)
		if err == nil {
			return adapter, buf, nil
		}

		if err != windows.ERROR_BUFFER_OVERFLOW {
			return nil, nil, err
		}
	}

	return nil, nil, windows.ERROR_BUFFER_OVERFLOW
}

func windowsAdapterMatchesInterface(adapter *windows.IpAdapterAddresses, ifaceName string, ifaceIndex uint64, hasIfaceIndex bool) bool {
	target := strings.TrimSpace(ifaceName)
	if target == "" || adapter == nil {
		return false
	}

	if hasIfaceIndex &&
		(uint64(adapter.IfIndex) == ifaceIndex || uint64(adapter.Ipv6IfIndex) == ifaceIndex) {
		return true
	}

	candidates := []string{
		windowsUTF16PtrToString(adapter.FriendlyName),
		windowsUTF16PtrToString(adapter.Description),
		windowsBytePtrToString(adapter.AdapterName),
	}

	for _, candidate := range candidates {
		if strings.EqualFold(strings.TrimSpace(candidate), target) {
			return true
		}
	}

	return false
}

func windowsUTF16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	return windows.UTF16PtrToString(p)
}

func windowsBytePtrToString(p *byte) string {
	if p == nil {
		return ""
	}
	return windows.BytePtrToString(p)
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

func isInvalidWindowsIPv6Addr(addr *windows.IpAdapterUnicastAddress) bool {
	if addr == nil {
		return true
	}

	if addr.ValidLifetime == 0 {
		return true
	}

	switch addr.DadState {
	case windows.IpDadStateInvalid, windows.IpDadStateTentative, windows.IpDadStateDuplicate:
		return true
	}

	return false
}

func isDeprecatedWindowsIPv6Addr(addr *windows.IpAdapterUnicastAddress) bool {
	if addr == nil {
		return true
	}

	if addr.PreferredLifetime == 0 {
		return true
	}

	return addr.DadState == windows.IpDadStateDeprecated
}

func selectIPv6FromInterface(ifaceName string, ip net.IP) (string, error) {
	ipLog(fmt.Sprintf(T.IPv6ViaInterface, ifaceName, ip.String()))

	return ip.String(), nil
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
