package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

// ============================================================================
// IP DETECTION
// ============================================================================

func getPublicIP(url string) (string, error) {
	debugLog("IP-CHECK", "", "🌐 "+url)

	ctx, cancel := context.WithTimeout(context.Background(), IPCheckTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		debugLog("IP-CHECK", "", fmt.Sprintf("❌ Request-Erstellung: %v", err))
		return "", fmt.Errorf("request error: %w", err)
	}

	resp, err := getHTTPClient().Do(req)
	if err != nil {
		debugLog("IP-CHECK", "", fmt.Sprintf("❌ HTTP: %v", err))
		return "", fmt.Errorf("http error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		debugLog("IP-CHECK", "", fmt.Sprintf("❌ Status Code: %d", resp.StatusCode))
		return "", fmt.Errorf("bad status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, IPCheckBodyMaxBytes))
	if err != nil {
		debugLog("IP-CHECK", "", fmt.Sprintf("❌ %s: %v", T.BodyReadError, err))
		return "", fmt.Errorf("read error: %w", err)
	}

	ip := strings.TrimSpace(string(body))

	if net.ParseIP(ip) == nil {
		debugLog("IP-CHECK", "", fmt.Sprintf("❌ Ungültige IP: '%s'", ip))
		return "", fmt.Errorf("invalid ip: %s", ip)
	}

	debugLog("IP-CHECK", "", fmt.Sprintf("✅ %s: %s", T.ReceivedIp, ip))
	return ip, nil
}

func getIPv6() (string, error) {
	if cfg.IfaceName != "" {
		debugLog("IP-CHECK", "", fmt.Sprintf("🔍 %s: %s", T.CheckingInterface, cfg.IfaceName))

		iface, err := net.InterfaceByName(cfg.IfaceName)
		if err != nil {
			debugLog("IP-CHECK", "", fmt.Sprintf("❌ %s: %v", T.InterfaceNotFound, err))
		} else {
			addrs, err := iface.Addrs()
			if err != nil {
				debugLog("IP-CHECK", "", fmt.Sprintf("❌ %s: %v", T.AddressesNotReadable, err))
			} else {
				for _, a := range addrs {
					ipnet, ok := a.(*net.IPNet)
					if !ok || ipnet.IP == nil {
						continue
					}

					ip := ipnet.IP

					if ip.To4() != nil {
						continue
					}
					if ip.IsLoopback() ||
						ip.IsLinkLocalUnicast() ||
						ip.IsPrivate() { // fc00::/7 (ULA)
						continue
					}
					debugLog(
						"IP-CHECK",
						"",
						fmt.Sprintf("✅ IPv6 via Interface %s: %s", cfg.IfaceName, ip.String()),
					)
					return ip.String(), nil
				}
				debugLog("IP-CHECK", "", "⚠️  "+T.NoIpv6OnInterface)
			}
		}
	}
	debugLog("IP-CHECK", "", "🌐 Fallback auf 6.ident.me")
	return getPublicIP("https://6.ident.me/")
}

func fetchCurrentIPs(_ context.Context) (ipv4, ipv6 string, err error) {
	var errV4, errV6 error

	if cfg.IPMode != "IPV6" {
		ipv4, errV4 = getPublicIP("https://4.ident.me/")
		if errV4 != nil {
			log(LogContext{
				Level:   LogError,
				Action:  ActionError,
				Message: "IPv4 check failed",
				Error:   errV4,
			})
		}
	}

	if cfg.IPMode != "IPV4" {
		ipv6, errV6 = getIPv6()
		if errV6 != nil {
			log(LogContext{
				Level:   LogError,
				Action:  ActionError,
				Message: "IPv6 check failed",
				Error:   errV6,
			})
		}
	}

	switch cfg.IPMode {
	case "IPV4":
		if errV4 != nil {
			return "", "", fmt.Errorf("IPv4 required but failed: %w", errV4)
		}
	case "IPV6":
		if errV6 != nil {
			return "", "", fmt.Errorf("IPv6 required but failed: %w", errV6)
		}
	case "BOTH":
		if errV4 != nil && errV6 != nil {
			return "", "", fmt.Errorf("both IP versions failed: v4=%v, v6=%v", errV4, errV6)
		}
	}

	return ipv4, ipv6, nil
}
