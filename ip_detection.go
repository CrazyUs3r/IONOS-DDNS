// Package main
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
func getPublicIP(url string, want IPVersion) (string, error) {
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
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log(LogContext{
				Level:   LogError,
				Action:  ActionError,
				Message: fmt.Sprintf("Failed to close response body: %v", err),
			})
		}
	}()

	if resp.StatusCode != http.StatusOK {
		debugLog("IP-CHECK", "", fmt.Sprintf("❌ Status Code: %d", resp.StatusCode))
		return "", fmt.Errorf("bad status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, IPCheckBodyMaxBytes))
	if err != nil {
		debugLog("IP-CHECK", "", fmt.Sprintf("❌ %s: %v", T.BodyReadError, err))
		return "", fmt.Errorf("read error: %w", err)
	}

	ipStr := strings.TrimSpace(string(body))
	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		debugLog("IP-CHECK", "", fmt.Sprintf("❌ Ungültige IP: '%s'", ipStr))
		return "", fmt.Errorf("invalid ip: %s", ipStr)
	}

	switch want {
	case IPV4:
		if parsed.To4() == nil {
			return "", fmt.Errorf("expected IPv4 but got: %s", ipStr)
		}
	case IPV6:
		if parsed.To4() != nil {
			return "", fmt.Errorf("expected IPv6 but got: %s", ipStr)
		}
	}

	debugLog("IP-CHECK", "", fmt.Sprintf("✅ %s: %s", T.ReceivedIp, ipStr))
	ipLog("", fmt.Sprintf("✅ Öffentliche IP (%v) erkannt via %s: %s", want, url, ipStr))

	return ipStr, nil
}

func getPublicIPFromAny(urls []string, want IPVersion) (string, error) {
	var lastErr error

	for _, u := range urls {
		ip, err := getPublicIP(u, want)
		if err == nil {
			return ip, nil
		}
		lastErr = err
		debugLog("IP-CHECK", "", fmt.Sprintf("⚠️  Fallback failed (%s): %v", u, err))
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no endpoints configured")
	}
	return "", fmt.Errorf("all IP endpoints failed: %w", lastErr)
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
					if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate() {
						continue
					}

					ipLog("", fmt.Sprintf("✅ IPv6 via Interface %s: %s", cfg.IfaceName, ip.String()))
					return ip.String(), nil
				}
				debugLog("IP-CHECK", "", "⚠️  "+T.NoIpv6OnInterface)
			}
		}
	}

	ipLog("", "ℹ️ IPv6 nicht lokal gefunden – nutze öffentliche IPv6-Endpunkte (Fallback)")
	debugLog("IP-CHECK", "", "🌐 Fallback auf öffentliche IPv6-Endpunkte")

	return getPublicIPFromAny(DefaultIPv6Endpoints, IPV6)
}

func fetchCurrentIPs(_ context.Context) (ipv4, ipv6 string, err error) {
	var errV4, errV6 error

	if cfg.IPMode != "IPV6" {
		ipLog("", "🔎 Prüfe öffentliche IPv4 ...")

		ipv4, errV4 = getPublicIPFromAny(DefaultIPv4Endpoints, IPV4)
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
		ipLog("", "🔎 Prüfe IPv6 ...")

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
		if ipv4 != "" {
			ipLog("", fmt.Sprintf("✅ IPv4 aktuell: %s", ipv4))
		}
	case "IPV6":
		if errV6 != nil {
			return "", "", fmt.Errorf("IPv6 required but failed: %w", errV6)
		}
		if ipv6 != "" {
			ipLog("", fmt.Sprintf("✅ IPv6 aktuell: %s", ipv6))
		}
	case "BOTH":
		if errV4 != nil && errV6 != nil {
			return "", "", fmt.Errorf("both IP versions failed: v4=%v, v6=%v", errV4, errV6)
		}
	}

	return ipv4, ipv6, nil
}
