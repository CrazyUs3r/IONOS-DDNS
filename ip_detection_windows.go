//go:build windows

// Package main
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const ipSuffixOriginRandom = 5

type windowsIPv6Candidate struct {
	ip   net.IP
	addr *windows.IpAdapterUnicastAddress
}

// ============================================================================
// IP DETECTION WINDOWS
// ============================================================================

func getIPv6FromInterface(ctx context.Context, ifaceName string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	debugLog(logCategoryIPCheck, "", fmt.Sprintf("🔍 %s: %s", phrases().CheckingInterface, ifaceName))

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		debugLog(logCategoryIPCheck, "", fmt.Sprintf("❌ %s: %v", phrases().InterfaceNotFound, err))

		return "", err
	}
	if iface.Index < 0 {
		err := fmt.Errorf("invalid negative interface index: %d", iface.Index)
		debugLog(logCategoryIPCheck, "", fmt.Sprintf("❌ invalid interface index for %s: %v", ifaceName, err))

		return "", err
	}

	ifaceIndex := uint64(iface.Index)

	adapters, buf, err := getWindowsIPv6Adapters()
	defer runtime.KeepAlive(buf)
	if err != nil {
		debugLog(logCategoryIPCheck, "", fmt.Sprintf("❌ %s: %v", phrases().AddressesNotReadable, err))

		return "", err
	}

	matchedInterface := false
	var stable, temporary *windowsIPv6Candidate

	for adapter := adapters; adapter != nil; adapter = adapter.Next {
		if !windowsAdapterMatchesInterface(adapter, ifaceName, ifaceIndex) {
			continue
		}

		matchedInterface = true

		for addr := adapter.FirstUnicastAddress; addr != nil; addr = addr.Next {
			ip := addr.Address.IP()
			if ip == nil {
				continue
			}

			if !isUsableGlobalIPv6(ip) {
				continue
			}

			if isInvalidWindowsIPv6Addr(addr) {
				ipLog("⚠️ SKIP invalid IPv6: " + ip.String())

				continue
			}

			if isDeprecatedWindowsIPv6Addr(addr) {
				ipLog("⚠️ SKIP deprecated/expired IPv6: " + ip.String())

				continue
			}

			candidate := &windowsIPv6Candidate{ip: ip, addr: addr}

			if addr.SuffixOrigin == ipSuffixOriginRandom {
				if temporary == nil {
					temporary = candidate
				}

				continue
			}

			if stable == nil {
				stable = candidate
			}
		}
	}

	if !matchedInterface {
		err := fmt.Errorf("%s: %s", phrases().InterfaceNotFound, ifaceName)
		debugLog(logCategoryIPCheck, "", "❌ "+err.Error())

		return "", err
	}

	selected := stable
	if selected == nil {
		selected = temporary
	}

	if selected != nil {
		return selectIPv6FromInterface(
			ifaceName,
			selected.ip,
			selected.addr.DadState,
			selected.addr.PreferredLifetime,
			selected.addr.ValidLifetime,
			selected.addr.Flags,
		)
	}

	debugLog(logCategoryIPCheck, "", "⚠️  "+phrases().NoIPv6OnInterface)

	return "", errors.New(phrases().NoIPv6OnInterface)
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
		if size < uint32(unsafe.Sizeof(windows.IpAdapterAddresses{})) {
			return nil, nil, errors.New("windows adapter buffer too small")
		}
		buf := make([]byte, size)

		// #nosec G103 -- GetAdaptersAddresses requires a native
		// Windows structure pointer into an appropriately sized buffer.
		// The backing buffer is retained by the caller.
		adapter := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))

		err := windows.GetAdaptersAddresses(windows.AF_INET6, flags, 0, adapter, &size)
		if err == nil {
			return adapter, buf, nil
		}

		if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			return nil, nil, err
		}
	}

	return nil, nil, windows.ERROR_BUFFER_OVERFLOW
}

func windowsAdapterMatchesInterface(adapter *windows.IpAdapterAddresses, ifaceName string, ifaceIndex uint64) bool {
	target := strings.TrimSpace(ifaceName)
	if target == "" || adapter == nil {
		return false
	}

	if uint64(adapter.IfIndex) == ifaceIndex || uint64(adapter.Ipv6IfIndex) == ifaceIndex {
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

func selectIPv6FromInterface(ifaceName string, ip net.IP, dadState int32, preferredLifetime, validLifetime, flags uint32) (string, error) {
	ipLog(fmt.Sprintf(
		"%s dad_state=%d preferred_lft=%d valid_lft=%d flags=%#x", fmt.Sprintf(phrases().IPv6ViaInterface, ifaceName, ip.String()),
		dadState,
		preferredLifetime,
		validLifetime,
		flags,
	))

	return ip.String(), nil
}
