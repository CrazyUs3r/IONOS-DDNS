//go:build linux

// Package main
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/vishvananda/netlink"
)

// ============================================================================
// IP DETECTION LINUX
// ============================================================================

const (
	ifaFFlagDadFailed  = 0x08
	ifaFFlagDeprecated = 0x20
	ifaFFlagTentative  = 0x40
	ifaFFlagTemporary  = 0x01
)

type ipv6Candidate struct {
	ip           net.IP
	flags        int
	preferredLft int
	validLft     int
}

func getIPv6FromInterface(ctx context.Context, ifaceName string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	debugLog(logCategoryIPCheck, "", fmt.Sprintf("🔍 %s: %s", phrases().CheckingInterface, ifaceName))

	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		debugLog(logCategoryIPCheck, "", fmt.Sprintf("❌ %s: %v", phrases().InterfaceNotFound, err))

		return "", err
	}

	addrs, err := netlink.AddrList(link, syscall.AF_INET6)
	if err != nil {
		debugLog(logCategoryIPCheck, "", fmt.Sprintf("❌ %s: %v", phrases().AddressesNotReadable, err))

		return "", err
	}

	var stable *ipv6Candidate
	var temporary *ipv6Candidate

	for _, addr := range addrs {
		if addr.IPNet == nil || addr.IP == nil {
			continue
		}

		ip := addr.IP
		if !isUsableGlobalIPv6(ip) {
			continue
		}

		if isInvalidIPv6Addr(addr) {
			ipLog("⚠️ SKIP invalid IPv6: " + ip.String())

			continue
		}

		if isDeprecatedIPv6Addr(addr) {
			ipLog("⚠️ SKIP deprecated/expired IPv6: " + ip.String())

			continue
		}

		candidate := &ipv6Candidate{
			ip:           ip,
			flags:        addr.Flags,
			preferredLft: addr.PreferedLft,
			validLft:     addr.ValidLft,
		}

		if addr.Flags&ifaFFlagTemporary != 0 {
			if temporary == nil {
				temporary = candidate
			}

			continue
		}

		if stable == nil {
			stable = candidate
		}
	}

	selected := stable
	if selected == nil {
		selected = temporary
	}

	if selected != nil {
		return selectIPv6FromInterface(
			ifaceName,
			selected.ip,
			selected.flags,
			selected.preferredLft,
			selected.validLft,
		)
	}

	debugLog(logCategoryIPCheck, "", "⚠️  "+phrases().NoIPv6OnInterface)

	return "", errors.New(phrases().NoIPv6OnInterface)
}

func isInvalidIPv6Addr(addr netlink.Addr) bool {
	if addr.ValidLft == 0 {
		return true
	}

	return addr.Flags&(ifaFFlagTentative|ifaFFlagDadFailed) != 0
}

func isDeprecatedIPv6Addr(addr netlink.Addr) bool {
	if addr.PreferedLft == 0 {
		return true
	}

	return addr.Flags&ifaFFlagDeprecated != 0
}

func selectIPv6FromInterface(ifaceName string, ip net.IP, flags, preferredLft, validLft int) (string, error) {
	ipLog(fmt.Sprintf(
		phrases().IPv6ViaInterface+" | flags=%d preferred_lft=%d valid_lft=%d",
		ifaceName,
		ip.String(),
		flags,
		preferredLft,
		validLft,
	))

	return ip.String(), nil
}
