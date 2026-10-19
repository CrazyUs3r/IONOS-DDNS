//go:build freebsd

// Package main
package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// ============================================================================
// IP DETECTION FREEBSD
// ============================================================================

type freebsdIPv6Candidate struct {
	ip         net.IP
	source     string
	flags      string
	temporary  bool
	deprecated bool
}

type freebsdIPv6ScanResult struct {
	candidate *freebsdIPv6Candidate
	sawGlobal bool
}

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

	if scan, err := getFreeBSDIPv6FromIfconfig(ctx, ifaceName); err == nil {
		if scan.candidate != nil {
			return selectIPv6FromInterface(ifaceName, scan.candidate)
		}

		if scan.sawGlobal {
			debugLog(logCategoryIPCheck, "", "⚠️  "+phrases().NoIPv6OnInterface)

			return "", errors.New(phrases().NoIPv6OnInterface)
		}
	} else {
		debugLog(logCategoryIPCheck, "", fmt.Sprintf("⚠️ ifconfig IPv6 lookup failed, falling back to net.Interface.Addrs: %v", err))
	}

	addrs, err := iface.Addrs()
	if err != nil {
		debugLog(logCategoryIPCheck, "", fmt.Sprintf("❌ %s: %v", phrases().AddressesNotReadable, err))

		return "", err
	}

	for _, addr := range addrs {
		ip := ipFromNetAddr(addr)
		if !isUsableGlobalIPv6(ip) {
			continue
		}

		return selectIPv6FromInterface(ifaceName, &freebsdIPv6Candidate{
			ip:     ip,
			source: "net.Interface.Addrs",
			flags:  "unknown",
		})
	}

	debugLog(logCategoryIPCheck, "", "⚠️  "+phrases().NoIPv6OnInterface)

	return "", errors.New(phrases().NoIPv6OnInterface)
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

func getFreeBSDIPv6FromIfconfig(ctx context.Context, ifaceName string) (freebsdIPv6ScanResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "/sbin/ifconfig", "-a").CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return freebsdIPv6ScanResult{}, ctx.Err()
		}

		out, err = exec.CommandContext(ctx, "ifconfig", "-a").CombinedOutput()
		if err != nil {
			return freebsdIPv6ScanResult{}, err
		}
	}

	interfaceOutput, err := extractIfconfigInterface(out, ifaceName)
	if err != nil {
		return freebsdIPv6ScanResult{}, err
	}
	return parseFreeBSDIfconfigIPv6(interfaceOutput)
}

func extractIfconfigInterface(out []byte, ifaceName string) ([]byte, error) {
	var selected bytes.Buffer
	inside := false
	for _, line := range bytes.SplitAfter(out, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' && line[0] != '\r' && line[0] != '\n' {
			if inside {
				break
			}
			inside = bytes.HasPrefix(line, []byte(ifaceName+":"))
		}
		if inside {
			selected.Write(line)
		}
	}
	if !inside {
		return nil, fmt.Errorf("interface %q not found in ifconfig output", ifaceName)
	}
	return selected.Bytes(), nil
}

func parseFreeBSDIfconfigIPv6(out []byte) (freebsdIPv6ScanResult, error) {
	var fallbackTemporary *freebsdIPv6Candidate
	var fallbackDeprecated *freebsdIPv6Candidate
	result := freebsdIPv6ScanResult{}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "inet6" {
			continue
		}

		ip := parseFreeBSDInet6Field(fields[1])
		if !isUsableGlobalIPv6(ip) {
			continue
		}

		result.sawGlobal = true

		if hasFreeBSDIPv6Flag(fields, "tentative", "duplicated", "duplicate", "dadfailed", "detached", "invalid") ||
			freebsdIfconfigLifetimeIsZero(fields, "vltime") {
			ipLog("⚠️ SKIP invalid IPv6: " + ip.String())

			continue
		}

		candidate := &freebsdIPv6Candidate{
			ip:         ip,
			source:     "ifconfig",
			flags:      strings.Join(fields[2:], " "),
			temporary:  hasFreeBSDIPv6Flag(fields, "temporary"),
			deprecated: hasFreeBSDIPv6Flag(fields, "deprecated") || freebsdIfconfigLifetimeIsZero(fields, "pltime"),
		}

		if candidate.deprecated {
			ipLog("⚠️ SKIP deprecated/expired IPv6: " + ip.String())
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

		return result, nil
	}

	if err := scanner.Err(); err != nil {
		return freebsdIPv6ScanResult{}, fmt.Errorf("failed to scan ifconfig output: %w", err)
	}

	if fallbackTemporary != nil {
		result.candidate = fallbackTemporary

		return result, nil
	}

	if fallbackDeprecated != nil {
		result.candidate = fallbackDeprecated

		return result, nil
	}

	return result, nil
}

func parseFreeBSDInet6Field(raw string) net.IP {
	ipStr := strings.TrimSpace(raw)
	if i := strings.IndexByte(ipStr, '%'); i >= 0 {
		ipStr = ipStr[:i]
	}

	return net.ParseIP(ipStr)
}

func hasFreeBSDIPv6Flag(fields []string, flags ...string) bool {
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

func freebsdIfconfigLifetimeIsZero(fields []string, key string) bool {
	for i := range len(fields) - 1 {
		if strings.EqualFold(fields[i], key) {
			n, err := strconv.ParseUint(fields[i+1], 10, 64)

			return err == nil && n == 0
		}
	}

	return false
}

func selectIPv6FromInterface(ifaceName string, candidate *freebsdIPv6Candidate) (string, error) {
	ipLog(fmt.Sprintf(
		"%s | source=%s flags=%s temporary=%t deprecated=%t",
		fmt.Sprintf(phrases().IPv6ViaInterface, ifaceName, candidate.ip.String()),
		candidate.source,
		candidate.flags,
		candidate.temporary,
		candidate.deprecated,
	))

	return candidate.ip.String(), nil
}
