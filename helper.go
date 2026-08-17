// Package main
package main

import (
	"bufio"
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"math"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	gopsutilcpu "github.com/shirou/gopsutil/v4/cpu"
	gopsutildisk "github.com/shirou/gopsutil/v4/disk"
	gopsutilmem "github.com/shirou/gopsutil/v4/mem"
	gopsutilnet "github.com/shirou/gopsutil/v4/net"
	gopsutilprocess "github.com/shirou/gopsutil/v4/process"
	"golang.org/x/sync/singleflight"
)

// ============================================================================
// DASHBOARD - CONTAINER / SYSTEM RESOURCE STATS
// ============================================================================

type dashboardSystemCPUStats struct {
	Percent          float64 `json:"percent"`
	UsageSeconds     float64 `json:"usage_seconds"`
	LimitCores       float64 `json:"limit_cores"`
	ThrottledSeconds float64 `json:"throttled_seconds"`
	ThrottledPeriods uint64  `json:"throttled_periods"`
}

type dashboardSystemMemoryStats struct {
	UsedBytes  int64   `json:"used_bytes"`
	LimitBytes int64   `json:"limit_bytes"`
	CacheBytes int64   `json:"cache_bytes"`
	Percent    float64 `json:"percent"`
}

type dashboardSystemNetworkStats struct {
	RXBytes          uint64  `json:"rx_bytes"`
	TXBytes          uint64  `json:"tx_bytes"`
	RXPackets        uint64  `json:"rx_packets"`
	TXPackets        uint64  `json:"tx_packets"`
	RXBytesPerSecond float64 `json:"rx_bytes_per_second"`
	TXBytesPerSecond float64 `json:"tx_bytes_per_second"`
}

type dashboardSystemIOStats struct {
	ReadBytes           uint64  `json:"read_bytes"`
	WriteBytes          uint64  `json:"write_bytes"`
	ReadOps             uint64  `json:"read_ops"`
	WriteOps            uint64  `json:"write_ops"`
	ReadBytesPerSecond  float64 `json:"read_bytes_per_second"`
	WriteBytesPerSecond float64 `json:"write_bytes_per_second"`
}

type dashboardSystemPIDsStats struct {
	Current int64 `json:"current"`
	Limit   int64 `json:"limit"`
}

type dashboardSystemPressureStats struct {
	CPUAvg10    float64 `json:"cpu_avg10"`
	MemoryAvg10 float64 `json:"memory_avg10"`
	IOAvg10     float64 `json:"io_avg10"`
}

type dashboardSystemProcessStats struct {
	PID        int    `json:"pid"`
	Goroutines int    `json:"goroutines"`
	HeapBytes  uint64 `json:"heap_bytes"`
}

type dashboardSystemStats struct {
	CollectedAt   string                       `json:"collected_at"`
	Environment   string                       `json:"environment"`
	Hostname      string                       `json:"hostname"`
	CgroupVersion int                          `json:"cgroup_version"`
	CPU           dashboardSystemCPUStats      `json:"cpu"`
	Memory        dashboardSystemMemoryStats   `json:"memory"`
	Network       dashboardSystemNetworkStats  `json:"network"`
	IO            dashboardSystemIOStats       `json:"io"`
	PIDs          dashboardSystemPIDsStats     `json:"pids"`
	Pressure      dashboardSystemPressureStats `json:"pressure"`
	Process       dashboardSystemProcessStats  `json:"process"`
}

type dashboardSystemRawStats struct {
	collectedAt       time.Time
	environment       string
	hostname          string
	cgroupVersion     int
	cpuUsageSeconds   float64
	cpuLimitCores     float64
	cpuThrottleSecs   float64
	cpuThrottleCount  uint64
	memoryUsed        int64
	memoryLimit       int64
	memoryCache       int64
	netRXBytes        uint64
	netTXBytes        uint64
	netRXPackets      uint64
	netTXPackets      uint64
	ioReadBytes       uint64
	ioWriteBytes      uint64
	ioReadOps         uint64
	ioWriteOps        uint64
	pidsCurrent       int64
	pidsLimit         int64
	cpuPressureAvg10  float64
	memPressureAvg10  float64
	ioPressureAvg10   float64
	processHeapBytes  uint64
	processGoroutines int
}

var dashboardSystemCollector = struct {
	sync.Mutex
	last dashboardSystemRawStats
}{
	last: dashboardSystemRawStats{},
}

func getDashboardSystemStats() dashboardSystemStats {
	dashboardSystemCollector.Lock()
	defer dashboardSystemCollector.Unlock()

	current := collectDashboardSystemRawStats()
	previous := dashboardSystemCollector.last
	dashboardSystemCollector.last = current

	cpuPercent := -1.0
	rxRate := 0.0
	txRate := 0.0
	readRate := 0.0
	writeRate := 0.0

	if !previous.collectedAt.IsZero() && current.collectedAt.After(previous.collectedAt) {
		elapsed := current.collectedAt.Sub(previous.collectedAt).Seconds()
		if elapsed > 0 {
			if current.cpuUsageSeconds >= previous.cpuUsageSeconds {
				capacity := current.cpuLimitCores
				if capacity <= 0 {
					capacity = float64(runtime.NumCPU())
				}
				if capacity < 0.01 {
					capacity = 1
				}
				cpuPercent = (current.cpuUsageSeconds - previous.cpuUsageSeconds) / (elapsed * capacity) * 100
				cpuPercent = math.Max(0, math.Min(cpuPercent, 999.9))
			}
			if current.netRXBytes >= previous.netRXBytes {
				rxRate = float64(current.netRXBytes-previous.netRXBytes) / elapsed
			}
			if current.netTXBytes >= previous.netTXBytes {
				txRate = float64(current.netTXBytes-previous.netTXBytes) / elapsed
			}
			if current.ioReadBytes >= previous.ioReadBytes {
				readRate = float64(current.ioReadBytes-previous.ioReadBytes) / elapsed
			}
			if current.ioWriteBytes >= previous.ioWriteBytes {
				writeRate = float64(current.ioWriteBytes-previous.ioWriteBytes) / elapsed
			}
		}
	}

	memoryPercent := -1.0
	if current.memoryLimit > 0 {
		memoryPercent = math.Max(0, math.Min(float64(current.memoryUsed)/float64(current.memoryLimit)*100, 999.9))
	}

	return dashboardSystemStats{
		CollectedAt:   current.collectedAt.Format(time.RFC3339),
		Environment:   current.environment,
		Hostname:      current.hostname,
		CgroupVersion: current.cgroupVersion,
		CPU: dashboardSystemCPUStats{
			Percent:          cpuPercent,
			UsageSeconds:     current.cpuUsageSeconds,
			LimitCores:       current.cpuLimitCores,
			ThrottledSeconds: current.cpuThrottleSecs,
			ThrottledPeriods: current.cpuThrottleCount,
		},
		Memory: dashboardSystemMemoryStats{
			UsedBytes:  current.memoryUsed,
			LimitBytes: current.memoryLimit,
			CacheBytes: current.memoryCache,
			Percent:    memoryPercent,
		},
		Network: dashboardSystemNetworkStats{
			RXBytes:          current.netRXBytes,
			TXBytes:          current.netTXBytes,
			RXPackets:        current.netRXPackets,
			TXPackets:        current.netTXPackets,
			RXBytesPerSecond: rxRate,
			TXBytesPerSecond: txRate,
		},
		IO: dashboardSystemIOStats{
			ReadBytes:           current.ioReadBytes,
			WriteBytes:          current.ioWriteBytes,
			ReadOps:             current.ioReadOps,
			WriteOps:            current.ioWriteOps,
			ReadBytesPerSecond:  readRate,
			WriteBytesPerSecond: writeRate,
		},
		PIDs: dashboardSystemPIDsStats{
			Current: current.pidsCurrent,
			Limit:   current.pidsLimit,
		},
		Pressure: dashboardSystemPressureStats{
			CPUAvg10:    current.cpuPressureAvg10,
			MemoryAvg10: current.memPressureAvg10,
			IOAvg10:     current.ioPressureAvg10,
		},
		Process: dashboardSystemProcessStats{
			PID:        os.Getpid(),
			Goroutines: current.processGoroutines,
			HeapBytes:  current.processHeapBytes,
		},
	}
}

func collectDashboardSystemRawStats() dashboardSystemRawStats {
	now := time.Now()
	hostname, _ := os.Hostname()

	cgroupText := ""
	if runtime.GOOS == PlatformLinux {
		if data, err := os.ReadFile("/proc/self/cgroup"); err == nil {
			cgroupText = string(data)
		}
	}

	raw := dashboardSystemRawStats{
		collectedAt:   now,
		environment:   detectContainerEnvironment(cgroupText),
		hostname:      hostname,
		pidsCurrent:   -1,
		pidsLimit:     -1,
		memoryLimit:   0,
		cpuLimitCores: 0,
	}

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	raw.processHeapBytes = mem.HeapAlloc
	raw.processGoroutines = runtime.NumGoroutine()

	if runtime.GOOS == PlatformLinux {
		if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil {
			raw.cgroupVersion = 2
			collectCgroupV2Stats(&raw, cgroupText)
		} else if strings.TrimSpace(cgroupText) != "" {
			raw.cgroupVersion = 1
			collectCgroupV1Stats(&raw, cgroupText)
		}

		collectNetworkNamespaceStats(&raw)

		if raw.cgroupVersion == 0 {
			collectHostPlatformStats(&raw)
		}
		return raw
	}

	collectHostPlatformStats(&raw)
	return raw
}

func collectHostPlatformStats(raw *dashboardSystemRawStats) {
	raw.cgroupVersion = 0
	raw.cpuLimitCores = float64(runtime.NumCPU())

	if cpuTimes, err := gopsutilcpu.Times(false); err == nil && len(cpuTimes) > 0 {
		t := cpuTimes[0]
		raw.cpuUsageSeconds = t.User + t.System + t.Nice + t.Irq + t.Softirq + t.Steal
	}

	if vm, err := gopsutilmem.VirtualMemory(); err == nil && vm != nil {
		raw.memoryUsed = uint64ToInt64Saturated(vm.Used)
		raw.memoryLimit = uint64ToInt64Saturated(vm.Total)
		raw.memoryCache = uint64ToInt64Saturated(vm.Cached)
	}

	if counters, err := gopsutilnet.IOCounters(false); err == nil && len(counters) > 0 {
		all := counters[0]
		raw.netRXBytes = all.BytesRecv
		raw.netTXBytes = all.BytesSent
		raw.netRXPackets = all.PacketsRecv
		raw.netTXPackets = all.PacketsSent
	}

	if counters, err := gopsutildisk.IOCounters(); err == nil {
		for _, disk := range counters {
			raw.ioReadBytes += disk.ReadBytes
			raw.ioWriteBytes += disk.WriteBytes
			raw.ioReadOps += disk.ReadCount
			raw.ioWriteOps += disk.WriteCount
		}
	}

	if pids, err := gopsutilprocess.Pids(); err == nil {
		raw.pidsCurrent = int64(len(pids))
		raw.pidsLimit = 0
	}
}

func uint64ToInt64Saturated(value uint64) int64 {
	const maxInt64 = uint64(1<<63 - 1)
	if value > maxInt64 {
		return int64(1<<63 - 1)
	}
	return int64(value)
}

func detectContainerEnvironment(cgroupText string) string {
	lower := strings.ToLower(cgroupText)
	switch {
	case strings.Contains(lower, "kubepods"):
		return "Kubernetes / Container"
	case strings.Contains(lower, "containerd"):
		return "containerd / Container"
	case strings.Contains(lower, "docker"):
		return "Docker"
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "Docker"
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return "Container"
	}
	switch runtime.GOOS {
	case PlatformWindows:
		return "Windows Host"
	case PlatformDarwin:
		return "macOS Host"
	case PlatformLinux:
		return "Linux Host"
	default:
		return runtime.GOOS + " Host"
	}
}

func collectCgroupV2Stats(raw *dashboardSystemRawStats, cgroupText string) {
	base := cgroupV2Base(cgroupText)
	if base == "" {
		return
	}

	cpuStat := readSpaceKeyUintValueFile(filepath.Join(base, "cpu.stat"))
	raw.cpuUsageSeconds = float64(cpuStat["usage_usec"]) / 1e6
	raw.cpuThrottleSecs = float64(cpuStat["throttled_usec"]) / 1e6
	raw.cpuThrottleCount = cpuStat["nr_throttled"]
	raw.cpuLimitCores = readCgroupV2CPULimit(base)

	raw.memoryUsed = readInt64File(filepath.Join(base, "memory.current"), 0)
	raw.memoryLimit = readCgroupLimitFile(filepath.Join(base, "memory.max"))
	memStat := readSpaceKeyValueFile(filepath.Join(base, "memory.stat"))
	raw.memoryCache = max64(memStat["file"], memStat["cache"])

	for _, line := range readLines(filepath.Join(base, "io.stat")) {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		for _, field := range fields[1:] {
			key, value, ok := strings.Cut(field, "=")
			if !ok {
				continue
			}
			n, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				continue
			}
			switch key {
			case "rbytes":
				raw.ioReadBytes += n
			case "wbytes":
				raw.ioWriteBytes += n
			case "rios":
				raw.ioReadOps += n
			case "wios":
				raw.ioWriteOps += n
			}
		}
	}

	raw.pidsCurrent = readInt64File(filepath.Join(base, "pids.current"), -1)
	raw.pidsLimit = readCgroupLimitFile(filepath.Join(base, "pids.max"))
	raw.cpuPressureAvg10 = readPressureAvg10(filepath.Join(base, "cpu.pressure"))
	raw.memPressureAvg10 = readPressureAvg10(filepath.Join(base, "memory.pressure"))
	raw.ioPressureAvg10 = readPressureAvg10(filepath.Join(base, "io.pressure"))
}

func cgroupV2Base(cgroupText string) string {
	path := ""
	for line := range strings.SplitSeq(cgroupText, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && parts[0] == "0" && parts[1] == "" {
			path = strings.TrimSpace(parts[2])
			break
		}
	}

	candidates := []string{}
	if path != "" && path != "/" {
		candidates = append(candidates, filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(path, "/")))
	}
	candidates = append(candidates, "/sys/fs/cgroup")

	for _, candidate := range candidates {
		if _, err := os.Stat(filepath.Join(candidate, "cpu.stat")); err == nil {
			return candidate
		}
	}
	return ""
}

func readCgroupV2CPULimit(base string) float64 {
	capacity := 0.0
	if data, err := os.ReadFile(filepath.Join(base, "cpu.max")); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 2 && fields[0] != "max" {
			quota, qErr := strconv.ParseFloat(fields[0], 64)
			period, pErr := strconv.ParseFloat(fields[1], 64)
			if qErr == nil && pErr == nil && quota > 0 && period > 0 {
				capacity = quota / period
			}
		}
	}

	cpuset := strings.TrimSpace(readTextFile(filepath.Join(base, "cpuset.cpus.effective")))
	if cpuset == "" {
		cpuset = strings.TrimSpace(readTextFile(filepath.Join(base, "cpuset.cpus")))
	}
	if count := parseCPUSetCount(cpuset); count > 0 {
		cpusetCapacity := float64(count)
		if capacity <= 0 || cpusetCapacity < capacity {
			capacity = cpusetCapacity
		}
	}
	return capacity
}

func collectCgroupV1Stats(raw *dashboardSystemRawStats, cgroupText string) {
	controllers := parseCgroupV1Controllers(cgroupText)

	cpuBase := cgroupV1Base(controllers, []string{"cpuacct", "cpu"}, []string{"cpu,cpuacct", "cpuacct,cpu", "cpuacct", "cpu"})
	if cpuBase != "" {
		usageNS := readInt64File(filepath.Join(cpuBase, "cpuacct.usage"), 0)
		raw.cpuUsageSeconds = float64(usageNS) / 1e9
		cpuStat := readSpaceKeyUintValueFile(filepath.Join(cpuBase, "cpu.stat"))
		raw.cpuThrottleSecs = float64(cpuStat["throttled_time"]) / 1e9
		raw.cpuThrottleCount = cpuStat["nr_throttled"]
		quota := readInt64File(filepath.Join(cpuBase, "cpu.cfs_quota_us"), -1)
		period := readInt64File(filepath.Join(cpuBase, "cpu.cfs_period_us"), -1)
		if quota > 0 && period > 0 {
			raw.cpuLimitCores = float64(quota) / float64(period)
		}
	}

	cpusetBase := cgroupV1Base(controllers, []string{"cpuset"}, []string{"cpuset"})
	if cpusetBase != "" {
		if count := parseCPUSetCount(strings.TrimSpace(readTextFile(filepath.Join(cpusetBase, "cpuset.cpus")))); count > 0 {
			capacity := float64(count)
			if raw.cpuLimitCores <= 0 || capacity < raw.cpuLimitCores {
				raw.cpuLimitCores = capacity
			}
		}
	}

	memoryBase := cgroupV1Base(controllers, []string{"memory"}, []string{"memory"})
	if memoryBase != "" {
		raw.memoryUsed = readInt64File(filepath.Join(memoryBase, "memory.usage_in_bytes"), 0)
		raw.memoryLimit = normalizeCgroupV1Limit(readInt64File(filepath.Join(memoryBase, "memory.limit_in_bytes"), 0))
		memStat := readSpaceKeyValueFile(filepath.Join(memoryBase, "memory.stat"))
		raw.memoryCache = max64(memStat["total_cache"], memStat["cache"])
	}

	blkioBase := cgroupV1Base(controllers, []string{"blkio"}, []string{"blkio"})
	if blkioBase != "" {
		for _, line := range readLines(filepath.Join(blkioBase, "blkio.throttle.io_service_bytes")) {
			fields := strings.Fields(line)
			if len(fields) != 3 || fields[0] == "Total" {
				continue
			}
			value, err := strconv.ParseUint(fields[2], 10, 64)
			if err != nil {
				continue
			}
			switch strings.ToLower(fields[1]) {
			case "read":
				raw.ioReadBytes += value
			case "write":
				raw.ioWriteBytes += value
			}
		}
		for _, line := range readLines(filepath.Join(blkioBase, "blkio.throttle.io_serviced")) {
			fields := strings.Fields(line)
			if len(fields) != 3 || fields[0] == "Total" {
				continue
			}
			value, err := strconv.ParseUint(fields[2], 10, 64)
			if err != nil {
				continue
			}
			switch strings.ToLower(fields[1]) {
			case "read":
				raw.ioReadOps += value
			case "write":
				raw.ioWriteOps += value
			}
		}
	}

	pidsBase := cgroupV1Base(controllers, []string{"pids"}, []string{"pids"})
	if pidsBase != "" {
		raw.pidsCurrent = readInt64File(filepath.Join(pidsBase, "pids.current"), -1)
		raw.pidsLimit = readCgroupLimitFile(filepath.Join(pidsBase, "pids.max"))
	}
}

func parseCgroupV1Controllers(cgroupText string) map[string]string {
	result := make(map[string]string)
	for line := range strings.SplitSeq(cgroupText, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || strings.TrimSpace(parts[1]) == "" {
			continue
		}
		for controller := range strings.SplitSeq(parts[1], ",") {
			result[strings.TrimSpace(controller)] = strings.TrimSpace(parts[2])
		}
	}
	return result
}

func cgroupV1Base(controllerPaths map[string]string, controllers, mountNames []string) string {
	path := ""
	for _, controller := range controllers {
		if p := controllerPaths[controller]; p != "" {
			path = p
			break
		}
	}
	if path == "" {
		return ""
	}

	for _, mount := range mountNames {
		base := filepath.Join("/sys/fs/cgroup", mount)
		candidate := filepath.Join(base, strings.TrimPrefix(path, "/"))
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
		if info, err := os.Stat(base); err == nil && info.IsDir() {
			return base
		}
	}
	return ""
}

func collectNetworkNamespaceStats(raw *dashboardSystemRawStats) {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return
	}
	defer func() {
		if err := file.Close(); err != nil {
			debugLog("HELPER", "", fmt.Sprintf(phrases().ErrBodyClose+": %v", err))
		}
	}()

	var rxBytesTotal, rxPacketsTotal, txBytesTotal, txPacketsTotal uint64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		name, values, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(name) == "lo" {
			continue
		}
		fields := strings.Fields(values)
		if len(fields) < 16 {
			continue
		}
		rxBytes, err1 := strconv.ParseUint(fields[0], 10, 64)
		rxPackets, err2 := strconv.ParseUint(fields[1], 10, 64)
		txBytes, err3 := strconv.ParseUint(fields[8], 10, 64)
		txPackets, err4 := strconv.ParseUint(fields[9], 10, 64)
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
			continue
		}
		rxBytesTotal += rxBytes
		rxPacketsTotal += rxPackets
		txBytesTotal += txBytes
		txPacketsTotal += txPackets
	}
	if err := scanner.Err(); err != nil {
		return
	}

	raw.netRXBytes = rxBytesTotal
	raw.netRXPackets = rxPacketsTotal
	raw.netTXBytes = txBytesTotal
	raw.netTXPackets = txPacketsTotal
}

func readSpaceKeyValueFile(path string) map[string]int64 {
	result := make(map[string]int64)
	for _, line := range readLines(path) {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		value, err := strconv.ParseInt(fields[1], 10, 64)
		if err == nil {
			result[fields[0]] = value
		}
	}
	return result
}

func readSpaceKeyUintValueFile(path string) map[string]uint64 {
	result := make(map[string]uint64)
	for _, line := range readLines(path) {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err == nil {
			result[fields[0]] = value
		}
	}
	return result
}

func readPressureAvg10(path string) float64 {
	for _, line := range readLines(path) {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "some" {
			continue
		}
		for _, field := range fields[1:] {
			key, value, ok := strings.Cut(field, "=")
			if key != "avg10" || !ok {
				continue
			}
			if parsed, err := strconv.ParseFloat(value, 64); err == nil {
				return parsed
			}
		}
	}
	return 0
}

func readLines(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() {
		if err := file.Close(); err != nil {
			debugLog("HELPER", "", fmt.Sprintf(phrases().ErrBodyClose+": %v", err))
		}
	}()

	lines := make([]string, 0, 16)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil
	}
	return lines
}

func readTextFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

func readInt64File(path string, fallback int64) int64 {
	text := strings.TrimSpace(readTextFile(path))
	if text == "" {
		return fallback
	}
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return fallback
	}
	return value
}

func readCgroupLimitFile(path string) int64 {
	text := strings.TrimSpace(readTextFile(path))
	if text == "" || text == "max" {
		return 0
	}
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil || value < 0 {
		return 0
	}
	return normalizeCgroupV1Limit(value)
}

func normalizeCgroupV1Limit(value int64) int64 {
	if value <= 0 || value >= (1<<60) {
		return 0
	}
	return value
}

func parseCPUSetCount(value string) int {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	count := 0
	for part := range strings.SplitSeq(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "-") {
			if _, err := strconv.Atoi(part); err == nil {
				count++
			}
			continue
		}
		bounds := strings.SplitN(part, "-", 2)
		start, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
		end, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
		if err1 == nil && err2 == nil && end >= start {
			count += end - start + 1
		}
	}
	return count
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// ============================================================================
// HELPERS
// ============================================================================

func (s *SafeErrorMsg) Set(msg string) {
	s.Lock()
	defer s.Unlock()
	s.msg = msg
}

func (s *SafeErrorMsg) Get() string {
	s.RLock()
	defer s.RUnlock()

	return s.msg
}

// ============================================================================
// HELPERS -DASHBOARD
// ============================================================================

func getAvailableLanguages(dir string) (map[string]bool, error) {
	langs := make(map[string]bool)

	addEntries := func(entries []os.DirEntry) {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			addLanguageFilename(langs, entry.Name())
		}
	}

	var readErr error
	if entries, err := os.ReadDir(dir); err == nil {
		addEntries(entries)
	} else if !errors.Is(err, os.ErrNotExist) {
		readErr = err
	}
	if entries, err := embeddedLang.ReadDir("lang"); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			addLanguageFilename(langs, entry.Name())
		}
	} else if readErr == nil {
		readErr = err
	}

	if len(langs) == 0 && readErr != nil {
		return nil, readErr
	}

	return langs, nil
}

func addLanguageFilename(langs map[string]bool, filename string) {
	ext := filepath.Ext(filename)
	if !strings.EqualFold(ext, ".json") {
		return
	}

	base := strings.TrimSuffix(filename, ext)
	code := normalizeLang(base)

	if code == "" {
		return
	}

	langs[code] = true
}

func normalizeLang(value string) string {
	value = prepareLanguageValue(value)
	if value == "" {
		return ""
	}

	parts := strings.Split(value, "-")
	normalized := make([]string, 0, len(parts))

	for index, part := range parts {
		normalizedPart, ok := normalizeLanguagePart(index, part)
		if !ok {
			return ""
		}

		normalized = append(normalized, normalizedPart)
	}

	return strings.Join(normalized, "-")
}

func prepareLanguageValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	if index := strings.IndexAny(value, ".@"); index >= 0 {
		value = value[:index]
	}

	return strings.ReplaceAll(value, "_", "-")
}

func normalizeLanguagePart(index int, part string) (string, bool) {
	if part == "" || !isASCIIAlphaNumeric(part) {
		return "", false
	}

	if index == 0 {
		return normalizePrimaryLanguage(part)
	}

	return normalizeLanguageSubtag(part), true
}

func normalizePrimaryLanguage(part string) (string, bool) {
	if len(part) < 2 || len(part) > 8 {
		return "", false
	}

	if !isASCIILetters(part) {
		return "", false
	}

	return strings.ToLower(part), true
}

func normalizeLanguageSubtag(part string) string {
	switch {
	case isScriptSubtag(part):
		return strings.ToUpper(part[:1]) +
			strings.ToLower(part[1:])

	case isRegionSubtag(part):
		return strings.ToUpper(part)

	default:
		return strings.ToLower(part)
	}
}

func isScriptSubtag(part string) bool {
	return len(part) == 4 && isASCIILetters(part)
}

func isRegionSubtag(part string) bool {
	if len(part) == 2 {
		return isASCIILetters(part)
	}

	if len(part) == 3 {
		return isASCIIDigits(part)
	}

	return false
}

func isASCIILetters(value string) bool {
	if value == "" {
		return false
	}

	for i := range len(value) {
		char := value[i]

		if (char < 'a' || char > 'z') &&
			(char < 'A' || char > 'Z') {
			return false
		}
	}

	return true
}

func isASCIIDigits(value string) bool {
	if value == "" {
		return false
	}

	for i := range len(value) {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}

	return true
}

func isASCIIAlphaNumeric(value string) bool {
	if value == "" {
		return false
	}

	for i := range len(value) {
		char := value[i]

		isLetter := (char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z')

		isDigit := char >= '0' && char <= '9'

		if !isLetter && !isDigit {
			return false
		}
	}

	return true
}

func languageBase(code string) string {
	code = normalizeLang(code)
	if code == "" {
		return ""
	}

	if before, _, ok := strings.Cut(code, "-"); ok {
		return before
	}

	return code
}

func resolveAvailableLanguage(
	preferred string,
	available map[string]bool,
) (string, bool) {
	preferred = normalizeLang(preferred)
	if preferred == "" {
		return "", false
	}

	if available[preferred] {
		return preferred, true
	}

	base := languageBase(preferred)
	defaultLocale := defaultLocaleByBase[base]

	if preferred == base &&
		defaultLocale != "" &&
		available[defaultLocale] {
		return defaultLocale, true
	}

	if preferred != base && available[base] {
		return base, true
	}

	if defaultLocale != "" && available[defaultLocale] {
		return defaultLocale, true
	}

	var family []string

	for code := range available {
		if languageBase(code) == base {
			family = append(family, code)
		}
	}

	sort.Strings(family)

	if len(family) > 0 {
		return family[0], true
	}

	return "", false
}

func detectLanguage(langDir, preferred string) string {
	langs, err := getAvailableLanguages(langDir)
	if err != nil {
		fmt.Printf(
			"[WARN] Konnte Sprachdateien nicht lesen: %v\n",
			err,
		)

		return "en"
	}

	if resolved, ok := resolveAvailableLanguage(preferred, langs); ok {
		return resolved
	}

	if strings.TrimSpace(preferred) != "" {
		fmt.Printf(
			"[WARN] Sprache '%s' nicht gefunden\n",
			preferred,
		)
	}

	if english, ok := resolveAvailableLanguage("en", langs); ok {
		return english
	}

	codes := make([]string, 0, len(langs))

	for code := range langs {
		codes = append(codes, code)
	}

	sort.Strings(codes)

	if len(codes) > 0 {
		return codes[0]
	}

	return "en"
}

func dashboardI18NJSON() string {
	m := map[string]string{
		"audit_col_action":                      t(phrases().AuditColActionJS, "Aktion"),
		"audit_col_ip":                          t(phrases().AuditColIPJS, "IP"),
		"audit_col_status":                      t(phrases().AuditColStatusJS, "Status"),
		"audit_col_time":                        t(phrases().AuditColTimeJS, "Zeit"),
		"audit_col_user":                        t(phrases().AuditColUserJS, "Benutzer"),
		"audit_delete_failed":                   t(phrases().AuditDeleteFailed, "Löschen fehlgeschlagen"),
		"audit_empty":                           t(phrases().AuditEmptyJS, "Noch keine Audit-Einträge vorhanden."),
		"audit_entry_deleted":                   t(phrases().AuditEntryDeleted, "Audit-Eintrag gelöscht"),
		"audit_load_failed":                     t(phrases().AuditLoadFailedJS, "Audit-Log konnte nicht geladen werden."),
		"audit_loading":                         t(phrases().AuditLoadingJS, "Audit-Einträge werden geladen…"),
		"auth_pass_min":                         t(phrases().AuthPassMinJS, "Password min. 8 characters"),
		"auth_user_min":                         t(phrases().AuthUserMinJS, "Username min. 3 characters"),
		"backup_confirm_config":                 t(phrases().BackupConfirmConfig, "• Config will be overwritten"),
		"backup_confirm_hint":                   t(phrases().BackupConfirmHint, "This action may replace existing data."),
		"backup_confirm_status":                 t(phrases().BackupConfirmStatus, "• Domain status will be overwritten"),
		"backup_confirm_title":                  t(phrases().BackupConfirmTitle, "Really restore backup?"),
		"backup_confirm_users":                  t(phrases().BackupConfirmUsers, "• Users will be overwritten"),
		"backup_download_failed":                t(phrases().BackupDownloadFailed, "❌ Backup failed"),
		"backup_download_success":               t(phrases().BackupDownloadSuccess, "✅ Backup downloaded"),
		"backup_restore_failed":                 t(phrases().BackupRestoreFailed, "❌ Restore failed"),
		"backup_restore_running":                t(phrases().BackupRestoreRunning, "⏳ Restore running..."),
		"backup_restore_success_format":         t(phrases().BackupRestoreSuccessFormat, "✅ Restored: {restored}"),
		"backup_select_area":                    t(phrases().BackupSelectArea, "❌ Please select at least one area"),
		"backup_select_file":                    t(phrases().BackupSelectFile, "❌ Please select a backup file"),
		"cleared":                               t(phrases().ClearedJS, "Cleared."),
		"connection_error":                      t(phrases().ConnectionErrorJS, "❌ Connection error"),
		"copied":                                t(phrases().CopiedJS, "✓ Copied: "),
		"copy_failed":                           t(phrases().CopyFailedJS, "❌ Copy failed"),
		"copy_title":                            t(phrases().CopyTitle, "Kopieren"),
		"cname_provider_unsupported":            t(phrases().CNAMEProviderUnsupported, "CNAME wird von diesem Provider nicht unterstützt"),
		"cname_target_missing":                  t(phrases().CNAMETargetMissing, "CNAME-Ziel fehlt"),
		"delete_domain_confirm":                 t(phrases().DeleteDomainConfirmJS, `Domain "{domain}" remove from status?`),
		"delete_entry_title":                    t(phrases().DeleteEntryTitle, "Eintrag löschen"),
		"delete_failed":                         t(phrases().DeleteFailedJS, "Deletion failed"),
		"diagnose_active_updates":               t(phrases().DiagnoseActiveUpdates, "Active updates"),
		"diagnose_api_metrics_title":            t(phrases().DiagnoseAPIMetricsTitle, "API metrics"),
		"diagnose_average_latency":              t(phrases().DiagnoseAverageLatency, "Average latency"),
		"diagnose_bytes":                        t(phrases().DiagnoseBytes, "bytes"),
		"diagnose_config_title":                 t(phrases().DiagnoseConfigTitle, "Config"),
		"diagnose_configured_domains":           t(phrases().DiagnoseConfiguredDomains, "Domains in status"),
		"diagnose_connection_failed":            t(phrases().DiagnoseConnectionFailed, "Connection failed"),
		"diagnose_file_missing":                 t(phrases().DiagnoseFileMissing, "missing"),
		"diagnose_files_title":                  t(phrases().DiagnoseFilesTitle, "Files"),
		"diagnose_flag_debug":                   t(phrases().DiagnoseFlagDebugJS, "Debug"),
		"diagnose_flag_dry_run":                 t(phrases().DiagnoseFlagDryRunJS, "Dry Run"),
		"diagnose_flag_http_raw":                t(phrases().DiagnoseFlagHTTPRawJS, "HTTP Raw"),
		"diagnose_interval":                     t(phrases().DiagnoseInterval, "Interval"),
		"diagnose_ip_dns_title":                 t(phrases().DiagnoseIPDNSTitle, "IP / DNS"),
		"diagnose_ip_mode":                      t(phrases().DiagnoseIPMode, "IP mode"),
		"diagnose_ipv4_endpoints":               t(phrases().DiagnoseIPv4Endpoints, "IPv4 endpoints"),
		"diagnose_ipv6_endpoints":               t(phrases().DiagnoseIPv6Endpoints, "IPv6 endpoints"),
		"diagnose_last_domain_change":           t(phrases().DiagnoseLastDomainChange, "Last domain change"),
		"diagnose_last_ipv4":                    t(phrases().DiagnoseLastIPv4, "Last IPv4"),
		"diagnose_last_ipv6":                    t(phrases().DiagnoseLastIPv6, "Last IPv6"),
		"diagnose_last_run_ok":                  t(phrases().DiagnoseLastRunOK, "Last run OK"),
		"diagnose_load_failed":                  t(phrases().DiagnoseLoadFailed, "Diagnosis failed"),
		"diagnose_loading":                      t(phrases().DiagnoseLoading, "Loading diagnosis..."),
		"diagnose_log_errors":                   t(phrases().DiagnoseLogErrors, "Log errors"),
		"diagnose_log_warnings":                 t(phrases().DiagnoseLogWarnings, "Log warnings"),
		"diagnose_no":                           t(phrases().DiagnoseNo, "No"),
		"diagnose_no_config_warnings":           t(phrases().DiagnoseNoConfigWarnings, "No config warnings"),
		"diagnose_no_notifiers":                 t(phrases().DiagnoseNoNotifiers, "No notifiers"),
		"diagnose_no_providers":                 t(phrases().DiagnoseNoProviders, "No providers found"),
		"diagnose_notifier_title":               t(phrases().DiagnoseNotifierTitle, "Notifier"),
		"diagnose_provider_title":               t(phrases().DiagnoseProviderTitle, "Provider"),
		"diagnose_scheduler_ran":                t(phrases().DiagnoseSchedulerRan, "Scheduler ran"),
		"diagnose_status_degraded":              t(phrases().DiagnoseStatusDegraded, "Degraded"),
		"diagnose_status_healthy":               t(phrases().DiagnoseStatusHealthy, "Healthy"),
		"diagnose_status_starting":              t(phrases().DiagnoseStatusStarting, "Starting"),
		"diagnose_status_unhealthy":             t(phrases().DiagnoseStatusUnhealthy, "Unhealthy"),
		"diagnose_success_rate":                 t(phrases().DiagnoseSuccessRate, "Success rate"),
		"diagnose_system_title":                 t(phrases().DiagnoseSystemTitle, "System"),
		"diagnose_title":                        t(phrases().DiagnoseTitle, "Diagnose / Health Center"),
		"diagnose_total_requests":               t(phrases().DiagnoseTotalRequests, "Total requests"),
		"diagnose_update_running":               t(phrases().DiagnoseUpdateRunning, "Update running"),
		"diagnose_uptime":                       t(phrases().DiagnoseUptime, "Uptime"),
		"diagnose_warnings_title":               t(phrases().DiagnoseWarningsTitle, "Warnings"),
		"diagnose_yes":                          t(phrases().DiagnoseYes, "Yes"),
		"dns_check_failed":                      t(phrases().DNSCheckFailedJS, "DNS-Prüfung fehlgeschlagen."),
		"dns_col_duration_error":                t(phrases().DNSColDurationErrorJS, "Dauer / Fehler"),
		"dns_col_ipv4":                          t(phrases().DNSColIPv4JS, "IPv4"),
		"dns_col_ipv6":                          t(phrases().DNSColIPv6JS, "IPv6"),
		"dns_col_resolver":                      t(phrases().DNSColResolverJS, "Resolver"),
		"dns_domain_required":                   t(phrases().DNSDomainRequiredJS, "❌ Bitte eine Domain eingeben."),
		"dns_expected_ipv4":                     t(phrases().DNSExpectedIPv4JS, "IPv4-Soll"),
		"dns_expected_ipv6":                     t(phrases().DNSExpectedIPv6JS, "IPv6-Soll"),
		"dns_loading":                           t(phrases().DNSLoadingJS, "DNS-Resolver werden abgefragt…"),
		"dns_match_mismatch":                    t(phrases().DNSMatchMismatchJS, "abweichend"),
		"dns_match_ok":                          t(phrases().DNSMatchOKJS, "passt"),
		"dns_no_expected":                       t(phrases().DNSNoExpectedJS, "kein Sollwert"),
		"dns_no_results":                        t(phrases().DNSNoResultsJS, "Keine Ergebnisse."),
		"dnscale_api_key_missing":               t(phrases().DNScaleAPIKeyMissingJS, "DNScale API Key fehlt"),
		"domain_removed":                        t(phrases().DomainRemovedJS, "🗑️ {domain} removed"),
		"domain_updated":                        t(phrases().DomainUpdatedJS, "✓ {domain} updated"),
		"edit_domain_cancelled":                 t(phrases().EditDomainCancelledJS, "Edit cancelled"),
		"edit_domain_saved":                     t(phrases().EditDomainSavedJS, "Changes saved"),
		"error_prefix":                          t(phrases().ErrorPrefixJS, "❌ Error: "),
		"export_failed":                         t(phrases().ExportFailedJS, "Export failed"),
		"export_started":                        t(phrases().ExportStartedJS, "✓ Export started"),
		"febas_update_url_missing":              t(phrases().FebasUpdateURLMissingJS, "Febas DynDNS Update-URL fehlt"),
		"fqdn_missing":                          t(phrases().FQDNMissingJS, "FQDN missing"),
		"generic_error":                         t(phrases().GenericErrorJS, "Error"),
		"ipv64_domain_add_running":              t(phrases().IPv64DomainAddRunningJS, "⏳ IPv64 Domain wird hinzugefügt..."),
		"ipv64_domain_add_success":              t(phrases().IPv64DomainAddSuccessJS, "✅ IPv64 Domain hinzugefügt: {fqdn}"),
		"ipv64_domain_delete_confirm":           t(phrases().IPv64DomainDeleteConfirmJS, `IPv64 Domain "{fqdn}" wirklich löschen? Diese Aktion kann nicht rückgängig gemacht werden.`),
		"ipv64_domain_delete_running":           t(phrases().IPv64DomainDeleteRunningJS, "⏳ IPv64 Domain wird gelöscht..."),
		"ipv64_domain_delete_success":           t(phrases().IPv64DomainDeleteSuccessJS, "🗑️ IPv64 Domain gelöscht: {fqdn}"),
		"keyboard_shortcuts_help":               t(phrases().KeyboardShortcutsHelpJS, "⌨️ R=Update  S=Settings  D=Dashboard  M=Metrics  L=Logs  I=Diagnose"),
		"loading_saving":                        t(phrases().LoadingSavingJS, "⏳ Saving configuration..."),
		"loading_slow":                          t(phrases().LoadingSlowJS, "⚠️ Taking longer than expected..."),
		"log_delete_failed":                     t(phrases().LogDeleteFailedJS, "Löschen fehlgeschlagen"),
		"log_entry_deleted":                     t(phrases().LogEntryDeletedJS, "Eintrag gelöscht:"),
		"metrics_reset_failed":                  t(phrases().MetricsResetFailedJS, "❌ Reset failed"),
		"metrics_reset_ok":                      t(phrases().MetricsResetOKJS, "✅ Metrics reset"),
		"nav_audit":                             t(phrases().NavAuditJS, "🛡️ Audit & DNS"),
		"nav_backup":                            t(phrases().NavBackupJS, "💾 Backup & Restore"),
		"nav_dashboard":                         t(phrases().NavDashboardJS, "🌐 Dashboard"),
		"nav_debug":                             t(phrases().NavDebugJS, "🐞 Debug"),
		"nav_diagnose":                          t(phrases().NavDiagnoseJS, "🩺 Diagnose"),
		"nav_domains":                           t(phrases().NavDomainsJS, "🌐 Domains"),
		"nav_logs":                              t(phrases().NavLogsJS, "🧾 Logs"),
		"nav_metrics":                           t(phrases().NavMetricsJS, "📊 Metrics"),
		"nav_settings_security":                 t(phrases().SettingsSecurity, "🔒 Sicherheit"),
		"nav_settings_system":                   t(phrases().SettingsSystem, "⚙️ System"),
		"nav_settings_domains":                  t(phrases().SettingsDomains, "🌐 Domains"),
		"nav_settings_notify":                   t(phrases().SettingsNotify, "🔔 Benachrichtigungen"),
		"nav_totp":                              t(phrases().NavTotpJS, "🔐 2FA / Account Security"),
		"nav_users":                             t(phrases().SettingsUserManagement, "👥 User Management"),
		"no_ip_to_copy":                         t(phrases().NoIPToCopyJS, "❌ No IP to copy"),
		"no_log_entries":                        t(phrases().NoLogEntries, "No log entries visible"),
		"no_users_found":                        t(phrases().NoUsersFoundJS, "No users found."),
		"notif_empty":                           t(phrases().NotifEmptyJS, "Keine Ereignisse"),
		"notify_btn_sending":                    t(phrases().NotifyBtnSending, "⏳ Sende..."),
		"notify_btn_test":                       t(phrases().NotifyBtnTest, "🧪 Test-Nachricht senden"),
		"notify_no_notifier":                    t(phrases().NotifyNoNotifier, "⚠️ Keine aktiven Notifier konfiguriert."),
		"notify_stat_success":                   t(phrases().NotifyStatSuccess, "erfolgreich"),
		"notify_test_conn_error":                t(phrases().NotifyTestConnError, "❌ Connection error to server"),
		"notify_test_error":                     t(phrases().NotifyTestError, "❌ Error while sending"),
		"notify_test_success":                   t(phrases().NotifyTestSuccess, "✅ Test message sent successfully!"),
		"notify_test_unauthorized":              t(phrases().NotifyTestUnauthorized, "❌ Unauthorized (check token)"),
		"page_reload_failed":                    t(phrases().PageReloadFailedJS, "Seite konnte nicht aktualisiert werden"),
		"password_reset":                        t(phrases().PasswordResetJS, "Password changed"),
		"provider_invalid":                      t(phrases().ProviderInvalidJS, "Ungültiger Provider"),
		"entries_label":                         t(phrases().EntriesLabel, "Records"),
		"remove_btn":                            t(phrases().RemoveBtn, "🗑️ Remove"),
		"reset_metrics_confirm":                 t(phrases().ResetMetricsConfirmJS, "Clear all metrics?"),
		"reset_password":                        t(phrases().ResetPasswordJS, "Set password"),
		"reset_password_prompt":                 t(phrases().ResetPasswordPromptJS, `New password for "{username}":`),
		"role_admin":                            t(phrases().RoleAdminJS, "Admin"),
		"role_changed":                          t(phrases().RoleChangedJS, "Role changed"),
		"role_editor":                           t(phrases().RoleEditorJS, "Editor"),
		"role_viewer":                           t(phrases().RoleViewerJS, "Viewer"),
		"save_config_confirm":                   t(phrases().SaveConfigConfirmJS, "Save all settings to config.json?"),
		"saved_reload":                          t(phrases().SavedReloadJS, "✅ Saved! Reloading..."),
		"settings_add_btn":                      t(phrases().SettingsAddBtnJS, "➕ Add to list"),
		"settings_checkbox_active":              t(phrases().SettingsCheckboxActiveJS, "Aktiv"),
		"settings_checkbox_inactive":            t(phrases().SettingsCheckboxInactiveJS, "Inaktiv"),
		"settings_reload_failed":                t(phrases().SettingsReloadFailedJS, "Einstellungen konnten nicht geladen werden"),
		"system_stats_block_io_cgroup":          t(phrases().SystemStatsBlockIOCgroup, "Block I/O from cgroup"),
		"system_stats_cpu_usage_total_format":   t(phrases().SystemStatsCPUUsageTotalFormat, "Total usage {duration}"),
		"system_stats_env_container":            t(phrases().SystemStatsEnvContainer, "Container"),
		"system_stats_env_containerd":           t(phrases().SystemStatsEnvContainerd, "containerd / container"),
		"system_stats_env_docker":               t(phrases().SystemStatsEnvDocker, "Docker"),
		"system_stats_env_host_process":         t(phrases().SystemStatsEnvHostProcess, "Host / process"),
		"system_stats_env_kubernetes":           t(phrases().SystemStatsEnvKubernetes, "Kubernetes / container"),
		"system_stats_io_rate_format":           t(phrases().SystemStatsIORateFormat, "R {read} · W {write}"),
		"system_stats_io_total_format":          t(phrases().SystemStatsIOTotalFormat, "R {read} · W {write}"),
		"system_stats_live":                     t(phrases().SystemStatsLive, "Live"),
		"system_stats_live_with_time_format":    t(phrases().SystemStatsLiveWithTimeFormat, "Live · {time}"),
		"system_stats_memory_no_limit_format":   t(phrases().SystemStatsMemoryNoLimitFormat, "{used} · no limit · Cache {cache}"),
		"system_stats_memory_with_limit_format": t(phrases().SystemStatsMemoryWithLimitFormat, "{used} / {limit} · Cache {cache}"),
		"system_stats_network_namespace":        t(phrases().SystemStatsNetworkNamespace, "RX/TX in the network namespace"),
		"system_stats_network_rate_format":      t(phrases().SystemStatsNetworkRateFormat, "↓ {rx} · ↑ {tx}"),
		"system_stats_network_total":            t(phrases().SystemStatsNetworkTotal, "Network total"),
		"system_stats_network_total_format":     t(phrases().SystemStatsNetworkTotalFormat, "↓ {rx} · ↑ {tx}"),
		"system_stats_no_cgroup_limit":          t(phrases().SystemStatsNoCgroupLimit, "No cgroup limit"),
		"system_stats_process_format":           t(phrases().SystemStatsProcessFormat, "{heap} Heap · {goroutines} Goroutines"),
		"system_stats_unavailable":              t(phrases().SystemStatsUnavailable, "Unavailable"),
		"system_stats_unknown":                  t(phrases().SystemStatsUnknown, "Unknown"),
		"theme":                                 t(phrases().ThemeLabelJS, "Theme"),
		"token_deleted":                         t(phrases().TokenDeletedJS, "🗑️ Token deleted"),
		"token_enter":                           t(phrases().TokenEnterJS, "Enter token..."),
		"token_saved":                           t(phrases().TokenSavedJS, "✅ Token saved"),
		"token_saved_masked":                    t(phrases().TokenSavedMaskedJS, "●●●●●● (saved)"),
		"totp_action_failed":                    t(phrases().TotpActionFailedJS, "2FA action failed"),
		"totp_badge_active":                     t(phrases().TotpBadgeActiveJS, "🔐 2FA active"),
		"totp_badge_inactive":                   t(phrases().TotpBadgeInactiveJS, "🔓 2FA inactive"),
		"totp_settings_load_failed":             t(phrases().TotpSettingsLoadFailedJS, "2FA settings could not be loaded"),
		"update_running":                        t(phrases().UpdateRunningJS, "Update läuft bereits"),
		"update_started":                        t(phrases().UpdateStartedJS, "✅ Update started"),
		"update_starting":                       t(phrases().UpdateStartingJS, "⏳ Starting update..."),
		"user_created":                          t(phrases().UserCreatedJS, "User created"),
		"user_delete_confirm":                   t(phrases().UserDeleteConfirmJS, `Benutzer "{username}" wirklich löschen?`),
		"user_deleted":                          t(phrases().UserDeletedJS, "User deleted"),
		"user_last_login":                       t(phrases().UserLastLoginJS, "Letzter Login: {time}"),
		"user_load_failed":                      t(phrases().UserLoadFailedJS, "Failed to load"),
	}

	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "{}"
	}

	return string(b)
}

var defaultLocaleByBase = map[string]string{
	"bg": "bg-BG",
	"cs": "cs-CZ",
	"da": "da-DK",
	"de": "de-DE",
	"el": "el-GR",
	"en": "en-GB",
	"es": "es-ES",
	"et": "et-EE",
	"fi": "fi-FI",
	"fr": "fr-FR",
	"hr": "hr-HR",
	"hu": "hu-HU",
	"is": "is-IS",
	"it": "it-IT",
	"lt": "lt-LT",
	"lv": "lv-LV",
	"nb": "nb-NO",
	"nl": "nl-NL",
	"pl": "pl-PL",
	"pt": "pt-PT",
	"ro": "ro-RO",
	"ru": "ru-RU",
	"sk": "sk-SK",
	"sl": "sl-SI",
	"sv": "sv-SE",
	"tr": "tr-TR",
	"uk": "uk-UA",
}

var knownLangLabels = map[string]string{
	"bg": "🇧🇬 Български", "bg-BG": "🇧🇬 Български (България)",
	"cs": "🇨🇿 Čeština", "cs-CZ": "🇨🇿 Čeština (Česko)",
	"da": "🇩🇰 Dansk", "da-DK": "🇩🇰 Dansk (Danmark)",
	"de": "🇩🇪 Deutsch", "de-DE": "🇩🇪 Deutsch (Deutschland)", "de-AT": "🇦🇹 Deutsch (Österreich)", "de-CH": "🇨🇭 Deutsch (Schweiz)",
	"el": "🇬🇷 Ελληνικά", "el-GR": "🇬🇷 Ελληνικά (Ελλάδα)",
	"en": "🇬🇧 English", "en-GB": "🇬🇧 English (United Kingdom)", "en-US": "🇺🇸 English (United States)",
	"es": "🇪🇸 Español", "es-ES": "🇪🇸 Español (España)", "es-MX": "🇲🇽 Español (México)",
	"et": "🇪🇪 Eesti", "et-EE": "🇪🇪 Eesti (Eesti)",
	"fi": "🇫🇮 Suomi", "fi-FI": "🇫🇮 Suomi (Suomi)",
	"fr": "🇫🇷 Français", "fr-FR": "🇫🇷 Français (France)", "fr-CA": "🇨🇦 Français (Canada)", "fr-CH": "🇨🇭 Français (Suisse)",
	"hr": "🇭🇷 Hrvatski", "hr-HR": "🇭🇷 Hrvatski (Hrvatska)",
	"hu": "🇭🇺 Magyar", "hu-HU": "🇭🇺 Magyar (Magyarország)",
	"is": "🇮🇸 Íslenska", "is-IS": "🇮🇸 Íslenska (Ísland)",
	"it": "🇮🇹 Italiano", "it-IT": "🇮🇹 Italiano (Italia)",
	"lt": "🇱🇹 Lietuvių", "lt-LT": "🇱🇹 Lietuvių (Lietuva)",
	"lv": "🇱🇻 Latviešu", "lv-LV": "🇱🇻 Latviešu (Latvija)",
	"nb": "🇳🇴 Norsk", "nb-NO": "🇳🇴 Norsk (Norge)",
	"nl": "🇳🇱 Nederlands", "nl-NL": "🇳🇱 Nederlands (Nederland)", "nl-BE": "🇧🇪 Nederlands (België)",
	"pl": "🇵🇱 Polski", "pl-PL": "🇵🇱 Polski (Polska)",
	"pt": "🇵🇹 Português", "pt-PT": "🇵🇹 Português (Portugal)", "pt-BR": "🇧🇷 Português (Brasil)",
	"ro": "🇷🇴 Română", "ro-RO": "🇷🇴 Română (România)",
	"ru": "🇷🇺 Русский", "ru-RU": "🇷🇺 Русский (Россия)",
	"sk": "🇸🇰 Slovenčina", "sk-SK": "🇸🇰 Slovenčina (Slovensko)",
	"sl": "🇸🇮 Slovenščina", "sl-SI": "🇸🇮 Slovenščina (Slovenija)",
	"sv": "🇸🇪 Svenska", "sv-SE": "🇸🇪 Svenska (Sverige)",
	"tr": "🇹🇷 Türkçe", "tr-TR": "🇹🇷 Türkçe (Türkiye)",
	"uk": "🇺🇦 Українська", "uk-UA": "🇺🇦 Українська (Україна)",
}

func getLangLabel(code string) string {
	code = normalizeLang(code)

	if label, ok := knownLangLabels[code]; ok {
		return label
	}

	return code
}

func buildDynamicLangOptions(current string) string {
	langs, err := getAvailableLanguages(langDir)

	if err != nil || len(langs) == 0 {
		current = normalizeLang(current)

		if current == "" {
			current = "en"
		}

		return `<option value="` +
			esc(current) +
			`" selected>` +
			esc(getLangLabel(current)) +
			`</option>`
	}

	if resolved, ok := resolveAvailableLanguage(current, langs); ok {
		current = resolved
	} else {
		current = normalizeLang(current)
	}

	codes := make([]string, 0, len(langs))

	for code := range langs {
		codes = append(codes, code)
	}

	sort.Strings(codes)

	var out strings.Builder

	for _, code := range codes {
		selected := ""

		if code == current {
			selected = ` selected`
		}

		out.WriteString(`<option value="`)
		out.WriteString(esc(code))
		out.WriteString(`"`)
		out.WriteString(selected)
		out.WriteString(`>`)
		out.WriteString(esc(getLangLabel(code)))
		out.WriteString(`</option>`)
	}

	return out.String()
}

func expectedTranslationKeys() []string {
	v := reflect.TypeFor[Phrases]()
	keys := make([]string, 0, v.NumField())
	for field := range v.Fields() {
		keys = append(keys, toSnakeCase(field.Name))
	}
	sort.Strings(keys)

	return keys
}

func expectedTranslationKeySet() map[string]struct{} {
	expected := expectedTranslationKeys()
	keys := make(map[string]struct{}, len(expected))

	for _, key := range expected {
		keys[key] = struct{}{}
	}

	return keys
}

func esc(s string) string {
	return html.EscapeString(s)
}

func ipEntriesJSONAttr(entries []IPEntry) string {
	b, err := json.Marshal(entries)
	if err != nil {
		return "[]"
	}

	return esc(string(b))
}

func jsString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	s = strings.ReplaceAll(s, "<", `\u003c`)
	s = strings.ReplaceAll(s, ">", `\u003e`)
	s = strings.ReplaceAll(s, "&", `\u0026`)

	return s
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer

	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		http.Error(w, `{"error":"failed to encode response"}`, http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if _, err := w.Write(buf.Bytes()); err != nil {
		debugLog("HTTP", "", fmt.Sprintf("write JSON response: %v", err))
	}
}

func dryRunEnabled() bool {
	cfgMu.RLock()
	enabled := cfg.DryRun
	cfgMu.RUnlock()

	return enabled
}

func writeFileAtomic(path string, data []byte) (err error) {
	dir := filepath.Dir(path)

	tmpFile, err := os.CreateTemp(
		dir,
		"."+filepath.Base(path)+".*.tmp",
	)
	if err != nil {
		return err
	}

	tmpPath := tmpFile.Name()

	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
	}()

	if err := tmpFile.Chmod(0o600); err != nil {
		return err
	}

	if _, err := tmpFile.Write(data); err != nil {
		return err
	}

	if err := tmpFile.Sync(); err != nil {
		return err
	}

	if err := tmpFile.Close(); err != nil {
		return err
	}

	return os.Rename(tmpPath, path)
}

func deleteLogEntryStreaming(path, wantedID string) (bool, error) {
	source, err := os.Open(path)
	if err != nil {
		return false, err
	}

	dir := filepath.Dir(path)
	base := filepath.Base(path)

	temp, err := os.CreateTemp(dir, "."+base+".delete-*")
	if err != nil {
		_ = source.Close()

		return false, err
	}

	tempPath := temp.Name()
	keepTemp := true

	defer func() {
		_ = source.Close()
		_ = temp.Close()

		if keepTemp {
			_ = os.Remove(tempPath)
		}
	}()

	if err := temp.Chmod(0o600); err != nil {
		return false, err
	}

	reader := bufio.NewReaderSize(source, 64*1024)
	writer := bufio.NewWriterSize(temp, 64*1024)

	deleted := false

	for {
		line, readErr := reader.ReadBytes('\n')

		if len(line) > 0 {
			remove := false
			trimmed := bytes.TrimSpace(line)

			if len(trimmed) > 0 {
				var entry LogEntry

				if err := json.Unmarshal(trimmed, &entry); err == nil {
					entry.Timestamp = formatDashboardLogTimestamp(
						entry.Timestamp,
					)

					remove = logEntryID(entry) == wantedID
				}
			}

			if remove {
				deleted = true
			} else {
				if _, err := writer.Write(line); err != nil {
					return false, err
				}

				if readErr == io.EOF && line[len(line)-1] != '\n' {
					if err := writer.WriteByte('\n'); err != nil {
						return false, err
					}
				}
			}
		}

		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}

			return false, readErr
		}
	}

	if err := writer.Flush(); err != nil {
		return false, err
	}

	if err := temp.Sync(); err != nil {
		return false, err
	}

	if err := temp.Close(); err != nil {
		return false, err
	}

	if err := source.Close(); err != nil {
		return false, err
	}

	if err := os.Rename(tempPath, path); err != nil {
		return false, err
	}

	keepTemp = false

	return deleted, nil
}

// ============================================================================
// HELPER - DNS
// ============================================================================

func recordNameFromFQDN(fqdn, zone string) string {
	if fqdn == zone {
		return "@"
	}

	suffix := "." + zone
	if before, ok := strings.CutSuffix(fqdn, suffix); ok {
		return before
	}

	return fqdn
}

func isNonRecoverableError(err error) bool {
	if apiErr, ok := errors.AsType[*APIError](err); ok {
		switch apiErr.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return true
		}
	}

	return false
}

func loadZonesForDomainConfig(ctx context.Context, dc *DomainConfig) ([]Zone, error) {
	switch dc.Provider {
	case ProviderCloudflare:
		return loadCloudflareZones(ctx, dc)
	case ProviderIPv64:
		return loadIPv64Domains(ctx, dc)
	case ProviderIONOS:
		return loadIONOSZones(ctx, dc)
	case ProviderHetzner:
		return loadHetznerDNSZones(ctx, dc)
	case ProviderHetznerCloud:
		return loadHetznerCloudZones(ctx, dc)
	case ProviderFebas:
		return loadFebasZones(ctx)
	case ProviderDNScale:
		return loadDNScaleZones(ctx, dc)
	default:
		return nil, fmt.Errorf("unknown provider: %s", dc.Provider)
	}
}

func loadAllProviderZones(ctx context.Context) (map[string][]Zone, error) {
	zonesByProvider := make(map[string][]Zone)
	providerConfigs := make(map[ProviderType]*DomainConfig)

	cfgMu.RLock()
	domainConfigs := make([]DomainConfig, len(cfg.DomainConfigs))
	copy(domainConfigs, cfg.DomainConfigs)
	cfgMu.RUnlock()

	for i := range domainConfigs {
		dc := &domainConfigs[i]

		if _, exists := providerConfigs[dc.Provider]; !exists {
			providerConfigs[dc.Provider] = dc
		}
	}

	type zoneResult struct {
		err      error
		provider string
		zones    []Zone
	}

	count := len(providerConfigs)
	if count == 0 {
		return zonesByProvider, nil
	}

	results := make(chan zoneResult, count)

	for provider, dc := range providerConfigs {
		go func(p ProviderType, d *DomainConfig) {
			zones, err := loadZonesForDomainConfig(ctx, d)

			results <- zoneResult{
				provider: string(p),
				zones:    zones,
				err:      err,
			}
		}(provider, dc)
	}

	var loadErrors []error

	for range count {
		result := <-results

		if result.err != nil {
			wrappedErr := fmt.Errorf(
				"failed to load zones for %s: %w",
				result.provider,
				result.err,
			)

			loadErrors = append(loadErrors, wrappedErr)

			log(LogContext{
				Level:   LogWarn,
				Action:  ActionZone,
				Message: wrappedErr.Error(),
			})

			continue
		}

		zonesByProvider[result.provider] = result.zones

		debugLog(
			"ZONE",
			"",
			fmt.Sprintf(
				"✅ Loaded %d zones for %s",
				len(result.zones),
				result.provider,
			),
		)
	}

	if len(zonesByProvider) == 0 && len(loadErrors) > 0 {
		return nil, errors.Join(loadErrors...)
	}

	return zonesByProvider, nil
}

func doSingleflight[T any](
	ctx context.Context,
	g *singleflight.Group,
	key string,
	fn func() (T, error),
) (T, error) {
	var zero T

	ch := g.DoChan(key, func() (any, error) {
		v, err := fn()
		if err != nil {
			return nil, err
		}

		return v, nil
	})

	select {
	case <-ctx.Done():
		return zero, ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return zero, res.Err
		}

		return res.Val.(T), nil
	}
}

func calculateRetryDelay(attempt int, isServerError bool) time.Duration {
	baseWait := min(
		max(
			time.Duration(math.Pow(
				RetryExponentBase,
				float64(attempt+1),
			))*RetryBaseDelay,
			RetryBaseDelay,
		),
		RetryMaxDelay,
	)

	var jitter time.Duration

	if RetryJitterMaxMs > 0 {
		randomValue, err := cryptorand.Int(
			cryptorand.Reader,
			big.NewInt(int64(RetryJitterMaxMs)),
		)
		if err == nil {
			jitter = time.Duration(randomValue.Int64()) * time.Millisecond
		}
	}

	wait := baseWait + jitter

	if isServerError {
		wait *= 2
		if wait > RetryMaxDelay {
			wait = RetryMaxDelay
		}
	}

	return wait
}

func sleepOrCancel(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func effectiveTTL(dc *DomainConfig) int {
	if dc == nil {
		return 60
	}
	if dc.TTL <= 0 {
		return 60
	}

	return dc.TTL
}
