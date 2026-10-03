// Package main
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

const (
	LogTDbg  = "DBG"
	LogTInfo = "INFO"
	LogTWarn = "WARN"
	LogTErr  = "ERR"

	DefaultMaxLogMB      = 5
	DefaultMaxLogBackups = 5

	MaxLogMBLimit      = 50
	MaxLogBackupsLimit = 20

	dashboardLogLineLimit = 5000
)

var (
	logFileSize         int64
	atomicLogMaxBytes   atomic.Int64
	atomicLogMaxBackups atomic.Int64
)

// ============================================================================
// LOGGING
// ============================================================================

func log(ctx LogContext) {
	if shouldSkipLog(ctx) {
		return
	}

	levelStr, icon := logLevelPresentation(ctx)
	ts := time.Now().Format(statusTimestampLayout)
	msg := buildLogMessage(ctx)
	icon = overrideLogIcon(icon, ctx)

	printLogLine(ts, levelStr, icon, ctx, msg)

	if !ctx.SkipPersist && shouldPersistLevel(ctx.Level, ctx.Action) {
		persistLog(ctx)
	}

	broadcastDebugLogIfNeeded(ctx, msg, icon)
}

func shouldSkipLog(ctx LogContext) bool {
	if ctx.Level != LogDebug {
		return false
	}

	return !atomicDebugEnabled.Load() && !atomicDebugHTTPRaw.Load()
}

func setAtomicDebugFlags(debugEnabled, debugHTTPRaw bool) {
	atomicDebugEnabled.Store(debugEnabled)
	atomicDebugHTTPRaw.Store(debugHTTPRaw)
}

func logLevelPresentation(ctx LogContext) (string, string) {
	switch ctx.Level {
	case LogDebug:
		return LogTDbg, IconDBG
	case LogInfo:
		return LogTInfo, IconInfo
	case LogWarn:
		return LogTWarn, IconWarn
	case LogError:
		return LogTErr, IconError
	default:
		return LogTInfo, IconInfo
	}
}

func buildLogMessage(ctx LogContext) string {
	message := ctx.Message
	if ctx.Error != nil {
		message = fmt.Sprintf("%s: %v", ctx.Message, ctx.Error)
	}

	return sanitizeText(message)
}

func overrideLogIcon(icon string, ctx LogContext) string {
	if ctx.Level == LogInfo && ctx.Action == ActionCurrent {
		icon = "✅"
	}
	if ctx.Category != "" {
		icon = getCategoryIcon(ctx.Category)
	}

	return icon
}

func printLogLine(ts, levelStr, icon string, ctx LogContext, msg string) {
	switch {
	case ctx.Domain != "" && ctx.Category != "":
		fmt.Printf("[%s] [%-4s] %s %-12s | %-35s: %s\n",
			ts, levelStr, icon, ctx.Category, ctx.Domain, msg)

	case ctx.Domain != "":
		fmt.Printf("[%s] [%-4s] %s %-35s: %s\n",
			ts, levelStr, icon, ctx.Domain, msg)

	case ctx.Category != "":
		fmt.Printf("[%s] [%-4s] %s %-12s: %s\n",
			ts, levelStr, icon, ctx.Category, msg)

	default:
		fmt.Printf("[%s] [%-4s] %s %s\n",
			ts, levelStr, icon, msg)
	}
}

type debugLogPayload struct {
	Timestamp string `json:"timestamp"`
	Category  string `json:"category"`
	Domain    string `json:"domain"`
	Message   string `json:"message"`
	Icon      string `json:"icon"`
}

func broadcastDebugLogIfNeeded(ctx LogContext, msg, icon string) {
	switch ctx.Level {
	case LogDebug, LogInfo, LogWarn, LogError:
		broadcastUpdate("debug_log", debugLogPayload{
			Timestamp: time.Now().Format(statusTimestampLayout),
			Category:  ctx.Category,
			Domain:    ctx.Domain,
			Message:   msg,
			Icon:      icon,
		})
	}
}

var categoryIcons = map[string]string{
	"SYSTEM": IconConfig, "CONFIG": IconConfig, "DNS": IconZone, "ZONE": IconZone,
	"API": IconZone, "NETWORK": IconNetwork, "IP": IconNetwork, "IP-CHECK": IconNetwork,
	"SCHEDULER": "⏱️", "MAINTENANCE": IconCleanup, "SERVER": "📊",
	"HTTP": "📊", "HTTP-RAW": "📝", "WS": IconAPI, "WORKER": "👷",
	"DNS-LOGIC": "🔧", "CACHE": "💾", "DNS-FAILOVER": "🔀",
	"STATUS": "📄", "NOTIFY": "🔔",
}

func getCategoryIcon(category string) string {
	if icon, ok := categoryIcons[category]; ok {
		return icon
	}

	return IconDBG
}

func shouldPersistLevel(level LogLevel, action string) bool {
	if level == LogError || level == LogWarn {
		_, ok := persistOnWarnError[action]

		return ok
	}
	_, ok := persistOnOtherLevels[action]

	return ok
}

func persistLog(ctx LogContext) {
	sanitizedMsg := ctx.Message
	if ctx.Error != nil {
		sanitizedMsg = fmt.Sprintf("%s: %v", ctx.Message, ctx.Error)
	}
	sanitizedMsg = sanitizeText(sanitizedMsg)

	entry := LogEntry{
		Timestamp: time.Now().Format(statusTimestampLayoutT),
		Level:     levelToString(ctx.Level),
		Action:    ctx.Action,
		Domain:    ctx.Domain,
		Message:   sanitizedMsg,
	}

	select {
	case logWriteQueue <- entry:
	default:
		reportLogInfrastructureError(
			fmt.Sprintf(t(phrases().LogQueueFull, "Log queue full, dropped: %s"), entry.Message),
			nil,
		)
	}

	if !ctx.SkipNotify {
		notify(ctx)
	}
}

func reportLogInfrastructureError(message string, err error) {
	now := time.Now().Unix()
	last := lastLogInfrastructureWarning.Load()
	if last != 0 && now-last < 30 {
		return
	}
	if !lastLogInfrastructureWarning.CompareAndSwap(last, now) {
		return
	}

	message = sanitizeText(message)
	if err != nil {
		fmt.Fprintf(os.Stderr, "log infrastructure error: %s: %v\n", message, err)

		return
	}
	fmt.Fprintf(os.Stderr, "log infrastructure warning: %s\n", message)
}

func levelToString(level LogLevel) string {
	switch level {
	case LogDebug:
		return "DBG"
	case LogInfo:
		return "INFO"
	case LogWarn:
		return "WARN"
	case LogError:
		return "ERR"
	default:
		return "INFO"
	}
}

func debugLog(category, domain, msg string) {
	log(LogContext{
		Level:    LogDebug,
		Category: category,
		Domain:   domain,
		Message:  msg,
	})
}

func ipLog(msg string) {
	log(LogContext{
		Level:    LogInfo,
		Category: "IP-CHECK",
		Message:  msg,
	})
}

// ============================================================================
// LOG WRITER
// ============================================================================

func startLogWriter() {
	if !logWriterStarted.CompareAndSwap(false, true) {
		return
	}

	go runLogWriterLoop()
}

func runLogWriterLoop() {
	defer func() {
		if recovered := recover(); recovered != nil {
			fmt.Fprintf(
				os.Stderr,
				"log writer panic: %v\n",
				recovered,
			)
		}

		closeLogWriterResources()
		close(logWriterDone)
	}()

	flushTicker := time.NewTicker(2 * time.Second)
	defer flushTicker.Stop()

	batchCount := 0
	const maxBatchSize = 1000

	for {
		select {
		case entry, ok := <-logWriteQueue:
			if !ok {
				return
			}

			batchCount = handleLogWriterEntry(
				entry,
				batchCount,
				maxBatchSize,
			)

		case <-flushTicker.C:
			batchCount = flushLogWriterBatch(batchCount)

		case <-logWriterStop:
			for {
				select {
				case entry, ok := <-logWriteQueue:
					if !ok {
						return
					}

					batchCount = handleLogWriterEntry(
						entry,
						batchCount,
						maxBatchSize,
					)

				default:
					_ = flushLogWriterBatch(batchCount)

					return
				}
			}
		}
	}
}

func handleLogWriterEntry(entry LogEntry, batchCount, maxBatchSize int) int {
	logMutex.Lock()

	if err := ensureLogWriterOpen(); err != nil {
		logMutex.Unlock()
		reportLogInfrastructureError(
			fmt.Sprintf(t(phrases().LogCannotOpenFile, "Cannot open log file %s"), logPath),
			err,
		)

		return batchCount
	}

	data, err := json.Marshal(entry)
	if err != nil {
		logMutex.Unlock()

		return batchCount
	}
	data = append(data, '\n')

	if logFileSize > 0 && logFileSize+int64(len(data)) > logMaxBytes() {
		rotErr := rotateLogBySizeUnsafe()
		batchCount = 0

		if rotErr != nil {
			reportLogInfrastructureError("log rotation failed", rotErr)
		}
		if err := ensureLogWriterOpen(); err != nil {
			if err := ensureLogWriterOpen(); err != nil {
				logMutex.Unlock()
				reportLogInfrastructureError(
					fmt.Sprintf(t(phrases().LogCannotOpenFile, "Cannot open log file %s"), logPath),
					err,
				)

				return batchCount
			}
			if rotErr != nil {
				logFileSize = 0
			}
		}

		if err := writeLogEntry(data); err != nil {
			logMutex.Unlock()
			reportLogInfrastructureError(
				fmt.Sprintf(t(phrases().LogCannotOpenFile, "Cannot open log file %s"), logPath),
				err,
			)

			return batchCount
		}
	}

	if err := writeLogEntry(data); err != nil {
		closeLogWriterUnsafe()
		logMutex.Unlock()

		reportLogInfrastructureError(
			t(phrases().LogWriteFailed, "Write failed"),
			err,
		)

		return batchCount
	}

	batchCount++
	if shouldFlushLogBatch(entry, batchCount, maxBatchSize) {
		_ = logWriter.Flush()
		batchCount = 0
	}

	logMutex.Unlock()

	return batchCount
}

func ensureLogWriterOpen() error {
	if logWriter != nil && logFile != nil {
		return nil
	}

	dir := filepath.Dir(logPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}

	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()

		return err
	}

	logFileSize = 0
	if st, err := f.Stat(); err == nil {
		logFileSize = st.Size()
	}

	logFile = f
	logWriter = bufio.NewWriterSize(logFile, 256*1024)

	return nil
}

func writeLogEntry(line []byte) error {
	n, err := logWriter.Write(line)
	logFileSize += int64(n)

	return err
}

func shouldFlushLogBatch(entry LogEntry, batchCount, maxBatchSize int) bool {
	return entry.Level == "ERR" || entry.Level == "WARN" || batchCount >= maxBatchSize
}

func flushLogWriterBatch(batchCount int) int {
	logMutex.Lock()
	defer logMutex.Unlock()

	if logWriter != nil && batchCount > 0 {
		_ = logWriter.Flush()

		return 0
	}

	return batchCount
}

func closeLogWriterResources() {
	logMutex.Lock()
	defer logMutex.Unlock()
	closeLogWriterUnsafe()
}

func closeLogWriterUnsafe() {
	if logWriter != nil {
		_ = logWriter.Flush()
		logWriter = nil
	}
	if logFile != nil {
		_ = logFile.Close()
		logFile = nil
	}
}

// ============================================================================
// LOG ROTATION & LIMITS
// ============================================================================

type logGenerationInfo struct {
	Gen     int       `json:"gen"`
	ModTime time.Time `json:"mod_time"`
	Size    int64     `json:"size"`
}

func logGenerationPath(gen int) string {
	if gen <= 0 {
		return logPath
	}

	return fmt.Sprintf("%s.%d", logPath, gen)
}

func listLogGenerations() []logGenerationInfo {
	var out []logGenerationInfo
	for gen := 0; gen <= logMaxBackups(); gen++ {
		if st, err := os.Stat(logGenerationPath(gen)); err == nil {
			out = append(out, logGenerationInfo{Gen: gen, ModTime: st.ModTime(), Size: st.Size()})
		}
	}

	return out
}

func rotateFileGenerations(path string, backups int) error {
	for i := backups; i <= MaxLogBackupsLimit; i++ {
		_ = os.Remove(fmt.Sprintf("%s.%d", path, i))
	}

	for i := backups - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", path, i)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if err := os.Rename(src, fmt.Sprintf("%s.%d", path, i+1)); err != nil {
			return err
		}
	}

	return os.Rename(path, path+".1")
}

func rotateLogBySizeUnsafe() error {
	closeLogWriterUnsafe()

	err := rotateFileGenerations(logPath, logMaxBackups())

	logMemCacheMu.Lock()
	logMemCache = nil
	logMemCacheTime = time.Time{}
	logMemCacheMu.Unlock()

	return err
}

func openLogGenerationsOldestFirst() []*os.File {
	logMutex.Lock()
	defer logMutex.Unlock()

	if logWriter != nil {
		_ = logWriter.Flush()
	}

	files := make([]*os.File, 0, logMaxBackups()+1)
	for gen := logMaxBackups(); gen >= 0; gen-- {
		f, err := os.Open(logGenerationPath(gen))
		if err != nil {
			continue
		}
		files = append(files, f)
	}

	return files
}

func clampOrDefault(v, def, upper int) int {
	if v <= 0 {
		return def
	}

	return min(v, upper)
}

func normalizeLogMB(mb int) int {
	return clampOrDefault(mb, DefaultMaxLogMB, MaxLogMBLimit)
}

func normalizeLogBackups(n int) int {
	return clampOrDefault(n, DefaultMaxLogBackups, MaxLogBackupsLimit)
}

func setAtomicLogLimits(mb, backups int) {
	atomicLogMaxBytes.Store(int64(normalizeLogMB(mb)) << 20)
	atomicLogMaxBackups.Store(int64(normalizeLogBackups(backups)))
}

func logMaxBackups() int {
	if v := atomicLogMaxBackups.Load(); v > 0 {
		return int(v)
	}

	return DefaultMaxLogBackups
}

func logMaxBytes() int64 {
	if v := atomicLogMaxBytes.Load(); v > 0 {
		return v
	}

	return int64(DefaultMaxLogMB) << 20
}
