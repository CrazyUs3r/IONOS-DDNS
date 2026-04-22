// Package main
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	LogTDbg  = "DBG"
	LogTInfo = "INFO"
	LogTWarn = "WARN"
	LogTErr  = "ERR"
)

const (
	IconDBG  = "🐞"
	IconInfo = "ℹ️"
	IconWarn = "⚠️"
	IconErr  = "❌"
)

// ============================================================================
// LOGGING
// ============================================================================
func log(ctx LogContext) {
	if shouldSkipLog(ctx) {
		return
	}

	levelStr, icon := logLevelPresentation(ctx)
	ts := time.Now().Local().Format("02.01.2006 15:04:05")
	msg := buildLogMessage(ctx)
	icon = overrideLogIcon(icon, ctx)

	printLogLine(ts, levelStr, icon, ctx, msg)

	if shouldPersistLevel(ctx.Level, ctx.Action) {
		persistLog(ctx)
	}

	broadcastDebugLogIfNeeded(ctx, msg, icon)
}

func shouldSkipLog(ctx LogContext) bool {
	cfgMu.RLock()
	debugEnabled := cfg.DebugEnabled
	debugHTTPRaw := cfg.DebugHTTPRaw
	cfgMu.RUnlock()

	return ctx.Level == LogDebug && !debugEnabled && !debugHTTPRaw
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
		return LogTErr, IconErr
	default:
		return LogTInfo, IconInfo
	}
}

func buildLogMessage(ctx LogContext) string {
	if ctx.Error != nil {
		return fmt.Sprintf("%s: %v", ctx.Message, ctx.Error)
	}
	return ctx.Message
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

func broadcastDebugLogIfNeeded(ctx LogContext, msg, icon string) {
	switch ctx.Level {
	case LogDebug, LogWarn, LogError:
		broadcastUpdate("debug_log", map[string]string{
			"timestamp": time.Now().Local().Format("02.01.2006 15:04:05"),
			"category":  ctx.Category,
			"domain":    ctx.Domain,
			"message":   msg,
			"icon":      icon,
		})
	}
}

func getCategoryIcon(category string) string {
	icons := map[string]string{
		"SYSTEM":       "⚙️",
		"CONFIG":       "⚙️",
		"DNS":          "🌐",
		"ZONE":         "🌐",
		"API":          "🌐",
		"NETWORK":      "📡",
		"IP":           "📡",
		"IP-CHECK":     "📡",
		"SCHEDULER":    "⏱️",
		"MAINTENANCE":  "🧹",
		"SERVER":       "📊",
		"HTTP":         "📊",
		"HTTP-RAW":     "📝",
		"WS":           "🔌",
		"WORKER":       "👷",
		"DNS-LOGIC":    "🔧",
		"CACHE":        "💾",
		"DNS-FAILOVER": "🔀",
		"STATUS":       "📄",
		"NOTIFY":       "🔔",
	}

	if icon, ok := icons[category]; ok {
		return icon
	}
	return "🐞"
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
	if replacer := getSecretReplacer(); replacer != nil {
		sanitizedMsg = replacer.Replace(sanitizedMsg)
	}

	entry := LogEntry{
		Timestamp: time.Now().Local().Format("2006-01-02T15:04:05"),
		Level:     levelToString(ctx.Level),
		Action:    ctx.Action,
		Domain:    ctx.Domain,
		Message:   sanitizedMsg,
	}

	select {
	case logWriteQueue <- entry:
	default:
		log(LogContext{
			Level:      LogWarn,
			Category:   "SYSTEM",
			Action:     ActionError,
			Message:    fmt.Sprintf(t(T.LogQueueFull, "Log queue full, dropped: %s"), entry.Message),
			SkipNotify: true,
		})
	}

	if !ctx.SkipNotify {
		notify(ctx)
	}
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
	go runLogWriterLoop()
}

func runLogWriterLoop() {
	defer recoverLogWriterPanic()

	flushTicker := time.NewTicker(2 * time.Second)
	defer flushTicker.Stop()

	batchCount := 0
	const maxBatchSize = 1000

	for {
		select {
		case entry, ok := <-logWriteQueue:
			if !ok {
				closeLogWriterResources()
				return
			}

			batchCount = handleLogWriterEntry(entry, batchCount, maxBatchSize)

		case <-flushTicker.C:
			batchCount = flushLogWriterBatch(batchCount)

		case <-shutdownCtx.Done():
			closeLogWriterResources()
			return
		}
	}
}

func recoverLogWriterPanic() {
	if r := recover(); r != nil {
		log(LogContext{
			Level:      LogError,
			Category:   "SYSTEM",
			Action:     ActionError,
			Message:    t(T.LogWriterPanic, "Log writer panic"),
			Error:      fmt.Errorf("%v", r),
			SkipNotify: true,
		})
	}
}

func handleLogWriterEntry(entry LogEntry, batchCount, maxBatchSize int) int {
	logMutex.Lock()

	if err := ensureLogWriterOpen(); err != nil {
		logMutex.Unlock()
		log(LogContext{
			Level:      LogError,
			Category:   "SYSTEM",
			Action:     ActionError,
			Message:    fmt.Sprintf(t(T.LogCannotOpenFile, "Cannot open log file %s"), logPath),
			Error:      err,
			SkipNotify: true,
		})
		return batchCount
	}

	data, err := json.Marshal(entry)
	if err != nil {
		logMutex.Unlock()
		return batchCount
	}

	if err := writeLogEntry(data); err != nil {
		closeLogWriterUnsafe()
		logMutex.Unlock()

		log(LogContext{
			Level:      LogError,
			Category:   "SYSTEM",
			Action:     ActionError,
			Message:    t(T.LogWriteFailed, "Write failed"),
			Error:      err,
			SkipNotify: true,
		})
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

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}

	logFile = f
	logWriter = bufio.NewWriterSize(logFile, 256*1024)
	return nil
}

func writeLogEntry(data []byte) error {
	_, err := logWriter.Write(append(data, '\n'))
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

func startLogRotationWorker() {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log(LogContext{
					Level:    LogError,
					Category: "MAINTENANCE",
					Action:   ActionError,
					Message:  t(T.RotationWorkerPanic, "Log rotation worker panic"),
					Error:    fmt.Errorf("%v", r),
				})
			}
		}()

		for {
			select {
			case job, ok := <-rotationQueue:
				if !ok {
					return
				}
				doLogRotation(job.path, job.maxLines)

			case <-shutdownCtx.Done():
				return
			}
		}
	}()
}

func doLogRotation(path string, maxLines int) {
	logMutex.Lock()
	defer logMutex.Unlock()

	if filepath.Clean(path) == filepath.Clean(logPath) {
		if logWriter != nil {
			_ = logWriter.Flush()
			logWriter = nil
		}
		if logFile != nil {
			_ = logFile.Close()
			logFile = nil
		}
	}

	newLines, totalCount, err := tailLines(path, maxLines)
	if err != nil {
		fmt.Fprintf(os.Stderr, "log rotation error: %v\n", err)
		return
	}

	if totalCount <= maxLines {
		return
	}

	output := strings.Join(newLines, "\n") + "\n"
	tmpPath := path + ".tmp." + strconv.FormatInt(time.Now().UnixNano(), 10)

	if err := os.WriteFile(tmpPath, []byte(output), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "log rotation write error: %v\n", err)
		return
	}

	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "log rotation remove failed: %v\n", err)
		_ = os.Remove(tmpPath)
		return
	}

	if err := os.Rename(tmpPath, path); err != nil {
		fmt.Fprintf(os.Stderr, "log rotation rename failed: %v\n", err)
		_ = os.Remove(tmpPath)
		return
	}

	debugLog("MAINTENANCE", "", fmt.Sprintf("✅ %s: %d → %d", T.LogRotated, totalCount, len(newLines)))
}

func tailLines(path string, maxLines int) ([]string, int, error) {
	if maxLines <= 0 {
		return nil, 0, fmt.Errorf("maxLines must be > 0")
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()

	lines := make([]string, maxLines)
	count := 0

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 8*1024*1024)

	for scanner.Scan() {
		lines[count%maxLines] = scanner.Text()
		count++
	}

	if err := scanner.Err(); err != nil {
		return nil, 0, err
	}

	if count <= maxLines {
		return lines[:count], count, nil
	}

	start := count % maxLines
	out := make([]string, 0, maxLines)
	out = append(out, lines[start:]...)
	out = append(out, lines[:start]...)
	return out, count, nil
}

func rotateLogFile(path string, maxLines int) {
	select {
	case rotationQueue <- rotationJob{path: path, maxLines: maxLines}:
		debugLog("MAINTENANCE", "", t(T.RotationQueued, "Log rotation queued"))
	default:
		debugLog("MAINTENANCE", "", t(T.RotationQueueFull, "Rotation queue full, skipping"))
	}
}

// ============================================================================
// LOG QUEUE FLUSH
// ============================================================================
func flushLogQueue() {
	timer := time.NewTimer(logFlushTimeout)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			if n := len(logWriteQueue); n > 0 {
				log(LogContext{
					Level:      LogWarn,
					Category:   "SYSTEM",
					Action:     ActionError,
					Message:    fmt.Sprintf(t(T.LogFlushQueueNotEmptyWithN, "Log queue not fully flushed (%d remaining)"), n),
					SkipNotify: true,
				})
			}
			return
		default:
			if len(logWriteQueue) == 0 {
				time.Sleep(10 * time.Millisecond)
				if len(logWriteQueue) == 0 {
					return
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}
