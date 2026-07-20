// Package main
package main

import (
	"bufio"
	"encoding/json"
	"errors"
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

// ============================================================================.
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

// ============================================================================.
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
					Message:  t(phrases().RotationWorkerPanic, "Log rotation worker panic"),
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

	if filepath.Clean(path) == filepath.Clean(logPath) {
		logMemCacheMu.Lock()
		logMemCache = nil
		logMemCacheTime = time.Time{}
		logMemCacheMu.Unlock()
	}

	debugLog("MAINTENANCE", "", fmt.Sprintf("✅ %s: %d → %d", phrases().LogRotated, totalCount, len(newLines)))
}

func tailLines(path string, maxLines int) ([]string, int, error) {
	if maxLines <= 0 {
		return nil, 0, errors.New("maxLines must be > 0")
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}

	defer func() {
		if err := file.Close(); err != nil {
			log(LogContext{
				Level:    LogError,
				Category: "FILE",
				Action:   ActionError,
				Message:  fmt.Sprintf("%s: %v", t(phrases().FileCloseError, "Failed to close file"), err),
			})
		}
	}()

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
		log(LogContext{
			Level:    LogError,
			Category: "FILE",
			Action:   ActionError,
			Message:  fmt.Sprintf("%s: %v", t(phrases().ScannerError, "Scanner error"), err),
		})

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
		debugLog("MAINTENANCE", "", t(phrases().RotationQueued, "Log rotation queued"))
	default:
		debugLog("MAINTENANCE", "", t(phrases().RotationQueueFull, "Rotation queue full, skipping"))
	}
}
