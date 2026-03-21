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

// ============================================================================
// LOGGING
// ============================================================================
func log(ctx LogContext) {
	if ctx.Level == LogDebug && !cfg.DebugEnabled {
		return
	}

	var levelStr, icon string
	switch ctx.Level {
	case LogDebug:
		levelStr, icon = "DBG", "🐞"
	case LogInfo:
		levelStr, icon = "INFO", "ℹ️"
	case LogWarn:
		levelStr, icon = "WARN", "⚠️"
	case LogError:
		levelStr, icon = "ERR", "❌"
	}

	if ctx.Level == LogInfo && ctx.Action == ActionCurrent {
		icon = "✅"
	}

	ts := time.Now().Local().Format("02.01.2006 15:04:05")

	var msg string
	if ctx.Error != nil {
		msg = fmt.Sprintf("%s: %v", ctx.Message, ctx.Error)
	} else {
		msg = ctx.Message
	}

	if ctx.Category != "" {
		icon = getCategoryIcon(ctx.Category)
	}

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

	if shouldPersistLevel(ctx.Level, ctx.Action) {
		persistLog(ctx)
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
		fmt.Fprintf(os.Stderr, "[WARN] Log queue full, dropped: %s\n", entry.Message)
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

func notifyError(msg string) {
	fmt.Fprintf(os.Stderr, "[WARN] %s\n", msg)
	go notify(LogContext{
		Level:   LogError,
		Action:  ActionError,
		Message: msg,
	})
}

// ============================================================================
// LOG WRITER
// ============================================================================
func startLogWriter() {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "[FATAL] Log writer panic: %v\n", r)
			}
		}()

		var file *os.File
		var writer *bufio.Writer

		ensureOpen := func() error {
			if writer != nil && file != nil {
				return nil
			}

			dir := filepath.Dir(logPath)
			if err := os.MkdirAll(dir, 0755); err != nil {
				return err
			}

			f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				return err
			}

			file = f
			writer = bufio.NewWriterSize(file, 64*1024)
			return nil
		}

		flushTicker := time.NewTicker(500 * time.Millisecond)
		defer flushTicker.Stop()

		batchCount := 0
		const maxBatchSize = 10

		for {
			select {
			case entry, ok := <-logWriteQueue:
				if !ok {
					if writer != nil {
						_ = writer.Flush()
						_ = file.Close()
					}
					return
				}

				logMutex.Lock()
				if err := ensureOpen(); err != nil {
					fmt.Fprintf(os.Stderr, "[ERROR] Cannot open log file %s: %v\n", logPath, err)
					logMutex.Unlock()
					continue
				}

				data, err := json.Marshal(entry)
				if err != nil {
					logMutex.Unlock()
					continue
				}

				_, err = writer.Write(append(data, '\n'))
				if err != nil {
					fmt.Fprintf(os.Stderr, "[ERROR] Write failed: %v\n", err)
					_ = file.Close()
					writer = nil
					file = nil
				} else {
					batchCount++
					if entry.Level == "ERR" || entry.Level == "WARN" || batchCount >= maxBatchSize {
						_ = writer.Flush()
						batchCount = 0
					}
				}
				logMutex.Unlock()

			case <-flushTicker.C:
				logMutex.Lock()
				if writer != nil && batchCount > 0 {
					_ = writer.Flush()
					batchCount = 0
				}
				logMutex.Unlock()

			case <-shutdownCtx.Done():
				logMutex.Lock()
				if writer != nil {
					_ = writer.Flush()
					_ = file.Close()
				}
				logMutex.Unlock()
				return
			}
		}
	}()
}

func startLogRotationWorker() {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "[WARN] Rotation worker panic: %v\n", r)
				go notify(LogContext{
					Level:   LogError,
					Action:  ActionError,
					Message: fmt.Sprintf("Log rotation worker panic: %v", r),
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
	rotationMutex.Lock()
	defer rotationMutex.Unlock()

	file, err := os.Open(path)
	if err != nil {
		if !os.IsNotExist(err) {
			notifyError(fmt.Sprintf("%s: %v", T.LogRotationError, err))
		}
		return
	}

	var lines []string
	scanner := bufio.NewScanner(file)
	buf := make([]byte, 1024*1024)
	scanner.Buffer(buf, len(buf))
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		notifyError(fmt.Sprintf("Rotation scanner error: %v", err))
	}
	if closeErr := file.Close(); closeErr != nil {
		fmt.Fprintf(os.Stderr, "[WARN] Failed to close file: %v\n", closeErr)
	}

	if len(lines) <= maxLines {
		return
	}

	startIdx := len(lines) - maxLines
	newLines := lines[startIdx:]
	output := strings.Join(newLines, "\n") + "\n"

	tmpPath := path + ".tmp." + strconv.FormatInt(time.Now().Local().UnixNano(), 10)
	if err := os.WriteFile(tmpPath, []byte(output), 0644); err != nil {
		notifyError(fmt.Sprintf("%s: %v", T.LogRotationError, err))
		return
	}

	if err := os.Rename(tmpPath, path); err != nil {
		notifyError(fmt.Sprintf("%s (rename): %v", T.LogRotationError, err))
		_ = os.Remove(tmpPath)
		return
	}

	debugLog("MAINTENANCE", "", fmt.Sprintf("✅ %s: %d → %d", T.LogRotated, len(lines), len(newLines)))
}

func rotateLogFile(path string, maxLines int) {
	select {
	case rotationQueue <- rotationJob{path: path, maxLines: maxLines}:
		debugLog("MAINTENANCE", "", "📋 Log-Rotation eingereiht")
	default:
		debugLog("MAINTENANCE", "", "⚠️ Rotation-Queue voll, überspringe")
	}
}

// ============================================================================
// LOG QUEUE FLUSH
// ============================================================================
func flushLogQueue(timeout time.Duration) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			if n := len(logWriteQueue); n > 0 {
				fmt.Fprintf(os.Stderr, "[WARN] Log-Queue nicht vollständig geleert (%d verbleibend)\n", n)
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