package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
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

	if ctx.Domain != "" {
		if ctx.Category != "" {
			fmt.Printf("[%s] [%-4s] %s %-12s | %-35s: %s\n",
				ts, levelStr, icon, ctx.Category, ctx.Domain, msg)
		} else {
			fmt.Printf("[%s] [%-4s] %s %-35s: %s\n",
				ts, levelStr, icon, ctx.Domain, msg)
		}
	} else if ctx.Category != "" {
		fmt.Printf("[%s] [%-4s] %s %-12s: %s\n",
			ts, levelStr, icon, ctx.Category, msg)
	} else {
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

func writeLog(level, action, domain, msg string) {
	var logLevel LogLevel
	switch level {
	case "DBG":
		logLevel = LogDebug
	case "WARN":
		logLevel = LogWarn
	case "ERR":
		logLevel = LogError
	case "CURRENT":
		logLevel = LogInfo
	default:
		logLevel = LogInfo
	}

	log(LogContext{
		Level:   logLevel,
		Action:  action,
		Domain:  domain,
		Message: msg,
	})
}

func debugLog(category, domain, msg string) {
	log(LogContext{
		Level:    LogDebug,
		Category: category,
		Domain:   domain,
		Message:  msg,
	})
}

func ipLog(domain, msg string) {
	log(LogContext{
		Level:    LogInfo,
		Category: "IP-CHECK",
		Domain:   domain,
		Message:  msg,
	})
}

// ============================================================================
// LOG ROTATION
// ============================================================================
func startLogWriter() {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "[FATAL] Log writer panic: %v\n", r)
			}
		}()

		for entry := range logWriteQueue {
			logMutex.Lock()

			file, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[ERROR] Failed to open log file: %v\n", err)
				logMutex.Unlock()
				continue
			}

			data, err := json.Marshal(entry)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[ERROR] Failed to marshal log entry: %v\n", err)
				if err := file.Close(); err != nil {
					fmt.Fprintf(os.Stderr, "[WARN] Failed to close file: %v\n", err)
				}
				logMutex.Unlock()
				continue
			}

			_, err = file.Write(append(data, '\n'))
			if err != nil {
				fmt.Fprintf(os.Stderr, "[ERROR] Failed to write log entry: %v\n", err)
			}

			if err := file.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "[WARN] Failed to close file: %v\n", err)
			}
			logMutex.Unlock()
		}

		debugLog("SYSTEM", "", "📝 Log-Writer beendet")
	}()
}
func startLogRotationWorker() {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				debugLog("MAINTENANCE", "", fmt.Sprintf("🚨 Rotation worker panic: %v", r))
			}
		}()

		for job := range rotationQueue {
			doLogRotation(job.path, job.maxLines)
		}
	}()
}

func doLogRotation(path string, maxLines int) {
	logMutex.Lock()
	defer logMutex.Unlock()

	file, err := os.Open(path)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Printf("[WARN] %s: %v\n", T.LogRotationError, err)
		}
		return
	}

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := file.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] Failed to close file: %v\n", err)
	}

	if len(lines) <= maxLines {
		return
	}

	startIdx := len(lines) - maxLines
	newLines := lines[startIdx:]
	output := strings.Join(newLines, "\n") + "\n"

	tmpPath := path + ".tmp." + strconv.FormatInt(time.Now().Local().UnixNano(), 10)
	if err := os.WriteFile(tmpPath, []byte(output), 0644); err != nil {
		fmt.Printf("[WARN] %s: %v\n", T.LogRotationError, err)
		return
	}

	if err := os.Rename(tmpPath, path); err != nil {
		fmt.Printf("[WARN] %s: %v\n", T.LogRotationError, err)
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
	deadline := time.Now().Local().Add(timeout)

	for time.Now().Local().Before(deadline) {
		if len(logWriteQueue) == 0 {
			time.Sleep(10 * time.Millisecond)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}

	debugLog("SYSTEM", "", fmt.Sprintf("⚠️ Log-Queue nicht vollständig geleert (%d verbleibend)", len(logWriteQueue)))
}
