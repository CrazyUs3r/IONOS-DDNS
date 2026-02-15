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
		var err error

		openLogFile := func() error {
			if file != nil {
				if writer != nil {
					if flushErr := writer.Flush(); flushErr != nil {
						fmt.Fprintf(os.Stderr, "[WARN] Failed to flush writer: %v\n", flushErr)
					}
				}
				if closeErr := file.Close(); closeErr != nil {
					fmt.Fprintf(os.Stderr, "[WARN] Failed to close file: %v\n", closeErr)
				}
			}

			file, err = os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				return err
			}

			writer = bufio.NewWriterSize(file, 64*1024) // 64KB Buffer
			return nil
		}

		if err := openLogFile(); err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] Failed to open log file: %v\n", err)
			return
		}
		defer func() {
			if writer != nil {
				if flushErr := writer.Flush(); flushErr != nil {
					fmt.Fprintf(os.Stderr, "[WARN] Failed to flush writer on exit: %v\n", flushErr)
				}
			}
			if file != nil {
				if closeErr := file.Close(); closeErr != nil {
					fmt.Fprintf(os.Stderr, "[WARN] Failed to close file on exit: %v\n", closeErr)
				}
			}
		}()

		flushTicker := time.NewTicker(500 * time.Millisecond)
		defer flushTicker.Stop()

		batchCount := 0
		const maxBatchSize = 10

		for {
			select {
			case entry, ok := <-logWriteQueue:
				if !ok {
					if writer != nil {
						if flushErr := writer.Flush(); flushErr != nil {
							fmt.Fprintf(os.Stderr, "[ERROR] Failed to flush on channel close: %v\n", flushErr)
						}
					}
					debugLog("SYSTEM", "", "📝 Log-Writer beendet")
					return
				}

				logMutex.Lock()

				data, err := json.Marshal(entry)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[ERROR] Failed to marshal log entry: %v\n", err)
					logMutex.Unlock()
					continue
				}

				_, err = writer.Write(append(data, '\n'))
				if err != nil {
					// Bei Fehler: File neu öffnen versuchen
					fmt.Fprintf(os.Stderr, "[ERROR] Failed to write log entry: %v\n", err)
					if err := openLogFile(); err != nil {
						fmt.Fprintf(os.Stderr, "[ERROR] Failed to reopen log file: %v\n", err)
					}
				}

				batchCount++

				if entry.Level == "ERR" || entry.Level == "WARN" {
					if flushErr := writer.Flush(); flushErr != nil {
						fmt.Fprintf(os.Stderr, "[ERROR] Failed to flush on error/warn: %v\n", flushErr)
					}
					batchCount = 0
				} else if batchCount >= maxBatchSize {
					if flushErr := writer.Flush(); flushErr != nil {
						fmt.Fprintf(os.Stderr, "[ERROR] Failed to flush batch: %v\n", flushErr)
					}
					batchCount = 0
				}

				logMutex.Unlock()

			case <-flushTicker.C:
				// Regelmäßiges Flush
				logMutex.Lock()
				if writer != nil && batchCount > 0 {
					if flushErr := writer.Flush(); flushErr != nil {
						fmt.Fprintf(os.Stderr, "[ERROR] Failed to flush on timer: %v\n", flushErr)
					}
					batchCount = 0
				}
				logMutex.Unlock()

			case <-shutdownCtx.Done():
				// Graceful shutdown
				if writer != nil {
					if flushErr := writer.Flush(); flushErr != nil {
						fmt.Fprintf(os.Stderr, "[ERROR] Failed to flush on shutdown: %v\n", flushErr)
					}
				}
				return
			}
		}
	}()
}

func startLogRotationWorker() {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				debugLog("MAINTENANCE", "", fmt.Sprintf("🚨 Rotation worker panic: %v", r))
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
				debugLog("MAINTENANCE", "", "Log rotation worker stopping...")
				return
			}
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
	closeErr := file.Close()
	if closeErr != nil {
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
