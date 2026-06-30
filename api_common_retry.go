// Package main
package main

import (
	"context"
	"fmt"
)

type apiAttemptFunc func(attempt, maxRetries int) ([]byte, bool, error)

func configuredAPIMaxAttempts() int {
	cfgMu.RLock()
	maxAttempts := cfg.MaxAPIRetries
	cfgMu.RUnlock()

	if maxAttempts <= 0 {
		return 1
	}

	return maxAttempts
}

func canRetryAPIAttempt(attempt, maxAttempts int) bool {
	return attempt+1 < maxAttempts
}

// ============================================================================
// COMMON RETRY
// ============================================================================
func apiWithRetry(
	ctx context.Context,
	providerName string,
	failedFormat string,
	attemptFn apiAttemptFunc,
) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", phrases().ErrContextError, err)
	}

	maxRetries := configuredAPIMaxAttempts()

	var lastErr error
	for attempt := range maxRetries {
		respBody, retry, err := attemptFn(attempt, maxRetries)
		if err == nil {
			return respBody, nil
		}
		lastErr = err
		if !retry {
			return nil, err
		}
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("%s API failed", providerName)
	}

	return nil, fmt.Errorf("%s: %w", fmt.Sprintf(failedFormat, maxRetries), lastErr)
}
