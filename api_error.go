// Package main
package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ============================================================================
// API ERROR HANDLING
// ============================================================================
func (e *APIError) Error() string {
	return fmt.Sprintf("API Error [%s %s]: Status %d - %s", e.Method, e.URL, e.StatusCode, e.Message)
}

func (e *APIError) IsRetryable() bool {
	return e.Retryable
}

func parseRetryAfter(h http.Header) (time.Duration, bool) {
	if h == nil {
		return 0, false
	}
	ra := strings.TrimSpace(h.Get("Retry-After"))
	if ra == "" {
		return 0, false
	}

	if secs, err := time.ParseDuration(ra + "s"); err == nil {
		if secs < 0 {
			return 0, false
		}
		return secs, true
	}

	if t, err := http.ParseTime(ra); err == nil {
		d := time.Until(t)
		if d < 0 {
			return 0, false
		}
		return d, true
	}

	return 0, false
}

func classifyAPIErrorWithHeaders(statusCode int, method, url, responseBody string, headers http.Header) *APIError {
	apiErr := &APIError{
		StatusCode: statusCode,
		Method:     method,
		URL:        url,
		Message:    responseBody,
		Retryable:  false,
		RetryAfter: 0,
	}

	if statusCode >= 200 && statusCode < 300 {
		return nil
	}

	switch statusCode {
	case 400:
		apiErr.Message = T.BadRequest
		log(LogContext{Level: LogError, Action: ActionError, Message: fmt.Sprintf("%s %s %s: %s", method, url, T.BadRequest, responseBody)})

	case 401:
		apiErr.Message = T.Unauthorized
		log(LogContext{Level: LogError, Action: ActionConfig, Message: fmt.Sprintf("%s %s: %s", method, url, T.Unauthorized)})

	case 403:
		apiErr.Message = T.Forbidden
		log(LogContext{Level: LogError, Action: ActionError, Message: fmt.Sprintf("%s %s: %s", method, url, T.Forbidden)})

	case 404:
		apiErr.Message = T.NotFound
		log(LogContext{Level: LogWarn, Action: ActionZone, Message: fmt.Sprintf("%s %s: %s", method, url, T.NotFound)})

	case 422:
		apiErr.Message = T.UnprocessableEntity
		log(LogContext{Level: LogError, Action: ActionError, Message: fmt.Sprintf("%s %s: %s - %s", method, url, T.UnprocessableEntity, responseBody)})

	case 429:
		apiErr.Message = T.RateLimitExceeded
		apiErr.Retryable = true

		if d, ok := parseRetryAfter(headers); ok {
			apiErr.RetryAfter = d
		} else {
			apiErr.RetryAfter = RateLimitRetryDelay
		}

		log(LogContext{Level: LogWarn, Action: ActionRetry, Message: fmt.Sprintf("%s %s: %s", method, url, T.RateLimitExceeded)})

	case 500:
		apiErr.Message = T.InternalServerError
		apiErr.Retryable = true
		log(LogContext{Level: LogError, Action: ActionError, Message: fmt.Sprintf("%s %s: %s", method, url, T.InternalServerError)})

	case 502:
		apiErr.Message = T.BadGateway
		apiErr.Retryable = true
		log(LogContext{Level: LogError, Action: ActionError, Message: fmt.Sprintf("%s %s: %s", method, url, T.BadGateway)})

	case 503:
		apiErr.Message = T.ServiceUnavailable
		apiErr.Retryable = true
		apiErr.RetryAfter = ServerErrorRetryDelay
		log(LogContext{Level: LogError, Action: ActionError, Message: fmt.Sprintf("%s %s: %s", method, url, T.ServiceUnavailable)})

	case 504:
		apiErr.Message = T.GatewayTimeout
		apiErr.Retryable = true
		log(LogContext{Level: LogError, Action: ActionError, Message: fmt.Sprintf("%s %s: %s", method, url, T.GatewayTimeout)})

	default:
		if statusCode >= 500 {
			apiErr.Message = fmt.Sprintf("Server Error %d", statusCode)
			apiErr.Retryable = true
			log(LogContext{Level: LogError, Action: ActionError, Message: fmt.Sprintf("%s %s: Server Error %d - %s", method, url, statusCode, responseBody)})
		} else {
			apiErr.Message = fmt.Sprintf("Client Error %d", statusCode)
			apiErr.Retryable = false
			log(LogContext{Level: LogError, Action: ActionError, Message: fmt.Sprintf("%s %s: Client Error %d - %s", method, url, statusCode, responseBody)})
		}
	}

	return apiErr
}

func classifyAPIError(statusCode int, method, url, responseBody string) *APIError {
	return classifyAPIErrorWithHeaders(statusCode, method, url, responseBody, nil)
}
