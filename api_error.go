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

type apiErrorSpec struct {
	messageKey func() string
	fallback   string
	logLevel   LogLevel
	action     string
	retryable  bool
	useHeader  bool
	retryAfter time.Duration
}

var apiErrorSpecs = map[int]apiErrorSpec{
	400: {func() string { return phrases().APIErrorBadRequest }, "Bad Request (check payload)", LogError, ActionError, false, false, 0},
	401: {func() string { return phrases().APIErrorUnauthorized }, "Unauthorized - API key invalid", LogError, ActionConfig, false, false, 0},
	403: {func() string { return phrases().APIErrorForbidden }, "Forbidden - No permission", LogError, ActionError, false, false, 0},
	404: {func() string { return phrases().APIErrorNotFound }, "Not Found - Resource does not exist", LogWarn, ActionZone, false, false, 0},
	405: {func() string { return phrases().APIErrorMethodNotAllowed }, "Method Not Allowed", LogError, ActionError, false, false, 0},
	408: {func() string { return phrases().APIErrorRequestTimeout }, "Request Timeout", LogWarn, ActionRetry, true, false, ServerErrorRetryDelay},
	409: {func() string { return phrases().APIErrorConflict }, "Conflict", LogError, ActionError, false, false, 0},
	410: {func() string { return phrases().APIErrorGone }, "Gone", LogWarn, ActionError, false, false, 0},
	412: {func() string { return phrases().APIErrorPreconditionFailed }, "Precondition Failed", LogError, ActionError, false, false, 0},
	413: {func() string { return phrases().APIErrorPayloadTooLarge }, "Payload Too Large", LogError, ActionError, false, false, 0},
	415: {func() string { return phrases().APIErrorUnsupportedMediaType }, "Unsupported Media Type", LogError, ActionError, false, false, 0},
	422: {func() string { return phrases().APIErrorUnprocessableEntity }, "Validation error (TTL/Format)", LogError, ActionError, false, false, 0},
	425: {func() string { return phrases().APIErrorTooEarly }, "Too Early", LogWarn, ActionRetry, true, false, ServerErrorRetryDelay},
	428: {func() string { return phrases().APIErrorPreconditionRequired }, "Precondition Required", LogError, ActionError, false, false, 0},
	429: {func() string { return phrases().APIErrorRateLimitExceeded }, "Rate limit exceeded", LogWarn, ActionRetry, true, true, RateLimitRetryDelay},
	431: {func() string { return phrases().APIErrorRequestHeaderFieldsTooLarge }, "Request Header Fields Too Large", LogError, ActionError, false, false, 0},
	451: {func() string { return phrases().APIErrorUnavailableForLegalReasons }, "Unavailable For Legal Reasons", LogError, ActionError, false, false, 0},
	500: {func() string { return phrases().APIErrorInternalServerError }, "API server error", LogError, ActionError, true, false, ServerErrorRetryDelay},
	501: {func() string { return phrases().APIErrorNotImplemented }, "Not Implemented", LogError, ActionError, false, false, 0},
	502: {func() string { return phrases().APIErrorBadGateway }, "Gateway error", LogError, ActionRetry, true, false, ServerErrorRetryDelay},
	503: {func() string { return phrases().APIErrorServiceUnavailable }, "Service unavailable", LogError, ActionRetry, true, true, ServerErrorRetryDelay},
	504: {func() string { return phrases().APIErrorGatewayTimeout }, "Gateway timeout", LogError, ActionRetry, true, false, ServerErrorRetryDelay},
	507: {func() string { return phrases().APIErrorInsufficientStorage }, "Insufficient Storage", LogError, ActionRetry, true, false, ServerErrorRetryDelay},
	508: {func() string { return phrases().APIErrorLoopDetected }, "Loop Detected", LogError, ActionRetry, true, false, 0},
	511: {func() string { return phrases().APIErrorNetworkAuthenticationRequired }, "Network Authentication Required", LogError, ActionError, false, false, 0},
}

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
	if statusCode >= 200 && statusCode < 300 {
		return nil
	}

	apiErr := &APIError{
		StatusCode: statusCode,
		Method:     method,
		URL:        url,
		Message:    responseBody,
	}

	if spec, ok := apiErrorSpecs[statusCode]; ok {
		applyAPIErrorSpec(apiErr, spec, responseBody, headers)
		logAPIError(spec.logLevel, spec.action, method, url, apiErr.Message)
		return apiErr
	}

	applyDefaultAPIErrorSpec(apiErr, statusCode, responseBody)
	logAPIError(LogError, defaultAction(statusCode), method, url, apiErr.Message)

	return apiErr
}

func applyAPIErrorSpec(
	apiErr *APIError,
	spec apiErrorSpec,
	responseBody string,
	headers http.Header,
) {
	apiErr.Message = withBody(t(spec.messageKey(), spec.fallback), responseBody)
	apiErr.Retryable = spec.retryable
	apiErr.RetryAfter = resolveRetryAfter(spec, headers)
}

func applyDefaultAPIErrorSpec(apiErr *APIError, statusCode int, responseBody string) {
	if statusCode >= 500 {
		apiErr.Message = withBody(
			tf(phrases().APIErrorServerErrorGeneric, "Server Error %d", statusCode),
			responseBody,
		)
		apiErr.Retryable = true
		apiErr.RetryAfter = ServerErrorRetryDelay
		return
	}

	apiErr.Message = withBody(
		tf(phrases().APIErrorClientErrorGeneric, "Client Error %d", statusCode),
		responseBody,
	)
}

func resolveRetryAfter(spec apiErrorSpec, headers http.Header) time.Duration {
	if !spec.retryable {
		return 0
	}

	if spec.useHeader {
		if d, ok := parseRetryAfter(headers); ok {
			return d
		}
	}

	return spec.retryAfter
}

func defaultAction(statusCode int) string {
	if statusCode >= 500 {
		return ActionRetry
	}
	return ActionError
}

func logAPIError(level LogLevel, action, method, url, message string) {
	log(LogContext{
		Level:   level,
		Action:  action,
		Message: fmt.Sprintf("%s %s: %s", method, url, message),
	})
}

func withBody(base, responseBody string) string {
	if strings.TrimSpace(responseBody) == "" {
		return base
	}
	return fmt.Sprintf("%s - %s", base, responseBody)
}

func tf(value, fallback string, args ...any) string {
	format := t(value, fallback)
	return fmt.Sprintf(format, args...)
}
