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
	400: {func() string { return T.APIErrorBadRequest }, "Bad Request (check payload)", LogError, ActionError, false, false, 0},
	401: {func() string { return T.APIErrorUnauthorized }, "Unauthorized - API key invalid", LogError, ActionConfig, false, false, 0},
	403: {func() string { return T.APIErrorForbidden }, "Forbidden - No permission", LogError, ActionError, false, false, 0},
	404: {func() string { return T.APIErrorNotFound }, "Not Found - Resource does not exist", LogWarn, ActionZone, false, false, 0},
	405: {func() string { return T.APIErrorMethodNotAllowed }, "Method Not Allowed", LogError, ActionError, false, false, 0},
	408: {func() string { return T.APIErrorRequestTimeout }, "Request Timeout", LogWarn, ActionRetry, true, false, ServerErrorRetryDelay},
	409: {func() string { return T.APIErrorConflict }, "Conflict", LogError, ActionError, false, false, 0},
	410: {func() string { return T.APIErrorGone }, "Gone", LogWarn, ActionError, false, false, 0},
	412: {func() string { return T.APIErrorPreconditionFailed }, "Precondition Failed", LogError, ActionError, false, false, 0},
	413: {func() string { return T.APIErrorPayloadTooLarge }, "Payload Too Large", LogError, ActionError, false, false, 0},
	415: {func() string { return T.APIErrorUnsupportedMediaType }, "Unsupported Media Type", LogError, ActionError, false, false, 0},
	422: {func() string { return T.APIErrorUnprocessableEntity }, "Validation error (TTL/Format)", LogError, ActionError, false, false, 0},
	425: {func() string { return T.APIErrorTooEarly }, "Too Early", LogWarn, ActionRetry, true, false, ServerErrorRetryDelay},
	428: {func() string { return T.APIErrorPreconditionRequired }, "Precondition Required", LogError, ActionError, false, false, 0},
	429: {func() string { return T.APIErrorRateLimitExceeded }, "Rate limit exceeded", LogWarn, ActionRetry, true, true, RateLimitRetryDelay},
	431: {func() string { return T.APIErrorRequestHeaderFieldsTooLarge }, "Request Header Fields Too Large", LogError, ActionError, false, false, 0},
	451: {func() string { return T.APIErrorUnavailableForLegalReasons }, "Unavailable For Legal Reasons", LogError, ActionError, false, false, 0},
	500: {func() string { return T.APIErrorInternalServerError }, "API server error", LogError, ActionError, true, false, ServerErrorRetryDelay},
	501: {func() string { return T.APIErrorNotImplemented }, "Not Implemented", LogError, ActionError, false, false, 0},
	502: {func() string { return T.APIErrorBadGateway }, "Gateway error", LogError, ActionRetry, true, false, ServerErrorRetryDelay},
	503: {func() string { return T.APIErrorServiceUnavailable }, "Service unavailable", LogError, ActionRetry, true, true, ServerErrorRetryDelay},
	504: {func() string { return T.APIErrorGatewayTimeout }, "Gateway timeout", LogError, ActionRetry, true, false, ServerErrorRetryDelay},
	507: {func() string { return T.APIErrorInsufficientStorage }, "Insufficient Storage", LogError, ActionRetry, true, false, ServerErrorRetryDelay},
	508: {func() string { return T.APIErrorLoopDetected }, "Loop Detected", LogError, ActionRetry, true, false, 0},
	511: {func() string { return T.APIErrorNetworkAuthenticationRequired }, "Network Authentication Required", LogError, ActionError, false, false, 0},
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
			tf(T.APIErrorServerErrorGeneric, "Server Error %d", statusCode),
			responseBody,
		)
		apiErr.Retryable = true
		apiErr.RetryAfter = ServerErrorRetryDelay
		return
	}

	apiErr.Message = withBody(
		tf(T.APIErrorClientErrorGeneric, "Client Error %d", statusCode),
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
