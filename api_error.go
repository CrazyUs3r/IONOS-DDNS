package main

import "fmt"

// ============================================================================
// API ERROR HANDLING
// ============================================================================

func (e *APIError) Error() string {
	return fmt.Sprintf("API Error [%s %s]: Status %d - %s", e.Method, e.URL, e.StatusCode, e.Message)
}

func (e *APIError) IsRetryable() bool {
	return e.Retryable
}

func classifyAPIError(statusCode int, method, url, responseBody string) *APIError {
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
	case 401:
		apiErr.Message = T.Unauthorized
		log(LogContext{Level: LogError, Action: ActionConfig, Message: T.Unauthorized})
	case 403:
		apiErr.Message = T.Forbidden
	case 404:
		apiErr.Message = T.NotFound
	case 422:
		apiErr.Message = T.UnprocessableEntity
	case 429:
		apiErr.Message = T.RateLimitExceeded
		apiErr.Retryable = true
		apiErr.RetryAfter = RateLimitRetryDelay
		log(LogContext{Level: LogWarn, Action: ActionRetry, Message: "⚠️ " + T.RateLimitExceeded})
	case 500:
		apiErr.Message = T.InternalServerError
		apiErr.Retryable = true
	case 502:
		apiErr.Message = T.BadGateway
		apiErr.Retryable = true
	case 503:
		apiErr.Message = T.ServiceUnavailable
		apiErr.Retryable = true
		apiErr.RetryAfter = ServerErrorRetryDelay
	case 504:
		apiErr.Message = T.GatewayTimeout
		apiErr.Retryable = true
	default:
		if statusCode >= 500 {
			apiErr.Message = fmt.Sprintf("Server Error %d", statusCode)
			apiErr.Retryable = true
		} else {
			apiErr.Message = fmt.Sprintf("Client Error %d", statusCode)
			apiErr.Retryable = false
		}
	}

	return apiErr
}
