package middleware

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/aws/aws-lambda-go/events"
)

// LoggingMiddleware is a middleware for logging requests and responses
type LoggingMiddleware struct{}

// NewLoggingMiddleware creates a new logging middleware
func NewLoggingMiddleware() LoggingMiddleware {
	return LoggingMiddleware{}
}

// Handle handles the logging middleware
func (m LoggingMiddleware) Handle(next APIGatewayHandler) APIGatewayHandler {
	return func(ctx context.Context, logger *slog.Logger, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
		// Start time
		startTime := time.Now()

		// Log the request
		logRequest(request, logger)

		// Call the next handler
		response, err := next(ctx, logger, request)

		// Log the response
		logResponse(response, err, time.Since(startTime), logger)

		// Return the response
		return response, err
	}
}

// logRequest logs the request
func logRequest(request events.APIGatewayProxyRequest, logger *slog.Logger) {
	// Mask sensitive data
	maskedHeaders := maskSensitiveHeaders(request.Headers)

	logger.Info("REQUEST",
		"method", request.HTTPMethod,
		"path", request.Path,
		"requestId", request.RequestContext.RequestID,
		"queryParameters", request.QueryStringParameters,
		"headers", maskedHeaders)

	// Log the request body (if not empty)
	if request.Body != "" {
		// Try to parse the body as JSON for pretty printing
		var body interface{}
		if err := json.Unmarshal([]byte(request.Body), &body); err == nil {
			if bodyJSON, err := json.MarshalIndent(body, "", "  "); err == nil {
				logger.Info("REQUEST", "Body", string(bodyJSON))
			} else {
				logger.Info("REQUEST", "Body", request.Body)
			}
		} else {
			logger.Info("REQUEST", "Body", request.Body)
		}
	}
}

// logResponse logs the response
func logResponse(response events.APIGatewayProxyResponse, err error, duration time.Duration, logger *slog.Logger) {
	// Log the error if any
	if err != nil {
		logger.Info("ERROR", "error", err)
	}

	// Log the response
	logger.Info("RESPONSE",
		"status", response.StatusCode,
		"duration", duration,
	)

	// Log the response body (if not empty)
	if response.Body != "" {
		// Try to parse the body as JSON for pretty printing
		var body interface{}
		if err := json.Unmarshal([]byte(response.Body), &body); err == nil {
			if bodyJSON, err := json.MarshalIndent(body, "", "  "); err == nil {
				logger.Info("RESPONSE", "Body", string(bodyJSON))
			} else {
				logger.Info("RESPONSE", "Body", response.Body)
			}
		} else {
			logger.Info("RESPONSE", "Body", response.Body)
		}
	}
}

// maskSensitiveHeaders masks sensitive headers
func maskSensitiveHeaders(headers map[string]string) map[string]string {
	// Create a copy of the headers
	maskedHeaders := make(map[string]string, len(headers))
	for k, v := range headers {
		maskedHeaders[k] = v
	}

	// List of headers to mask
	sensitiveHeaders := []string{
		"Authorization",
		"X-Api-Key",
		"Cookie",
	}

	// Mask sensitive headers
	for _, header := range sensitiveHeaders {
		if _, ok := maskedHeaders[header]; ok {
			maskedHeaders[header] = "***"
		}
	}

	return maskedHeaders
}
