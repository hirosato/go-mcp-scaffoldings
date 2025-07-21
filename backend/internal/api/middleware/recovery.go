package middleware

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"

	"github.com/aws/aws-lambda-go/events"
	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/api/response"
	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/domain/errors"
)

// RecoveryMiddleware is a middleware for recovering from panics
type RecoveryMiddleware struct{}

// NewRecoveryMiddleware creates a new recovery middleware
func NewRecoveryMiddleware() RecoveryMiddleware {
	return RecoveryMiddleware{}
}

// Handle handles the recovery middleware
func (m RecoveryMiddleware) Handle(next APIGatewayHandler) APIGatewayHandler {
	return func(ctx context.Context, logger *slog.Logger, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
		// Defer recovery function
		defer func() {
			if r := recover(); r != nil {
				// Log the panic
				stack := debug.Stack()
				fmt.Printf("[PANIC] %v\n%s\n", r, stack)
			}
		}()

		// Try to handle the request
		resp, err := next(ctx, logger, request)

		// Check if there was an error
		if err != nil {
			// Convert the error to an AppError if it's not already
			var appErr errors.AppError
			if e, ok := err.(errors.AppError); ok {
				appErr = e
			} else {
				// Create a generic internal error
				appErr = errors.NewInternalError("An unexpected error occurred", err)
			}

			// Log the error
			fmt.Printf("[ERROR] %s: %v\n", appErr.Code, appErr.Error())

			// Return the error response
			return response.Error(appErr, request.RequestContext.RequestID), nil
		}

		// Return the response
		return resp, nil
	}
}
