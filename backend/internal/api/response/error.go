package response

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/domain/errors"
)

// ErrorResponse represents an error response
type ErrorResponse struct {
	Success          bool             `json:"success"`
	Error            string           `json:"error"`
	ErrorDescription ErrorDescription `json:"error_description"`
	Metadata         ResponseMetadata `json:"metadata"`
}

// ErrorDescription represents the error details
type ErrorDescription struct {
	Message string                 `json:"message"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// Error sends an error response with the specified status code, message, and error details
func ErrorWithStatusAndMessage(w http.ResponseWriter, status int, message string, err error) {
	// Create error response
	resp := ErrorResponse{
		Success: false,
		Error:   strconv.Itoa(status),
		ErrorDescription: ErrorDescription{
			Message: message,
			Details: nil,
		},
		Metadata: ResponseMetadata{
			Version:   "1.0",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			RequestID: "",
		},
	}

	// Set content type and status code
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	// Write response
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		// If we can't encode the error response, fall back to a simple error
		http.Error(w, message, status)
	}
}

// Error creates an error response
func Error(appErr errors.AppError, requestID string) events.APIGatewayProxyResponse {
	// Create the response body
	response := ErrorResponse{
		Success: false,
		Error:   appErr.Code,
		ErrorDescription: ErrorDescription{
			Message: appErr.Message,
			Details: appErr.Details,
		},
		Metadata: ResponseMetadata{
			Version:   "1.0",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			RequestID: requestID,
		},
	}

	// Convert the response to JSON
	body, err := json.Marshal(response)
	if err != nil {
		// Fallback for JSON marshaling errors
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusInternalServerError,
			Body:       `{"success":false,"error":"INTERNAL_ERROR","error_description":{"message":"Failed to marshal error response"}}`,
			Headers:    DefaultHeaders(),
		}
	}

	return events.APIGatewayProxyResponse{
		StatusCode: appErr.StatusCode,
		Body:       string(body),
		Headers:    DefaultHeaders(),
	}
}

// ValidationError creates a validation error response
func ValidationError(message string, requestID string) events.APIGatewayProxyResponse {
	return Error(errors.NewValidationError(message), requestID)
}

// NotFound creates a not found error response
func NotFound(message string) events.APIGatewayProxyResponse {
	return Error(errors.NewNotFoundError(message), "")
}

// InternalError creates an internal error response
func InternalError(message string, err error, requestID string) events.APIGatewayProxyResponse {
	// Log the error for internal debugging
	fmt.Printf("Internal error: %s: %v\n", message, err)

	// Return a generic error message to the client
	return Error(errors.NewInternalError(message, err), requestID)
}

// AuthenticationError creates an authentication error response
func AuthenticationError(message string, requestID string) events.APIGatewayProxyResponse {
	return Error(errors.NewAuthenticationError(message), requestID)
}

// AuthenticationErrorWithWWWAuthenticate creates an authentication error response with WWW-Authenticate header
func AuthenticationErrorWithWWWAuthenticate(message string, requestID string) events.APIGatewayProxyResponse {
	resp := Error(errors.NewAuthenticationError(message), requestID)

	// Add WWW-Authenticate header
	if resp.Headers == nil {
		resp.Headers = make(map[string]string)
	}

	// Include the authorization server URL in the WWW-Authenticate header
	authServerURL := os.Getenv("BASE_URL")
	if authServerURL == "" {
		authServerURL = "https://api.myapp.io"
	}

	// Format: Bearer realm="<realm>", authorization_uri="<auth_server_url>/.well-known/oauth-protected-resource"
	resp.Headers["WWW-Authenticate"] = fmt.Sprintf(`Bearer authorization_uri="%s/.well-known/oauth-protected-resource"`, authServerURL)

	return resp
}

// AuthorizationError creates an authorization error response
func AuthorizationError(message string, requestID string) events.APIGatewayProxyResponse {
	return Error(errors.NewAuthorizationError(message), requestID)
}

// ConflictError creates a conflict error response
func ConflictError(message string, requestID string) events.APIGatewayProxyResponse {
	return Error(errors.NewConflictError(message), requestID)
}

// TenantError creates a tenant-related error response
func TenantError(message string, requestID string) events.APIGatewayProxyResponse {
	return Error(errors.NewTenantError(message), requestID)
}

// BadRequest creates a bad request error response
func BadRequest(message string, requestID string) events.APIGatewayProxyResponse {
	return Error(errors.NewValidationError(message), requestID)
}

func Unauthorized(message string, requestID string) events.APIGatewayProxyResponse {
	return Error(errors.NewAuthorizationError(message), requestID)
}

// WriteError writes an error response to an HTTP response writer
func WriteError(w http.ResponseWriter, err error) {
	statusCode := http.StatusInternalServerError
	errorCode := "INTERNAL_ERROR"
	message := "An unexpected error occurred"
	details := make(map[string]interface{})

	// Convert to AppError if possible
	if appErr, ok := err.(errors.AppError); ok {
		statusCode = appErr.StatusCode
		errorCode = appErr.Code
		message = appErr.Message
		details = appErr.Details
	} else {
		// For non-AppError, use the error message
		message = err.Error()
	}

	// Create the response body
	response := ErrorResponse{
		Success: false,
		Error:   errorCode,
		ErrorDescription: ErrorDescription{
			Message: message,
			Details: details,
		},
		Metadata: ResponseMetadata{
			Version:   "1.0",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	}

	// Set headers and write response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

// ErrBadRequest creates a bad request error
func ErrBadRequest(message string) errors.AppError {
	return errors.NewValidationError(message)
}
