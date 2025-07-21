package errors

import (
	"fmt"
	"net/http"
)

// AppError is a custom error type for application errors
type AppError struct {
	Code       string
	Message    string
	StatusCode int // Same rule as HTTP status codes
	Err        error
	Details    map[string]interface{}
}

// Error returns a string representation of the error
func (e AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Is implements the errors.Is interface
func (e AppError) Is(target error) bool {
	if target, ok := target.(AppError); ok {
		return target.Code == e.Code
	}
	return false
}

// Unwrap returns the underlying error
func (e AppError) Unwrap() error {
	return e.Err
}

// WithDetails adds details to the error
func (e AppError) WithDetails(details map[string]interface{}) AppError {
	e.Details = details
	return e
}

// WithDetail adds a single detail to the error
func (e AppError) WithDetail(key string, value interface{}) AppError {
	if e.Details == nil {
		e.Details = make(map[string]interface{})
	}
	e.Details[key] = value
	return e
}

// NewValidationError creates a new validation error
func NewValidationError(message string) AppError {
	return AppError{
		Code:       "VALIDATION_ERROR",
		Message:    message,
		StatusCode: http.StatusBadRequest,
	}
}

// NewInvalidInputError creates a new invalid input error
func NewInvalidInputError(message string, err error) AppError {
	return AppError{
		Code:       "INVALID_INPUT",
		Message:    message,
		StatusCode: http.StatusBadRequest,
		Err:        err,
	}
}

// NewAuthenticationError creates a new authentication error
func NewAuthenticationError(message string) AppError {
	return AppError{
		Code:       "AUTHENTICATION_ERROR",
		Message:    message,
		StatusCode: http.StatusUnauthorized,
	}
}

// NewAuthorizationError creates a new authorization error
func NewAuthorizationError(message string) AppError {
	return AppError{
		Code:       "AUTHORIZATION_ERROR",
		Message:    message,
		StatusCode: http.StatusForbidden,
	}
}

// NewNotFoundError creates a new not found error
func NewNotFoundError(message string) AppError {
	return AppError{
		Code:       "NOT_FOUND",
		Message:    message,
		StatusCode: http.StatusNotFound,
	}
}

// NewConflictError creates a new conflict error
func NewConflictError(message string) AppError {
	return AppError{
		Code:       "CONFLICT",
		Message:    message,
		StatusCode: http.StatusConflict,
	}
}

// NewInternalError creates a new internal error
func NewInternalError(message string, err error) AppError {
	return AppError{
		Code:       "INTERNAL_ERROR",
		Message:    message,
		StatusCode: http.StatusInternalServerError,
		Err:        err,
	}
}

// NewTenantError creates a new tenant-related error
func NewTenantError(message string) AppError {
	return AppError{
		Code:       "TENANT_ERROR",
		Message:    message,
		StatusCode: http.StatusBadRequest,
	}
}
