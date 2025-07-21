package auth

import (
	"errors"
	"fmt"
)

// Standard error definitions for auth domain
var (
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrInvalidToken       = errors.New("invalid or expired token")
	ErrInvalidInput       = errors.New("invalid input")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrForbidden          = errors.New("forbidden")
)

// UserNotFoundError returns an error for when a user is not found
func UserNotFoundError(userID string) error {
	return fmt.Errorf("%w: user with ID %s not found", ErrUserNotFound, userID)
}

// InvalidCredentialsError returns an error for invalid credentials
func InvalidCredentialsError() error {
	return ErrInvalidCredentials
}

// UserExistsError returns an error for when a user already exists
func UserExistsError(email string) error {
	return fmt.Errorf("%w: user with email %s already exists", ErrUserAlreadyExists, email)
}

// InvalidTokenError returns an error for an invalid token
func InvalidTokenError() error {
	return ErrInvalidToken
}

// ValidationError returns an error for invalid input
func ValidationError(details string) error {
	return fmt.Errorf("%w: %s", ErrInvalidInput, details)
}

// UnauthorizedError returns an error for unauthorized access
func UnauthorizedError() error {
	return ErrUnauthorized
}

// ForbiddenError returns an error for forbidden access
func ForbiddenError() error {
	return ErrForbidden
}