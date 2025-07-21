package utils

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/domain/errors"
)

var (
	// EmailRegex validates email addresses
	EmailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

	// UUIDRegex validates UUID strings
	UUIDRegex = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`)

	// AccountPathRegex validates account paths
	AccountPathRegex = regexp.MustCompile(`^[a-zA-Z0-9]+(?::[a-zA-Z0-9_\-]+)*$`)

	// DateRegex validates ISO 8601 date strings (YYYY-MM-DD)
	DateRegex = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
)

// ValidateEmail validates an email address
func ValidateEmail(email string) error {
	if !EmailRegex.MatchString(email) {
		return errors.NewValidationError("invalid email format")
	}
	return nil
}

// ValidateUUID validates a UUID string
func ValidateUUID(uuid string) error {
	if !UUIDRegex.MatchString(uuid) {
		return errors.NewValidationError("invalid UUID format")
	}
	return nil
}

// ValidateAccountPath validates an account path
func ValidateAccountPath(path string) error {
	if !AccountPathRegex.MatchString(path) {
		return errors.NewValidationError("invalid account path format, should use format like 'assets:bank:checking'")
	}
	return nil
}

// ValidateISODate validates an ISO 8601 date string (YYYY-MM-DD)
func ValidateISODate(date string) error {
	if !DateRegex.MatchString(date) {
		return errors.NewValidationError("invalid date format, should be YYYY-MM-DD")
	}

	// Parse the date to ensure it's valid
	_, err := time.Parse("2006-01-02", date)
	if err != nil {
		return errors.NewValidationError("invalid date value")
	}

	return nil
}

// ValidateCurrency validates a currency code
func ValidateCurrency(currency string) error {
	// This is a simplified validation, in production you would use a comprehensive list
	// of currency codes or a currency library
	if len(currency) != 3 || !regexp.MustCompile(`^[A-Z]{3}$`).MatchString(currency) {
		return errors.NewValidationError("invalid currency code, should be a 3-letter code (e.g., USD)")
	}
	return nil
}

// ValidatePositiveInt validates that a string is a positive integer
func ValidatePositiveInt(value string) error {
	num, err := strconv.Atoi(value)
	if err != nil {
		return errors.NewValidationError("value must be a valid integer")
	}
	if num <= 0 {
		return errors.NewValidationError("value must be a positive integer")
	}
	return nil
}

// ValidateTenantID validates a tenant ID
func ValidateTenantID(tenantID string) error {
	if strings.TrimSpace(tenantID) == "" {
		return errors.NewTenantError("tenant ID is required")
	}
	return nil
}

// ValidateRequiredString validates that a string is not empty
func ValidateRequiredString(value, fieldName string) error {
	if strings.TrimSpace(value) == "" {
		return errors.NewValidationError(fieldName + " is required")
	}
	return nil
}
