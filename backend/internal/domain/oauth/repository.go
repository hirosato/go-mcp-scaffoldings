package oauth

import (
	"context"
	"time"
)

// ClientRepository defines the interface for OAuth client storage
type ClientRepository interface {
	// CreateClient creates a new OAuth client
	CreateClient(ctx context.Context, client *Client) error

	// GetClient retrieves a client by ID
	GetClient(ctx context.Context, clientID string) (*Client, error)

	// UpdateClient updates an existing client
	UpdateClient(ctx context.Context, client *Client) error

	// DeleteClient deletes a client
	DeleteClient(ctx context.Context, clientID string) error

	// ValidateClientCredentials validates client ID and secret
	ValidateClientCredentials(ctx context.Context, clientID, clientSecret string) error

	// IncrementFailedAuthCount increments the failed authentication count
	IncrementFailedAuthCount(ctx context.Context, clientID string) error

	// ResetFailedAuthCount resets the failed authentication count
	ResetFailedAuthCount(ctx context.Context, clientID string) error

	// LockClient temporarily locks a client due to too many failed attempts
	LockClient(ctx context.Context, clientID string, lockUntil time.Time) error
}

// AuthorizationCodeRepository defines the interface for authorization code storage
type AuthorizationCodeRepository interface {
	// StoreAuthorizationCode stores a new authorization code
	StoreAuthorizationCode(ctx context.Context, code *AuthorizationCode) error

	// GetAuthorizationCode retrieves an authorization code
	GetAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error)

	// DeleteAuthorizationCode deletes an authorization code (one-time use)
	DeleteAuthorizationCode(ctx context.Context, code string) error

	// CleanupExpiredCodes removes expired authorization codes
	CleanupExpiredCodes(ctx context.Context) error
}

// TokenRepository defines the interface for token storage
type TokenRepository interface {
	// StoreToken stores a new access or refresh token
	StoreToken(ctx context.Context, token *Token) error

	// GetToken retrieves a token by ID
	GetToken(ctx context.Context, tokenID string) (*Token, error)

	// GetTokenByRefreshToken retrieves a token by refresh token
	GetTokenByRefreshToken(ctx context.Context, refreshToken string) (*Token, error)

	// RevokeToken revokes a token
	RevokeToken(ctx context.Context, tokenID string) error

	// RevokeTokensByClientID revokes all tokens for a client
	RevokeTokensByClientID(ctx context.Context, clientID string) error

	// RevokeTokensByUserID revokes all tokens for a user
	RevokeTokensByUserID(ctx context.Context, userID string) error

	// CleanupExpiredTokens removes expired tokens
	CleanupExpiredTokens(ctx context.Context) error

	// GetActiveTokensByClientID retrieves all active tokens for a client
	GetActiveTokensByClientID(ctx context.Context, clientID string) ([]*Token, error)
}

// JWKSRepository defines the interface for JSON Web Key Set storage
type JWKSRepository interface {
	// GetSigningKey retrieves the current signing key
	GetSigningKey(ctx context.Context) ([]byte, string, error) // returns key, keyID, error

	// RotateSigningKey rotates the signing key
	RotateSigningKey(ctx context.Context) error

	// GetPublicKeySet retrieves the public key set for JWKS endpoint
	GetPublicKeySet(ctx context.Context) (interface{}, error)
}

// SecurityEventRepository defines the interface for security audit logging
type SecurityEventRepository interface {
	// LogSecurityEvent logs a security event
	LogSecurityEvent(ctx context.Context, event *SecurityEvent) error

	// GetSecurityEvents retrieves security events with filtering
	GetSecurityEvents(ctx context.Context, clientID string, eventType string, limit int) ([]*SecurityEvent, error)

	// GetSecurityEventsByTimeRange retrieves security events within a time range
	GetSecurityEventsByTimeRange(ctx context.Context, start, end time.Time, limit int) ([]*SecurityEvent, error)
}

// AuthAttemptRepository defines the interface for authentication attempt tracking
type AuthAttemptRepository interface {
	// LogAuthAttempt logs an authentication attempt
	LogAuthAttempt(ctx context.Context, attempt *AuthAttempt) error

	// GetRecentFailedAttempts gets recent failed attempts for a client
	GetRecentFailedAttempts(ctx context.Context, clientID string, since time.Time) ([]*AuthAttempt, error)

	// GetFailedAttemptsCount gets count of failed attempts for a client in time window
	GetFailedAttemptsCount(ctx context.Context, clientID string, since time.Time) (int, error)

	// CleanupOldAttempts removes old authentication attempt records
	CleanupOldAttempts(ctx context.Context, before time.Time) error
}
