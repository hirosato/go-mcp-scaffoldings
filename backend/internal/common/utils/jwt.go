package utils

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// CognitoClaims represents the claims in a Cognito JWT token
type CognitoClaims struct {
	jwt.RegisteredClaims
	Username string `json:"username"`
	Email    string `json:"email"`
	TenantID string `json:"custom:tenantId"`
	// Role        string   `json:"custom:role"`
	Scopes   []string `json:"scope"`
	TokenUse string   `json:"token_use"`
	ClientID string   `json:"client_id"`
	Version  int      `json:"version"`
	JTI      string   `json:"jti"`
	Origin   string   `json:"origin_jti"`
}

// ParseJWT parses a JWT token and validates it
func ParseJWT(tokenString string, keyFunc jwt.Keyfunc) (*CognitoClaims, error) {
	// Parse the token
	token, err := jwt.ParseWithClaims(tokenString, &CognitoClaims{}, keyFunc)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Check if the token is valid
	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	// Extract the claims
	claims, ok := token.Claims.(*CognitoClaims)
	if !ok {
		return nil, errors.New("invalid claims type")
	}

	// Validate the claims
	if claims.ExpiresAt.Time.Before(time.Now().UTC()) {
		return nil, errors.New("token has expired")
	}

	return claims, nil
}

// ExtractBearerToken extracts the token from the Authorization header
func ExtractBearerToken(authHeader string) (string, error) {
	if authHeader == "" {
		return "", errors.New("authorization header is required")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", errors.New("authorization header format must be: Bearer {token}")
	}

	return parts[1], nil
}

// GetTokenIssuer constructs the token issuer URL from the Cognito user pool ID
func GetTokenIssuer(userPoolID string, region string) string {
	return fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", region, userPoolID)
}

// BuildJWKSURL constructs the JWKS URL from the Cognito user pool ID
func BuildJWKSURL(userPoolID string, region string) string {
	return fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", region, userPoolID)
}

// HasScope checks if the token has the required scope
func HasScope(claims *CognitoClaims, requiredScope string) bool {
	for _, scope := range claims.Scopes {
		if scope == requiredScope {
			return true
		}
	}
	return false
}

// HasAnyScope checks if the token has any of the required scopes
func HasAnyScope(claims *CognitoClaims, requiredScopes []string) bool {
	for _, requiredScope := range requiredScopes {
		if HasScope(claims, requiredScope) {
			return true
		}
	}
	return false
}

// HasAllScopes checks if the token has all of the required scopes
func HasAllScopes(claims *CognitoClaims, requiredScopes []string) bool {
	for _, requiredScope := range requiredScopes {
		if !HasScope(claims, requiredScope) {
			return false
		}
	}
	return true
}
