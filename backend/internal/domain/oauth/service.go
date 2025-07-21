package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Service handles OAuth 2.1 operations
type Service struct {
	clientRepo      ClientRepository
	codeRepo        AuthorizationCodeRepository
	tokenRepo       TokenRepository
	jwksRepo        JWKSRepository
	securityRepo    SecurityEventRepository
	authAttemptRepo AuthAttemptRepository
	baseMcpURL      string
	baseWebURL      string
	tokenTTL        time.Duration
	codeTTL         time.Duration
}

// NewService creates a new OAuth service
func NewService(
	clientRepo ClientRepository,
	codeRepo AuthorizationCodeRepository,
	tokenRepo TokenRepository,
	jwksRepo JWKSRepository,
	securityRepo SecurityEventRepository,
	authAttemptRepo AuthAttemptRepository,
) *Service {
	baseMcpURL := os.Getenv("BASE_MCP_URL")
	if baseMcpURL == "" {
		baseMcpURL = "https://mcp.myapp.io"
	}
	baseWebURL := os.Getenv("BASE_WEB_URL")
	if baseWebURL == "" {
		baseWebURL = "https://myapp.io"
	}

	return &Service{
		clientRepo:      clientRepo,
		codeRepo:        codeRepo,
		tokenRepo:       tokenRepo,
		jwksRepo:        jwksRepo,
		securityRepo:    securityRepo,
		authAttemptRepo: authAttemptRepo,
		baseMcpURL:      baseMcpURL,
		baseWebURL:      baseWebURL,
		tokenTTL:        time.Hour,
		codeTTL:         10 * time.Minute,
	}
}

// GetMetadata returns the OAuth 2.1 authorization server metadata
func (s *Service) GetMetadata(ctx context.Context) *AuthorizationServerMetadata {
	return &AuthorizationServerMetadata{
		Issuer:                            s.baseMcpURL,
		AuthorizationEndpoint:             s.baseWebURL + "/authorize",
		TokenEndpoint:                     s.baseMcpURL + "/oauth/token",
		RegistrationEndpoint:              s.baseMcpURL + "/oauth/register",
		JwksURI:                           s.baseMcpURL + "/.well-known/jwks.json",
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code", "client_credentials", "refresh_token"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post"},
		ScopesSupported:                   []string{"read", "write"},
		ClaimsSupported:                   []string{"sub", "iss", "aud", "exp", "iat", "jti", "client_id", "scope", "resource"},
		ServiceDocumentation:              s.baseMcpURL + "/docs/oauth",
		AuthorizationResponseIssParameterSupported: true,
		ResourceIndicatorsSupported:                true, // MCP OAuth support
	}
}

// GetProtectedResourceMetadata returns the OAuth 2.0 protected resource metadata (RFC9728)
func (s *Service) GetProtectedResourceMetadata(ctx context.Context) *ProtectedResourceMetadata {
	return &ProtectedResourceMetadata{
		Resource:               s.baseMcpURL,
		AuthorizationServers:   []string{s.baseMcpURL + "/.well-known/oauth-authorization-server"},
		BearerMethodsSupported: []string{"header"},
		ScopesSupported:        []string{"read", "write"},
		ResourceDocumentation:  s.baseWebURL + "/docs/api",
	}
}

// GenerateAuthorizationCode generates an authorization code after user authentication
// This is called by the backend after the frontend has authenticated the user
func (s *Service) GenerateAuthorizationCode(ctx context.Context, req *AuthorizeRequest, userID string) (string, error) {
	// Validate client
	client, err := s.clientRepo.GetClient(ctx, req.ClientID)
	if err != nil {
		return "", ErrInvalidClient
	}

	// Validate redirect URI
	if !s.isValidRedirectURI(client, req.RedirectURI) {
		return "", ErrInvalidRedirectURI
	}

	// Validate requested resources (MCP compliance)
	if err := s.validateResources(req.Resource); err != nil {
		return "", err
	}

	// Generate authorization code
	code := s.generateSecureToken(32)

	authCode := &AuthorizationCode{
		Code:                code,
		ClientID:            req.ClientID,
		UserID:              userID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		State:               req.State,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		Resource:            req.Resource,
		ExpiresAt:           time.Now().Add(s.codeTTL),
		CreatedAt:           time.Now(),
	}

	// Store authorization code
	if err := s.codeRepo.StoreAuthorizationCode(ctx, authCode); err != nil {
		return "", err
	}

	// Build redirect URL
	redirectURL := fmt.Sprintf("%s?code=%s", req.RedirectURI, code)
	if req.State != "" {
		redirectURL += "&state=" + req.State
	}
	redirectURL += "&iss=" + s.baseMcpURL // OAuth 2.1 requires iss parameter

	return redirectURL, nil
}

// Token handles the token endpoint
func (s *Service) Token(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	switch req.GrantType {
	case "authorization_code":
		return s.handleAuthorizationCodeGrant(ctx, req)
	case "client_credentials":
		return s.handleClientCredentialsGrant(ctx, req)
	case "refresh_token":
		return s.handleRefreshTokenGrant(ctx, req)
	default:
		return nil, ErrUnsupportedGrantType
	}
}

// RegisterClient handles client registration
func (s *Service) RegisterClient(ctx context.Context, req *ClientRegistrationRequest) (*ClientRegistrationResponse, error) {
	// Generate client credentials
	clientID := uuid.New().String()
	clientSecret := s.generateSecureToken(32)

	// Set default values
	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"authorization_code"}
	}
	if len(req.Scopes) == 0 {
		req.Scopes = []string{"openid", "profile", "email"}
	}
	if req.TokenEndpointAuthMethod == "" {
		req.TokenEndpointAuthMethod = "client_secret_post" // Default to POST method
	}

	// Hash the client secret before storing
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	client := &Client{
		ID:                          clientID,
		Secret:                      string(hashedSecret),
		Name:                        req.ClientName,
		RedirectURIs:                req.RedirectURIs,
		GrantTypes:                  req.GrantTypes,
		Scopes:                      req.Scopes,
		TokenEndpointAuthMethod:     req.TokenEndpointAuthMethod,
		TokenEndpointAuthSigningAlg: req.TokenEndpointAuthSigningAlg,
		FailedAuthCount:             0,
		CreatedAt:                   time.Now(),
		UpdatedAt:                   time.Now(),
	}

	// Store client
	if err := s.clientRepo.CreateClient(ctx, client); err != nil {
		return nil, err
	}

	return &ClientRegistrationResponse{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		ClientName:   client.Name,
		RedirectURIs: client.RedirectURIs,
		GrantTypes:   client.GrantTypes,
		Scopes:       client.Scopes,
	}, nil
}

// ValidateToken validates an access token
func (s *Service) ValidateToken(ctx context.Context, tokenString string) (*JWTClaims, error) {

	// Parse and validate JWT with custom claims
	type CustomClaims struct {
		jwt.RegisteredClaims
		Scope    string   `json:"scope,omitempty"`
		ClientID string   `json:"client_id,omitempty"`
		Resource []string `json:"resource,omitempty"`
	}

	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			slog.Error("unexpected signing method", "method", token.Header["alg"])
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Get signing key (PEM-encoded)
		signingKeyPEM, keyID, err := s.jwksRepo.GetSigningKey(ctx)
		if err != nil {
			slog.Error("s.jwksRepo.GetSigningKey", "error", err, "keyID", keyID)
			return nil, err
		}

		// Parse the PEM-encoded private key to get public key
		privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(signingKeyPEM)
		if err != nil {
			slog.Error("jwt.ParseRSAPrivateKeyFromPEM", "error", err, "keyPEM_length", len(signingKeyPEM))
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}

		// Return the public key for verification
		return &privateKey.PublicKey, nil
	})

	if err != nil {
		// Limit token prefix to avoid index out of range
		tokenPrefix := tokenString
		if len(tokenString) > 50 {
			tokenPrefix = tokenString[:50]
		}
		slog.Error("jwt.ParseWithClaims", "error", err, "tokenString_prefix", tokenPrefix)

		// Check specific JWT errors by string matching since errors.Is doesn't work with jwt errors
		errStr := err.Error()
		if strings.Contains(errStr, "signature is invalid") {
			slog.Error("Token signature verification failed", "error_detail", errStr)
		} else if strings.Contains(errStr, "token is malformed") {
			slog.Error("Token is malformed", "error_detail", errStr)
		} else if strings.Contains(errStr, "token is unverifiable") {
			slog.Error("Token is unverifiable", "error_detail", errStr)
		} else if strings.Contains(errStr, "token used before issued") {
			slog.Error("Token used before issued", "error_detail", errStr)
		} else if strings.Contains(errStr, "token is expired") {
			slog.Error("Token is expired", "error_detail", errStr)
		}

		return nil, ErrInvalidTokenFormat
	}

	customClaims, ok := token.Claims.(*CustomClaims)
	if !ok || !token.Valid {
		slog.Error("token.Claims.(*CustomClaims)", "ok", ok, "valid", token.Valid)
		return nil, ErrInvalidTokenFormat
	}

	// Convert audience to []string
	audience := []string{}
	if customClaims.Audience != nil {
		audience = customClaims.Audience
	}

	// Convert to JWTClaims
	claims := &JWTClaims{
		Subject:   customClaims.Subject,
		Issuer:    customClaims.Issuer,
		Audience:  audience,
		ExpiresAt: customClaims.ExpiresAt.Unix(),
		IssuedAt:  customClaims.IssuedAt.Unix(),
		JTI:       customClaims.ID,
		Scope:     customClaims.Scope,
		ClientID:  customClaims.ClientID,
		Resource:  customClaims.Resource,
	}

	// Check if token is revoked
	tokenData, err := s.tokenRepo.GetToken(ctx, claims.JTI)
	if err != nil {
		slog.Error("s.tokenRepo.GetToken", "error", err, "jti", claims.JTI)
		return nil, ErrTokenRevoked
	}
	if tokenData != nil && tokenData.RevokedAt != nil {
		slog.Error("Token is revoked", "jti", claims.JTI, "revokedAt", tokenData.RevokedAt)
		return nil, ErrTokenRevoked
	}

	// Validate issuer
	if claims.Issuer != s.baseMcpURL {
		slog.Error("Invalid issuer", "expected", s.baseMcpURL, "got", claims.Issuer)
		return nil, ErrInvalidTokenFormat
	}

	// Validate audience - must contain base URL
	hasValidAudience := false
	for _, aud := range claims.Audience {
		if aud == s.baseMcpURL {
			hasValidAudience = true
			break
		}
	}
	if !hasValidAudience {
		slog.Error("Invalid audience", "expected", s.baseMcpURL, "got", claims.Audience)
		return nil, ErrInvalidTokenFormat
	}

	return claims, nil
}

// RevokeToken revokes an access token
func (s *Service) RevokeToken(ctx context.Context, tokenID string) error {
	return s.tokenRepo.RevokeToken(ctx, tokenID)
}

// GetJWKS returns the JSON Web Key Set
func (s *Service) GetJWKS(ctx context.Context) (interface{}, error) {
	return s.jwksRepo.GetPublicKeySet(ctx)
}

// Private methods

func (s *Service) handleAuthorizationCodeGrant(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	// Retrieve authorization code
	authCode, err := s.codeRepo.GetAuthorizationCode(ctx, req.Code)
	if err != nil {
		return nil, err
	}

	// Check expiration
	if time.Now().After(authCode.ExpiresAt) {
		return nil, NewOAuthError(ErrCodeExpired, "Authorization code expired")
	}

	_, err = s.clientRepo.GetClient(ctx, req.ClientID)
	if err != nil {
		return nil, ErrInvalidClient
	}

	// Validate redirect URI
	if authCode.RedirectURI != req.RedirectURI {
		return nil, NewOAuthError(ErrInvalidGrant, "Redirect URI mismatch")
	}

	// Validate PKCE
	if !s.validatePKCE(authCode.CodeChallenge, req.CodeVerifier) {
		return nil, NewOAuthError(ErrInvalidPKCEVerifier, "PKCE verification failed")
	}

	// Delete authorization code (one-time use)
	if err := s.codeRepo.DeleteAuthorizationCode(ctx, req.Code); err != nil {
		// Log error but continue
		fmt.Printf("Failed to delete authorization code: %v\n", err)
	}

	// Generate tokens
	accessToken, tokenID, err := s.generateAccessToken(ctx, req.ClientID, authCode.Scope, authCode.UserID, authCode.Resource)
	if err != nil {
		// Log the actual error for debugging
		fmt.Printf("Failed to generate access token: %v\n", err)
		return nil, NewOAuthError(ErrServerError, "Failed to generate access token")
	}

	refreshToken := s.generateSecureToken(32)

	// Store tokens
	token := &Token{
		ID:        tokenID,
		TokenType: "access",
		ClientID:  req.ClientID,
		Scope:     authCode.Scope,
		ExpiresAt: time.Now().Add(s.tokenTTL),
		CreatedAt: time.Now(),
	}

	if err := s.tokenRepo.StoreToken(ctx, token); err != nil {
		return nil, err
	}

	// Store refresh token with proper indexing
	refreshTokenData := &Token{
		ID:           uuid.New().String(),
		TokenType:    "refresh",
		ClientID:     req.ClientID,
		Scope:        authCode.Scope,
		RefreshToken: refreshToken,                        // Store the refresh token value for GSI3 indexing
		ExpiresAt:    time.Now().Add(30 * 24 * time.Hour), // 30 days
		CreatedAt:    time.Now(),
	}

	if err := s.tokenRepo.StoreToken(ctx, refreshTokenData); err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.tokenTTL.Seconds()),
		RefreshToken: refreshToken,
		Scope:        authCode.Scope,
	}, nil
}

func (s *Service) handleClientCredentialsGrant(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	// Validate client
	if err := s.clientRepo.ValidateClientCredentials(ctx, req.ClientID, req.ClientSecret); err != nil {
		return nil, ErrInvalidClient
	}

	// Generate access token
	accessToken, tokenID, err := s.generateAccessToken(ctx, req.ClientID, req.Scope, "", req.Resource)
	if err != nil {
		// Log the actual error for debugging
		fmt.Printf("Failed to generate access token for client credentials: %v\n", err)
		return nil, NewOAuthError(ErrServerError, "Failed to generate access token")
	}

	// Store token
	token := &Token{
		ID:        tokenID,
		TokenType: "access",
		ClientID:  req.ClientID,
		Scope:     req.Scope,
		ExpiresAt: time.Now().Add(s.tokenTTL),
		CreatedAt: time.Now(),
	}

	if err := s.tokenRepo.StoreToken(ctx, token); err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(s.tokenTTL.Seconds()),
		Scope:       req.Scope,
	}, nil
}

func (s *Service) handleRefreshTokenGrant(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	// OAuth 2.1 requires client authentication for refresh token grant
	// Validate client credentials first
	client, err := s.clientRepo.GetClient(ctx, req.ClientID)
	if err != nil {
		return nil, ErrInvalidClient
	}

	// For confidential clients (those with a secret), authentication is required
	// Check if this is a confidential client by looking at the stored secret
	if client.Secret != "" {
		// Client authentication is required for confidential clients
		if req.ClientSecret == "" {
			return nil, NewOAuthError(ErrInvalidClient, "Client authentication required for refresh token grant")
		}

		// Validate client credentials
		if err := s.clientRepo.ValidateClientCredentials(ctx, req.ClientID, req.ClientSecret); err != nil {
			return nil, ErrInvalidClient
		}
	}

	// Retrieve refresh token
	refreshToken, err := s.tokenRepo.GetTokenByRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		return nil, err
	}

	// Check if revoked
	if refreshToken.RevokedAt != nil {
		return nil, ErrTokenRevoked
	}

	// Check expiration
	if time.Now().After(refreshToken.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	// Validate that the refresh token belongs to the authenticated client
	if refreshToken.ClientID != req.ClientID {
		return nil, NewOAuthError(ErrInvalidGrant, "Refresh token was issued to a different client")
	}

	// Generate new access token
	// For refresh tokens, use the original resource from the request if provided, otherwise use empty
	accessToken, tokenID, err := s.generateAccessToken(ctx, req.ClientID, refreshToken.Scope, refreshToken.UserID, req.Resource)
	if err != nil {
		// Log the actual error for debugging
		fmt.Printf("Failed to generate access token for refresh token: %v\n", err)
		return nil, NewOAuthError(ErrServerError, "Failed to generate access token")
	}

	// Store new token
	token := &Token{
		ID:        tokenID,
		TokenType: "access",
		ClientID:  req.ClientID,
		UserID:    refreshToken.UserID,
		Scope:     refreshToken.Scope,
		ExpiresAt: time.Now().Add(s.tokenTTL),
		CreatedAt: time.Now(),
	}

	if err := s.tokenRepo.StoreToken(ctx, token); err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(s.tokenTTL.Seconds()),
		Scope:       refreshToken.Scope,
	}, nil
}

func (s *Service) generateAccessToken(ctx context.Context, clientID, scope, userID string, resources []string) (string, string, error) {
	// Get signing key
	signingKeyPEM, keyID, err := s.jwksRepo.GetSigningKey(ctx)
	if err != nil {
		return "", "", err
	}

	// Parse the PEM-encoded private key
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(signingKeyPEM)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse private key: %w", err)
	}

	// Generate JWT ID
	jti := uuid.New().String()

	// Build audience list: always include base URL plus any requested resources
	audience := []string{s.baseMcpURL}
	if len(resources) > 0 {
		audience = append(audience, resources...)
	}

	// Create custom claims with jwt.RegisteredClaims
	type CustomClaims struct {
		jwt.RegisteredClaims
		Scope    string   `json:"scope,omitempty"`
		ClientID string   `json:"client_id,omitempty"`
		Resource []string `json:"resource,omitempty"`
	}

	claims := CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   clientID,
			Issuer:    s.baseMcpURL,
			Audience:  audience,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.tokenTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        jti,
		},
		Scope:    scope,
		ClientID: clientID,
		Resource: resources,
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID

	// Sign token
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", "", err
	}

	return tokenString, jti, nil
}

func (s *Service) validatePKCE(codeChallenge, codeVerifier string) bool {
	// Calculate challenge from verifier
	h := sha256.New()
	h.Write([]byte(codeVerifier))
	calculatedChallenge := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return calculatedChallenge == codeChallenge
}

func (s *Service) isValidRedirectURI(client *Client, redirectURI string) bool {
	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			return true
		}
	}
	return false
}

func (s *Service) generateSecureToken(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// validateResources validates the requested resources for MCP compliance
func (s *Service) validateResources(resources []string) error {
	// For now, we allow any resource to be requested
	// In a production system, you would validate against a list of allowed MCP servers
	// or check if the resources are registered in your system

	// Example validation:
	// for _, resource := range resources {
	//     if !s.isAllowedResource(resource) {
	//         return NewOAuthError("invalid_resource", fmt.Sprintf("Invalid resource: %s", resource))
	//     }
	// }

	return nil
}

// validateClientCredentialsWithLogging validates client credentials with security logging and rate limiting
func (s *Service) validateClientCredentialsWithLogging(ctx context.Context, clientID, clientSecret, ipAddress, userAgent string) error {
	// Check rate limiting first
	if err := s.checkRateLimit(ctx, clientID); err != nil {
		s.logAuthAttempt(ctx, clientID, ipAddress, userAgent, "rate_limited", false)
		return err
	}

	// Validate credentials
	err := s.clientRepo.ValidateClientCredentials(ctx, clientID, clientSecret)

	if err != nil {
		// Log failed attempt
		s.logAuthAttempt(ctx, clientID, ipAddress, userAgent, "invalid_credentials", false)
		s.logSecurityEvent(ctx, "auth_failure", clientID, "",
			fmt.Sprintf("Failed authentication for client %s", clientID),
			"medium", map[string]string{
				"ip_address": ipAddress,
				"user_agent": userAgent,
				"reason":     "invalid_credentials",
			})

		// Increment failed count
		s.clientRepo.IncrementFailedAuthCount(ctx, clientID)

		return ErrInvalidClient
	}

	// Success - log and reset failed count
	s.logAuthAttempt(ctx, clientID, ipAddress, userAgent, "success", true)
	s.logSecurityEvent(ctx, "auth_success", clientID, "",
		fmt.Sprintf("Successful authentication for client %s", clientID),
		"low", map[string]string{
			"ip_address": ipAddress,
			"user_agent": userAgent,
		})

	// Reset failed count on successful auth
	s.clientRepo.ResetFailedAuthCount(ctx, clientID)

	return nil
}

// Security logging helper methods

func (s *Service) logSecurityEvent(ctx context.Context, eventType, clientID, userID, message, severity string, metadata map[string]string) {
	if s.securityRepo == nil {
		return // Security logging is optional
	}

	event := &SecurityEvent{
		ID:        uuid.New().String(),
		EventType: eventType,
		ClientID:  clientID,
		UserID:    userID,
		Message:   message,
		Metadata:  metadata,
		Timestamp: time.Now(),
		Severity:  severity,
	}

	// Log asynchronously to avoid blocking main flow
	go func() {
		s.securityRepo.LogSecurityEvent(context.Background(), event)
	}()
}

func (s *Service) logAuthAttempt(ctx context.Context, clientID, ipAddress, userAgent, reason string, success bool) {
	if s.authAttemptRepo == nil {
		return // Auth attempt logging is optional
	}

	attempt := &AuthAttempt{
		ID:        uuid.New().String(),
		ClientID:  clientID,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Reason:    reason,
		Timestamp: time.Now(),
		Success:   success,
	}

	// Log asynchronously to avoid blocking main flow
	go func() {
		s.authAttemptRepo.LogAuthAttempt(context.Background(), attempt)
	}()
}

// Rate limiting constants
const (
	MaxFailedAttempts   = 5
	LockoutDuration     = 15 * time.Minute
	FailedAttemptWindow = 5 * time.Minute
)

func (s *Service) checkRateLimit(ctx context.Context, clientID string) error {
	// Check if client is currently locked
	client, err := s.clientRepo.GetClient(ctx, clientID)
	if err != nil {
		return err
	}

	if client.LockedUntil != nil && time.Now().Before(*client.LockedUntil) {
		s.logSecurityEvent(ctx, "auth_rate_limited", clientID, "",
			fmt.Sprintf("Client %s is locked until %v", clientID, client.LockedUntil),
			"medium", map[string]string{"reason": "rate_limited"})
		return NewOAuthError(ErrTemporarilyUnavailable, "Client is temporarily locked due to too many failed attempts")
	}

	// Check recent failed attempts
	since := time.Now().Add(-FailedAttemptWindow)
	failedCount, err := s.authAttemptRepo.GetFailedAttemptsCount(ctx, clientID, since)
	if err != nil {
		return err // Continue on error, don't block auth
	}

	if failedCount >= MaxFailedAttempts {
		// Lock the client
		lockUntil := time.Now().Add(LockoutDuration)
		s.clientRepo.LockClient(ctx, clientID, lockUntil)

		s.logSecurityEvent(ctx, "client_locked", clientID, "",
			fmt.Sprintf("Client %s locked due to %d failed attempts", clientID, failedCount),
			"high", map[string]string{
				"failed_attempts": fmt.Sprintf("%d", failedCount),
				"lock_duration":   LockoutDuration.String(),
			})

		return NewOAuthError(ErrTemporarilyUnavailable, "Client is temporarily locked due to too many failed attempts")
	}

	return nil
}
