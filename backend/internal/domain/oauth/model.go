package oauth

import (
	"time"
)

// Client represents an OAuth 2.1 client application
type Client struct {
	ID                          string     `json:"client_id"`
	Secret                      string     `json:"client_secret,omitempty"`
	Name                        string     `json:"client_name"`
	RedirectURIs                []string   `json:"redirect_uris"`
	GrantTypes                  []string   `json:"grant_types"`
	Scopes                      []string   `json:"scopes"`
	TokenEndpointAuthMethod     string     `json:"token_endpoint_auth_method"`                // "client_secret_basic", "client_secret_post", "none"
	TokenEndpointAuthSigningAlg string     `json:"token_endpoint_auth_signing_alg,omitempty"` // For JWT auth methods
	FailedAuthCount             int        `json:"failed_auth_count"`
	LastFailedAuthAt            *time.Time `json:"last_failed_auth_at,omitempty"`
	LockedUntil                 *time.Time `json:"locked_until,omitempty"`
	CreatedAt                   time.Time  `json:"created_at"`
	UpdatedAt                   time.Time  `json:"updated_at"`
}

// AuthorizationCode represents a temporary authorization code
type AuthorizationCode struct {
	Code                string    `json:"code"`
	ClientID            string    `json:"client_id"`
	UserID              string    `json:"user_id"` // Added to track the authenticated user
	RedirectURI         string    `json:"redirect_uri"`
	Scope               string    `json:"scope"`
	State               string    `json:"state,omitempty"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	Resource            []string  `json:"resource,omitempty"` // MCP OAuth resource indicator
	ExpiresAt           time.Time `json:"expires_at"`
	CreatedAt           time.Time `json:"created_at"`
}

// Token represents an OAuth access token or refresh token
type Token struct {
	ID           string     `json:"jti"`
	TokenType    string     `json:"token_type"` // "access" or "refresh"
	ClientID     string     `json:"client_id"`
	UserID       string     `json:"user_id,omitempty"`
	Scope        string     `json:"scope"`
	RefreshToken string     `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time  `json:"expires_at"`
	CreatedAt    time.Time  `json:"created_at"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
}

// AuthorizationServerMetadata represents the OAuth 2.1 server metadata
type AuthorizationServerMetadata struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	RegistrationEndpoint                       string   `json:"registration_endpoint"`
	JwksURI                                    string   `json:"jwks_uri"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	ScopesSupported                            []string `json:"scopes_supported"`
	ClaimsSupported                            []string `json:"claims_supported"`
	ServiceDocumentation                       string   `json:"service_documentation,omitempty"`
	AuthorizationResponseIssParameterSupported bool     `json:"authorization_response_iss_parameter_supported"`
	ResourceIndicatorsSupported                bool     `json:"resource_indicators_supported"` // MCP OAuth support
}

// ProtectedResourceMetadata represents the OAuth 2.0 protected resource metadata (RFC9728)
type ProtectedResourceMetadata struct {
	Resource                  string   `json:"resource"`
	AuthorizationServers      []string `json:"authorization_servers"`
	BearerMethodsSupported    []string `json:"bearer_methods_supported,omitempty"`
	ResourceSigningAlgValues  []string `json:"resource_signing_alg_values_supported,omitempty"`
	ResourceDocumentation     string   `json:"resource_documentation,omitempty"`
	ResourcePolicyURI         string   `json:"resource_policy_uri,omitempty"`
	ResourceTermsOfServiceURI string   `json:"resource_terms_of_service_uri,omitempty"`
	ScopesSupported           []string `json:"scopes_supported"`
}

// TokenRequest represents a token endpoint request
type TokenRequest struct {
	GrantType    string   `json:"grant_type"`
	Code         string   `json:"code,omitempty"`
	RedirectURI  string   `json:"redirect_uri,omitempty"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret,omitempty"`
	CodeVerifier string   `json:"code_verifier,omitempty"`
	RefreshToken string   `json:"refresh_token,omitempty"`
	Scope        string   `json:"scope,omitempty"`
	Resource     []string `json:"resource,omitempty"` // MCP OAuth resource indicator
}

// TokenResponse represents a token endpoint response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// AuthorizeRequest represents an authorization endpoint request
type AuthorizeRequest struct {
	ResponseType        string   `json:"response_type"`
	ClientID            string   `json:"client_id"`
	RedirectURI         string   `json:"redirect_uri"`
	Scope               string   `json:"scope,omitempty"`
	State               string   `json:"state,omitempty"`
	CodeChallenge       string   `json:"code_challenge"`
	CodeChallengeMethod string   `json:"code_challenge_method"`
	Resource            []string `json:"resource,omitempty"` // MCP OAuth resource indicator
}

// ClientRegistrationRequest represents a client registration request
type ClientRegistrationRequest struct {
	ClientName                  string   `json:"client_name"`
	RedirectURIs                []string `json:"redirect_uris"`
	GrantTypes                  []string `json:"grant_types,omitempty"`
	Scopes                      []string `json:"scopes,omitempty"`
	TokenEndpointAuthMethod     string   `json:"token_endpoint_auth_method,omitempty"`
	TokenEndpointAuthSigningAlg string   `json:"token_endpoint_auth_signing_alg,omitempty"`
}

// ClientRegistrationResponse represents a client registration response
type ClientRegistrationResponse struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	ClientName   string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
	GrantTypes   []string `json:"grant_types"`
	Scopes       []string `json:"scopes"`
}

// JWTClaims represents the claims in an OAuth JWT
type JWTClaims struct {
	Subject   string   `json:"sub"`
	Issuer    string   `json:"iss"`
	Audience  []string `json:"aud"` // Changed to array for MCP compliance
	ExpiresAt int64    `json:"exp"`
	IssuedAt  int64    `json:"iat"`
	JTI       string   `json:"jti"`
	Scope     string   `json:"scope,omitempty"`
	ClientID  string   `json:"client_id,omitempty"`
	Resource  []string `json:"resource,omitempty"` // MCP OAuth resource claim
}

// SecurityEvent represents a security audit log entry
type SecurityEvent struct {
	ID        string            `json:"id"`
	EventType string            `json:"event_type"` // "auth_success", "auth_failure", "token_issued", "token_revoked", etc.
	ClientID  string            `json:"client_id,omitempty"`
	UserID    string            `json:"user_id,omitempty"`
	IPAddress string            `json:"ip_address,omitempty"`
	UserAgent string            `json:"user_agent,omitempty"`
	Message   string            `json:"message"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
	Severity  string            `json:"severity"` // "low", "medium", "high", "critical"
}

// AuthAttempt represents a failed authentication attempt
type AuthAttempt struct {
	ID        string    `json:"id"`
	ClientID  string    `json:"client_id"`
	IPAddress string    `json:"ip_address,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	Reason    string    `json:"reason"` // "invalid_secret", "invalid_client", "rate_limited", etc.
	Timestamp time.Time `json:"timestamp"`
	Success   bool      `json:"success"`
}
