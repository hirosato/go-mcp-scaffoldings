package oauth

import "errors"

var (
	// OAuth 2.1 standard errors
	ErrInvalidRequest          = errors.New("invalid_request")
	ErrInvalidClient           = errors.New("invalid_client")
	ErrInvalidGrant            = errors.New("invalid_grant")
	ErrUnauthorizedClient      = errors.New("unauthorized_client")
	ErrUnsupportedGrantType    = errors.New("unsupported_grant_type")
	ErrInvalidScope            = errors.New("invalid_scope")
	ErrAccessDenied            = errors.New("access_denied")
	ErrUnsupportedResponseType = errors.New("unsupported_response_type")
	ErrServerError             = errors.New("server_error")
	ErrTemporarilyUnavailable  = errors.New("temporarily_unavailable")

	// Additional errors
	ErrPKCERequired         = errors.New("pkce_required")
	ErrInvalidPKCEVerifier  = errors.New("invalid_pkce_verifier")
	ErrInvalidRedirectURI   = errors.New("invalid_redirect_uri")
	ErrCodeExpired          = errors.New("authorization_code_expired")
	ErrTokenExpired         = errors.New("token_expired")
	ErrTokenRevoked         = errors.New("token_revoked")
	ErrClientNotFound       = errors.New("client_not_found")
	ErrInvalidTokenFormat   = errors.New("invalid_token_format")
	ErrInvalidCodeChallenge = errors.New("invalid_code_challenge")
)

// OAuthError represents an OAuth 2.1 error response
type OAuthError struct {
	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

// Error implements the error interface
func (e *OAuthError) Error() string {
	if e.ErrorDescription != "" {
		return e.ErrorCode + ": " + e.ErrorDescription
	}
	return e.ErrorCode
}

// NewOAuthError creates a new OAuth error with description
func NewOAuthError(err error, description string) *OAuthError {
	return &OAuthError{
		ErrorCode:        err.Error(),
		ErrorDescription: description,
	}
}