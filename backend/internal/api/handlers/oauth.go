package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/api/response"
	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/common/config"
	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/domain/oauth"
)

// OAuthHandler handles OAuth 2.1 endpoints
type OAuthHandler struct {
	service *oauth.Service
	config  *config.Config
}

// NewOAuthHandler creates a new OAuth handler
func NewOAuthHandler(service *oauth.Service) *OAuthHandler {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		panic(err)
	}
	return &OAuthHandler{
		service: service,
		config:  cfg,
	}
}
func (h *OAuthHandler) GetRoot(ctx context.Context, logger *slog.Logger, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Get token from Authorization header
	authHeader := request.Headers["Authorization"]
	if authHeader == "" {
		authHeader = request.Headers["authorization"]
	}

	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return response.AuthenticationErrorWithWWWAuthenticate("Missing or invalid Authorization header", request.RequestContext.RequestID), nil
	}

	// POSTでこれが来る, Accept:application/json で返す。
	/**
	{
		"method": "initialize",
		"params": {
			"protocolVersion": "2024-11-05",
			"capabilities": {},
			"clientInfo": {
				"name": "claude-ai",
				"version": "0.1.0"
			}
		},
		"jsonrpc": "2.0",
		"id": 0
	}
	*/

	return response.InternalError("root is just for returning www-authentication information", nil, request.RequestContext.RequestID), nil
}

// GetMetadata handles GET /.well-known/oauth-authorization-server
func (h *OAuthHandler) GetMetadata(ctx context.Context, logger *slog.Logger, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	metadata := h.service.GetMetadata(ctx)
	return response.JSON(http.StatusOK, metadata, request.RequestContext.RequestID), nil
}

// GetProtectedResourceMetadata handles GET /.well-known/oauth-protected-resource
func (h *OAuthHandler) GetProtectedResourceMetadata(ctx context.Context, logger *slog.Logger, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	metadata := h.service.GetProtectedResourceMetadata(ctx)
	return response.JSON(http.StatusOK, metadata, request.RequestContext.RequestID), nil
}

// Token handles POST /oauth/token
func (h *OAuthHandler) Token(ctx context.Context, logger *slog.Logger, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Parse request body
	var req oauth.TokenRequest

	contentType := request.Headers["Content-Type"]
	if contentType == "" {
		contentType = request.Headers["content-type"]
	}

	if strings.Contains(contentType, "application/json") {
		if err := json.Unmarshal([]byte(request.Body), &req); err != nil {
			return response.BadRequest("Invalid JSON body", request.RequestContext.RequestID), nil
		}
	} else {
		// Handle form-urlencoded
		values, err := url.ParseQuery(request.Body)
		if err != nil {
			return response.BadRequest("Invalid form data", request.RequestContext.RequestID), nil
		}
		req = oauth.TokenRequest{
			GrantType:    values.Get("grant_type"),
			Code:         values.Get("code"),
			RedirectURI:  values.Get("redirect_uri"),
			ClientID:     values.Get("client_id"),
			ClientSecret: values.Get("client_secret"),
			CodeVerifier: values.Get("code_verifier"),
			RefreshToken: values.Get("refresh_token"),
			Scope:        values.Get("scope"),
			Resource:     values["resource"], // Handle multiple resource values
		}
	}

	// Check for Basic Auth in case client credentials are in header
	// OAuth 2.1 requires client authentication for confidential clients
	// Client credentials can be provided via:
	// 1. Basic Authentication header (preferred)
	// 2. client_id and client_secret in request body
	authHeader := request.Headers["Authorization"]
	if authHeader == "" {
		authHeader = request.Headers["authorization"]
	}
	if authHeader != "" && strings.HasPrefix(authHeader, "Basic ") {
		clientID, clientSecret := parseBasicAuth(authHeader)
		if clientID != "" && req.ClientID == "" {
			req.ClientID = clientID
			req.ClientSecret = clientSecret
		}
	}

	// Process token request
	tokenResp, err := h.service.Token(ctx, &req)
	if err != nil {
		oauthErr, ok := err.(*oauth.OAuthError)
		if ok {
			// Return OAuth error response
			errorResp := map[string]string{
				"error": oauthErr.ErrorCode,
			}
			if oauthErr.ErrorDescription != "" {
				errorResp["error_description"] = oauthErr.ErrorDescription
			}
			return response.JSON(http.StatusBadRequest, errorResp, request.RequestContext.RequestID), nil
		}
		return response.BadRequest(err.Error(), request.RequestContext.RequestID), nil
	}

	return response.JSON(http.StatusOK, tokenResp, request.RequestContext.RequestID), nil
}

// Register handles POST /oauth/register
func (h *OAuthHandler) Register(ctx context.Context, logger *slog.Logger, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Parse request body
	var req oauth.ClientRegistrationRequest
	if err := json.Unmarshal([]byte(request.Body), &req); err != nil {
		return response.BadRequest("Invalid request body", request.RequestContext.RequestID), err
	}

	// Validate required fields
	if req.ClientName == "" || len(req.RedirectURIs) == 0 {
		return response.BadRequest("Missing required fields", request.RequestContext.RequestID), nil
	}

	// Process registration
	clientResp, err := h.service.RegisterClient(ctx, &req)
	if err != nil {
		return response.InternalError("Failed to register client", err, request.RequestContext.RequestID), nil
	}

	return response.RawCreated(clientResp, request.RequestContext.RequestID), nil
}

// GenerateCode handles POST /oauth/authorize/callback
// This endpoint is called by the frontend after user authentication
func (h *OAuthHandler) GenerateCode(ctx context.Context, logger *slog.Logger, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Extract user ID from Cognito claims
	userID := ""
	if claims, ok := request.RequestContext.Authorizer["claims"].(map[string]interface{}); ok {
		if sub, exists := claims["sub"].(string); exists {
			userID = sub
		}
	}

	if userID == "" {
		return response.BadRequest("User not authenticated or missing user ID", request.RequestContext.RequestID), nil
	}

	// Parse request body (no user_id needed - extracted from JWT)
	var req oauth.AuthorizeRequest

	if err := json.Unmarshal([]byte(request.Body), &req); err != nil {
		return response.BadRequest("Invalid request body", request.RequestContext.RequestID), nil
	}

	// Generate authorization code
	redirectURL, err := h.service.GenerateAuthorizationCode(ctx, &req, userID)
	if err != nil {
		// For authorization endpoint errors, return them in a structured format
		oauthErr, ok := err.(*oauth.OAuthError)
		if ok {
			return response.JSON(http.StatusBadRequest, map[string]string{
				"error":             oauthErr.ErrorCode,
				"error_description": oauthErr.ErrorDescription,
			}, request.RequestContext.RequestID), nil
		}
		return response.BadRequest(err.Error(), request.RequestContext.RequestID), nil
	}

	// Return the redirect URL for the frontend to use
	return response.JSON(http.StatusOK, map[string]string{
		"redirect_url": redirectURL,
	}, request.RequestContext.RequestID), nil
}

// GetJWKS handles GET /.well-known/jwks.json
func (h *OAuthHandler) GetJWKS(ctx context.Context, logger *slog.Logger, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	jwks, err := h.service.GetJWKS(ctx)
	if err != nil {
		return response.InternalError("Failed to get JWKS", err, request.RequestContext.RequestID), nil
	}

	// Build response with cache headers
	resp := response.JSON(http.StatusOK, jwks, request.RequestContext.RequestID)
	if resp.Headers == nil {
		resp.Headers = make(map[string]string)
	}
	resp.Headers["Cache-Control"] = "public, max-age=3600"

	return resp, nil
}

// ValidateToken validates an OAuth token (for internal use)
func (h *OAuthHandler) ValidateToken(ctx context.Context, logger *slog.Logger, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Get token from Authorization header
	authHeader := request.Headers["Authorization"]
	if authHeader == "" {
		authHeader = request.Headers["authorization"]
	}

	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return response.AuthenticationErrorWithWWWAuthenticate("Missing or invalid Authorization header", request.RequestContext.RequestID), nil
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")

	if !h.config.IsProd() {
		slog.Info("Token Body", "token", token, "authorizer header", authHeader)
	}

	// Validate token
	claims, err := h.service.ValidateToken(ctx, token)
	if err != nil {
		return response.AuthenticationErrorWithWWWAuthenticate(err.Error(), request.RequestContext.RequestID), nil
	}

	return response.JSON(http.StatusOK, claims, request.RequestContext.RequestID), nil
}

// Private helper functions

func parseBasicAuth(auth string) (string, string) {
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || parts[0] != "Basic" {
		return "", ""
	}

	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ""
	}

	credentials := strings.SplitN(string(decoded), ":", 2)
	if len(credentials) != 2 {
		return "", ""
	}

	return credentials[0], credentials[1]
}
