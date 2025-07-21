package middleware

import (
	"go.uber.org/zap"

	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/common/config"
	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/common/utils"
	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/domain/auth"
)

// UserClaimsKey is the key for the user claims in the request context
type UserClaimsKey string

// UserContextKey is the key for the user object in the request context
type UserContextKey string

const (
	// UserClaimsKeyValue is the context key for user claims
	UserClaimsKeyValue UserClaimsKey = "userClaims"
	// UserContextKeyValue is the context key for user object
	UserContextKeyValue UserContextKey = "user"
)

// AuthMiddleware is a middleware for JWT authentication
type AuthMiddleware struct {
	cfg         *config.Config
	authService auth.Service
	jwksURL     string
	tokenIssuer string
	log         *zap.Logger
}

// NewAuthMiddleware creates a new auth middleware
func NewAuthMiddleware(cfg *config.Config, authService auth.Service, log *zap.Logger) AuthMiddleware {
	return AuthMiddleware{
		cfg:         cfg,
		authService: authService,
		jwksURL:     utils.BuildJWKSURL(cfg.UserPoolID, cfg.AWSRegion),
		tokenIssuer: utils.GetTokenIssuer(cfg.UserPoolID, cfg.AWSRegion),
		log:         log,
	}
}

// // Handle handles the auth middleware
// func (m AuthMiddleware) Handle(next APIGatewayHandler) APIGatewayHandler {
// 	return func(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
// 		// Check for public paths that don't require authentication
// 		if isPublicPath(request.Resource, request.HTTPMethod) {
// 			return next(ctx, request)
// 		}

// 		// Extract the Authorization header
// 		authHeader := request.Headers["Authorization"]
// 		if authHeader == "" {
// 			return response.AuthenticationError("authorization header is required", request.RequestContext.RequestID), nil
// 		}

// 		// Extract the token from the Authorization header
// 		token, err := extractBearerToken(authHeader)
// 		if err != nil {
// 			return response.AuthenticationError(err.Error(), request.RequestContext.RequestID), nil
// 		}

// 		// Use auth service to validate token if available
// 		if m.authService != nil {
// 			user, err := m.authService.ValidateToken(ctx, token)
// 			if err != nil {
// 				m.log.Warn("Token validation failed", zap.Error(err))
// 				return response.AuthenticationError("invalid or expired token", request.RequestContext.RequestID), nil
// 			}

// 			// Add the user to the context
// 			ctx = context.WithValue(ctx, UserContextKeyValue, user)

// 			// For backwards compatibility, create and add claims
// 			claims := &utils.CognitoClaims{
// 				RegisteredClaims: jwt.RegisteredClaims{
// 					Subject: user.ID,
// 					Issuer:  m.tokenIssuer,
// 				},
// 				Email:    user.Email,
// 				TenantID: extractTenantIDFromUser(user),
// 				Role:     extractRoleFromUser(user),
// 			}

// 			ctx = context.WithValue(ctx, UserClaimsKeyValue, claims)
// 		} else {
// 			// Fallback to JWT parsing for backwards compatibility
// 			claims, err := utils.ParseJWT(token, m.getKeyFunc())
// 			if err != nil {
// 				return response.AuthenticationError("invalid token: "+err.Error(), request.RequestContext.RequestID), nil
// 			}

// 			// Validate the token issuer
// 			if claims.Issuer != m.tokenIssuer {
// 				return response.AuthenticationError("invalid token issuer", request.RequestContext.RequestID), nil
// 			}

// 			// Add the claims to the context
// 			ctx = context.WithValue(ctx, UserClaimsKeyValue, claims)
// 		}

// 		// Call the next handler
// 		return next(ctx, request)
// 	}
// }

// Middleware is the HTTP middleware function for authentication (for regular HTTP handlers)
// func (m AuthMiddleware) Middleware(next http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		// Check for public paths that don't require authentication
// 		if isPublicPathHTTP(r.URL.Path, r.Method) {
// 			next.ServeHTTP(w, r)
// 			return
// 		}

// 		// Extract token from Authorization header
// 		authHeader := r.Header.Get("Authorization")
// 		if authHeader == "" {
// 			response.Error(w, http.StatusUnauthorized, "Authorization header is required", nil)
// 			return
// 		}

// 		// Check if the header has the Bearer prefix
// 		token, err := extractBearerToken(authHeader)
// 		if err != nil {
// 			response.Error(w, http.StatusUnauthorized, err.Error(), nil)
// 			return
// 		}

// 		// Use auth service to validate token
// 		user, err := m.authService.ValidateToken(r.Context(), token)
// 		if err != nil {
// 			m.log.Warn("Token validation failed", zap.Error(err))
// 			response.Error(w, http.StatusUnauthorized, "Invalid or expired token", nil)
// 			return
// 		}

// 		// Store user in context
// 		ctx := context.WithValue(r.Context(), UserContextKeyValue, user)

// 		// For backwards compatibility, create and add claims
// 		claims := &utils.CognitoClaims{
// 			RegisteredClaims: jwt.RegisteredClaims{
// 				Subject: user.ID,
// 				Issuer:  m.tokenIssuer,
// 			},
// 			Email:    user.Email,
// 			TenantID: extractTenantIDFromUser(user),
// 			Role:     extractRoleFromUser(user),
// 		}

// 		ctx = context.WithValue(ctx, UserClaimsKeyValue, claims)

// 		// Proceed with the request
// 		next.ServeHTTP(w, r.WithContext(ctx))
// 	})
// }

// // RequireScopes creates middleware that requires specific scopes
// func (m AuthMiddleware) RequireScopes(scopes ...string) func(http.Handler) http.Handler {
// 	return func(next http.Handler) http.Handler {
// 		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 			// Get user from context
// 			user, ok := r.Context().Value(UserContextKeyValue).(auth.User)
// 			if !ok {
// 				response.Error(w, http.StatusUnauthorized, "User not authenticated", nil)
// 				return
// 			}

// 			// Check if user has required scopes
// 			if !hasAllScopes(user.Scopes, scopes) {
// 				m.log.Warn("Insufficient scopes", zap.Strings("required", scopes), zap.Strings("provided", user.Scopes))
// 				response.Error(w, http.StatusForbidden, "Insufficient permissions", nil)
// 				return
// 			}

// 			// Proceed with the request
// 			next.ServeHTTP(w, r)
// 		})
// 	}
// }

// // RequirePermissions creates middleware that requires specific permissions
// func (m AuthMiddleware) RequirePermissions(permissions ...string) func(http.Handler) http.Handler {
// 	return func(next http.Handler) http.Handler {
// 		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 			// Get user from context
// 			user, ok := r.Context().Value(UserContextKeyValue).(auth.User)
// 			if !ok {
// 				response.Error(w, http.StatusUnauthorized, "User not authenticated", nil)
// 				return
// 			}

// 			// Check if user has required permissions
// 			if !hasAnyPermission(user.Permissions, permissions) {
// 				m.log.Warn("Insufficient permissions", zap.Strings("required", permissions), zap.Strings("provided", user.Permissions))
// 				response.Error(w, http.StatusForbidden, "Insufficient permissions", nil)
// 				return
// 			}

// 			// Proceed with the request
// 			next.ServeHTTP(w, r)
// 		})
// 	}
// }

// // GetUser gets the user from the request context
// func GetUser(ctx context.Context) (auth.User, bool) {
// 	user, ok := ctx.Value(UserContextKeyValue).(auth.User)
// 	return user, ok
// }

// // GetUserID gets the user ID from the request context
// func GetUserID(ctx context.Context) string {
// 	user, ok := ctx.Value(UserContextKeyValue).(auth.User)
// 	if !ok {
// 		// Try to get from claims for backwards compatibility
// 		if claims, ok := ctx.Value(UserClaimsKeyValue).(*utils.CognitoClaims); ok {
// 			return claims.Subject
// 		}
// 		return ""
// 	}
// 	return user.ID
// }

// // getKeyFunc returns a function that retrieves the key for JWT validation
// func (m AuthMiddleware) getKeyFunc() jwt.Keyfunc {
// 	return func(token *jwt.Token) (interface{}, error) {
// 		// Validate the token algorithm
// 		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
// 			return nil, errors.New("unexpected signing method: " + token.Header["alg"].(string))
// 		}

// 		// Get the key ID from the token header
// 		kid, ok := token.Header["kid"].(string)
// 		if !ok {
// 			return nil, errors.New("key ID not found in token header")
// 		}

// 		// In a real implementation, you would get the key from JWKS
// 		// Here we're using a placeholder implementation
// 		return []byte("mock-key"), nil
// 	}
// }

// // isPublicPath checks if the path is public (doesn't require authentication)
// func isPublicPath(path string, method string) bool {
// 	// List of public paths
// 	publicPaths := map[string][]string{
// 		"/auth/register": {"POST"},
// 		"/auth/login":    {"POST"},
// 		"/auth/refresh":  {"POST"},
// 		"/health":        {"GET"},
// 	}

// 	// Check if the path exists in the public paths map
// 	if methods, ok := publicPaths[path]; ok {
// 		// Check if the method is allowed for this path
// 		for _, allowedMethod := range methods {
// 			if allowedMethod == method {
// 				return true
// 			}
// 		}
// 	}

// 	// Check for OPTIONS requests (CORS preflight)
// 	if method == "OPTIONS" {
// 		return true
// 	}

// 	return false
// }

// // isPublicPathHTTP checks if the HTTP path is public (doesn't require authentication)
// func isPublicPathHTTP(path string, method string) bool {
// 	// List of public paths
// 	publicPaths := map[string][]string{
// 		"/api/auth/register": {"POST"},
// 		"/api/auth/login":    {"POST"},
// 		"/api/auth/refresh":  {"POST"},
// 		"/api/health":        {"GET"},
// 	}

// 	// Check if the path exists in the public paths map
// 	if methods, ok := publicPaths[path]; ok {
// 		// Check if the method is allowed for this path
// 		for _, allowedMethod := range methods {
// 			if allowedMethod == method {
// 				return true
// 			}
// 		}
// 	}

// 	// Check for OPTIONS requests (CORS preflight)
// 	if method == "OPTIONS" {
// 		return true
// 	}

// 	return false
// }

// // extractBearerToken extracts the token from a bearer authorization header
// func extractBearerToken(authHeader string) (string, error) {
// 	// Check if the header has the Bearer prefix
// 	parts := strings.Split(authHeader, " ")
// 	if len(parts) != 2 || parts[0] != "Bearer" {
// 		return "", errors.New("authorization header must be in the format 'Bearer {token}'")
// 	}
// 	return parts[1], nil
// }

// // hasAllScopes checks if the provided scopes contain all required scopes
// func hasAllScopes(providedScopes, requiredScopes []string) bool {
// 	if len(requiredScopes) == 0 {
// 		return true
// 	}

// 	scopeMap := make(map[string]bool)
// 	for _, scope := range providedScopes {
// 		scopeMap[scope] = true
// 	}

// 	for _, required := range requiredScopes {
// 		if !scopeMap[required] {
// 			return false
// 		}
// 	}

// 	return true
// }

// // hasAnyPermission checks if the provided permissions contain any of the required permissions
// func hasAnyPermission(providedPermissions, requiredPermissions []string) bool {
// 	if len(requiredPermissions) == 0 {
// 		return true
// 	}

// 	permMap := make(map[string]bool)
// 	for _, perm := range providedPermissions {
// 		permMap[perm] = true
// 	}

// 	for _, required := range requiredPermissions {
// 		if permMap[required] {
// 			return true
// 		}
// 	}

// 	return false
// }
