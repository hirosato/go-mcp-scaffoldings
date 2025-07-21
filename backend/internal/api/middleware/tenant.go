package middleware

import (
	"context"
	"log/slog"
	"strings"

	"github.com/aws/aws-lambda-go/events"

	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/domain/auth"
	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/domain/tenant"
)

// TenantContextKey is the key for the tenant context in the request context
type TenantContextKey string

const (
	// TenantContextKeyValue is the context key for tenant information
	TenantContextKeyValue TenantContextKey = "tenant"
)

// TenantMiddleware is a middleware for extracting and validating tenant information
type TenantMiddleware struct {
}

// NewTenantMiddleware creates a new tenant middleware
func NewTenantMiddleware() *TenantMiddleware {
	return &TenantMiddleware{}
}

// Handle handles the tenant middleware for Lambda functions
func (m *TenantMiddleware) Handle(next APIGatewayHandler) APIGatewayHandler {
	return func(ctx context.Context, logger *slog.Logger, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
		// Extract the claims from the context
		// claims, ok := ctx.Value(UserClaimsKeyValue).(*utils.CognitoClaims)
		// if !ok {
		// 	return response.AuthenticationError("user claims not found in context", request.RequestContext.RequestID), nil
		// }

		// // Get tenant ID from the claim
		// tenantID := claims.TenantID
		// userID := claims.Subject
		// role := claims.Role

		// If the X-Tenant-Id header is present, validate access to that tenant
		if headerTenantID := request.Headers["X-Tenant-Id"]; headerTenantID != "" {
			// if err := m.tenantService.ValidateTenantID(ctx, headerTenantID); err != nil {
			// 	return response.AuthorizationError("invalid tenant ID", request.RequestContext.RequestID), nil
			// }

			// Check if user has access to the tenant
			// hasAccess, err := m.tenantService.UserHasAccessToTenant(ctx, headerTenantID, userID)
			// if err != nil {
			// 	m.log.Error("Failed to validate tenant access", zap.Error(err), zap.String("tenantId", headerTenantID), zap.String("userId", userID))
			// 	return response.InternalError("failed to validate tenant access", err, request.RequestContext.RequestID), nil
			// }

			// if !hasAccess {
			// 	return response.AuthorizationError(fmt.Sprintf("user does not have access to tenant %s", headerTenantID), request.RequestContext.RequestID), nil
			// }

			// // Override the tenant ID from the token with the requested tenant ID
			// tenantID = headerTenantID
		}

		// Create tenant context
		tenantCtx := &tenant.TenantContext{
			TenantID: "test", //tenantID,
			UserID:   "test", // userID,
			// Role:     role,
			// TenantID   string
			// UserID     string
			// BookID     string
			// Role       string
			// IsAdmin    bool
			// IsOwner    bool
			// Permissions []string
			// Timestamp: claims.IssuedAt.Time,
		}

		// Add tenant context to the request context
		ctx = context.WithValue(ctx, TenantContextKeyValue, tenantCtx)

		// Call the next handler
		return next(ctx, logger, request)
	}
}

// // Middleware is the HTTP middleware function for tenant validation
// func (m *TenantMiddleware) Middleware(next http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		// Try to get user from context
// 		user, ok := r.Context().Value(UserContextKeyValue).(auth.User)
// 		if !ok {
// 			// Try to get from claims
// 			claims, ok := r.Context().Value(UserClaimsKeyValue).(*utils.CognitoClaims)
// 			if !ok {
// 				response.Error(w, http.StatusUnauthorized, "User not authenticated", nil)
// 				return
// 			}

// 			// Extract tenant ID from claims
// 			tenantID := claims.TenantID
// 			userID := claims.Subject
// 			role := claims.Role

// 			// If header tenant ID is present, override and validate
// 			if headerTenantID := r.Header.Get("X-Tenant-ID"); headerTenantID != "" {
// 				if err := m.tenantService.ValidateTenantID(r.Context(), headerTenantID); err != nil {
// 					response.Error(w, http.StatusBadRequest, "Invalid tenant ID", err)
// 					return
// 				}

// 				// Check if user has access to the tenant
// 				hasAccess, err := m.tenantService.UserHasAccessToTenant(r.Context(), headerTenantID, userID)
// 				if err != nil {
// 					m.log.Error("Failed to validate tenant access", zap.Error(err), zap.String("tenantId", headerTenantID), zap.String("userId", userID))
// 					response.Error(w, http.StatusInternalServerError, "Failed to validate tenant access", err)
// 					return
// 				}

// 				if !hasAccess {
// 					response.Error(w, http.StatusForbidden, fmt.Sprintf("User does not have access to tenant %s", headerTenantID), nil)
// 					return
// 				}

// 				tenantID = headerTenantID
// 			}

// 			// Create tenant context
// 			tenantCtx := &tenant.Context{
// 				TenantID:  tenantID,
// 				UserID:    userID,
// 				Role:      role,
// 				Timestamp: claims.IssuedAt.Time,
// 			}

// 			// Add tenant context to the request context
// 			ctx := context.WithValue(r.Context(), TenantContextKeyValue, tenantCtx)
// 			next.ServeHTTP(w, r.WithContext(ctx))
// 			return
// 		}

// 		// Extract tenant ID from user
// 		tenantID := extractTenantIDFromUser(user)
// 		userID := user.ID
// 		role := extractRoleFromUser(user)

// 		// If header tenant ID is present, override and validate
// 		if headerTenantID := r.Header.Get("X-Tenant-ID"); headerTenantID != "" {
// 			if err := m.tenantService.ValidateTenantID(r.Context(), headerTenantID); err != nil {
// 				response.Error(w, http.StatusBadRequest, "Invalid tenant ID", err)
// 				return
// 			}

// 			// Check if user has access to the tenant
// 			hasAccess, err := m.tenantService.UserHasAccessToTenant(r.Context(), headerTenantID, userID)
// 			if err != nil {
// 				m.log.Error("Failed to validate tenant access", zap.Error(err), zap.String("tenantId", headerTenantID), zap.String("userId", userID))
// 				response.Error(w, http.StatusInternalServerError, "Failed to validate tenant access", err)
// 				return
// 			}

// 			if !hasAccess {
// 				response.Error(w, http.StatusForbidden, fmt.Sprintf("User does not have access to tenant %s", headerTenantID), nil)
// 				return
// 			}

// 			tenantID = headerTenantID
// 		}

// 		// If no tenant ID was found, return an error
// 		if tenantID == "" {
// 			response.Error(w, http.StatusBadRequest, "Tenant ID is required", nil)
// 			return
// 		}

// 		// Create tenant context
// 		tenantCtx := &tenant.Context{
// 			TenantID:  tenantID,
// 			UserID:    userID,
// 			Role:      role,
// 			Timestamp: user.TokenMetadata.IssuedAt,
// 		}

// 		// Add tenant context to the request context
// 		ctx := context.WithValue(r.Context(), TenantContextKeyValue, tenantCtx)

// 		// Proceed with the request
// 		next.ServeHTTP(w, r.WithContext(ctx))
// 	})
// }

// GetTenantID gets the tenant ID from the request context
func GetTenantID(ctx context.Context) string {
	tenantCtx, ok := ctx.Value(TenantContextKeyValue).(*tenant.TenantContext)
	if !ok {
		return ""
	}
	return tenantCtx.TenantID
}

// GetTenantContext gets the tenant context from the request context
func GetTenantContext(ctx context.Context) (*tenant.TenantContext, bool) {
	tenantCtx, ok := ctx.Value(TenantContextKeyValue).(*tenant.TenantContext)
	return tenantCtx, ok
}

// extractTenantIDFromUser extracts tenant ID from user permissions and scopes
func extractTenantIDFromUser(user auth.User) string {
	// Extract tenant ID from user permissions
	// Format could be "tenant:<tenant-id>:read" or similar
	for _, perm := range user.Permissions {
		if strings.HasPrefix(perm, "tenant:") {
			parts := strings.Split(perm, ":")
			if len(parts) >= 2 {
				return parts[1]
			}
		}
	}

	// No tenant ID found in permissions, return empty string
	return ""
}

// extractRoleFromUser extracts role from user permissions
func extractRoleFromUser(user auth.User) string {
	// Extract role from user permissions
	// Format could be "role:admin" or similar
	for _, perm := range user.Permissions {
		if strings.HasPrefix(perm, "role:") {
			parts := strings.Split(perm, ":")
			if len(parts) >= 2 {
				return parts[1]
			}
		}
	}

	// No role found in permissions, return default role
	return "user"
}
