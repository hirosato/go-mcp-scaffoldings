package cognito

import (
	"context"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/lestrrat-go/jwx/jwk"

	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/domain/auth"
)

// Config contains configuration for the Cognito service
type Config struct {
	UserPoolID      string
	ClientID        string
	Region          string
	CognitoEndpoint string
}

// OAuthApp represents an OAuth client application in Cognito
type OAuthApp struct {
	ClientID     string
	ClientSecret string
	RedirectURIs []string
	GrantTypes   []string
	Scopes       []string
}

// Service implements the auth.Service interface using AWS Cognito
type Service struct {
	cognitoClient *cognitoidentityprovider.Client
	repository    Repository
	userPoolID    string
	clientID      string
	jwksURL       string
	jwkSet        jwk.Set
	log           slog.Logger
	region        string
}

// Repository defines operations for storing and retrieving auth-related data
type Repository interface {
	// Define repository operations for auth data, specific to Cognito implementation
	GetUserByID(ctx context.Context, userID string) (auth.User, error)
	SaveUser(ctx context.Context, user auth.User) error
	GetAppByClientID(ctx context.Context, clientID string) (OAuthApp, error)
}
