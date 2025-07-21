package auth

import (
	"log/slog"

	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/common/config"
	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/domain/auth"
)

// ProviderType represents the type of auth provider
type ProviderType string

const (
	// ProviderCognito represents AWS Cognito auth provider
	ProviderCognito ProviderType = "cognito"
	// ProviderMock represents a mock auth provider for testing
	ProviderMock ProviderType = "mock"
)

// NewService creates a new auth service based on the provider type
func NewService(cfg *config.Config, log slog.Logger) (auth.Service, error) {
	// Default to Cognito provider
	providerType := ProviderCognito
	if cfg.AuthProvider != "" {
		providerType = ProviderType(cfg.AuthProvider)
	}

	switch providerType {
	case ProviderCognito:
		return newMockService(log)
		// return newCognitoService(cfg, log)
	case ProviderMock:
		return newMockService(log)
	default:
		return newMockService(log)
		// return newCognitoService(cfg, log)
	}
}

// // newCognitoService creates a new Cognito auth service
// func newCognitoService(cfg *config.Config, log logger.Logger) (auth.Service, error) {
// 	// Create Cognito client
// 	cognitoClient, err := cognito.NewClient(cfg)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Create DynamoDB client for repository
// 	dynamoClient, err := client.NewDynamoDBClient(*cfg)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Create repository
// 	repository := cognito.NewDynamoRepository(dynamoClient, log)

// 	// Create service
// 	return cognito.NewService(cognitoClient, repository, cfg), nil
// }

// newMockService creates a new mock auth service for testing
func newMockService(log slog.Logger) (auth.Service, error) {
	// In a real implementation, this would create a mock service
	// For now, we'll return nil
	return nil, nil
}
