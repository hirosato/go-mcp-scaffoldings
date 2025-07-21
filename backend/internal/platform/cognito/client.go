package cognito

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"

	appConfig "github.com/hirosato/go-mcp-scaffoldings/backend/internal/common/config"
)

// NewClient creates a new AWS Cognito client
func NewClient(cfg *appConfig.Config) (*cognitoidentityprovider.Client, error) {
	// Load AWS configuration
	awsCfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(cfg.AWSRegion),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS configuration: %w", err)
	}

	// Create Cognito client
	client := cognitoidentityprovider.NewFromConfig(awsCfg)

	return client, nil
}
