package config

import (
	"errors"
	"os"
)

// Config represents the application configuration
// This struct contains all configuration parameters for the application
type Config struct {
	// AWS-specific configuration
	AWSRegion         string
	DynamoDBTableName string
	UserPoolID        string
	UserPoolClientID  string
	CognitoClientID   string // Alias for UserPoolClientID for backward compatibility

	// Environment and region info
	Environment string
	Region      string

	// SQLite configuration
	SQLiteBasePath string

	// Auth configuration
	AuthProvider string

	// Lambda detection flag (cached)
	isLambda bool

	// Only available for VPC attatched Lambda.
	SQLitePath string

	baseMcpURL string
	baseWebURL string
}

// LoadFromEnv loads the configuration from environment variables
func LoadFromEnv() (*Config, error) {
	// Create a new config object and load values from environment
	cfg := &Config{}

	// Required environment variables
	cfg.DynamoDBTableName = os.Getenv("DYNAMODB_TABLE_NAME")
	if cfg.DynamoDBTableName == "" {
		return nil, errors.New("DYNAMODB_TABLE_NAME environment variable is required")
	}

	cfg.UserPoolID = os.Getenv("USER_POOL_ID")
	if cfg.UserPoolID == "" {
		return nil, errors.New("USER_POOL_ID environment variable is required")
	}

	cfg.UserPoolClientID = os.Getenv("USER_POOL_CLIENT_ID")
	if cfg.UserPoolClientID == "" {
		return nil, errors.New("USER_POOL_CLIENT_ID environment variable is required")
	}

	// Environment and region info
	cfg.Environment = os.Getenv("ENVIRONMENT")
	if cfg.Environment == "" {
		cfg.Environment = "dev" // Default to dev environment
	}

	cfg.Region = os.Getenv("REGION")
	if cfg.Region == "" {
		cfg.Region = "jp"
	}

	// AWS Region
	cfg.AWSRegion = os.Getenv("AWS_REGION")
	if cfg.AWSRegion == "" {
		// Default AWS regions based on our region code
		switch cfg.Region {
		case "us":
			cfg.AWSRegion = "us-west-2"
		case "eu":
			cfg.AWSRegion = "eu-west-1"
		case "jp":
			cfg.AWSRegion = "ap-northeast-1"
		default:
			cfg.AWSRegion = "ap-northeast-1" // Default fallback
		}
	}

	// SQLite configuration
	cfg.SQLiteBasePath = os.Getenv("SQLITE_BASE_PATH")
	if cfg.SQLiteBasePath == "" {
		cfg.SQLiteBasePath = "/mnt/sqlite" // Default SQLite mount path
	}

	// Auth configuration
	cfg.AuthProvider = os.Getenv("AUTH_PROVIDER")
	if cfg.AuthProvider == "" {
		cfg.AuthProvider = "cognito" // Default to Cognito auth provider
	}

	// Set CognitoClientID for backward compatibility
	cfg.CognitoClientID = cfg.UserPoolClientID

	// Check if running in Lambda
	cfg.isLambda = os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != ""

	// Determine SQLite path based on environment
	cfg.SQLitePath = os.Getenv("SQLITE_PATH")
	if cfg.SQLitePath == "" {
		if cfg.isLambda {
			cfg.SQLitePath = "/mnt/efs/sqlite" // EFS mount point
		} else {
			cfg.SQLitePath = "./data/sqlite" // Local development path
		}
	}

	cfg.baseMcpURL = os.Getenv("BASE_MCP_URL")
	if cfg.baseMcpURL == "" {
		cfg.baseMcpURL = "https://mcp.myapp.io"
	}

	cfg.baseWebURL = os.Getenv("BASE_WEB_URL")
	if cfg.baseWebURL == "" {
		cfg.baseWebURL = "https://myapp.io"
	}

	return cfg, nil
}

func (c *Config) IsProd() bool {
	return c.Environment == "prod"
}

// IsLambda returns true if the application is running in AWS Lambda
func (c *Config) IsLambda() bool {
	return c.isLambda
}
