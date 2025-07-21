package dynamodb

import (
	"context"
	"fmt"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/common/config"
)

// DynamoDBAPI defines the interface for DynamoDB operations
type DynamoDBAPI interface {
	// GetItem retrieves a single item from DynamoDB
	GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)

	// PutItem puts a single item into DynamoDB
	PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)

	// UpdateItem updates a single item in DynamoDB
	UpdateItem(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)

	// DeleteItem deletes a single item from DynamoDB
	DeleteItem(ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)

	// Query executes a query against a table or index
	Query(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)

	// Scan scans an entire table or index
	Scan(ctx context.Context, params *dynamodb.ScanInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error)

	// TransactWriteItems performs a transaction to write multiple items
	TransactWriteItems(ctx context.Context, params *dynamodb.TransactWriteItemsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error)

	// TransactGetItems performs a transaction to get multiple items
	TransactGetItems(ctx context.Context, params *dynamodb.TransactGetItemsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.TransactGetItemsOutput, error)

	// BatchWriteItem writes multiple items across multiple tables
	BatchWriteItem(ctx context.Context, params *dynamodb.BatchWriteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.BatchWriteItemOutput, error)

	// BatchGetItem gets multiple items across multiple tables
	BatchGetItem(ctx context.Context, params *dynamodb.BatchGetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.BatchGetItemOutput, error)
}

// Client is a wrapper for the DynamoDB client
type Client struct {
	api DynamoDBAPI
}

// NewClient creates a new DynamoDB client
func NewClient(ctx context.Context, cfg *config.Config) (*Client, error) {
	// Load AWS configuration
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(cfg.AWSRegion),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS configuration: %w", err)
	}

	// Create DynamoDB client
	api := dynamodb.NewFromConfig(awsCfg)

	return &Client{
		api: api,
	}, nil
}

// GetAPI returns the DynamoDB API client
func (c *Client) GetAPI() DynamoDBAPI {
	return c.api
}
