package client

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

// DynamoDBClient wraps the AWS DynamoDB client
type DynamoDBClient struct {
	client *dynamodb.Client
}

// NewDynamoDBClient creates a new DynamoDB client
func NewDynamoDBClient(ctx context.Context, region string) (*DynamoDBClient, error) {
	// Load AWS configuration
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, err
	}

	// Create DynamoDB client
	client := dynamodb.NewFromConfig(cfg)

	return &DynamoDBClient{
		client: client,
	}, nil
}

// GetItem implements the Client.GetItem method
func (c *DynamoDBClient) GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	return c.client.GetItem(ctx, params, optFns...)
}

// PutItem implements the Client.PutItem method
func (c *DynamoDBClient) PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	json, _ := json.Marshal(params)
	slog.Info("PutItem called", "params", params, "json", json)
	return c.client.PutItem(ctx, params, optFns...)
}

// UpdateItem implements the Client.UpdateItem method
func (c *DynamoDBClient) UpdateItem(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	return c.client.UpdateItem(ctx, params, optFns...)
}

// DeleteItem implements the Client.DeleteItem method
func (c *DynamoDBClient) DeleteItem(ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	return c.client.DeleteItem(ctx, params, optFns...)
}

// Query implements the Client.Query method
func (c *DynamoDBClient) Query(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	return c.client.Query(ctx, params, optFns...)
}

// Scan implements the Client.Scan method
func (c *DynamoDBClient) Scan(ctx context.Context, params *dynamodb.ScanInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error) {
	return c.client.Scan(ctx, params, optFns...)
}

// TransactWriteItems implements the Client.TransactWriteItems method
func (c *DynamoDBClient) TransactWriteItems(ctx context.Context, params *dynamodb.TransactWriteItemsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	return c.client.TransactWriteItems(ctx, params, optFns...)
}

// TransactGetItems implements the Client.TransactGetItems method
func (c *DynamoDBClient) TransactGetItems(ctx context.Context, params *dynamodb.TransactGetItemsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.TransactGetItemsOutput, error) {
	return c.client.TransactGetItems(ctx, params, optFns...)
}

// BatchWriteItem implements the Client.BatchWriteItem method
func (c *DynamoDBClient) BatchWriteItem(ctx context.Context, params *dynamodb.BatchWriteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.BatchWriteItemOutput, error) {
	return c.client.BatchWriteItem(ctx, params, optFns...)
}

// BatchGetItem implements the Client.BatchGetItem method
func (c *DynamoDBClient) BatchGetItem(ctx context.Context, params *dynamodb.BatchGetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.BatchGetItemOutput, error) {
	return c.client.BatchGetItem(ctx, params, optFns...)
}

// GetRawClient returns the underlying AWS DynamoDB client
func (c *DynamoDBClient) GetRawClient() *dynamodb.Client {
	return c.client
}
