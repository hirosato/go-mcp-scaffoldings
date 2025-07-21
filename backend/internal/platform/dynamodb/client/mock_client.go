package client

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

// MockDynamoDBClient is a mock implementation of the Client interface for testing
type MockDynamoDBClient struct {
	GetItemFn            func(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItemFn            func(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	UpdateItemFn         func(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
	DeleteItemFn         func(ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
	QueryFn              func(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)
	ScanFn               func(ctx context.Context, params *dynamodb.ScanInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error)
	TransactWriteItemsFn func(ctx context.Context, params *dynamodb.TransactWriteItemsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error)
	TransactGetItemsFn   func(ctx context.Context, params *dynamodb.TransactGetItemsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.TransactGetItemsOutput, error)
	BatchWriteItemFn     func(ctx context.Context, params *dynamodb.BatchWriteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.BatchWriteItemOutput, error)
	BatchGetItemFn       func(ctx context.Context, params *dynamodb.BatchGetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.BatchGetItemOutput, error)
}

// NewMockDynamoDBClient creates a new mock DynamoDB client
func NewMockDynamoDBClient() *MockDynamoDBClient {
	return &MockDynamoDBClient{}
}

// GetItem implements the Client.GetItem method
func (m *MockDynamoDBClient) GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	if m.GetItemFn != nil {
		return m.GetItemFn(ctx, params, optFns...)
	}
	return &dynamodb.GetItemOutput{}, nil
}

// PutItem implements the Client.PutItem method
func (m *MockDynamoDBClient) PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	if m.PutItemFn != nil {
		return m.PutItemFn(ctx, params, optFns...)
	}
	return &dynamodb.PutItemOutput{}, nil
}

// UpdateItem implements the Client.UpdateItem method
func (m *MockDynamoDBClient) UpdateItem(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	if m.UpdateItemFn != nil {
		return m.UpdateItemFn(ctx, params, optFns...)
	}
	return &dynamodb.UpdateItemOutput{}, nil
}

// DeleteItem implements the Client.DeleteItem method
func (m *MockDynamoDBClient) DeleteItem(ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	if m.DeleteItemFn != nil {
		return m.DeleteItemFn(ctx, params, optFns...)
	}
	return &dynamodb.DeleteItemOutput{}, nil
}

// Query implements the Client.Query method
func (m *MockDynamoDBClient) Query(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	if m.QueryFn != nil {
		return m.QueryFn(ctx, params, optFns...)
	}
	return &dynamodb.QueryOutput{}, nil
}

// Scan implements the Client.Scan method
func (m *MockDynamoDBClient) Scan(ctx context.Context, params *dynamodb.ScanInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error) {
	if m.ScanFn != nil {
		return m.ScanFn(ctx, params, optFns...)
	}
	return &dynamodb.ScanOutput{}, nil
}

// TransactWriteItems implements the Client.TransactWriteItems method
func (m *MockDynamoDBClient) TransactWriteItems(ctx context.Context, params *dynamodb.TransactWriteItemsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	if m.TransactWriteItemsFn != nil {
		return m.TransactWriteItemsFn(ctx, params, optFns...)
	}
	return &dynamodb.TransactWriteItemsOutput{}, nil
}

// TransactGetItems implements the Client.TransactGetItems method
func (m *MockDynamoDBClient) TransactGetItems(ctx context.Context, params *dynamodb.TransactGetItemsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.TransactGetItemsOutput, error) {
	if m.TransactGetItemsFn != nil {
		return m.TransactGetItemsFn(ctx, params, optFns...)
	}
	return &dynamodb.TransactGetItemsOutput{}, nil
}

// BatchWriteItem implements the Client.BatchWriteItem method
func (m *MockDynamoDBClient) BatchWriteItem(ctx context.Context, params *dynamodb.BatchWriteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.BatchWriteItemOutput, error) {
	if m.BatchWriteItemFn != nil {
		return m.BatchWriteItemFn(ctx, params, optFns...)
	}
	return &dynamodb.BatchWriteItemOutput{}, nil
}

// BatchGetItem implements the Client.BatchGetItem method
func (m *MockDynamoDBClient) BatchGetItem(ctx context.Context, params *dynamodb.BatchGetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.BatchGetItemOutput, error) {
	if m.BatchGetItemFn != nil {
		return m.BatchGetItemFn(ctx, params, optFns...)
	}
	return &dynamodb.BatchGetItemOutput{}, nil
}