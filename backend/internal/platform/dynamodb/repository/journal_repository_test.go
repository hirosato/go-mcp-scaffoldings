package repository

import (
	"context"
	"log/slog"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/domain/journal"
)

// TestClient is an in-memory implementation of the DynamoDB client interface for testing
type TestClient struct {
	items map[string]map[string]types.AttributeValue
}

// NewTestClient creates a new test client with an empty items map
func NewTestClient() *TestClient {
	return &TestClient{
		items: make(map[string]map[string]types.AttributeValue),
	}
}

// GetItem retrieves an item from the in-memory store
func (c *TestClient) GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	pk := params.Key["PK"].(*types.AttributeValueMemberS).Value
	sk := params.Key["SK"].(*types.AttributeValueMemberS).Value
	key := pk + "#" + sk

	if item, exists := c.items[key]; exists {
		return &dynamodb.GetItemOutput{Item: item}, nil
	}
	return &dynamodb.GetItemOutput{Item: map[string]types.AttributeValue{}}, nil
}

// PutItem adds or updates an item in the in-memory store
func (c *TestClient) PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	pk := params.Item["PK"].(*types.AttributeValueMemberS).Value
	sk := params.Item["SK"].(*types.AttributeValueMemberS).Value
	key := pk + "#" + sk

	// Check condition expression if provided
	if params.ConditionExpression != nil {
		if *params.ConditionExpression == "attribute_not_exists(PK)" {
			if _, exists := c.items[key]; exists {
				return nil, &types.ConditionalCheckFailedException{Message: aws.String("Item already exists")}
			}
		}
	}

	c.items[key] = params.Item
	return &dynamodb.PutItemOutput{}, nil
}

// Implement remaining methods of the client.Client interface with minimal functionality for testing

func (c *TestClient) UpdateItem(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	return &dynamodb.UpdateItemOutput{}, nil
}

func (c *TestClient) DeleteItem(ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	return &dynamodb.DeleteItemOutput{}, nil
}

func (c *TestClient) Query(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	return &dynamodb.QueryOutput{Items: []map[string]types.AttributeValue{}}, nil
}

func (c *TestClient) Scan(ctx context.Context, params *dynamodb.ScanInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error) {
	return &dynamodb.ScanOutput{}, nil
}

func (c *TestClient) TransactWriteItems(ctx context.Context, params *dynamodb.TransactWriteItemsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	return &dynamodb.TransactWriteItemsOutput{}, nil
}

func (c *TestClient) TransactGetItems(ctx context.Context, params *dynamodb.TransactGetItemsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.TransactGetItemsOutput, error) {
	return &dynamodb.TransactGetItemsOutput{}, nil
}

func (c *TestClient) BatchWriteItem(ctx context.Context, params *dynamodb.BatchWriteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.BatchWriteItemOutput, error) {
	return &dynamodb.BatchWriteItemOutput{}, nil
}

func (c *TestClient) BatchGetItem(ctx context.Context, params *dynamodb.BatchGetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.BatchGetItemOutput, error) {
	return &dynamodb.BatchGetItemOutput{}, nil
}

func (c *TestClient) GetRawClient() *dynamodb.Client {
	return nil
}

func TestCreateJournalEntry(t *testing.T) {
	t.Run("successful transaction creation", func(t *testing.T) {
		// Setup
		client := NewTestClient()
		repo := NewDynamoDBJournalRepository(client, "test-table", slog.Default())

		// Create test transaction request
		req := &journal.CreateJournalEntryRequest{
			BookID:      "book123",
			Date:        "2023-07-15",
			Description: "Test Transaction",
			Status:      "PENDING",
			Visibility:  "PRIVATE",
			Lines: []journal.CreateJournalEntryLine{
				{
					Account:     "assets:checking",
					Amount:      "100",
					Description: "Deposit",
				},
				{
					Account:     "income:salary",
					Amount:      "-100",
					Description: "Paycheck",
				},
			},
			Tags: []string{"test", "example"},
		}

		// Act
		tx, err := repo.CreateJournalEntry(context.Background(), req)

		// Assert
		require.NoError(t, err)
		assert.NotEmpty(t, tx.JournalEntryID)
		assert.Equal(t, "book123", tx.BookID)
		assert.Equal(t, "2023-07-15", tx.Date)
		assert.Equal(t, "Test Transaction", tx.Description)
		assert.Equal(t, "PENDING", tx.Status)
		assert.Equal(t, "PRIVATE", tx.Visibility)
		assert.Len(t, tx.Lines, 2)
		assert.Equal(t, []string{"test", "example"}, tx.Tags)
		assert.False(t, tx.CreatedAt.IsZero())
		assert.False(t, tx.UpdatedAt.IsZero())
	})

	t.Run("with specified transaction ID", func(t *testing.T) {
		// Setup
		client := NewTestClient()
		repo := NewDynamoDBJournalRepository(client, "test-table", slog.Default())

		// Create test transaction request with specific ID
		req := &journal.CreateJournalEntryRequest{
			JournalEntryID: "tx123",
			BookID:         "book123",
			Date:           "2023-07-15",
			Description:    "Test Transaction",
			Status:         "PENDING",
			Lines: []journal.CreateJournalEntryLine{
				{
					Account: "assets:checking",
					Amount:  "100",
				},
				{
					Account: "income:salary",
					Amount:  "-100",
				},
			},
		}

		// Act
		tx, err := repo.CreateJournalEntry(context.Background(), req)

		// Assert
		require.NoError(t, err)
		assert.Equal(t, "tx123", tx.JournalEntryID)
	})

	t.Run("duplicate transaction ID", func(t *testing.T) {
		// Setup
		client := NewTestClient()
		repo := NewDynamoDBJournalRepository(client, "test-table", slog.Default())

		// Create transaction
		req := &journal.CreateJournalEntryRequest{
			JournalEntryID: "duplicate-tx",
			BookID:         "book123",
			Date:           "2023-07-15",
			Description:    "Test Transaction",
			Status:         "PENDING",
			Lines: []journal.CreateJournalEntryLine{
				{
					Account: "assets:checking",
					Amount:  "100",
				},
				{
					Account: "income:salary",
					Amount:  "-100",
				},
			},
		}

		// First creation should succeed
		_, err := repo.CreateJournalEntry(context.Background(), req)
		require.NoError(t, err)

		// Second creation with same ID should fail
		_, err = repo.CreateJournalEntry(context.Background(), req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "CONFLICT")
	})

	t.Run("invalid date format", func(t *testing.T) {
		// Setup
		client := NewTestClient()
		repo := NewDynamoDBJournalRepository(client, "test-table", slog.Default())

		// Create transaction with invalid date
		req := &journal.CreateJournalEntryRequest{
			BookID:      "book123",
			Date:        "2023/07/15", // Wrong format
			Description: "Test Transaction",
			Status:      "PENDING",
			Lines: []journal.CreateJournalEntryLine{
				{
					Account: "assets:checking",
					Amount:  "100",
				},
				{
					Account: "income:salary",
					Amount:  "-100",
				},
			},
		}

		// Act
		_, err := repo.CreateJournalEntry(context.Background(), req)

		// Assert
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "date")
	})

	t.Run("unbalanced entries", func(t *testing.T) {
		// Setup
		client := NewTestClient()
		repo := NewDynamoDBJournalRepository(client, "test-table", slog.Default())

		// Create transaction with unbalanced entries
		req := &journal.CreateJournalEntryRequest{
			BookID:      "book123",
			Date:        "2023-07-15",
			Description: "Test Transaction",
			Status:      "PENDING",
			Lines: []journal.CreateJournalEntryLine{
				{
					Account: "assets:checking",
					Amount:  "100",
				},
				{
					Account: "income:salary",
					Amount:  "-50", // Doesn't balance to zero
				},
			},
		}

		// Act
		_, err := repo.CreateJournalEntry(context.Background(), req)

		// Assert
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "balance")
	})

	t.Run("too few entries", func(t *testing.T) {
		// Setup
		client := NewTestClient()
		repo := NewDynamoDBJournalRepository(client, "test-table", slog.Default())

		// Create transaction with only one entry
		req := &journal.CreateJournalEntryRequest{
			BookID:      "book123",
			Date:        "2023-07-15",
			Description: "Test Transaction",
			Status:      "PENDING",
			Lines: []journal.CreateJournalEntryLine{
				{
					Account: "assets:checking",
					Amount:  "0",
				},
			},
		}

		// Act
		_, err := repo.CreateJournalEntry(context.Background(), req)

		// Assert
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least two entries")
	})
}
