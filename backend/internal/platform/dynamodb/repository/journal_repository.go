package repository

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/expression"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	ulid "github.com/oklog/ulid/v2"

	commonErrors "github.com/hirosato/go-mcp-scaffoldings/backend/internal/domain/errors"
	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/domain/journal"
	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/platform/dynamodb/client"
)

// DynamoDBJournalRepository implements the journal.Repository interface
type DynamoDBJournalRepository struct {
	client client.Client
	table  string
	logger *slog.Logger
}

// NewDynamoDBJournalRepository creates a new DynamoDBJournalRepository
func NewDynamoDBJournalRepository(client client.Client, table string, logger *slog.Logger) *DynamoDBJournalRepository {
	return &DynamoDBJournalRepository{
		client: client,
		table:  table,
		logger: logger,
	}
}

type JournalEntryDDB struct {
	journal.JournalEntry
	Entries []EntryDDB `json:"entries,omitempty"`
}

type EntryDDB struct {
	journal.Entry
	Amount string `json:"amount"`
}

// CreateJournalEntry creates a new journal entry with entries
func (r *DynamoDBJournalRepository) CreateJournalEntry(
	ctx context.Context, req *journal.CreateJournalEntryRequest,
) (*journal.JournalEntry, error) {
	journalEntry := journal.JournalEntry{
		JournalEntryID: req.JournalEntryID,
		BookID:         req.BookID,
		Date:           req.Date,
		Description:    req.Description,
		Notes:          req.Notes,
		Status:         req.Status,
		Visibility:     req.Visibility,
		Segments:       req.Segments,
		Tags:           req.Tags,
		Lines:          make([]journal.Entry, 0, len(req.Lines)),
	}

	// Generate ID if not provided
	if journalEntry.JournalEntryID == "" {
		journalEntry.JournalEntryID = ulid.Make().String()
	}
	// Set timestamps
	now := time.Now().UTC()
	journalEntry.CreatedAt = now
	journalEntry.UpdatedAt = now

	yearStr := ""
	if journalEntry.Date != "" {
		// Validate date format is YYYY-MM-DD
		parsedDate, err := time.Parse("2006-01-02", journalEntry.Date)
		if err != nil {
			return &journal.JournalEntry{}, commonErrors.NewValidationError("journal entry date must be in YYYY-MM-DD format")
		}
		yearStr = parsedDate.Format("2006")
	}
	// TODO translate yearStr to accounting year.
	// TODO add validation for accounting year open status.

	// Validate journal entry entries
	if err := validateJournalEntries(req.Lines); err != nil {
		return &journal.JournalEntry{}, err
	}

	// Process entries - set IDs, timestamps, etc.
	for i := range req.Lines {
		// append entry to journal entry
		journalEntry.Lines = append(journalEntry.Lines,
			journal.Entry{
				EntryID:     ulid.Make().String(),
				Account:     req.Lines[i].Account,
				Description: req.Lines[i].Description,
				Segments:    req.Lines[i].Segments,
				Tags:        req.Lines[i].Tags,
				Amount:      req.Lines[i].Amount,
				CreatedAt:   now,
				UpdatedAt:   now,
			})
	}

	// Convert journal entry to DynamoDB item
	journalEntryItem, err := attributevalue.MarshalMap(journalEntry)
	if err != nil {
		return &journal.JournalEntry{}, commonErrors.NewInternalError("failed to marshal journal entry", err)
	}

	journalEntryItem["PK"] = &types.AttributeValueMemberS{Value: fmt.Sprintf("BOOK#%s#YEAR#%s", req.BookID, yearStr)}
	journalEntryItem["SK"] = &types.AttributeValueMemberS{Value: fmt.Sprintf("JOURNAL_ENTRY#%s", journalEntry.JournalEntryID)}
	journalEntryItem["GSI1PK"] = &types.AttributeValueMemberS{Value: fmt.Sprintf("BOOK#%s#JOURNAL_ENTRY#%s", req.BookID, journalEntry.JournalEntryID)}
	journalEntryItem["GSI1SK"] = &types.AttributeValueMemberS{Value: "JOURNAL_ENTRY"}
	journalEntryItem["Type"] = &types.AttributeValueMemberS{Value: "journal_entry"}

	// Write the journal entry with entries embedded
	_, err = r.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(r.table),
		Item:                journalEntryItem,
		ConditionExpression: aws.String("attribute_not_exists(PK)"),
	})

	if err != nil {
		var condCheckErr *types.ConditionalCheckFailedException
		if errors.As(err, &condCheckErr) {
			return &journal.JournalEntry{}, commonErrors.NewConflictError("journal entry already exists")
		}
		return &journal.JournalEntry{}, commonErrors.NewInternalError("failed to create journal entry", err)
	}

	return &journalEntry, nil
}

// validateJournalEntries ensures that the entries follow double-entry accounting rules
func validateJournalEntries(entries []journal.CreateJournalEntryLine) error {
	if len(entries) < 2 {
		return commonErrors.NewValidationError("transaction must have at least two entries")
	}

	var sum int64 = 0
	for _, entry := range entries {
		val, err := entry.Int64Amount()
		if err != nil {
			return commonErrors.NewValidationError("invalid amount value")
		}
		sum = sum + val
	}

	// Check if the sum of all entries is zero (within a small epsilon for floating point precision)
	if sum != 0 {
		return commonErrors.NewValidationError("transaction entries must balance to zero")
	}

	return nil
}

// Get a journal entry by ID with its entries
func (r *DynamoDBJournalRepository) GetJournalEntryRevison(ctx context.Context, bookID string, journalEntryID string, revision uint) (*journal.JournalEntry, error) {
	return nil, nil
}

// Get journal entries by criteria
func (r *DynamoDBJournalRepository) GetJournalEntries(ctx context.Context, bookID string, filter *journal.GetJournalEntriesRequest) (*journal.GetJournalEntriesResponse, error) {
	return nil, nil
}

// Update an existing transaction
// func (r *DynamoDBTransactionRepository) UpdateTransaction(ctx context.Context, bookID string, transactionID string, updateReq *transaction.UpdateTransactionRequest) (*transaction.Transaction, error) {
// 	return []journal.JournalEntry{}, nil
// }

// GetJournalEntry retrieves a journal entry with entries by ID
func (r *DynamoDBJournalRepository) GetJournalEntry(ctx context.Context, bookID, journalEntryID string) (*journal.JournalEntry, error) {
	gsi1pk := fmt.Sprintf("BOOK#%s#JOURNAL_ENTRY#%s", bookID, journalEntryID)
	gsi1sk := "JOURNAL_ENTRY"
	r.logger.Info("GetJournalEntry", "gsi1pk", gsi1pk, "gsi1sk", gsi1sk)

	// Build query expression
	keyCondition := expression.Key("GSI1PK").Equal(expression.Value(gsi1pk)).
		And(expression.Key("GSI1SK").Equal(expression.Value(gsi1sk)))

	expr, err := expression.NewBuilder().WithKeyCondition(keyCondition).Build()
	if err != nil {
		return &journal.JournalEntry{}, commonErrors.NewInternalError("failed to build expression", err)
	}

	// Query using GSI1
	result, err := r.client.Query(ctx, &dynamodb.QueryInput{
		TableName:                 aws.String(r.table),
		IndexName:                 aws.String("GSI1"),
		KeyConditionExpression:    expr.KeyCondition(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		Limit:                     aws.Int32(1), // We expect only one item
	})

	if err != nil {
		return &journal.JournalEntry{}, commonErrors.NewInternalError("failed to query journal entry", err)
	}

	if len(result.Items) == 0 {
		return &journal.JournalEntry{}, commonErrors.NewNotFoundError("journal entry not found")
	}

	var journalEntry journal.JournalEntry
	err = attributevalue.UnmarshalMap(result.Items[0], &journalEntry)
	if err != nil {
		return &journal.JournalEntry{}, commonErrors.NewInternalError("failed to unmarshal journal entry", err)
	}

	// Entries are already correctly unmarshaled from DynamoDB
	return &journalEntry, nil
}

// getJournalEntriesByDateRange retrieves journal entries using date-based index (GSI2)
func (r *DynamoDBJournalRepository) getJournalEntriesByDateRange(
	ctx context.Context,
	tenantID,
	bookID string,
	filter journal.JournalEntryFilter,
) ([]journal.JournalEntry, error) {
	pk := fmt.Sprintf("TENANT#%s#BOOK#%s", tenantID, bookID)

	// Build filter expression
	builder := expression.NewBuilder()

	// Key condition for partition key
	keyCondition := expression.Key("GSI2PK").Equal(expression.Value(pk))

	// Add date range conditions if specified
	if !filter.StartDate.IsZero() && !filter.EndDate.IsZero() {
		startDateStr := filter.StartDate.Format("2006-01-02")
		endDateStr := filter.EndDate.Format("2006-01-02")
		keyCondition = keyCondition.And(
			expression.Key("GSI2SK").Between(
				expression.Value(fmt.Sprintf("DATE#%s", startDateStr)),
				expression.Value(fmt.Sprintf("DATE#%s\uFFFF", endDateStr)),
			),
		)
	} else if !filter.StartDate.IsZero() {
		startDateStr := filter.StartDate.Format("2006-01-02")
		keyCondition = keyCondition.And(
			expression.Key("GSI2SK").GreaterThanEqual(
				expression.Value(fmt.Sprintf("DATE#%s", startDateStr)),
			),
		)
	} else if !filter.EndDate.IsZero() {
		endDateStr := filter.EndDate.Format("2006-01-02")
		keyCondition = keyCondition.And(
			expression.Key("GSI2SK").LessThanEqual(
				expression.Value(fmt.Sprintf("DATE#%s\uFFFF", endDateStr)),
			),
		)
	}

	// Add filter for transaction items only
	filterExpr := expression.Name("Type").Equal(expression.Value("Transaction"))

	// Add status filter if specified
	if filter.Status != "" {
		filterExpr = filterExpr.And(expression.Name("Status").Equal(expression.Value(filter.Status)))
	}

	// Build the expression
	expr, err := builder.WithKeyCondition(keyCondition).WithFilter(filterExpr).Build()
	if err != nil {
		return nil, err
	}

	// Query GSI2
	input := &dynamodb.QueryInput{
		TableName:                 aws.String(r.table),
		IndexName:                 aws.String("GSI2"),
		KeyConditionExpression:    expr.KeyCondition(),
		FilterExpression:          expr.Filter(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		ScanIndexForward:          aws.Bool(filter.SortAscending), // Control sort order
		Limit:                     aws.Int32(int32(filter.Limit)),
	}

	if filter.ExclusiveStartKey != "" {
		// Convert the pagination token to DynamoDB format
		// In a real implementation, we would decode a base64 encoded pagination token
		// This is a simplified version
		input.ExclusiveStartKey = map[string]types.AttributeValue{
			"PK":     &types.AttributeValueMemberS{Value: pk},
			"SK":     &types.AttributeValueMemberS{Value: filter.ExclusiveStartKey},
			"GSI2PK": &types.AttributeValueMemberS{Value: pk},
			"GSI2SK": &types.AttributeValueMemberS{Value: filter.ExclusiveStartKey},
		}
	}

	result, err := r.client.Query(ctx, input)
	if err != nil {
		return nil, err
	}

	var journalEntries []journal.JournalEntry
	err = attributevalue.UnmarshalListOfMaps(result.Items, &journalEntries)
	if err != nil {
		return nil, err
	}

	return journalEntries, nil
}

// getJournalEntriesByBook retrieves journal entries by book ID
func (r *DynamoDBJournalRepository) getJournalEntriesByBook(
	ctx context.Context,
	tenantID,
	bookID string,
	filter journal.JournalEntryFilter,
) ([]journal.JournalEntry, error) {
	pk := fmt.Sprintf("TENANT#%s#BOOK#%s", tenantID, bookID)

	// Build filter expression
	builder := expression.NewBuilder()

	// Key condition for partition key and transaction prefix
	keyCondition := expression.Key("PK").Equal(expression.Value(pk)).
		And(expression.Key("SK").BeginsWith("TRANSACTION#"))

	// Add filter for transaction items only
	filterExpr := expression.Name("Type").Equal(expression.Value("Transaction"))

	// Add status filter if specified
	if filter.Status != "" {
		filterExpr = filterExpr.And(expression.Name("Status").Equal(expression.Value(filter.Status)))
	}

	// Build the expression
	expr, err := builder.WithKeyCondition(keyCondition).WithFilter(filterExpr).Build()
	if err != nil {
		return nil, err
	}

	// Query the base table
	input := &dynamodb.QueryInput{
		TableName:                 aws.String(r.table),
		KeyConditionExpression:    expr.KeyCondition(),
		FilterExpression:          expr.Filter(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		Limit:                     aws.Int32(int32(filter.Limit)),
	}

	if filter.ExclusiveStartKey != "" {
		input.ExclusiveStartKey = map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: pk},
			"SK": &types.AttributeValueMemberS{Value: filter.ExclusiveStartKey},
		}
	}

	result, err := r.client.Query(ctx, input)
	if err != nil {
		return nil, err
	}

	var journalEntries []journal.JournalEntry
	err = attributevalue.UnmarshalListOfMaps(result.Items, &journalEntries)
	if err != nil {
		return nil, err
	}

	return journalEntries, nil
}

// UpdateJournalEntry updates an existing journal entry
func (r *DynamoDBJournalRepository) UpdateJournalEntry(
	ctx context.Context, bookID string, journalEntryID string, updateReq *journal.UpdateJournalEntryRequest) (*journal.JournalEntry, error) {
	return nil, nil
	// // Check that transaction exists
	// existing, err := r.GetTransaction(ctx, tenantID, bookID, tx.TransactionID)
	// if err != nil {
	// 	return transaction.Transaction{}, err
	// }

	// // Preserve keys and timestamps
	// // tx.PK = existing.PK
	// // tx.SK = existing.SK
	// tx.CreatedAt = existing.CreatedAt
	// tx.UpdatedAt = time.Now().UTC()

	// // Convert to DynamoDB item
	// item, err := attributevalue.MarshalMap(tx)
	// if err != nil {
	// 	return transaction.Transaction{}, err
	// }

	// // Update GSI keys if date has changed
	// // if !tx.Date.Equal(existing.Date) {
	// // 	txDateStr := tx.Date.Format("2006-01-02")
	// // 	item["GSI2PK"] = &types.AttributeValueMemberS{Value: fmt.Sprintf("TENANT#%s#BOOK#%s", tenantID, bookID)}
	// // 	item["GSI2SK"] = &types.AttributeValueMemberS{Value: fmt.Sprintf("DATE#%s#TRANSACTION#%s", txDateStr, tx.TransactionID)}
	// // }

	// // Update the transaction
	// _, err = r.client.PutItem(ctx, &dynamodb.PutItemInput{
	// 	TableName: aws.String(r.table),
	// 	Item:      item,
	// })

	// if err != nil {
	// 	return transaction.Transaction{}, err
	// }

	// // Get updated transaction with entries
	// return r.GetTransaction(ctx, tenantID, bookID, tx.TransactionID)
}

// DeleteJournalEntry removes a journal entry and all its entries
func (r *DynamoDBJournalRepository) DeleteJournalEntry(ctx context.Context, bookID string, journalEntryID string) error {

	return nil
}

// CreateJournalEntries adds entries to a journal entry
func (r *DynamoDBJournalRepository) CreateJournalEntries(
	ctx context.Context,
	tenantID,
	bookID,
	journalEntryID string,
	entries []journal.Entry,
) ([]journal.Entry, error) {
	return nil, nil
}
