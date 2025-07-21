package repository

// import (
// 	"context"
// 	"errors"
// 	"fmt"
// 	"time"

// 	"github.com/aws/aws-sdk-go-v2/aws"
// 	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
// 	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/expression"
// 	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
// 	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
// 	"github.com/google/uuid"

// 	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/domain/account"
// 	commonErrors "github.com/hirosato/go-mcp-scaffoldings/backend/internal/domain/errors"
// 	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/platform/dynamodb/client"
// )

// // DynamoDBAccountRepository implements the account.Repository interface
// type DynamoDBAccountRepository struct {
// 	client client.Client
// 	table  string
// }

// // NewDynamoDBAccountRepository creates a new DynamoDBAccountRepository
// func NewDynamoDBAccountRepository(client client.Client, table string) *DynamoDBAccountRepository {
// 	return &DynamoDBAccountRepository{
// 		client: client,
// 		table:  table,
// 	}
// }

// // CreateAccount creates a new account
// func (r *DynamoDBAccountRepository) CreateAccount(ctx context.Context, tenantID, bookID string, acc account.Account) (account.Account, error) {
// 	// Generate ID if not provided
// 	if acc.AccountID == "" {
// 		acc.AccountID = uuid.New().String()
// 	}

// 	// Set timestamps
// 	now := time.Now().UTC()
// 	acc.CreatedAt = now
// 	acc.UpdatedAt = now

// 	// Set keys for single-table design
// 	acc.PK = fmt.Sprintf("TENANT#%s#BOOK#%s", tenantID, bookID)
// 	acc.SK = fmt.Sprintf("ACCOUNT#%s", acc.AccountID)

// 	// Convert to DynamoDB attribute map
// 	item, err := attributevalue.MarshalMap(acc)
// 	if err != nil {
// 		return account.Account{}, err
// 	}

// 	// Add GSI keys for querying
// 	item["GSI1PK"] = &types.AttributeValueMemberS{Value: fmt.Sprintf("TENANT#%s", tenantID)}
// 	item["GSI1SK"] = &types.AttributeValueMemberS{Value: fmt.Sprintf("BOOK#%s#ACCOUNT#%s", bookID, acc.AccountID)}

// 	// Add item type
// 	item["Type"] = &types.AttributeValueMemberS{Value: "Account"}

// 	// Add parent path for hierarchical querying
// 	parentPath := ""
// 	if acc.ParentID != "" {
// 		parent, err := r.GetAccount(ctx, tenantID, bookID, acc.ParentID)
// 		if err != nil {
// 			return account.Account{}, err
// 		}
// 		parentPath = parent.Path
// 	}

// 	// Build path for hierarchical queries
// 	if parentPath != "" {
// 		acc.Path = fmt.Sprintf("%s#%s", parentPath, acc.AccountID)
// 	} else {
// 		acc.Path = acc.AccountID
// 	}
// 	item["Path"] = &types.AttributeValueMemberS{Value: acc.Path}

// 	// Store in DynamoDB
// 	_, err = r.client.PutItem(ctx, &dynamodb.PutItemInput{
// 		TableName:           aws.String(r.table),
// 		Item:                item,
// 		ConditionExpression: aws.String("attribute_not_exists(PK)"),
// 	})

// 	if err != nil {
// 		var conditionFailedErr *types.ConditionalCheckFailedException
// 		if errors.As(err, &conditionFailedErr) {
// 			return account.Account{}, commonErrors.NewConflictError("account already exists")
// 		}
// 		return account.Account{}, err
// 	}

// 	// Create initial balance record
// 	balanceKey := fmt.Sprintf("BALANCE#%s#%s", acc.AccountID, now.Format("2006-01-02"))
// 	balanceItem := map[string]types.AttributeValue{
// 		"PK":        &types.AttributeValueMemberS{Value: acc.PK},
// 		"SK":        &types.AttributeValueMemberS{Value: balanceKey},
// 		"Type":      &types.AttributeValueMemberS{Value: "AccountBalance"},
// 		"AccountID": &types.AttributeValueMemberS{Value: acc.AccountID},
// 		"Balance":   &types.AttributeValueMemberN{Value: "0"},
// 		"Date":      &types.AttributeValueMemberS{Value: now.Format("2006-01-02")},
// 		"CreatedAt": &types.AttributeValueMemberS{Value: now.Format(time.RFC3339)},
// 	}

// 	_, err = r.client.PutItem(ctx, &dynamodb.PutItemInput{
// 		TableName: aws.String(r.table),
// 		Item:      balanceItem,
// 	})

// 	if err != nil {
// 		// Try to clean up the account if balance creation fails
// 		_, _ = r.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
// 			TableName: aws.String(r.table),
// 			Key: map[string]types.AttributeValue{
// 				"PK": &types.AttributeValueMemberS{Value: acc.PK},
// 				"SK": &types.AttributeValueMemberS{Value: acc.SK},
// 			},
// 		})
// 		return account.Account{}, err
// 	}

// 	return acc, nil
// }

// // GetAccount retrieves an account by ID
// func (r *DynamoDBAccountRepository) GetAccount(ctx context.Context, tenantID, bookID, accountID string) (account.Account, error) {
// 	pk := fmt.Sprintf("TENANT#%s#BOOK#%s", tenantID, bookID)
// 	sk := fmt.Sprintf("ACCOUNT#%s", accountID)

// 	result, err := r.client.GetItem(ctx, &dynamodb.GetItemInput{
// 		TableName: aws.String(r.table),
// 		Key: map[string]types.AttributeValue{
// 			"PK": &types.AttributeValueMemberS{Value: pk},
// 			"SK": &types.AttributeValueMemberS{Value: sk},
// 		},
// 	})

// 	if err != nil {
// 		return account.Account{}, err
// 	}

// 	if len(result.Item) == 0 {
// 		return account.Account{}, commonErrors.NewNotFoundError("account not found")
// 	}

// 	var acc account.Account
// 	err = attributevalue.UnmarshalMap(result.Item, &acc)
// 	if err != nil {
// 		return account.Account{}, err
// 	}

// 	return acc, nil
// }

// // GetAccounts retrieves accounts based on filter criteria
// func (r *DynamoDBAccountRepository) GetAccounts(ctx context.Context, tenantID, bookID string, filter account.AccountFilter) ([]account.Account, error) {
// 	pk := fmt.Sprintf("TENANT#%s#BOOK#%s", tenantID, bookID)

// 	// Build filter expression
// 	builder := expression.NewBuilder()

// 	// Key condition for partition key
// 	keyCondition := expression.Key("PK").Equal(expression.Value(pk))

// 	// SK condition to match only accounts
// 	keyCondition = keyCondition.And(expression.Key("SK").BeginsWith("ACCOUNT#"))

// 	// Apply type filter
// 	filterExpr := expression.Name("Type").Equal(expression.Value("Account"))

// 	// Apply account type filter if specified
// 	if filter.Type != "" {
// 		filterExpr = filterExpr.And(expression.Name("AccountType").Equal(expression.Value(filter.Type)))
// 	}

// 	// Apply parent filter if specified
// 	if filter.ParentID != "" {
// 		filterExpr = filterExpr.And(expression.Name("ParentID").Equal(expression.Value(filter.ParentID)))
// 	}

// 	// Build expression with key condition and filter
// 	expr, err := builder.WithKeyCondition(keyCondition).WithFilter(filterExpr).Build()
// 	if err != nil {
// 		return nil, err
// 	}

// 	var accounts []account.Account
// 	var lastEvaluatedKey map[string]types.AttributeValue

// 	// Paginate through results
// 	for {
// 		input := &dynamodb.QueryInput{
// 			TableName:                 aws.String(r.table),
// 			KeyConditionExpression:    expr.KeyCondition(),
// 			FilterExpression:          expr.Filter(),
// 			ExpressionAttributeNames:  expr.Names(),
// 			ExpressionAttributeValues: expr.Values(),
// 			Limit:                     aws.Int32(100),
// 		}

// 		// Add pagination token if we have one
// 		if lastEvaluatedKey != nil {
// 			input.ExclusiveStartKey = lastEvaluatedKey
// 		}

// 		result, err := r.client.Query(ctx, input)
// 		if err != nil {
// 			return nil, err
// 		}

// 		// Unmarshal items into accounts
// 		var pageAccounts []account.Account
// 		err = attributevalue.UnmarshalListOfMaps(result.Items, &pageAccounts)
// 		if err != nil {
// 			return nil, err
// 		}

// 		accounts = append(accounts, pageAccounts...)

// 		// Check if we need to continue pagination
// 		lastEvaluatedKey = result.LastEvaluatedKey
// 		if lastEvaluatedKey == nil || len(lastEvaluatedKey) == 0 {
// 			break
// 		}
// 	}

// 	return accounts, nil
// }

// // UpdateAccount updates an existing account
// func (r *DynamoDBAccountRepository) UpdateAccount(ctx context.Context, tenantID, bookID string, acc account.Account) (account.Account, error) {
// 	// Check that account exists
// 	existing, err := r.GetAccount(ctx, tenantID, bookID, acc.AccountID)
// 	if err != nil {
// 		return account.Account{}, err
// 	}

// 	// Preserve certain fields
// 	acc.PK = existing.PK
// 	acc.SK = existing.SK
// 	acc.CreatedAt = existing.CreatedAt
// 	acc.Path = existing.Path
// 	acc.UpdatedAt = time.Now().UTC()

// 	// Convert to DynamoDB attribute map
// 	item, err := attributevalue.MarshalMap(acc)
// 	if err != nil {
// 		return account.Account{}, err
// 	}

// 	// Update item in DynamoDB
// 	_, err = r.client.PutItem(ctx, &dynamodb.PutItemInput{
// 		TableName: aws.String(r.table),
// 		Item:      item,
// 	})

// 	if err != nil {
// 		return account.Account{}, err
// 	}

// 	return acc, nil
// }

// // DeleteAccount deletes an account
// func (r *DynamoDBAccountRepository) DeleteAccount(ctx context.Context, tenantID, bookID, accountID string) error {
// 	// Check if account has children first
// 	filter := account.AccountFilter{
// 		ParentID: accountID,
// 	}

// 	children, err := r.GetAccounts(ctx, tenantID, bookID, filter)
// 	if err != nil {
// 		return err
// 	}

// 	if len(children) > 0 {
// 		return commonErrors.NewConflictError("cannot delete account with child accounts")
// 	}

// 	pk := fmt.Sprintf("TENANT#%s#BOOK#%s", tenantID, bookID)
// 	sk := fmt.Sprintf("ACCOUNT#%s", accountID)

// 	_, err = r.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
// 		TableName: aws.String(r.table),
// 		Key: map[string]types.AttributeValue{
// 			"PK": &types.AttributeValueMemberS{Value: pk},
// 			"SK": &types.AttributeValueMemberS{Value: sk},
// 		},
// 	})

// 	return err
// }

// // GetAccountBalance gets an account's balance at a specific date
// func (r *DynamoDBAccountRepository) GetAccountBalance(ctx context.Context, tenantID, bookID, accountID string, date time.Time) (account.Balance, error) {
// 	pk := fmt.Sprintf("TENANT#%s#BOOK#%s", tenantID, bookID)

// 	// Build expression to query for the latest balance record on or before the given date
// 	dateStr := date.Format("2006-01-02")

// 	// Build key condition for querying
// 	keyCondition := expression.Key("PK").Equal(expression.Value(pk)).
// 		And(expression.Key("SK").BeginsWith(fmt.Sprintf("BALANCE#%s#", accountID)))

// 	// Add filter to get only balance records
// 	filterExpr := expression.Name("Type").Equal(expression.Value("AccountBalance")).
// 		And(expression.Name("Date").LessThanEqual(expression.Value(dateStr)))

// 	// Build expression
// 	expr, err := expression.NewBuilder().
// 		WithKeyCondition(keyCondition).
// 		WithFilter(filterExpr).
// 		Build()

// 	if err != nil {
// 		return account.Balance{}, err
// 	}

// 	// Query with descending order by sort key to get the latest balance
// 	result, err := r.client.Query(ctx, &dynamodb.QueryInput{
// 		TableName:                 aws.String(r.table),
// 		KeyConditionExpression:    expr.KeyCondition(),
// 		FilterExpression:          expr.Filter(),
// 		ExpressionAttributeNames:  expr.Names(),
// 		ExpressionAttributeValues: expr.Values(),
// 		ScanIndexForward:          aws.Bool(false), // Descending order
// 		Limit:                     aws.Int32(1),    // Only need the most recent balance
// 	})

// 	if err != nil {
// 		return account.Balance{}, err
// 	}

// 	if len(result.Items) == 0 {
// 		// No balance record found, return zero balance
// 		return account.Balance{
// 			AccountID: accountID,
// 			Amount:    0,
// 			Date:      date,
// 		}, nil
// 	}

// 	// Unmarshal the balance record
// 	var balance struct {
// 		AccountID string    `dynamodbav:"AccountID"`
// 		Balance   float64   `dynamodbav:"Balance"`
// 		Date      string    `dynamodbav:"Date"`
// 		CreatedAt time.Time `dynamodbav:"CreatedAt"`
// 	}

// 	err = attributevalue.UnmarshalMap(result.Items[0], &balance)
// 	if err != nil {
// 		return account.Balance{}, err
// 	}

// 	balanceDate, err := time.Parse("2006-01-02", balance.Date)
// 	if err != nil {
// 		return account.Balance{}, err
// 	}

// 	return account.Balance{
// 		AccountID: balance.AccountID,
// 		Amount:    balance.Balance,
// 		Date:      balanceDate,
// 	}, nil
// }

// // GetAccountBalances gets balances for multiple accounts
// func (r *DynamoDBAccountRepository) GetAccountBalances(ctx context.Context, tenantID, bookID string, accountIDs []string, date time.Time) ([]account.Balance, error) {
// 	balances := make([]account.Balance, 0, len(accountIDs))

// 	// Get balance for each account
// 	for _, accountID := range accountIDs {
// 		balance, err := r.GetAccountBalance(ctx, tenantID, bookID, accountID, date)
// 		if err != nil {
// 			return nil, err
// 		}
// 		balances = append(balances, balance)
// 	}

// 	return balances, nil
// }

// // UpdateAccountBalance updates an account's balance
// func (r *DynamoDBAccountRepository) UpdateAccountBalance(ctx context.Context, tenantID, bookID string, balance account.Balance) error {
// 	pk := fmt.Sprintf("TENANT#%s#BOOK#%s", tenantID, bookID)
// 	dateStr := balance.Date.Format("2006-01-02")
// 	sk := fmt.Sprintf("BALANCE#%s#%s", balance.AccountID, dateStr)

// 	now := time.Now().UTC()

// 	balanceItem := map[string]types.AttributeValue{
// 		"PK":        &types.AttributeValueMemberS{Value: pk},
// 		"SK":        &types.AttributeValueMemberS{Value: sk},
// 		"Type":      &types.AttributeValueMemberS{Value: "AccountBalance"},
// 		"AccountID": &types.AttributeValueMemberS{Value: balance.AccountID},
// 		"Balance":   &types.AttributeValueMemberN{Value: fmt.Sprintf("%f", balance.Amount)},
// 		"Date":      &types.AttributeValueMemberS{Value: dateStr},
// 		"CreatedAt": &types.AttributeValueMemberS{Value: now.Format(time.RFC3339)},
// 	}

// 	_, err := r.client.PutItem(ctx, &dynamodb.PutItemInput{
// 		TableName: aws.String(r.table),
// 		Item:      balanceItem,
// 	})

// 	return err
// }

// // ReconcileAccount reconciles an account to a specified balance
// func (r *DynamoDBAccountRepository) ReconcileAccount(ctx context.Context, tenantID, bookID string, reconciliation account.Reconciliation) error {
// 	// Update the account balance for the reconciliation date
// 	balance := account.Balance{
// 		AccountID: reconciliation.AccountID,
// 		Amount:    reconciliation.Amount,
// 		Date:      reconciliation.Date,
// 	}

// 	err := r.UpdateAccountBalance(ctx, tenantID, bookID, balance)
// 	if err != nil {
// 		return err
// 	}

// 	// Store reconciliation record
// 	pk := fmt.Sprintf("TENANT#%s#BOOK#%s", tenantID, bookID)
// 	dateStr := reconciliation.Date.Format("2006-01-02")
// 	sk := fmt.Sprintf("RECONCILIATION#%s#%s", reconciliation.AccountID, dateStr)

// 	now := time.Now().UTC()

// 	reconcileItem := map[string]types.AttributeValue{
// 		"PK":           &types.AttributeValueMemberS{Value: pk},
// 		"SK":           &types.AttributeValueMemberS{Value: sk},
// 		"Type":         &types.AttributeValueMemberS{Value: "AccountReconciliation"},
// 		"AccountID":    &types.AttributeValueMemberS{Value: reconciliation.AccountID},
// 		"Amount":       &types.AttributeValueMemberN{Value: fmt.Sprintf("%f", reconciliation.Amount)},
// 		"Date":         &types.AttributeValueMemberS{Value: dateStr},
// 		"Notes":        &types.AttributeValueMemberS{Value: reconciliation.Notes},
// 		"ReconcilerID": &types.AttributeValueMemberS{Value: reconciliation.ReconcilerID},
// 		"CreatedAt":    &types.AttributeValueMemberS{Value: now.Format(time.RFC3339)},
// 	}

// 	_, err = r.client.PutItem(ctx, &dynamodb.PutItemInput{
// 		TableName: aws.String(r.table),
// 		Item:      reconcileItem,
// 	})

// 	return err
// }

// // GetAccountHierarchy retrieves the account hierarchy
// func (r *DynamoDBAccountRepository) GetAccountHierarchy(ctx context.Context, tenantID, bookID string) ([]account.Account, error) {
// 	// Get all accounts for the book
// 	accounts, err := r.GetAccounts(ctx, tenantID, bookID, account.AccountFilter{})
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Sort accounts by path to maintain hierarchy order
// 	// This assumes Path is structured correctly for hierarchical sorting
// 	// In a production implementation, we might use a more sophisticated sorting approach
// 	sortAccountsByPath(accounts)

// 	return accounts, nil
// }

// // sortAccountsByPath sorts accounts by their path for hierarchical display
// func sortAccountsByPath(accounts []account.Account) {
// 	// Simple bubble sort for demonstration
// 	// In production, a more efficient algorithm would be used
// 	for i := 0; i < len(accounts); i++ {
// 		for j := i + 1; j < len(accounts); j++ {
// 			if accounts[i].Path > accounts[j].Path {
// 				accounts[i], accounts[j] = accounts[j], accounts[i]
// 			}
// 		}
// 	}
// }

// // AccountExists checks if an account exists
// func (r *DynamoDBAccountRepository) AccountExists(ctx context.Context, tenantID, bookID, accountID string) (bool, error) {
// 	pk := fmt.Sprintf("TENANT#%s#BOOK#%s", tenantID, bookID)
// 	sk := fmt.Sprintf("ACCOUNT#%s", accountID)

// 	result, err := r.client.GetItem(ctx, &dynamodb.GetItemInput{
// 		TableName: aws.String(r.table),
// 		Key: map[string]types.AttributeValue{
// 			"PK": &types.AttributeValueMemberS{Value: pk},
// 			"SK": &types.AttributeValueMemberS{Value: sk},
// 		},
// 		ProjectionExpression: aws.String("PK"), // Only need one attribute to check existence
// 	})

// 	if err != nil {
// 		return false, err
// 	}

// 	return len(result.Item) > 0, nil
// }
