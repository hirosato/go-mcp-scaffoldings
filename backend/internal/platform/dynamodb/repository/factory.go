package repository

import (
	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/platform/dynamodb/client"
)

// Factory creates repository instances
type Factory struct {
	client    client.Client
	tableName string
}

// NewFactory creates a new repository factory
func NewFactory(client client.Client, tableName string) *Factory {
	return &Factory{
		client:    client,
		tableName: tableName,
	}
}

// // AccountRepository returns an implementation of the account.Repository interface
// func (f *Factory) AccountRepository() account.Repository {
// 	return NewDynamoDBAccountRepository(f.client, f.tableName)
// }

// // TransactionRepository returns an implementation of the transaction.Repository interface
// func (f *Factory) TransactionRepository() transaction.Repository {
// 	return NewDynamoDBTransactionRepository(f.client, f.tableName)
// }
