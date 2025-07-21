package account

import (
	"context"
)

// Repository defines the interface for account data operations
type Repository interface {
	// Create a new account
	CreateAccount(ctx context.Context, bookID string, account *Account) (*Account, error)
	
	// Get an account by ID
	GetAccount(ctx context.Context, bookID string, accountID string) (*Account, error)
	
	// Get accounts by criteria
	GetAccounts(ctx context.Context, bookID string, filter *GetAccountsRequest) ([]*Account, error)
	
	// Update an existing account
	UpdateAccount(ctx context.Context, bookID string, accountID string, updateReq *UpdateAccountRequest) (*Account, error)
	
	// Delete an account
	DeleteAccount(ctx context.Context, bookID string, accountID string) error
	
	// Get account balance
	GetAccountBalance(ctx context.Context, bookID string, accountID string, asOfDate string) (*AccountBalance, error)
	
	// Get account balances
	GetAccountBalances(ctx context.Context, bookID string, accountIDs []string, asOfDate string) ([]*AccountBalance, error)
	
	// Update account balance
	UpdateAccountBalance(ctx context.Context, balance *AccountBalance) error
	
	// Reconcile account
	ReconcileAccount(ctx context.Context, bookID string, reconcileReq *ReconcileAccountRequest) (*AccountBalance, error)
	
	// Get account hierarchy
	GetAccountHierarchy(ctx context.Context, bookID string) ([]*Account, error)
	
	// Check if account exists
	AccountExists(ctx context.Context, bookID string, accountPath string) (bool, error)
}