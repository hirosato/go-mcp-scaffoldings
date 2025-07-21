package account

import (
	"time"
)

// AccountType represents the type of an account
type AccountType string

const (
	// Asset represents an asset account
	Asset AccountType = "asset"
	// Liability represents a liability account
	Liability AccountType = "liability"
	// Equity represents an equity account
	Equity AccountType = "equity"
	// Income represents an income account
	Income AccountType = "income"
	// Expense represents an expense account
	Expense AccountType = "expense"
)

// VisibilityType represents the visibility level of an account
type VisibilityType string

const (
	// Private visibility means the account is only visible to the book owner
	Private VisibilityType = "private"
	// SharedSummary visibility means the account summary is shared but not individual transactions
	SharedSummary VisibilityType = "shared_summary"
	// SharedFull visibility means both account summary and transactions are shared
	SharedFull VisibilityType = "shared_full"
)

// Account represents an account in the double-entry accounting system
type Account struct {
	// Primary attributes
	BookID     string       `json:"bookId"`
	AccountID  string       `json:"accountId"`
	Name       string       `json:"name"`
	Path       string       `json:"path"`
	AccountType AccountType  `json:"accountType"`
	ParentAccountPath string `json:"parentAccountPath,omitempty"`
	
	// Metadata
	CreatedAt time.Time     `json:"createdAt"`
	UpdatedAt time.Time     `json:"updatedAt"`
	Metadata  AccountMetadata `json:"metadata,omitempty"`
	
	// Configuration
	DefaultCurrency string        `json:"defaultCurrency"`
	Visibility      VisibilityType `json:"visibility"`

	// DynamoDB specific attributes
	PK string `json:"-"`
	SK string `json:"-"`
}

// AccountMetadata contains additional information about an account
type AccountMetadata struct {
	Institution    string `json:"institution,omitempty"`
	AccountNumber  string `json:"accountNumber,omitempty"`
	BankConnectionID string `json:"bankConnectionId,omitempty"`
	Notes          string `json:"notes,omitempty"`
	Color          string `json:"color,omitempty"`
	Icon           string `json:"icon,omitempty"`
}

// AccountBalance represents the balance of an account at a specific point in time
type AccountBalance struct {
	BookID       string    `json:"bookId"`
	AccountID    string    `json:"accountId"`
	AccountPath  string    `json:"accountPath"`
	Date         string    `json:"date"` // ISO date format
	Balance      int64     `json:"balance"` // Amount in smallest currency unit (e.g., cents)
	Currency     string    `json:"currency"`
	LastTransactionID string `json:"lastTransactionId,omitempty"`
	LastTransactionTimestamp time.Time `json:"lastTransactionTimestamp,omitempty"`
	IsReconciled bool      `json:"isReconciled"`
	ReconciledAt *time.Time `json:"reconciledAt,omitempty"`
	Year         int       `json:"year"`
	Month        int       `json:"month"`

	// DynamoDB specific attributes
	PK string `json:"-"`
	SK string `json:"-"`
}

// CreateAccountRequest represents the request to create a new account
type CreateAccountRequest struct {
	Name           string       `json:"name" validate:"required"`
	Path           string       `json:"path" validate:"required"`
	AccountType    AccountType  `json:"accountType" validate:"required,oneof=asset liability equity income expense"`
	ParentAccountPath string    `json:"parentAccountPath,omitempty"`
	DefaultCurrency string      `json:"defaultCurrency" validate:"required"`
	Visibility      VisibilityType `json:"visibility" validate:"required,oneof=private shared_summary shared_full"`
	Metadata       AccountMetadata `json:"metadata,omitempty"`
}

// UpdateAccountRequest represents the request to update an existing account
type UpdateAccountRequest struct {
	Name           string       `json:"name,omitempty"`
	ParentAccountPath string    `json:"parentAccountPath,omitempty"`
	DefaultCurrency string      `json:"defaultCurrency,omitempty"`
	Visibility      VisibilityType `json:"visibility,omitempty" validate:"omitempty,oneof=private shared_summary shared_full"`
	Metadata       AccountMetadata `json:"metadata,omitempty"`
}

// GetAccountsRequest represents the request to get accounts
type GetAccountsRequest struct {
	AccountType    string `json:"accountType,omitempty"`
	ParentPath     string `json:"parentPath,omitempty"`
	IncludeBalances bool   `json:"includeBalances,omitempty"`
	AsOfDate       string `json:"asOfDate,omitempty"` // ISO date format
}

// GetAccountBalanceRequest represents the request to get an account balance
type GetAccountBalanceRequest struct {
	AccountID string `json:"accountId" validate:"required"`
	AsOfDate  string `json:"asOfDate,omitempty"` // ISO date format
}

// ReconcileAccountRequest represents the request to reconcile an account
type ReconcileAccountRequest struct {
	AccountID string `json:"accountId" validate:"required"`
	AsOfDate  string `json:"asOfDate" validate:"required"` // ISO date format
	Balance   int64  `json:"balance" validate:"required"`
	Currency  string `json:"currency" validate:"required"`
}

// AccountResponse represents the response for account-related operations
type AccountResponse struct {
	Account *Account `json:"account,omitempty"`
	Balance *AccountBalance `json:"balance,omitempty"`
}

// AccountListResponse represents the response for listing accounts
type AccountListResponse struct {
	Accounts []AccountResponse `json:"accounts"`
	TotalCount int `json:"totalCount"`
}