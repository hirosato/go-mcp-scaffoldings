package account

import (
	"time"
)

// AccountFilter represents the filtering criteria for accounts
type AccountFilter struct {
	ParentID        string
	AccountType     string
	Status          string
	SearchTerm      string
	IncludeInactive bool
	LastUpdatedSince time.Time
	SortBy          string
	SortOrder       string
	Limit           int
	ExclusiveStartKey string
}

// Balance represents an account balance record
type Balance struct {
	BookID       string
	AccountID    string
	AccountPath  string
	Date         string // ISO date format
	Balance      int64  // Amount in smallest currency unit (e.g., cents)
	Currency     string
	LastTransactionID string
	LastTransactionTimestamp time.Time
	IsReconciled bool
	ReconciledAt *time.Time
	Year         int
	Month        int
	
	// DynamoDB specific attributes
	PK string
	SK string
}

// Reconciliation represents an account reconciliation record
type Reconciliation struct {
	AccountID       string
	ReconciliationID string
	Date            string
	StartBalance    int64
	EndBalance      int64
	Cleared         int64
	Uncleared       int64
	Notes           string
	Status          string
	CreatedAt       time.Time
	UpdatedAt       time.Time
	
	// DynamoDB specific attributes
	PK string
	SK string
}