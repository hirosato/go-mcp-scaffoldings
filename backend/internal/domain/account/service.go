package account

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/domain/errors"
	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/domain/tenant"
)

// Service provides account-related business logic
type Service struct {
	repo Repository
}

// NewService creates a new account service
func NewService(repo Repository) *Service {
	return &Service{
		repo: repo,
	}
}

// CreateAccount creates a new account
func (s *Service) CreateAccount(ctx context.Context, tenantCtx *tenant.TenantContext, req *CreateAccountRequest) (*AccountResponse, error) {
	// Validate account path format
	if !isValidAccountPath(req.Path) {
		return nil, errors.NewValidationError("invalid account path format, should use format like 'assets:bank:checking'")
	}

	// Check if account with the same path already exists
	exists, err := s.repo.AccountExists(ctx, tenantCtx.TenantID, req.Path)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, errors.NewConflictError("account with this path already exists")
	}

	// Create parent accounts if they don't exist
	if req.ParentAccountPath != "" {
		// Ensure parent path exists
		exists, err = s.repo.AccountExists(ctx, tenantCtx.TenantID, req.ParentAccountPath)
		if err != nil {
			return nil, err
		}
		if !exists {
			return nil, errors.NewValidationError("parent account path does not exist")
		}
	} else if req.Path != string(req.AccountType) {
		// For non-root accounts, extract parent path
		pathParts := strings.Split(req.Path, ":")
		if len(pathParts) > 1 {
			req.ParentAccountPath = strings.Join(pathParts[:len(pathParts)-1], ":")
		}
	}

	// Create account entity
	now := time.Now().UTC()
	account := &Account{
		BookID:            tenantCtx.TenantID,
		AccountID:         uuid.New().String(),
		Name:              req.Name,
		Path:              req.Path,
		AccountType:       req.AccountType,
		ParentAccountPath: req.ParentAccountPath,
		CreatedAt:         now,
		UpdatedAt:         now,
		Metadata:          req.Metadata,
		DefaultCurrency:   req.DefaultCurrency,
		Visibility:        req.Visibility,
	}

	// Set DynamoDB keys
	account.PK = fmt.Sprintf("BOOK#%s", tenantCtx.TenantID)
	account.SK = fmt.Sprintf("ACCOUNT#%s", account.AccountID)

	// Save account
	createdAccount, err := s.repo.CreateAccount(ctx, tenantCtx.TenantID, account)
	if err != nil {
		return nil, err
	}

	// Create initial zero balance
	balance := &AccountBalance{
		BookID:       tenantCtx.TenantID,
		AccountID:    account.AccountID,
		AccountPath:  account.Path,
		Date:         now.Format("2006-01-02"),
		Balance:      0,
		Currency:     account.DefaultCurrency,
		IsReconciled: false,
		Year:         now.Year(),
		Month:        int(now.Month()),
	}

	// Set DynamoDB keys
	balance.PK = account.PK
	balance.SK = fmt.Sprintf("ACCOUNT#%s#BALANCE#%s", account.AccountID, balance.Date)

	// Save balance
	err = s.repo.UpdateAccountBalance(ctx, balance)
	if err != nil {
		return nil, err
	}

	return &AccountResponse{
		Account: createdAccount,
		Balance: balance,
	}, nil
}

// GetAccount retrieves an account by ID
func (s *Service) GetAccount(ctx context.Context, tenantCtx *tenant.TenantContext, accountID string) (*AccountResponse, error) {
	account, err := s.repo.GetAccount(ctx, tenantCtx.TenantID, accountID)
	if err != nil {
		return nil, err
	}

	// Get latest balance
	balance, err := s.repo.GetAccountBalance(ctx, tenantCtx.TenantID, accountID, time.Now().UTC().Format("2006-01-02"))
	if err != nil {
		// Just log the error but don't fail the request
		balance = nil
	}

	return &AccountResponse{
		Account: account,
		Balance: balance,
	}, nil
}

// GetAccounts retrieves accounts based on criteria
func (s *Service) GetAccounts(ctx context.Context, tenantCtx *tenant.TenantContext, req *GetAccountsRequest) (*AccountListResponse, error) {
	accounts, err := s.repo.GetAccounts(ctx, tenantCtx.TenantID, req)
	if err != nil {
		return nil, err
	}

	response := &AccountListResponse{
		Accounts:   make([]AccountResponse, 0, len(accounts)),
		TotalCount: len(accounts),
	}

	// If balances are requested, fetch them
	if req.IncludeBalances {
		// Create list of account IDs
		accountIDs := make([]string, 0, len(accounts))
		for _, acc := range accounts {
			accountIDs = append(accountIDs, acc.AccountID)
		}

		// Use asOfDate if provided, otherwise use today
		asOfDate := req.AsOfDate
		if asOfDate == "" {
			asOfDate = time.Now().UTC().Format("2006-01-02")
		}

		// Get balances for all accounts
		balances, err := s.repo.GetAccountBalances(ctx, tenantCtx.TenantID, accountIDs, asOfDate)
		if err != nil {
			return nil, err
		}

		// Create a map for quick lookup
		balanceMap := make(map[string]*AccountBalance, len(balances))
		for _, bal := range balances {
			balanceMap[bal.AccountID] = bal
		}

		// Combine accounts with their balances
		for _, acc := range accounts {
			accResp := AccountResponse{
				Account: acc,
				Balance: balanceMap[acc.AccountID],
			}
			response.Accounts = append(response.Accounts, accResp)
		}
	} else {
		// Just return accounts without balances
		for _, acc := range accounts {
			accResp := AccountResponse{
				Account: acc,
			}
			response.Accounts = append(response.Accounts, accResp)
		}
	}

	return response, nil
}

// UpdateAccount updates an existing account
func (s *Service) UpdateAccount(ctx context.Context, tenantCtx *tenant.TenantContext, accountID string, req *UpdateAccountRequest) (*AccountResponse, error) {
	// Check if the account exists
	_, err := s.repo.GetAccount(ctx, tenantCtx.TenantID, accountID)
	if err != nil {
		return nil, err
	}

	// Update the account
	updatedAccount, err := s.repo.UpdateAccount(ctx, tenantCtx.TenantID, accountID, req)
	if err != nil {
		return nil, err
	}

	// Get latest balance
	balance, err := s.repo.GetAccountBalance(ctx, tenantCtx.TenantID, accountID, time.Now().UTC().Format("2006-01-02"))
	if err != nil {
		// Just log the error but don't fail the request
		balance = nil
	}

	return &AccountResponse{
		Account: updatedAccount,
		Balance: balance,
	}, nil
}

// DeleteAccount deletes an account
func (s *Service) DeleteAccount(ctx context.Context, tenantCtx *tenant.TenantContext, accountID string) error {
	// Check if the account exists
	_, err := s.repo.GetAccount(ctx, tenantCtx.TenantID, accountID)
	if err != nil {
		return err
	}

	// Get the latest balance to check if it's zero
	balance, err := s.repo.GetAccountBalance(ctx, tenantCtx.TenantID, accountID, time.Now().UTC().Format("2006-01-02"))
	if err != nil {
		return err
	}

	// Can only delete accounts with zero balance
	if balance != nil && balance.Balance != 0 {
		return errors.NewValidationError("cannot delete account with non-zero balance")
	}

	// Delete the account
	return s.repo.DeleteAccount(ctx, tenantCtx.TenantID, accountID)
}

// GetAccountBalance gets the balance of an account as of a specific date
func (s *Service) GetAccountBalance(ctx context.Context, tenantCtx *tenant.TenantContext, req *GetAccountBalanceRequest) (*AccountBalance, error) {
	// Use provided date or default to today
	asOfDate := req.AsOfDate
	if asOfDate == "" {
		asOfDate = time.Now().UTC().Format("2006-01-02")
	}

	balance, err := s.repo.GetAccountBalance(ctx, tenantCtx.TenantID, req.AccountID, asOfDate)
	if err != nil {
		return nil, err
	}

	return balance, nil
}

// ReconcileAccount reconciles an account to a specific balance
func (s *Service) ReconcileAccount(ctx context.Context, tenantCtx *tenant.TenantContext, req *ReconcileAccountRequest) (*AccountBalance, error) {
	// Get the account to check if it exists
	_, err := s.repo.GetAccount(ctx, tenantCtx.TenantID, req.AccountID)
	if err != nil {
		return nil, err
	}

	// Get current balance
	currentBalance, err := s.repo.GetAccountBalance(ctx, tenantCtx.TenantID, req.AccountID, req.AsOfDate)
	if err != nil {
		return nil, err
	}

	// If balance matches, mark as reconciled
	if currentBalance != nil && currentBalance.Balance == req.Balance {
		// Update reconciliation status
		reconciled, err := s.repo.ReconcileAccount(ctx, tenantCtx.TenantID, req)
		if err != nil {
			return nil, err
		}
		return reconciled, nil
	}

	// Otherwise, return error with difference
	diff := int64(0)
	if currentBalance != nil {
		diff = currentBalance.Balance - req.Balance
	} else {
		diff = -req.Balance
	}

	return nil, errors.NewValidationError(fmt.Sprintf("account balance doesn't match: difference of %d %s", diff, req.Currency))
}

// GetAccountHierarchy gets the hierarchical structure of accounts
func (s *Service) GetAccountHierarchy(ctx context.Context, tenantCtx *tenant.TenantContext) ([]*Account, error) {
	return s.repo.GetAccountHierarchy(ctx, tenantCtx.TenantID)
}

// Helper functions

// isValidAccountPath checks if an account path is valid
func isValidAccountPath(path string) bool {
	// Ensure path consists of valid segments separated by colons
	if path == "" {
		return false
	}

	// Path should not start or end with colon
	if strings.HasPrefix(path, ":") || strings.HasSuffix(path, ":") {
		return false
	}

	// Validate that each segment is a valid account path segment
	// (alphanumeric, underscore, dash - reasonable constraints)
	segments := strings.Split(path, ":")
	for _, segment := range segments {
		if segment == "" {
			return false
		}

		// Additional validation can be added here
	}

	return true
}
