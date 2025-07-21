package journal

import (
	"context"
	"fmt"

	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/domain/errors"
)

// Service provides journal entry-related business logic
type Service struct {
	repo Repository
}

// NewService creates a new journal entry service
func NewService(repo Repository) *Service {
	return &Service{
		repo: repo,
	}
}

// CreateJournalEntry creates a new journal entry
func (s *Service) CreateJournalEntry(ctx context.Context, bookID string, req *CreateJournalEntryRequest) (*JournalEntry, error) {
	// Validate journal entry entries (ensure they balance to zero)
	balanceSum, err := s.validateJournalEntryBalance(req.Lines)
	if err != nil {
		return nil, err
	}
	if balanceSum != 0 {
		return nil, errors.NewValidationError(fmt.Sprintf("journal entry entries do not balance to zero: sum is %d", balanceSum))
	}

	// Verify that all accounts exist
	// if err := s.verifyAccountsExist(ctx,  req.Lines); err != nil {
	// 	return nil, err
	// }

	// Create the journal entry
	journalEntry, err := s.repo.CreateJournalEntry(ctx, req)
	if err != nil {
		return nil, err
	}

	return journalEntry, nil
}

// GetJournalEntry retrieves a journal entry by ID
func (s *Service) GetJournalEntry(ctx context.Context, bookID string, journalEntryID string) (*JournalEntry, error) {
	journalEntry, err := s.repo.GetJournalEntry(ctx, bookID, journalEntryID)
	if err != nil {
		return nil, err
	}

	return journalEntry, nil
}

// GetJournalEntries retrieves journal entries based on criteria
func (s *Service) GetJournalEntries(ctx context.Context, bookID string, req *GetJournalEntriesRequest) (*GetJournalEntriesResponse, error) {
	response, err := s.repo.GetJournalEntries(ctx, bookID, req)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// UpdateJournalEntry updates an existing journal entry
func (s *Service) UpdateJournalEntry(ctx context.Context, bookID string, journalEntryID string, req *UpdateJournalEntryRequest) (*JournalEntry, error) {
	// Check if the journal entry exists
	_, err := s.repo.GetJournalEntry(ctx, bookID, journalEntryID)
	if err != nil {
		return nil, err
	}

	// Update the journal entry
	updatedJournalEntry, err := s.repo.UpdateJournalEntry(ctx, bookID, journalEntryID, req)
	if err != nil {
		return nil, err
	}

	return updatedJournalEntry, nil
}

// DeleteJournalEntry deletes a journal entry
func (s *Service) DeleteJournalEntry(ctx context.Context, bookID string, journalEntryID string) error {
	// Check if the journal entry exists
	_, err := s.repo.GetJournalEntry(ctx, bookID, journalEntryID)
	if err != nil {
		return err
	}

	// Delete the journal entry
	return s.repo.DeleteJournalEntry(ctx, bookID, journalEntryID)
}

// validateJournalEntryBalance validates that journal entry entries balance to zero
func (s *Service) validateJournalEntryBalance(entries []CreateJournalEntryLine) (int64, error) {
	if len(entries) < 2 {
		return 0, errors.NewValidationError("at least two entries are required for a valid journal entry")
	}

	// Calculate the sum of all entries
	var sum int64 = 0
	for _, entry := range entries {
		val, err := entry.Int64Amount()
		if err != nil {
			return 0, errors.NewValidationError("invalid amount value")
		}
		sum = sum + val
	}

	return sum, nil
}

// // verifyAccountsExist verifies that all accounts in the journal entry exist
// func (s *Service) verifyAccountsExist(ctx context.Context, bookID string, entries []CreateEntry) error {
// 	for _, entry := range entries {
// 		// Check if account exists
// 		_, err := s.accountRepo.GetAccount(ctx, bookID, entry.Account)
// 		if err != nil {
// 			return errors.NewValidationError(fmt.Sprintf("account %s does not exist", entry.Account))
// 		}
// 	}
// 	return nil
// }
