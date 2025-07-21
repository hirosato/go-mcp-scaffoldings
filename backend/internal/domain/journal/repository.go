package journal

import (
	"context"
)

// Repository defines the interface for journal entry data operations
type Repository interface {
	// Create a new journal entry with entries
	CreateJournalEntry(ctx context.Context, req *CreateJournalEntryRequest) (*JournalEntry, error)

	// Get a journal entry by ID with its entries
	GetJournalEntry(ctx context.Context, bookID string, journalEntryID string) (*JournalEntry, error)

	// Get a journal entry by ID with its entries
	GetJournalEntryRevison(ctx context.Context, bookID string, journalEntryID string, revision uint) (*JournalEntry, error)

	// Get journal entries by criteria
	GetJournalEntries(ctx context.Context, bookID string, filter *GetJournalEntriesRequest) (*GetJournalEntriesResponse, error)

	// Update an existing journal entry
	UpdateJournalEntry(ctx context.Context, bookID string, journalEntryID string, updateReq *UpdateJournalEntryRequest) (*JournalEntry, error)

	// Delete a journal entry
	DeleteJournalEntry(ctx context.Context, bookID string, journalEntryID string) error
}
