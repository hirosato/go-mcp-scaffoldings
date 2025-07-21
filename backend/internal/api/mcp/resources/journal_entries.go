package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/domain/journal"
	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/domain/mcp"
)

type JournalEntriesResource struct {
	journalService *journal.Service
}

func NewJournalEntriesResource(journalService *journal.Service) *JournalEntriesResource {
	return &JournalEntriesResource{
		journalService: journalService,
	}
}

func (r *JournalEntriesResource) GetURI() string {
	return "myapp://journal-entries"
}

func (r *JournalEntriesResource) GetName() string {
	return "Journal Entries"
}

func (r *JournalEntriesResource) GetDescription() string {
	return "Access to journal entry data. Supports patterns: myapp://journal-entries/{bookId} for listing journal entries, myapp://journal-entries/{bookId}/{entryId} for specific journal entry"
}

func (r *JournalEntriesResource) GetMimeType() string {
	return "application/json"
}

func (r *JournalEntriesResource) Read(ctx context.Context) (*mcp.ReadResourceResult, error) {
	return &mcp.ReadResourceResult{
		Contents: []mcp.ResourceContent{
			{
				URI:      r.GetURI(),
				MimeType: r.GetMimeType(),
				Text:     "Journal entries resource. Use specific URIs like myapp://journal-entries/{bookId} or myapp://journal-entries/{bookId}/{entryId}",
			},
		},
	}, nil
}

type JournalEntryResource struct {
	journalService *journal.Service
	bookID         string
	journalEntryID string
}

func NewJournalEntryResource(journalService *journal.Service, bookID, journalEntryID string) *JournalEntryResource {
	return &JournalEntryResource{
		journalService: journalService,
		bookID:         bookID,
		journalEntryID: journalEntryID,
	}
}

func (r *JournalEntryResource) GetURI() string {
	if r.journalEntryID != "" {
		return fmt.Sprintf("myapp://journal-entries/%s/%s", r.bookID, r.journalEntryID)
	}
	return fmt.Sprintf("myapp://journal-entries/%s", r.bookID)
}

func (r *JournalEntryResource) GetName() string {
	if r.journalEntryID != "" {
		return fmt.Sprintf("Journal Entry %s", r.journalEntryID)
	}
	return fmt.Sprintf("Journal Entries for Book %s", r.bookID)
}

func (r *JournalEntryResource) GetDescription() string {
	if r.journalEntryID != "" {
		return fmt.Sprintf("Details of journal entry %s in book %s", r.journalEntryID, r.bookID)
	}
	return fmt.Sprintf("List of journal entries in book %s", r.bookID)
}

func (r *JournalEntryResource) GetMimeType() string {
	return "application/json"
}

func (r *JournalEntryResource) Read(ctx context.Context) (*mcp.ReadResourceResult, error) {
	var content string

	if r.journalEntryID != "" {
		// Get specific journal entry
		journalEntry, err := r.journalService.GetJournalEntry(ctx, r.bookID, r.journalEntryID)
		if err != nil {
			return nil, fmt.Errorf("failed to get journal entry %s: %w", r.journalEntryID, err)
		}

		data, err := json.MarshalIndent(journalEntry, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal journal entry: %w", err)
		}
		content = string(data)
	} else {
		// Get journal entries list
		req := &journal.GetJournalEntriesRequest{
			Count: 100, // Default count
		}

		response, err := r.journalService.GetJournalEntries(ctx, r.bookID, req)
		if err != nil {
			return nil, fmt.Errorf("failed to get journal entries: %w", err)
		}

		data, err := json.MarshalIndent(response, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal journal entries: %w", err)
		}
		content = string(data)
	}

	return &mcp.ReadResourceResult{
		Contents: []mcp.ResourceContent{
			{
				URI:      r.GetURI(),
				MimeType: r.GetMimeType(),
				Text:     content,
			},
		},
	}, nil
}

// ResourceFactory creates resources based on URI patterns
type JournalEntryResourceFactory struct {
	journalService *journal.Service
}

func NewJournalEntryResourceFactory(journalService *journal.Service) *JournalEntryResourceFactory {
	return &JournalEntryResourceFactory{
		journalService: journalService,
	}
}

func (f *JournalEntryResourceFactory) CreateResource(uri string) (mcp.ResourceHandler, error) {
	// Parse URI patterns:
	// myapp://journal-entries -> base resource
	// myapp://journal-entries/{bookId} -> journal entries list
	// myapp://journal-entries/{bookId}/{entryId} -> specific journal entry

	if uri == "myapp://journal-entries" {
		return NewJournalEntriesResource(f.journalService), nil
	}

	if !strings.HasPrefix(uri, "myapp://journal-entries/") {
		return nil, fmt.Errorf("invalid URI pattern: %s", uri)
	}

	parts := strings.Split(strings.TrimPrefix(uri, "myapp://journal-entries/"), "/")

	if len(parts) == 1 && parts[0] != "" {
		// myapp://journal-entries/{bookId}
		bookID := parts[0]
		return NewJournalEntryResource(f.journalService, bookID, ""), nil
	}

	if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
		// myapp://journal-entries/{bookId}/{entryId}
		bookID := parts[0]
		journalEntryID := parts[1]
		return NewJournalEntryResource(f.journalService, bookID, journalEntryID), nil
	}

	return nil, fmt.Errorf("invalid URI pattern: %s", uri)
}
