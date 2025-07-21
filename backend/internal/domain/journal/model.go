package journal

import (
	"strconv"
	"time"
)

// JournalEntry represents a financial journal entry
type JournalEntry struct {
	JournalEntryID string         `json:"journalEntryId"`
	BookID         string         `json:"bookId"`
	Date           string         `json:"date"` //YYYY-MM-DD
	Description    string         `json:"description"`
	Notes          string         `json:"notes,omitempty"`
	Status         string         `json:"status"`     // PENDING, CLEARED, RECONCILED, VOIDED
	Visibility     string         `json:"visibility"` // PRIVATE, SHARED_SUMMARY, SHARED_FULL
	Segments       map[string]any `json:"segments,omitempty"`
	Lines          []Entry        `json:"lines,omitempty"`
	CreatedAt      time.Time      `json:"createdAt"`
	UpdatedAt      time.Time      `json:"updatedAt"`
	Tags           []string       `json:"tags,omitempty"`
}

func (t *JournalEntry) Year() string {
	year, _ := strconv.Atoi(t.Date[:4])
	return strconv.Itoa(year)
}

// CreateJournalEntryRequest represents the data needed to create a journal entry
type CreateJournalEntryRequest struct {
	JournalEntryID string                   `json:"journalEntryId"`
	BookID         string                   `json:"bookId"`
	Date           string                   `json:"date"` //YYYY-MM-DD
	Description    string                   `json:"description"`
	Notes          string                   `json:"notes,omitempty"`
	Status         string                   `json:"status"`     // PENDING, CLEARED, RECONCILED, VOIDED
	Visibility     string                   `json:"visibility"` // PRIVATE, SHARED_SUMMARY, SHARED_FULL
	Segments       map[string]any           `json:"segments,omitempty"`
	Lines          []CreateJournalEntryLine `json:"lines"`
	Tags           []string                 `json:"tags,omitempty"`
}

// Entry represents an entry in a journal entry
type Entry struct {
	EntryID     string         `json:"entryId"`
	Account     string         `json:"account"`
	Amount      string         `json:"amount"`
	Scale       string         `json:"scale"`
	Currency    string         `json:"currency"`
	Description string         `json:"description,omitempty"`
	Segments    map[string]any `json:"segments,omitempty"`
	Tags        []string       `json:"tags,omitempty"`
	CreatedAt   time.Time      `json:"createdAt"`
	UpdatedAt   time.Time      `json:"updatedAt"`
}

// CreateJournalEntryLine represents a single entry in a journal entry creation request
type CreateJournalEntryLine struct {
	Account     string         `json:"account"`
	Amount      string         `json:"amount"`
	Scale       string         `json:"scale"`
	Currency    string         `json:"currency"`
	Description string         `json:"description,omitempty"`
	Segments    map[string]any `json:"segments,omitempty"`
	Tags        []string       `json:"tags,omitempty"`
}

func (entry CreateJournalEntryLine) Int64Amount() (int64, error) {
	return strconv.ParseInt(string(entry.Amount), 10, 64)
}

// UpdateJournalEntryRequest represents a request to update a journal entry
type UpdateJournalEntryRequest struct {
	JournalEntryID string               `json:"journalEntryId"`
	BookID         string               `json:"bookId"`
	Date           string               `json:"date,omitempty"`
	Description    string               `json:"description,omitempty"`
	Notes          string               `json:"notes,omitempty"`
	Status         string               `json:"status,omitempty"`
	Visibility     string               `json:"visibility,omitempty"`
	Segments       map[string]any       `json:"segments,omitempty"`
	Lines          []UpdateEntryRequest `json:"lines"`
	CreatedAt      time.Time            `json:"createdAt"`
	Tags           []string             `json:"tags,omitempty"`
}

// UpdateEntryRequest represents a request to update an entry
type UpdateEntryRequest struct {
	EntryID     string         `json:"entryId"` // index in the entries array
	Account     string         `json:"account"`
	Amount      int64          `json:"amount"`
	Currency    string         `json:"currency"`
	Description string         `json:"description,omitempty"`
	Segments    map[string]any `json:"segments,omitempty"`
	Tags        []string       `json:"tags,omitempty"`
}

// GetJournalEntriesRequest represents filtering criteria for journal entry queries
type GetJournalEntriesRequest struct {
	NextToken string `json:"nextToken,omitempty"`
	Count     uint64 `json:"count"`
}

// GetJournalEntriesResponse represents a list of journal entries
type GetJournalEntriesResponse struct {
	JournalEntries []JournalEntry `json:"journalEntries"`
	TotalCount     int            `json:"totalCount"`
	NextToken      string         `json:"nextToken"`
}

// JournalEntryFilter represents the filtering criteria for journal entries
type JournalEntryFilter struct {
	AccountID         string
	StartDate         time.Time
	EndDate           time.Time
	Status            string
	SearchTerm        string
	IncludeEntries    bool
	SegmentType       string
	SegmentValue      string
	SortAscending     bool
	Limit             int
	ExclusiveStartKey string
}
