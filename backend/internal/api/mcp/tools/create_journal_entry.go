package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/domain/journal"
	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/domain/mcp"
)

type CreateJournalEntryTool struct {
	journalService *journal.Service
}

func NewCreateJournalEntryTool(journalService *journal.Service) *CreateJournalEntryTool {
	return &CreateJournalEntryTool{
		journalService: journalService,
	}
}

func (t *CreateJournalEntryTool) GetName() string {
	return "create-journal-entry"
}

func (t *CreateJournalEntryTool) GetDescription() string {
	return "Creates a new accounting journal entry with double-entry bookkeeping validation"
}

func (t *CreateJournalEntryTool) GetInputSchema() mcp.JSONSchema {
	return mcp.JSONSchema{
		Type: "object",
		Properties: map[string]interface{}{
			"bookId": map[string]string{
				"type":        "string",
				"description": "The book ID for the journal entry",
			},
			"date": map[string]string{
				"type":        "string",
				"description": "Journal entry date in YYYY-MM-DD format",
				"pattern":     "^[0-9]{4}-[0-9]{2}-[0-9]{2}$",
			},
			"description": map[string]string{
				"type":        "string",
				"description": "Description of the journal entry",
			},
			"notes": map[string]string{
				"type":        "string",
				"description": "Optional notes for the journal entry",
			},
			"status": map[string]interface{}{
				"type":        "string",
				"description": "Journal entry status",
				"enum":        []string{"PENDING", "CLEARED", "RECONCILED", "VOIDED"},
				"default":     "PENDING",
			},
			"visibility": map[string]interface{}{
				"type":        "string",
				"description": "Journal entry visibility level",
				"enum":        []string{"PRIVATE", "SHARED_SUMMARY", "SHARED_FULL"},
				"default":     "PRIVATE",
			},
			"lines": map[string]interface{}{
				"type":        "array",
				"description": "Journal entry line items (must balance to zero)",
				"minItems":    2,
				"items": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"account": map[string]string{
							"type":        "string",
							"description": "Account code or identifier",
						},
						"amount": map[string]string{
							"type":        "string",
							"description": "Amount as decimal string (positive for debits, negative for credits)",
						},
						"scale": map[string]string{
							"type":        "string",
							"description": "Decimal scale (default: 2)",
							"default":     "2",
						},
						"currency": map[string]string{
							"type":        "string",
							"description": "Currency code (e.g., USD, EUR)",
							"default":     "USD",
						},
						"description": map[string]string{
							"type":        "string",
							"description": "Entry-specific description",
						},
					},
					"required": []string{"account", "amount"},
				},
			},
			"tags": map[string]interface{}{
				"type":        "array",
				"description": "Optional tags for categorization",
				"items": map[string]string{
					"type": "string",
				},
			},
		},
		Required: []string{"bookId", "date", "description", "lines"},
	}
}

func (t *CreateJournalEntryTool) Execute(ctx context.Context, arguments json.RawMessage) (*mcp.CallToolResult, error) {
	var args struct {
		BookID      string `json:"bookId"`
		Date        string `json:"date"`
		Description string `json:"description"`
		Notes       string `json:"notes,omitempty"`
		Status      string `json:"status,omitempty"`
		Visibility  string `json:"visibility,omitempty"`
		Lines       []struct {
			Account     string `json:"account"`
			Amount      string `json:"amount"`
			Scale       string `json:"scale,omitempty"`
			Currency    string `json:"currency,omitempty"`
			Description string `json:"description,omitempty"`
		} `json:"lines"`
		Tags []string `json:"tags,omitempty"`
	}

	if err := json.Unmarshal(arguments, &args); err != nil {
		return &mcp.CallToolResult{
			Content: []mcp.ToolResultContent{
				{
					Type: "text",
					Text: fmt.Sprintf("Error parsing arguments: %v", err),
				},
			},
			IsError: true,
		}, nil
	}

	// Set defaults
	if args.Status == "" {
		args.Status = "PENDING"
	}
	if args.Visibility == "" {
		args.Visibility = "PRIVATE"
	}

	// Convert entries to journal entry format
	entries := make([]journal.CreateJournalEntryLine, len(args.Lines))
	for i, entry := range args.Lines {
		scale := entry.Scale
		if scale == "" {
			scale = "2"
		}
		currency := entry.Currency
		if currency == "" {
			currency = "USD"
		}

		entries[i] = journal.CreateJournalEntryLine{
			Account:     entry.Account,
			Amount:      entry.Amount,
			Scale:       scale,
			Currency:    currency,
			Description: entry.Description,
		}
	}

	// Create journal entry request
	req := &journal.CreateJournalEntryRequest{
		BookID:      args.BookID,
		Date:        args.Date,
		Description: args.Description,
		Notes:       args.Notes,
		Status:      args.Status,
		Visibility:  args.Visibility,
		Lines:       entries,
		Tags:        args.Tags,
	}

	// Create the journal entry
	journalEntry, err := t.journalService.CreateJournalEntry(ctx, args.BookID, req)
	if err != nil {
		return &mcp.CallToolResult{
			Content: []mcp.ToolResultContent{
				{
					Type: "text",
					Text: fmt.Sprintf("Error creating journal entry: %v", err),
				},
			},
			IsError: true,
		}, nil
	}

	// Format successful response
	responseData, err := json.MarshalIndent(journalEntry, "", "  ")
	if err != nil {
		return &mcp.CallToolResult{
			Content: []mcp.ToolResultContent{
				{
					Type: "text",
					Text: fmt.Sprintf("Journal entry created but error formatting response: %v", err),
				},
			},
			IsError: true,
		}, nil
	}

	return &mcp.CallToolResult{
		Content: []mcp.ToolResultContent{
			{
				Type: "text",
				Text: fmt.Sprintf("Journal entry created successfully:\n%s", string(responseData)),
			},
		},
		IsError: false,
	}, nil
}
