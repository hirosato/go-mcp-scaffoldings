package prompts

import (
	"context"
	"fmt"

	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/domain/mcp"
)

// AnalyzeFinancialReportPrompt is a sample prompt for analyzing financial reports
type AnalyzeFinancialReportPrompt struct{}

func (p *AnalyzeFinancialReportPrompt) GetName() string {
	return "analyze-financial-report"
}

func (p *AnalyzeFinancialReportPrompt) GetDescription() string {
	return "Analyze financial data and generate insights based on journal entries"
}

func (p *AnalyzeFinancialReportPrompt) GetArguments() []mcp.PromptArgument {
	return []mcp.PromptArgument{
		{
			Name:        "period",
			Description: "The time period to analyze (e.g., 'Q1 2024', 'January 2024')",
			Required:    true,
		},
		{
			Name:        "focus_areas",
			Description: "Specific areas to focus on (e.g., 'revenue', 'expenses', 'cash flow')",
			Required:    false,
		},
	}
}

func (p *AnalyzeFinancialReportPrompt) GetPrompt(ctx context.Context, arguments map[string]interface{}) (*mcp.GetPromptResult, error) {
	// Extract arguments
	period, ok := arguments["period"].(string)
	if !ok || period == "" {
		return nil, fmt.Errorf("period argument is required")
	}

	focusAreas := "all areas"
	if fa, ok := arguments["focus_areas"].(string); ok && fa != "" {
		focusAreas = fa
	}

	// Build the prompt messages
	messages := []mcp.PromptMessage{
		{
			Role: "user",
			Content: mcp.PromptContent{
				Type: "text",
				Text: fmt.Sprintf(`Please analyze the financial data for %s and provide insights on %s.

Consider the following aspects:
1. Key financial metrics and trends
2. Significant changes from previous periods
3. Areas of concern or opportunity
4. Recommendations for improvement

Base your analysis on the journal entries available in the system.`, period, focusAreas),
			},
		},
		{
			Role: "assistant",
			Content: mcp.PromptContent{
				Type: "text",
				Text: "I'll analyze the financial data for the specified period. Let me start by examining the journal entries.",
			},
		},
		{
			Role: "user",
			Content: mcp.PromptContent{
				Type: "resource",
				Resource: &mcp.PromptResource{
					URI:  "journal-entries://" + period,
					Text: "Journal entries for the specified period",
				},
			},
		},
	}

	return &mcp.GetPromptResult{
		Messages: messages,
	}, nil
}

// CreateBudgetPrompt is another sample prompt for creating budgets
type CreateBudgetPrompt struct{}

func (p *CreateBudgetPrompt) GetName() string {
	return "create-budget"
}

func (p *CreateBudgetPrompt) GetDescription() string {
	return "Create a budget plan based on historical financial data"
}

func (p *CreateBudgetPrompt) GetArguments() []mcp.PromptArgument {
	return []mcp.PromptArgument{
		{
			Name:        "budget_period",
			Description: "The period for the budget (e.g., 'Q2 2024', 'FY 2024')",
			Required:    true,
		},
		{
			Name:        "baseline_period",
			Description: "Historical period to use as baseline (e.g., 'Q1 2024')",
			Required:    true,
		},
		{
			Name:        "growth_rate",
			Description: "Expected growth rate as percentage (e.g., '10' for 10%)",
			Required:    false,
		},
	}
}

func (p *CreateBudgetPrompt) GetPrompt(ctx context.Context, arguments map[string]interface{}) (*mcp.GetPromptResult, error) {
	// Extract arguments
	budgetPeriod, ok := arguments["budget_period"].(string)
	if !ok || budgetPeriod == "" {
		return nil, fmt.Errorf("budget_period argument is required")
	}

	baselinePeriod, ok := arguments["baseline_period"].(string)
	if !ok || baselinePeriod == "" {
		return nil, fmt.Errorf("baseline_period argument is required")
	}

	growthRate := "0"
	if gr, ok := arguments["growth_rate"].(string); ok && gr != "" {
		growthRate = gr
	}

	// Build the prompt messages
	messages := []mcp.PromptMessage{
		{
			Role: "user",
			Content: mcp.PromptContent{
				Type: "text",
				Text: fmt.Sprintf(`Create a detailed budget plan for %s based on the historical data from %s.

Requirements:
1. Apply a growth rate of %s%% to revenue projections
2. Analyze expense patterns and suggest optimizations
3. Identify fixed vs variable costs
4. Provide monthly breakdown
5. Include contingency recommendations

Use the historical journal entries as the foundation for your projections.`, budgetPeriod, baselinePeriod, growthRate),
			},
		},
		{
			Role: "assistant",
			Content: mcp.PromptContent{
				Type: "text",
				Text: "I'll create a comprehensive budget plan based on your historical data. Let me first analyze the baseline period.",
			},
		},
		{
			Role: "user",
			Content: mcp.PromptContent{
				Type: "resource",
				Resource: &mcp.PromptResource{
					URI:  "journal-entries://" + baselinePeriod,
					Text: "Historical journal entries for baseline period",
				},
			},
		},
	}

	return &mcp.GetPromptResult{
		Messages: messages,
	}, nil
}

// SimplePrompt is a demo prompt implementation
type SimplePrompt struct {
	Name        string
	Description string
}

func (p *SimplePrompt) GetName() string        { return p.Name }
func (p *SimplePrompt) GetDescription() string { return p.Description }
func (p *SimplePrompt) GetArguments() []mcp.PromptArgument {
	return []mcp.PromptArgument{
		{
			Name:        "name",
			Description: "The name to greet",
			Required:    true,
		},
	}
}

func (p *SimplePrompt) GetPrompt(ctx context.Context, arguments map[string]interface{}) (*mcp.GetPromptResult, error) {
	name, ok := arguments["name"].(string)
	if !ok || name == "" {
		return nil, fmt.Errorf("name argument is required")
	}

	return &mcp.GetPromptResult{
		Messages: []mcp.PromptMessage{
			{
				Role: "user",
				Content: mcp.PromptContent{
					Type: "text",
					Text: fmt.Sprintf("Hello, %s! Please introduce yourself.", name),
				},
			},
		},
	}, nil
}
