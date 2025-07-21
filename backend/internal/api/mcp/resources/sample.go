package resources

import (
	"context"

	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/domain/mcp"
)

// SimpleResource is a demo resource implementation
type SimpleResource struct {
	URI         string
	Name        string
	Description string
}

func (r *SimpleResource) GetURI() string         { return r.URI }
func (r *SimpleResource) GetName() string        { return r.Name }
func (r *SimpleResource) GetDescription() string { return r.Description }
func (r *SimpleResource) GetMimeType() string    { return "text/plain" }

func (r *SimpleResource) Read(ctx context.Context) (*mcp.ReadResourceResult, error) {
	return &mcp.ReadResourceResult{
		Contents: []mcp.ResourceContent{
			{
				URI:      r.URI,
				MimeType: r.GetMimeType(),
				Text:     "This is a sample resource content for " + r.Description,
			},
		},
	}, nil
}
