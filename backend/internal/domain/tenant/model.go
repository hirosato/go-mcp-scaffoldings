package tenant

import (
	"context"
	"time"
)

// TenantContext represents the context for tenant-related operations
type TenantContext struct {
	TenantID string
	UserID   string
	BookID   string
	// Role       string
	// IsAdmin    bool
	// IsOwner    bool
	// Permissions []string
}

// Tenant represents a tenant
type Tenant struct {
	TenantID  string
	Name      string
	Type      string
	CreatedAt time.Time
	UpdatedAt time.Time
	Status    string
	OwnerID   string
	Settings  map[string]interface{}
}

// Repository defines the interface for tenant repository
type Repository interface {
	GetTenant(ctx context.Context, tenantID string) (*Tenant, error)
	CreateTenant(ctx context.Context, tenant *Tenant) (*Tenant, error)
	UpdateTenant(ctx context.Context, tenantID string, tenant *Tenant) (*Tenant, error)
	DeleteTenant(ctx context.Context, tenantID string) error
}

// Service defines the interface for tenant service
type Service interface {
	GetTenant(ctx context.Context, tenantID string) (*Tenant, error)
	CreateTenant(ctx context.Context, tenant *Tenant) (*Tenant, error)
	UpdateTenant(ctx context.Context, tenantID string, tenant *Tenant) (*Tenant, error)
	DeleteTenant(ctx context.Context, tenantID string) error
	GetTenantContext(ctx context.Context, tenantID string, userID string) (*TenantContext, error)
}

// NewService creates a new tenant service
func NewService(repo Repository) Service {
	return &tenantService{
		repo: repo,
	}
}

type tenantService struct {
	repo Repository
}

func (s *tenantService) GetTenant(ctx context.Context, tenantID string) (*Tenant, error) {
	return s.repo.GetTenant(ctx, tenantID)
}

func (s *tenantService) CreateTenant(ctx context.Context, tenant *Tenant) (*Tenant, error) {
	return s.repo.CreateTenant(ctx, tenant)
}

func (s *tenantService) UpdateTenant(ctx context.Context, tenantID string, tenant *Tenant) (*Tenant, error) {
	return s.repo.UpdateTenant(ctx, tenantID, tenant)
}

func (s *tenantService) DeleteTenant(ctx context.Context, tenantID string) error {
	return s.repo.DeleteTenant(ctx, tenantID)
}

func (s *tenantService) GetTenantContext(ctx context.Context, tenantID string, userID string) (*TenantContext, error) {
	return &TenantContext{
		TenantID: tenantID,
		UserID:   userID,
	}, nil
}
