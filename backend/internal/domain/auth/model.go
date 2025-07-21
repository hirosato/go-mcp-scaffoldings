package auth

import (
	"time"
)

// UserRole represents the role of a user in the system
type UserRole string

const (
	// Admin represents a system administrator
	Admin UserRole = "admin"
	// BookOwner represents the owner of a book
	BookOwner UserRole = "book_owner"
	// BookMember represents a member with access to a book
	BookMember UserRole = "book_member"
	// BookViewer represents a user with view-only access to a book
	BookViewer UserRole = "book_viewer"
)

// AppUser represents a user in the system (application-specific user model)
type AppUser struct {
	UserID      string    `json:"userId"`
	Email       string    `json:"email"`
	Name        string    `json:"name"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
	AuthSettings AuthSettings `json:"authSettings,omitempty"`
	Preferences UserPreferences `json:"preferences,omitempty"`
}

// AuthSettings contains authentication-related settings for a user
type AuthSettings struct {
	MFAEnabled bool `json:"mfaEnabled"`
}

// UserPreferences contains user-specific preferences
type UserPreferences struct {
	Theme        string `json:"theme,omitempty"`
	DefaultView  string `json:"defaultView,omitempty"`
	DefaultBookID string `json:"defaultBookId,omitempty"`
}

// Book represents a financial book (collection of accounts and transactions)
type Book struct {
	BookID      string    `json:"bookId"`
	Name        string    `json:"name"`
	BookType    string    `json:"bookType"` // personal, business
	OwnerID     string    `json:"ownerId"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
	Status      string    `json:"status"`
	Settings    BookSettings `json:"settings,omitempty"`
}

// BookSettings contains settings for a book
type BookSettings struct {
	DefaultCurrency string `json:"defaultCurrency"`
	FiscalYearStart string `json:"fiscalYearStart"`
	DateFormat      string `json:"dateFormat"`
}

// BookShare represents a sharing configuration for a book
type BookShare struct {
	BookID      string    `json:"bookId"`
	ShareID     string    `json:"shareId"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	CreatedBy   string    `json:"createdBy"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
	Status      string    `json:"status"`
	ShareLevel  string    `json:"shareLevel"` // summary, detailed, custom
	CustomSettings ShareCustomSettings `json:"customSettings,omitempty"`
}

// ShareCustomSettings contains custom sharing settings
type ShareCustomSettings struct {
	ShowNetWorth           bool     `json:"showNetWorth"`
	ShowIncomeTotal        bool     `json:"showIncomeTotal"`
	ShowExpenseCategories  bool     `json:"showExpenseCategories"`
	ShowIndividualTransactions bool  `json:"showIndividualTransactions"`
	ExcludedAccounts       []string `json:"excludedAccounts,omitempty"`
	ExcludedCategories     []string `json:"excludedCategories,omitempty"`
}

// ShareMember represents a user with access to a shared book
type ShareMember struct {
	BookID      string    `json:"bookId"`
	ShareID     string    `json:"shareId"`
	UserID      string    `json:"userId"`
	Role        string    `json:"role"` // viewer, contributor
	InvitedBy   string    `json:"invitedBy"`
	InvitedAt   time.Time `json:"invitedAt"`
	AcceptedAt  *time.Time `json:"acceptedAt,omitempty"`
	LastAccessAt *time.Time `json:"lastAccessAt,omitempty"`
	Status      string    `json:"status"` // pending, active, revoked
	CustomPermissions ShareCustomPermissions `json:"customPermissions,omitempty"`
}

// ShareCustomPermissions contains custom permissions for a share member
type ShareCustomPermissions struct {
	CanSeeTransactions bool `json:"canSeeTransactions"`
	CanSeeBalances     bool `json:"canSeeBalances"`
	CanSeeNetWorth     bool `json:"canSeeNetWorth"`
}

// CreateBookRequest represents the request to create a new book
type CreateBookRequest struct {
	Name     string `json:"name" validate:"required"`
	BookType string `json:"bookType" validate:"required,oneof=personal business"`
	Settings BookSettings `json:"settings"`
}

// CreateShareRequest represents the request to create a new book share
type CreateShareRequest struct {
	BookID      string `json:"bookId" validate:"required"`
	Name        string `json:"name" validate:"required"`
	Description string `json:"description,omitempty"`
	ShareLevel  string `json:"shareLevel" validate:"required,oneof=summary detailed custom"`
	CustomSettings ShareCustomSettings `json:"customSettings,omitempty"`
}

// AddShareMemberRequest represents the request to add a member to a share
type AddShareMemberRequest struct {
	ShareID    string `json:"shareId" validate:"required"`
	Email      string `json:"email" validate:"required,email"`
	Role       string `json:"role" validate:"required,oneof=viewer contributor"`
	CustomPermissions ShareCustomPermissions `json:"customPermissions,omitempty"`
}