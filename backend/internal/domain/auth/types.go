package auth

import (
	"time"
)

// User represents an authenticated user with authentication details
type User struct {
	ID          string       `json:"id"`
	Email       string       `json:"email"`
	Name        string       `json:"name,omitempty"`
	FirstName   string       `json:"firstName,omitempty"`
	LastName    string       `json:"lastName,omitempty"`
	IsActive    bool         `json:"isActive"`
	Scopes      []string     `json:"scopes,omitempty"`
	Permissions []string     `json:"permissions,omitempty"`
	CreatedAt   time.Time    `json:"createdAt,omitempty"`
	UpdatedAt   time.Time    `json:"updatedAt,omitempty"`
	TokenMetadata TokenMetadata `json:"tokenMetadata,omitempty"`
}

// TokenMetadata contains information about the token
type TokenMetadata struct {
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// RegisterInput represents the input for user registration
type RegisterInput struct {
	Email       string `json:"email" validate:"required,email"`
	Password    string `json:"password" validate:"required,min=8"`
	FirstName   string `json:"firstName" validate:"required"`
	LastName    string `json:"lastName" validate:"required"`
	PhoneNumber string `json:"phoneNumber,omitempty"`
}

// RegisterOutput represents the output of user registration
type RegisterOutput struct {
	UserID              string `json:"userId"`
	UserConfirmed       bool   `json:"userConfirmed"`
	VerificationSent    bool   `json:"verificationSent"`
	VerificationMethod  string `json:"verificationMethod,omitempty"`
	VerificationChannel string `json:"verificationChannel,omitempty"`
}

// ConfirmRegistrationInput represents the input for confirming registration
type ConfirmRegistrationInput struct {
	Email            string `json:"email" validate:"required,email"`
	VerificationCode string `json:"verificationCode" validate:"required"`
}

// LoginInput represents the input for user login
type LoginInput struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// LoginOutput represents the output of user login
type LoginOutput struct {
	AccessToken      string `json:"accessToken,omitempty"`
	RefreshToken     string `json:"refreshToken,omitempty"`
	IdToken          string `json:"idToken,omitempty"`
	TokenType        string `json:"tokenType,omitempty"`
	ExpiresIn        int    `json:"expiresIn,omitempty"`
	RequiresChallenge bool   `json:"requiresChallenge,omitempty"`
	ChallengeType     string `json:"challengeType,omitempty"`
	ChallengeSession  string `json:"challengeSession,omitempty"`
}

// ChallengeInput represents the input for responding to an authentication challenge
type ChallengeInput struct {
	Email            string `json:"email" validate:"required,email"`
	ChallengeType    string `json:"challengeType" validate:"required"`
	ChallengeSession string `json:"challengeSession" validate:"required"`
	ChallengeResponse string `json:"challengeResponse" validate:"required"`
}

// RefreshTokenInput represents the input for refreshing a token
type RefreshTokenInput struct {
	RefreshToken string `json:"refreshToken" validate:"required"`
}

// RefreshTokenOutput represents the output of token refresh
type RefreshTokenOutput struct {
	AccessToken string `json:"accessToken"`
	IdToken     string `json:"idToken,omitempty"`
	TokenType   string `json:"tokenType"`
	ExpiresIn   int    `json:"expiresIn"`
}

// ResetPasswordInput represents the input for initiating a password reset
type ResetPasswordInput struct {
	Email string `json:"email" validate:"required,email"`
}

// ResetPasswordOutput represents the output of initiating a password reset
type ResetPasswordOutput struct {
	DeliveryMethod  string `json:"deliveryMethod"`
	DeliveryChannel string `json:"deliveryChannel"`
}

// ConfirmResetPasswordInput represents the input for confirming a password reset
type ConfirmResetPasswordInput struct {
	Email            string `json:"email" validate:"required,email"`
	VerificationCode string `json:"verificationCode" validate:"required"`
	NewPassword      string `json:"newPassword" validate:"required,min=8"`
}

// UpdateUserInput represents the input for updating user attributes
type UpdateUserInput struct {
	AccessToken string `json:"accessToken" validate:"required"`
	FirstName   string `json:"firstName"`
	LastName    string `json:"lastName"`
	PhoneNumber string `json:"phoneNumber"`
}

// ChangePasswordInput represents the input for changing a password
type ChangePasswordInput struct {
	AccessToken string `json:"accessToken" validate:"required"`
	OldPassword string `json:"oldPassword" validate:"required"`
	NewPassword string `json:"newPassword" validate:"required,min=8"`
}

// LogoutInput represents the input for logging out
type LogoutInput struct {
	RefreshToken string `json:"refreshToken" validate:"required"`
}

// OAuthClient represents a registered OAuth2 client application
type OAuthClient struct {
	ClientID         string   `json:"clientId"`
	ClientName       string   `json:"clientName"`
	ClientSecretHash string   `json:"clientSecretHash"`
	RedirectURIs     []string `json:"redirectUris"`
	GrantTypes       []string `json:"grantTypes"`
	Scopes           []string `json:"scopes"`
	ClientType       string   `json:"clientType"` // confidential, public
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
	Status           string    `json:"status"` // active, disabled, revoked
}

// OAuthToken represents an OAuth2 access token
type OAuthToken struct {
	UserID                string    `json:"userId"`
	ClientID              string    `json:"clientId"`
	AccessToken           string    `json:"accessToken"`
	RefreshToken          string    `json:"refreshToken,omitempty"`
	AccessTokenExpiresAt  time.Time `json:"accessTokenExpiresAt"`
	RefreshTokenExpiresAt time.Time `json:"refreshTokenExpiresAt,omitempty"`
	Scopes                []string  `json:"scopes"`
	CreatedAt             time.Time `json:"createdAt"`
	LastUsedAt            time.Time `json:"lastUsedAt,omitempty"`
	Status                string    `json:"status"` // active, revoked, expired
}