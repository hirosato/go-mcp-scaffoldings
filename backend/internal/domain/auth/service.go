package auth

import (
	"context"
)

// Service defines the interface for authentication service
// This is a technology-agnostic interface that can be implemented
// by any auth provider (Cognito, Firebase, custom JWT, etc.)
type Service interface {
	// User Registration and Authentication
	Register(ctx context.Context, input RegisterInput) (RegisterOutput, error)
	ConfirmRegistration(ctx context.Context, input ConfirmRegistrationInput) error
	Login(ctx context.Context, input LoginInput) (LoginOutput, error)
	RespondToChallenge(ctx context.Context, input ChallengeInput) (LoginOutput, error)
	RefreshToken(ctx context.Context, input RefreshTokenInput) (RefreshTokenOutput, error)
	ValidateToken(ctx context.Context, tokenString string) (User, error)
	
	// User Management
	GetUser(ctx context.Context, accessToken string) (User, error)
	UpdateUser(ctx context.Context, input UpdateUserInput) error
	ChangePassword(ctx context.Context, input ChangePasswordInput) error
	Logout(ctx context.Context, input LogoutInput) error
	
	// Password Reset
	ResetPassword(ctx context.Context, input ResetPasswordInput) (ResetPasswordOutput, error)
	ConfirmResetPassword(ctx context.Context, input ConfirmResetPasswordInput) error
}

// Repository defines the interface for storing and retrieving auth-related data
type Repository interface {
	// User Operations
	GetUserByID(ctx context.Context, userID string) (User, error)
	SaveUser(ctx context.Context, user User) error
	
	// OAuth Operations
	GetAppByClientID(ctx context.Context, clientID string) (OAuthClient, error)
	SaveOAuthClient(ctx context.Context, client OAuthClient) error
	GetOAuthTokenByRefreshToken(ctx context.Context, refreshToken string) (OAuthToken, error)
	SaveOAuthToken(ctx context.Context, token OAuthToken) error
}