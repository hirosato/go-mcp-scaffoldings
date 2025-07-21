package cognito

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"

	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/common/config"
	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/domain/auth"
	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/domain/errors"
)

// NewService creates a new Cognito auth service
func NewService(
	client *cognitoidentityprovider.Client,
	repository Repository,
	cfg *config.Config,
	log slog.Logger,
) auth.Service {
	// Construct JWKS URL for token validation
	jwksURL := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", cfg.AWSRegion, cfg.UserPoolID)

	// Create the service
	service := &Service{
		cognitoClient: client,
		repository:    repository,
		userPoolID:    cfg.UserPoolID,
		clientID:      cfg.CognitoClientID,
		jwksURL:       jwksURL,
		log:           log,
		region:        cfg.AWSRegion,
	}

	// Fetch JWK set (don't fail if this fails, we'll retry later)
	jwkSet, err := jwk.Fetch(context.Background(), jwksURL)
	if err == nil {
		service.jwkSet = jwkSet
	} else {
		service.log.Warn("Failed to fetch JWK set, will retry on first token validation", "error", err)
	}

	return service
}

// RefreshJWKSet refreshes the JWK set used for token validation
func (s *Service) RefreshJWKSet(ctx context.Context) error {
	jwkSet, err := jwk.Fetch(ctx, s.jwksURL)
	if err != nil {
		return fmt.Errorf("failed to refresh JWK set: %w", err)
	}
	s.jwkSet = jwkSet
	return nil
}

// Register registers a new user
func (s *Service) Register(ctx context.Context, input auth.RegisterInput) (auth.RegisterOutput, error) {
	// Map attributes to Cognito format
	attributes := []types.AttributeType{
		{
			Name:  aws.String("email"),
			Value: aws.String(input.Email),
		},
		{
			Name:  aws.String("given_name"),
			Value: aws.String(input.FirstName),
		},
		{
			Name:  aws.String("family_name"),
			Value: aws.String(input.LastName),
		},
	}

	// Add optional attributes
	if input.PhoneNumber != "" {
		attributes = append(attributes, types.AttributeType{
			Name:  aws.String("phone_number"),
			Value: aws.String(input.PhoneNumber),
		})
	}

	// Call Cognito to sign up the user
	result, err := s.cognitoClient.SignUp(ctx, &cognitoidentityprovider.SignUpInput{
		ClientId:       aws.String(s.clientID),
		Username:       aws.String(input.Email),
		Password:       aws.String(input.Password),
		UserAttributes: attributes,
	})

	if err != nil {
		return auth.RegisterOutput{}, fmt.Errorf("failed to register user: %w", err)
	}

	// Save user to our repository
	user := auth.User{
		ID:        *result.UserSub,
		Email:     input.Email,
		FirstName: input.FirstName,
		LastName:  input.LastName,
		IsActive:  true,
		CreatedAt: time.Now().UTC(),
	}

	if err := s.repository.SaveUser(ctx, user); err != nil {
		s.log.Warn("Failed to save user to repository", "error", err)
	}

	return auth.RegisterOutput{
		UserID:              *result.UserSub,
		UserConfirmed:       result.UserConfirmed,
		VerificationSent:    !result.UserConfirmed,
		VerificationMethod:  "email", // Cognito defaults to email verification
		VerificationChannel: input.Email,
	}, nil
}

// ConfirmRegistration confirms a user's registration
func (s *Service) ConfirmRegistration(ctx context.Context, input auth.ConfirmRegistrationInput) error {
	_, err := s.cognitoClient.ConfirmSignUp(ctx, &cognitoidentityprovider.ConfirmSignUpInput{
		ClientId:         aws.String(s.clientID),
		Username:         aws.String(input.Email),
		ConfirmationCode: aws.String(input.VerificationCode),
	})

	if err != nil {
		return fmt.Errorf("failed to confirm registration: %w", err)
	}

	return nil
}

// Login authenticates a user and returns tokens
func (s *Service) Login(ctx context.Context, input auth.LoginInput) (auth.LoginOutput, error) {
	// Authenticate with Cognito
	authResult, err := s.cognitoClient.InitiateAuth(ctx, &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow: types.AuthFlowTypeUserPasswordAuth,
		ClientId: aws.String(s.clientID),
		AuthParameters: map[string]string{
			"USERNAME": input.Email,
			"PASSWORD": input.Password,
		},
	})

	if err != nil {
		return auth.LoginOutput{}, fmt.Errorf("authentication failed: %w", err)
	}

	// Check if the result contains challenge details
	if authResult.ChallengeName != "" {
		return auth.LoginOutput{
			RequiresChallenge: true,
			ChallengeType:     string(authResult.ChallengeName),
			ChallengeSession:  *authResult.Session,
		}, nil
	}

	// Authentication successful, extract tokens
	return auth.LoginOutput{
		AccessToken:  *authResult.AuthenticationResult.AccessToken,
		RefreshToken: *authResult.AuthenticationResult.RefreshToken,
		TokenType:    *authResult.AuthenticationResult.TokenType,
		ExpiresIn:    int(authResult.AuthenticationResult.ExpiresIn),
		IdToken:      *authResult.AuthenticationResult.IdToken,
	}, nil
}

// RespondToChallenge responds to an authentication challenge
func (s *Service) RespondToChallenge(ctx context.Context, input auth.ChallengeInput) (auth.LoginOutput, error) {
	// Respond to challenge
	result, err := s.cognitoClient.RespondToAuthChallenge(ctx, &cognitoidentityprovider.RespondToAuthChallengeInput{
		ClientId:      aws.String(s.clientID),
		ChallengeName: types.ChallengeNameType(input.ChallengeType),
		Session:       aws.String(input.ChallengeSession),
		ChallengeResponses: map[string]string{
			"USERNAME":     input.Email,
			"ANSWER":       input.ChallengeResponse,
			"SMS_MFA_CODE": input.ChallengeResponse, // For MFA challenges
		},
	})

	if err != nil {
		return auth.LoginOutput{}, fmt.Errorf("failed to respond to challenge: %w", err)
	}

	// Check if we have another challenge
	if result.ChallengeName != "" {
		return auth.LoginOutput{
			RequiresChallenge: true,
			ChallengeType:     string(result.ChallengeName),
			ChallengeSession:  *result.Session,
		}, nil
	}

	// Authentication successful, extract tokens
	return auth.LoginOutput{
		AccessToken:  *result.AuthenticationResult.AccessToken,
		RefreshToken: *result.AuthenticationResult.RefreshToken,
		TokenType:    *result.AuthenticationResult.TokenType,
		ExpiresIn:    int(result.AuthenticationResult.ExpiresIn),
		IdToken:      *result.AuthenticationResult.IdToken,
	}, nil
}

// RefreshToken refreshes an expired access token
func (s *Service) RefreshToken(ctx context.Context, input auth.RefreshTokenInput) (auth.RefreshTokenOutput, error) {
	// Call Cognito to refresh the token
	authResult, err := s.cognitoClient.InitiateAuth(ctx, &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow: types.AuthFlowTypeRefreshToken,
		ClientId: aws.String(s.clientID),
		AuthParameters: map[string]string{
			"REFRESH_TOKEN": input.RefreshToken,
		},
	})

	if err != nil {
		return auth.RefreshTokenOutput{}, fmt.Errorf("failed to refresh token: %w", err)
	}

	return auth.RefreshTokenOutput{
		AccessToken: *authResult.AuthenticationResult.AccessToken,
		TokenType:   *authResult.AuthenticationResult.TokenType,
		ExpiresIn:   int(authResult.AuthenticationResult.ExpiresIn),
		IdToken:     *authResult.AuthenticationResult.IdToken,
	}, nil
}

// ValidateToken validates a JWT token
func (s *Service) ValidateToken(ctx context.Context, tokenString string) (auth.User, error) {
	// Parse and validate token using JWK
	token, err := jwt.Parse(
		[]byte(tokenString),
		jwt.WithKeySet(s.jwkSet),
		jwt.WithValidate(true),
		jwt.WithIssuer(fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", s.region, s.userPoolID)),
		jwt.WithAudience(s.clientID),
	)

	if err != nil {
		// If token validation fails, try refreshing the JWK set once
		if refreshErr := s.RefreshJWKSet(ctx); refreshErr == nil {
			// Try validation again with the fresh JWK set
			token, err = jwt.Parse(
				[]byte(tokenString),
				jwt.WithKeySet(s.jwkSet),
				jwt.WithValidate(true),
				jwt.WithIssuer(fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", s.region, s.userPoolID)),
				jwt.WithAudience(s.clientID),
			)
		}

		if err != nil {
			return auth.User{}, errors.NewAuthorizationError("unauthorized: invalid token")
		}
	}

	// Extract user information from token
	userID, _ := token.Get("sub")
	email, _ := token.Get("email")
	name, _ := token.Get("name")
	givenName, _ := token.Get("given_name")
	familyName, _ := token.Get("family_name")

	// Get scopes from token
	var scopes []string
	if scopesClaim, ok := token.Get("scope"); ok {
		if scopesStr, ok := scopesClaim.(string); ok {
			scopes = parseScopesString(scopesStr)
		}
	}

	// Extract permissions
	var permissions []string
	if groupsClaim, ok := token.Get("cognito:groups"); ok {
		if groups, ok := groupsClaim.([]interface{}); ok {
			for _, group := range groups {
				if groupStr, ok := group.(string); ok {
					// In a real implementation, you might map groups to permissions
					permissions = append(permissions, "group:"+groupStr)
				}
			}
		}
	}

	// Extract token metadata
	issuedAt := time.Time{}
	if iat, ok := token.Get("iat"); ok {
		if iatFloat, ok := iat.(float64); ok {
			issuedAt = time.Unix(int64(iatFloat), 0)
		}
	}

	expiresAt := time.Time{}
	if exp, ok := token.Get("exp"); ok {
		if expFloat, ok := exp.(float64); ok {
			expiresAt = time.Unix(int64(expFloat), 0)
		}
	}

	return auth.User{
		ID:          userID.(string),
		Email:       email.(string),
		Name:        getStringOrDefault(name, ""),
		FirstName:   getStringOrDefault(givenName, ""),
		LastName:    getStringOrDefault(familyName, ""),
		Scopes:      scopes,
		Permissions: permissions,
		TokenMetadata: auth.TokenMetadata{
			IssuedAt:  issuedAt,
			ExpiresAt: expiresAt,
		},
	}, nil
}

// ResetPassword initiates a password reset flow
func (s *Service) ResetPassword(ctx context.Context, input auth.ResetPasswordInput) (auth.ResetPasswordOutput, error) {
	// Initiate forgot password flow
	result, err := s.cognitoClient.ForgotPassword(ctx, &cognitoidentityprovider.ForgotPasswordInput{
		ClientId: aws.String(s.clientID),
		Username: aws.String(input.Email),
	})

	if err != nil {
		return auth.ResetPasswordOutput{}, fmt.Errorf("failed to initiate password reset: %w", err)
	}

	deliveryMedium := "email"
	destination := ""

	if result.CodeDeliveryDetails != nil {
		deliveryMedium = string(result.CodeDeliveryDetails.DeliveryMedium)
		if result.CodeDeliveryDetails.Destination != nil {
			destination = *result.CodeDeliveryDetails.Destination
		}
	}

	return auth.ResetPasswordOutput{
		DeliveryMethod:  deliveryMedium,
		DeliveryChannel: destination,
	}, nil
}

// ConfirmResetPassword completes a password reset flow
func (s *Service) ConfirmResetPassword(ctx context.Context, input auth.ConfirmResetPasswordInput) error {
	_, err := s.cognitoClient.ConfirmForgotPassword(ctx, &cognitoidentityprovider.ConfirmForgotPasswordInput{
		ClientId:         aws.String(s.clientID),
		Username:         aws.String(input.Email),
		ConfirmationCode: aws.String(input.VerificationCode),
		Password:         aws.String(input.NewPassword),
	})

	if err != nil {
		return fmt.Errorf("failed to confirm password reset: %w", err)
	}

	return nil
}

// GetUser retrieves user details
func (s *Service) GetUser(ctx context.Context, accessToken string) (auth.User, error) {
	// Call Cognito to get user details
	result, err := s.cognitoClient.GetUser(ctx, &cognitoidentityprovider.GetUserInput{
		AccessToken: aws.String(accessToken),
	})

	if err != nil {
		return auth.User{}, fmt.Errorf("failed to get user details: %w", err)
	}

	// Extract user attributes
	user := auth.User{
		ID:    *result.Username,
		Email: "", // Will be populated from attributes
	}

	for _, attr := range result.UserAttributes {
		switch *attr.Name {
		case "email":
			user.Email = *attr.Value
		case "given_name":
			user.FirstName = *attr.Value
		case "family_name":
			user.LastName = *attr.Value
		case "name":
			user.Name = *attr.Value
		}
	}

	// Validate the token to get additional metadata
	validatedUser, err := s.ValidateToken(ctx, accessToken)
	if err == nil {
		// Merge token metadata with user details
		user.Scopes = validatedUser.Scopes
		user.Permissions = validatedUser.Permissions
		user.TokenMetadata = validatedUser.TokenMetadata
	}

	return user, nil
}

// UpdateUser updates user attributes
func (s *Service) UpdateUser(ctx context.Context, input auth.UpdateUserInput) error {
	// Prepare user attributes to update
	attributes := []types.AttributeType{}

	if input.FirstName != "" {
		attributes = append(attributes, types.AttributeType{
			Name:  aws.String("given_name"),
			Value: aws.String(input.FirstName),
		})
	}

	if input.LastName != "" {
		attributes = append(attributes, types.AttributeType{
			Name:  aws.String("family_name"),
			Value: aws.String(input.LastName),
		})
	}

	if input.PhoneNumber != "" {
		attributes = append(attributes, types.AttributeType{
			Name:  aws.String("phone_number"),
			Value: aws.String(input.PhoneNumber),
		})
	}

	// Only call if there are attributes to update
	if len(attributes) > 0 {
		_, err := s.cognitoClient.UpdateUserAttributes(ctx, &cognitoidentityprovider.UpdateUserAttributesInput{
			AccessToken:    aws.String(input.AccessToken),
			UserAttributes: attributes,
		})

		if err != nil {
			return fmt.Errorf("failed to update user attributes: %w", err)
		}
	}

	return nil
}

// ChangePassword changes a user's password
func (s *Service) ChangePassword(ctx context.Context, input auth.ChangePasswordInput) error {
	_, err := s.cognitoClient.ChangePassword(ctx, &cognitoidentityprovider.ChangePasswordInput{
		AccessToken:      aws.String(input.AccessToken),
		PreviousPassword: aws.String(input.OldPassword),
		ProposedPassword: aws.String(input.NewPassword),
	})

	if err != nil {
		return fmt.Errorf("failed to change password: %w", err)
	}

	return nil
}

// Logout revokes a user's tokens
func (s *Service) Logout(ctx context.Context, input auth.LogoutInput) error {
	_, err := s.cognitoClient.RevokeToken(ctx, &cognitoidentityprovider.RevokeTokenInput{
		ClientId: aws.String(s.clientID),
		Token:    aws.String(input.RefreshToken),
	})

	if err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}

	return nil
}

// Helper functions

// parseScopesString splits a space-delimited scopes string into a slice
func parseScopesString(scopesStr string) []string {
	// This is a simplified implementation
	// In a real system, you might want to handle quoted scopes, etc.
	var scopes []string
	var currentScope string
	inQuotes := false

	for _, char := range scopesStr {
		switch char {
		case '"':
			inQuotes = !inQuotes
		case ' ':
			if inQuotes {
				currentScope += string(char)
			} else if currentScope != "" {
				scopes = append(scopes, currentScope)
				currentScope = ""
			}
		default:
			currentScope += string(char)
		}
	}

	if currentScope != "" {
		scopes = append(scopes, currentScope)
	}

	return scopes
}

// getStringOrDefault safely converts an interface to string
func getStringOrDefault(val interface{}, defaultVal string) string {
	if val == nil {
		return defaultVal
	}
	if s, ok := val.(string); ok {
		return s
	}
	return defaultVal
}
