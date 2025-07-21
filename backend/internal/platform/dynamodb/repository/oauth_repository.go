package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/domain/oauth"
	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/platform/dynamodb/client"
	"golang.org/x/crypto/bcrypt"
)

// OAuthClientRepository implements OAuth client storage in DynamoDB
type OAuthClientRepository struct {
	client    client.Client
	tableName string
}

// NewOAuthClientRepository creates a new OAuth client repository
func NewOAuthClientRepository(dbClient client.Client, tableName string) *OAuthClientRepository {
	return &OAuthClientRepository{
		client:    dbClient,
		tableName: tableName,
	}
}

// CreateClient creates a new OAuth client
func (r *OAuthClientRepository) CreateClient(ctx context.Context, client *oauth.Client) error {
	item, err := attributevalue.MarshalMap(map[string]interface{}{
		"PK":                          fmt.Sprintf("CLIENT#%s", client.ID),
		"SK":                          "METADATA",
		"Type":                        "OAuthClient",
		"ClientID":                    client.ID,
		"ClientSecret":                client.Secret,
		"ClientName":                  client.Name,
		"RedirectURIs":                client.RedirectURIs,
		"GrantTypes":                  client.GrantTypes,
		"Scopes":                      client.Scopes,
		"TokenEndpointAuthMethod":     client.TokenEndpointAuthMethod,
		"TokenEndpointAuthSigningAlg": client.TokenEndpointAuthSigningAlg,
		"FailedAuthCount":             client.FailedAuthCount,
		"CreatedAt":                   client.CreatedAt.Format(time.RFC3339),
		"UpdatedAt":                   client.UpdatedAt.Format(time.RFC3339),
	})
	if err != nil {
		return err
	}

	_, err = r.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(r.tableName),
		Item:                item,
		ConditionExpression: aws.String("attribute_not_exists(PK)"),
	})

	return err
}

// GetClient retrieves a client by ID
func (r *OAuthClientRepository) GetClient(ctx context.Context, clientID string) (*oauth.Client, error) {
	result, err := r.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(r.tableName),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: fmt.Sprintf("CLIENT#%s", clientID)},
			"SK": &types.AttributeValueMemberS{Value: "METADATA"},
		},
	})

	if err != nil {
		return nil, err
	}

	if result.Item == nil {
		return nil, oauth.ErrClientNotFound
	}

	var item struct {
		ClientID                    string   `dynamodbav:"ClientID"`
		ClientSecret                string   `dynamodbav:"ClientSecret"`
		ClientName                  string   `dynamodbav:"ClientName"`
		RedirectURIs                []string `dynamodbav:"RedirectURIs"`
		GrantTypes                  []string `dynamodbav:"GrantTypes"`
		Scopes                      []string `dynamodbav:"Scopes"`
		TokenEndpointAuthMethod     string   `dynamodbav:"TokenEndpointAuthMethod"`
		TokenEndpointAuthSigningAlg string   `dynamodbav:"TokenEndpointAuthSigningAlg"`
		FailedAuthCount             int      `dynamodbav:"FailedAuthCount"`
		LastFailedAuthAt            string   `dynamodbav:"LastFailedAuthAt"`
		LockedUntil                 string   `dynamodbav:"LockedUntil"`
		CreatedAt                   string   `dynamodbav:"CreatedAt"`
		UpdatedAt                   string   `dynamodbav:"UpdatedAt"`
	}

	if err := attributevalue.UnmarshalMap(result.Item, &item); err != nil {
		return nil, err
	}

	createdAt, _ := time.Parse(time.RFC3339, item.CreatedAt)
	updatedAt, _ := time.Parse(time.RFC3339, item.UpdatedAt)

	// Parse optional timestamp fields
	var lastFailedAuthAt *time.Time
	if item.LastFailedAuthAt != "" {
		if t, err := time.Parse(time.RFC3339, item.LastFailedAuthAt); err == nil {
			lastFailedAuthAt = &t
		}
	}

	var lockedUntil *time.Time
	if item.LockedUntil != "" {
		if t, err := time.Parse(time.RFC3339, item.LockedUntil); err == nil {
			lockedUntil = &t
		}
	}

	return &oauth.Client{
		ID:                          item.ClientID,
		Secret:                      item.ClientSecret,
		Name:                        item.ClientName,
		RedirectURIs:                item.RedirectURIs,
		GrantTypes:                  item.GrantTypes,
		Scopes:                      item.Scopes,
		TokenEndpointAuthMethod:     item.TokenEndpointAuthMethod,
		TokenEndpointAuthSigningAlg: item.TokenEndpointAuthSigningAlg,
		FailedAuthCount:             item.FailedAuthCount,
		LastFailedAuthAt:            lastFailedAuthAt,
		LockedUntil:                 lockedUntil,
		CreatedAt:                   createdAt,
		UpdatedAt:                   updatedAt,
	}, nil
}

// UpdateClient updates an existing client
func (r *OAuthClientRepository) UpdateClient(ctx context.Context, client *oauth.Client) error {
	_, err := r.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(r.tableName),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: fmt.Sprintf("CLIENT#%s", client.ID)},
			"SK": &types.AttributeValueMemberS{Value: "METADATA"},
		},
		UpdateExpression: aws.String("SET ClientName = :name, RedirectURIs = :uris, GrantTypes = :grants, Scopes = :scopes, UpdatedAt = :updated"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":name":    &types.AttributeValueMemberS{Value: client.Name},
			":uris":    &types.AttributeValueMemberL{Value: marshalStringList(client.RedirectURIs)},
			":grants":  &types.AttributeValueMemberL{Value: marshalStringList(client.GrantTypes)},
			":scopes":  &types.AttributeValueMemberL{Value: marshalStringList(client.Scopes)},
			":updated": &types.AttributeValueMemberS{Value: time.Now().Format(time.RFC3339)},
		},
	})

	return err
}

// DeleteClient deletes a client
func (r *OAuthClientRepository) DeleteClient(ctx context.Context, clientID string) error {
	_, err := r.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(r.tableName),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: fmt.Sprintf("CLIENT#%s", clientID)},
			"SK": &types.AttributeValueMemberS{Value: "METADATA"},
		},
	})

	return err
}

// ValidateClientCredentials validates client ID and secret
func (r *OAuthClientRepository) ValidateClientCredentials(ctx context.Context, clientID, clientSecret string) error {
	client, err := r.GetClient(ctx, clientID)
	if err != nil {
		return err
	}

	// Compare the provided secret with the stored hash
	if err := bcrypt.CompareHashAndPassword([]byte(client.Secret), []byte(clientSecret)); err != nil {
		return oauth.ErrInvalidClient
	}

	return nil
}

// IncrementFailedAuthCount increments the failed authentication count
func (r *OAuthClientRepository) IncrementFailedAuthCount(ctx context.Context, clientID string) error {
	now := time.Now()
	_, err := r.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(r.tableName),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: fmt.Sprintf("CLIENT#%s", clientID)},
			"SK": &types.AttributeValueMemberS{Value: "METADATA"},
		},
		UpdateExpression: aws.String("ADD FailedAuthCount :inc SET LastFailedAuthAt = :timestamp, UpdatedAt = :updated"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":inc":       &types.AttributeValueMemberN{Value: "1"},
			":timestamp": &types.AttributeValueMemberS{Value: now.Format(time.RFC3339)},
			":updated":   &types.AttributeValueMemberS{Value: now.Format(time.RFC3339)},
		},
	})
	return err
}

// ResetFailedAuthCount resets the failed authentication count
func (r *OAuthClientRepository) ResetFailedAuthCount(ctx context.Context, clientID string) error {
	_, err := r.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(r.tableName),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: fmt.Sprintf("CLIENT#%s", clientID)},
			"SK": &types.AttributeValueMemberS{Value: "METADATA"},
		},
		UpdateExpression: aws.String("SET FailedAuthCount = :zero, UpdatedAt = :updated REMOVE LastFailedAuthAt, LockedUntil"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":zero":    &types.AttributeValueMemberN{Value: "0"},
			":updated": &types.AttributeValueMemberS{Value: time.Now().Format(time.RFC3339)},
		},
	})
	return err
}

// LockClient temporarily locks a client due to too many failed attempts
func (r *OAuthClientRepository) LockClient(ctx context.Context, clientID string, lockUntil time.Time) error {
	_, err := r.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(r.tableName),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: fmt.Sprintf("CLIENT#%s", clientID)},
			"SK": &types.AttributeValueMemberS{Value: "METADATA"},
		},
		UpdateExpression: aws.String("SET LockedUntil = :lock_until, UpdatedAt = :updated"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":lock_until": &types.AttributeValueMemberS{Value: lockUntil.Format(time.RFC3339)},
			":updated":    &types.AttributeValueMemberS{Value: time.Now().Format(time.RFC3339)},
		},
	})
	return err
}

// OAuthCodeRepository implements authorization code storage in DynamoDB
type OAuthCodeRepository struct {
	client    client.Client
	tableName string
}

// NewOAuthCodeRepository creates a new authorization code repository
func NewOAuthCodeRepository(dbClient client.Client, tableName string) *OAuthCodeRepository {
	return &OAuthCodeRepository{
		client:    dbClient,
		tableName: tableName,
	}
}

// StoreAuthorizationCode stores a new authorization code
func (r *OAuthCodeRepository) StoreAuthorizationCode(ctx context.Context, code *oauth.AuthorizationCode) error {
	item, err := attributevalue.MarshalMap(map[string]interface{}{
		"PK":                  fmt.Sprintf("CODE#%s", code.Code),
		"SK":                  "METADATA",
		"Type":                "AuthorizationCode",
		"Code":                code.Code,
		"ClientID":            code.ClientID,
		"RedirectURI":         code.RedirectURI,
		"Scope":               code.Scope,
		"State":               code.State,
		"CodeChallenge":       code.CodeChallenge,
		"CodeChallengeMethod": code.CodeChallengeMethod,
		"ExpiresAt":           code.ExpiresAt.Unix(),
		"CreatedAt":           code.CreatedAt.Format(time.RFC3339),
		"TTL":                 code.ExpiresAt.Unix(), // DynamoDB TTL
	})
	if err != nil {
		return err
	}

	_, err = r.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(r.tableName),
		Item:      item,
	})

	return err
}

// GetAuthorizationCode retrieves an authorization code
func (r *OAuthCodeRepository) GetAuthorizationCode(ctx context.Context, code string) (*oauth.AuthorizationCode, error) {
	result, err := r.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(r.tableName),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: fmt.Sprintf("CODE#%s", code)},
			"SK": &types.AttributeValueMemberS{Value: "METADATA"},
		},
	})

	if err != nil {
		return nil, err
	}

	if result.Item == nil {
		return nil, errors.New("authorization code not found")
	}

	var item struct {
		Code                string `dynamodbav:"Code"`
		ClientID            string `dynamodbav:"ClientID"`
		RedirectURI         string `dynamodbav:"RedirectURI"`
		Scope               string `dynamodbav:"Scope"`
		State               string `dynamodbav:"State"`
		CodeChallenge       string `dynamodbav:"CodeChallenge"`
		CodeChallengeMethod string `dynamodbav:"CodeChallengeMethod"`
		ExpiresAt           int64  `dynamodbav:"ExpiresAt"`
		CreatedAt           string `dynamodbav:"CreatedAt"`
	}

	if err := attributevalue.UnmarshalMap(result.Item, &item); err != nil {
		return nil, err
	}

	createdAt, _ := time.Parse(time.RFC3339, item.CreatedAt)

	return &oauth.AuthorizationCode{
		Code:                item.Code,
		ClientID:            item.ClientID,
		RedirectURI:         item.RedirectURI,
		Scope:               item.Scope,
		State:               item.State,
		CodeChallenge:       item.CodeChallenge,
		CodeChallengeMethod: item.CodeChallengeMethod,
		ExpiresAt:           time.Unix(item.ExpiresAt, 0),
		CreatedAt:           createdAt,
	}, nil
}

// DeleteAuthorizationCode deletes an authorization code (one-time use)
func (r *OAuthCodeRepository) DeleteAuthorizationCode(ctx context.Context, code string) error {
	_, err := r.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(r.tableName),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: fmt.Sprintf("CODE#%s", code)},
			"SK": &types.AttributeValueMemberS{Value: "METADATA"},
		},
	})

	return err
}

// CleanupExpiredCodes removes expired authorization codes (handled by DynamoDB TTL)
func (r *OAuthCodeRepository) CleanupExpiredCodes(ctx context.Context) error {
	// DynamoDB TTL handles this automatically
	return nil
}

// OAuthTokenRepository implements token storage in DynamoDB
type OAuthTokenRepository struct {
	client    client.Client
	tableName string
}

// NewOAuthTokenRepository creates a new token repository
func NewOAuthTokenRepository(dbClient client.Client, tableName string) *OAuthTokenRepository {
	return &OAuthTokenRepository{
		client:    dbClient,
		tableName: tableName,
	}
}

// StoreToken stores a new access or refresh token
func (r *OAuthTokenRepository) StoreToken(ctx context.Context, token *oauth.Token) error {
	item, err := attributevalue.MarshalMap(map[string]interface{}{
		"PK":           fmt.Sprintf("TOKEN#%s", token.ID),
		"SK":           "METADATA",
		"Type":         "Token",
		"TokenID":      token.ID,
		"TokenType":    token.TokenType,
		"ClientID":     token.ClientID,
		"UserID":       token.UserID,
		"Scope":        token.Scope,
		"RefreshToken": token.RefreshToken,
		"ExpiresAt":    token.ExpiresAt.Unix(),
		"CreatedAt":    token.CreatedAt.Format(time.RFC3339),
		"GSI1PK":       fmt.Sprintf("CLIENT#%s", token.ClientID),
		"GSI1SK":       fmt.Sprintf("TOKEN#%s", token.ID),
	})
	if err != nil {
		return err
	}

	// Only set TTL for access tokens, not refresh tokens
	// This allows us to track refresh token usage even after expiration
	// which is important for security (OAuth 2.1 requirement)
	if token.TokenType == "access" {
		item["TTL"] = &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", token.ExpiresAt.Unix())}
	}

	// Add GSI2 attributes if UserID is present
	if token.UserID != "" {
		item["GSI2PK"] = &types.AttributeValueMemberS{Value: fmt.Sprintf("USER#%s", token.UserID)}
		item["GSI2SK"] = &types.AttributeValueMemberS{Value: fmt.Sprintf("TOKEN#%s", token.ID)}
	}

	// Add refresh token index if present
	if token.TokenType == "refresh" {
		item["GSI3PK"] = &types.AttributeValueMemberS{Value: fmt.Sprintf("REFRESH#%s", token.RefreshToken)}
		item["GSI3SK"] = &types.AttributeValueMemberS{Value: "METADATA"}
	}

	_, err = r.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(r.tableName),
		Item:      item,
	})

	return err
}

// GetToken retrieves a token by ID
func (r *OAuthTokenRepository) GetToken(ctx context.Context, tokenID string) (*oauth.Token, error) {
	result, err := r.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(r.tableName),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: fmt.Sprintf("TOKEN#%s", tokenID)},
			"SK": &types.AttributeValueMemberS{Value: "METADATA"},
		},
	})

	if err != nil {
		return nil, err
	}

	if result.Item == nil {
		return nil, oauth.ErrInvalidGrant
	}

	return unmarshalToken(result.Item)
}

// GetTokenByRefreshToken retrieves a token by refresh token
func (r *OAuthTokenRepository) GetTokenByRefreshToken(ctx context.Context, refreshToken string) (*oauth.Token, error) {
	result, err := r.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(r.tableName),
		IndexName:              aws.String("GSI3"),
		KeyConditionExpression: aws.String("GSI3PK = :pk"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: fmt.Sprintf("REFRESH#%s", refreshToken)},
		},
		Limit: aws.Int32(1),
	})

	if err != nil {
		return nil, err
	}

	if len(result.Items) == 0 {
		return nil, oauth.ErrInvalidGrant
	}

	return unmarshalToken(result.Items[0])
}

// RevokeToken revokes a token
func (r *OAuthTokenRepository) RevokeToken(ctx context.Context, tokenID string) error {
	_, err := r.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(r.tableName),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: fmt.Sprintf("TOKEN#%s", tokenID)},
			"SK": &types.AttributeValueMemberS{Value: "METADATA"},
		},
		UpdateExpression: aws.String("SET RevokedAt = :revoked"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":revoked": &types.AttributeValueMemberS{Value: time.Now().Format(time.RFC3339)},
		},
	})

	return err
}

// RevokeTokensByClientID revokes all tokens for a client
func (r *OAuthTokenRepository) RevokeTokensByClientID(ctx context.Context, clientID string) error {
	// Query all tokens for the client
	result, err := r.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(r.tableName),
		IndexName:              aws.String("GSI1"),
		KeyConditionExpression: aws.String("GSI1PK = :pk"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: fmt.Sprintf("CLIENT#%s", clientID)},
		},
	})

	if err != nil {
		return err
	}

	// Revoke each token
	for _, item := range result.Items {
		var tokenID string
		if v, ok := item["TokenID"]; ok {
			if s, ok := v.(*types.AttributeValueMemberS); ok {
				tokenID = s.Value
			}
		}
		if tokenID != "" {
			_ = r.RevokeToken(ctx, tokenID)
		}
	}

	return nil
}

// RevokeTokensByUserID revokes all tokens for a user
func (r *OAuthTokenRepository) RevokeTokensByUserID(ctx context.Context, userID string) error {
	// Query all tokens for the user
	result, err := r.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(r.tableName),
		IndexName:              aws.String("GSI2"),
		KeyConditionExpression: aws.String("GSI2PK = :pk"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: fmt.Sprintf("USER#%s", userID)},
		},
	})

	if err != nil {
		return err
	}

	// Revoke each token
	for _, item := range result.Items {
		var tokenID string
		if v, ok := item["TokenID"]; ok {
			if s, ok := v.(*types.AttributeValueMemberS); ok {
				tokenID = s.Value
			}
		}
		if tokenID != "" {
			_ = r.RevokeToken(ctx, tokenID)
		}
	}

	return nil
}

// CleanupExpiredTokens removes expired tokens (handled by DynamoDB TTL)
func (r *OAuthTokenRepository) CleanupExpiredTokens(ctx context.Context) error {
	// DynamoDB TTL handles this automatically
	return nil
}

// GetActiveTokensByClientID retrieves all active tokens for a client
func (r *OAuthTokenRepository) GetActiveTokensByClientID(ctx context.Context, clientID string) ([]*oauth.Token, error) {
	result, err := r.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(r.tableName),
		IndexName:              aws.String("GSI1"),
		KeyConditionExpression: aws.String("GSI1PK = :pk"),
		FilterExpression:       aws.String("attribute_not_exists(RevokedAt)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: fmt.Sprintf("CLIENT#%s", clientID)},
		},
	})

	if err != nil {
		return nil, err
	}

	tokens := make([]*oauth.Token, 0, len(result.Items))
	for _, item := range result.Items {
		token, err := unmarshalToken(item)
		if err == nil && token.RevokedAt == nil {
			tokens = append(tokens, token)
		}
	}

	return tokens, nil
}

// Helper functions

func marshalStringList(list []string) []types.AttributeValue {
	values := make([]types.AttributeValue, len(list))
	for i, s := range list {
		values[i] = &types.AttributeValueMemberS{Value: s}
	}
	return values
}

func unmarshalToken(item map[string]types.AttributeValue) (*oauth.Token, error) {
	var tokenData struct {
		TokenID      string  `dynamodbav:"TokenID"`
		TokenType    string  `dynamodbav:"TokenType"`
		ClientID     string  `dynamodbav:"ClientID"`
		UserID       string  `dynamodbav:"UserID"`
		Scope        string  `dynamodbav:"Scope"`
		RefreshToken string  `dynamodbav:"RefreshToken"`
		ExpiresAt    int64   `dynamodbav:"ExpiresAt"`
		CreatedAt    string  `dynamodbav:"CreatedAt"`
		RevokedAt    *string `dynamodbav:"RevokedAt"`
	}

	if err := attributevalue.UnmarshalMap(item, &tokenData); err != nil {
		return nil, err
	}

	createdAt, _ := time.Parse(time.RFC3339, tokenData.CreatedAt)

	token := &oauth.Token{
		ID:           tokenData.TokenID,
		TokenType:    tokenData.TokenType,
		ClientID:     tokenData.ClientID,
		UserID:       tokenData.UserID,
		Scope:        tokenData.Scope,
		RefreshToken: tokenData.RefreshToken,
		ExpiresAt:    time.Unix(tokenData.ExpiresAt, 0),
		CreatedAt:    createdAt,
	}

	if tokenData.RevokedAt != nil {
		revokedAt, _ := time.Parse(time.RFC3339, *tokenData.RevokedAt)
		token.RevokedAt = &revokedAt
	}

	return token, nil
}

// SecurityEventRepository implements security event logging in DynamoDB
type SecurityEventRepository struct {
	client    client.Client
	tableName string
}

// NewSecurityEventRepository creates a new security event repository
func NewSecurityEventRepository(dbClient client.Client, tableName string) *SecurityEventRepository {
	return &SecurityEventRepository{
		client:    dbClient,
		tableName: tableName,
	}
}

// LogSecurityEvent logs a security event
func (r *SecurityEventRepository) LogSecurityEvent(ctx context.Context, event *oauth.SecurityEvent) error {
	item, err := attributevalue.MarshalMap(map[string]interface{}{
		"PK":        fmt.Sprintf("SECURITY_EVENT#%s", event.Timestamp.Format("2006-01-02")),
		"SK":        fmt.Sprintf("EVENT#%s#%s", event.Timestamp.Format(time.RFC3339Nano), event.ID),
		"Type":      "SecurityEvent",
		"ID":        event.ID,
		"EventType": event.EventType,
		"ClientID":  event.ClientID,
		"UserID":    event.UserID,
		"IPAddress": event.IPAddress,
		"UserAgent": event.UserAgent,
		"Message":   event.Message,
		"Metadata":  event.Metadata,
		"Timestamp": event.Timestamp.Format(time.RFC3339),
		"Severity":  event.Severity,
		"TTL":       event.Timestamp.Add(90 * 24 * time.Hour).Unix(), // 90 days retention
	})
	if err != nil {
		return err
	}

	_, err = r.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(r.tableName),
		Item:      item,
	})

	return err
}

// GetSecurityEvents retrieves security events with filtering
func (r *SecurityEventRepository) GetSecurityEvents(ctx context.Context, clientID string, eventType string, limit int) ([]*oauth.SecurityEvent, error) {
	// Implementation would use Query with GSI on ClientID
	// For now, return empty slice
	return []*oauth.SecurityEvent{}, nil
}

// GetSecurityEventsByTimeRange retrieves security events within a time range
func (r *SecurityEventRepository) GetSecurityEventsByTimeRange(ctx context.Context, start, end time.Time, limit int) ([]*oauth.SecurityEvent, error) {
	// Implementation would use Query with date range
	// For now, return empty slice
	return []*oauth.SecurityEvent{}, nil
}

// AuthAttemptRepository implements authentication attempt tracking in DynamoDB
type AuthAttemptRepository struct {
	client    client.Client
	tableName string
}

// NewAuthAttemptRepository creates a new auth attempt repository
func NewAuthAttemptRepository(dbClient client.Client, tableName string) *AuthAttemptRepository {
	return &AuthAttemptRepository{
		client:    dbClient,
		tableName: tableName,
	}
}

// LogAuthAttempt logs an authentication attempt
func (r *AuthAttemptRepository) LogAuthAttempt(ctx context.Context, attempt *oauth.AuthAttempt) error {
	item, err := attributevalue.MarshalMap(map[string]interface{}{
		"PK":        fmt.Sprintf("AUTH_ATTEMPT#%s", attempt.ClientID),
		"SK":        fmt.Sprintf("ATTEMPT#%s#%s", attempt.Timestamp.Format(time.RFC3339Nano), attempt.ID),
		"Type":      "AuthAttempt",
		"ID":        attempt.ID,
		"ClientID":  attempt.ClientID,
		"IPAddress": attempt.IPAddress,
		"UserAgent": attempt.UserAgent,
		"Reason":    attempt.Reason,
		"Timestamp": attempt.Timestamp.Format(time.RFC3339),
		"Success":   attempt.Success,
		"TTL":       attempt.Timestamp.Add(30 * 24 * time.Hour).Unix(), // 30 days retention
	})
	if err != nil {
		return err
	}

	_, err = r.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(r.tableName),
		Item:      item,
	})

	return err
}

// GetRecentFailedAttempts gets recent failed attempts for a client
func (r *AuthAttemptRepository) GetRecentFailedAttempts(ctx context.Context, clientID string, since time.Time) ([]*oauth.AuthAttempt, error) {
	result, err := r.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(r.tableName),
		KeyConditionExpression: aws.String("PK = :pk AND SK >= :since"),
		FilterExpression:       aws.String("Success = :success"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk":      &types.AttributeValueMemberS{Value: fmt.Sprintf("AUTH_ATTEMPT#%s", clientID)},
			":since":   &types.AttributeValueMemberS{Value: fmt.Sprintf("ATTEMPT#%s", since.Format(time.RFC3339Nano))},
			":success": &types.AttributeValueMemberBOOL{Value: false},
		},
		ScanIndexForward: aws.Bool(false), // Latest first
		Limit:            aws.Int32(50),
	})
	if err != nil {
		return nil, err
	}

	var attempts []*oauth.AuthAttempt
	for _, item := range result.Items {
		var attemptData struct {
			ID        string `dynamodbav:"ID"`
			ClientID  string `dynamodbav:"ClientID"`
			IPAddress string `dynamodbav:"IPAddress"`
			UserAgent string `dynamodbav:"UserAgent"`
			Reason    string `dynamodbav:"Reason"`
			Timestamp string `dynamodbav:"Timestamp"`
			Success   bool   `dynamodbav:"Success"`
		}

		if err := attributevalue.UnmarshalMap(item, &attemptData); err != nil {
			continue
		}

		timestamp, _ := time.Parse(time.RFC3339, attemptData.Timestamp)
		attempts = append(attempts, &oauth.AuthAttempt{
			ID:        attemptData.ID,
			ClientID:  attemptData.ClientID,
			IPAddress: attemptData.IPAddress,
			UserAgent: attemptData.UserAgent,
			Reason:    attemptData.Reason,
			Timestamp: timestamp,
			Success:   attemptData.Success,
		})
	}

	return attempts, nil
}

// GetFailedAttemptsCount gets count of failed attempts for a client in time window
func (r *AuthAttemptRepository) GetFailedAttemptsCount(ctx context.Context, clientID string, since time.Time) (int, error) {
	result, err := r.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(r.tableName),
		KeyConditionExpression: aws.String("PK = :pk AND SK >= :since"),
		FilterExpression:       aws.String("Success = :success"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk":      &types.AttributeValueMemberS{Value: fmt.Sprintf("AUTH_ATTEMPT#%s", clientID)},
			":since":   &types.AttributeValueMemberS{Value: fmt.Sprintf("ATTEMPT#%s", since.Format(time.RFC3339Nano))},
			":success": &types.AttributeValueMemberBOOL{Value: false},
		},
		Select: types.SelectCount,
	})
	if err != nil {
		return 0, err
	}

	return int(result.Count), nil
}

// CleanupOldAttempts removes old authentication attempt records
func (r *AuthAttemptRepository) CleanupOldAttempts(ctx context.Context, before time.Time) error {
	// Implementation would scan and delete old records
	// For now, TTL handles cleanup automatically
	return nil
}
