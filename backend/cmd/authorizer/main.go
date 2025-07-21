package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"runtime"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/common/config"
	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/domain/oauth"
	ddbclient "github.com/hirosato/go-mcp-scaffoldings/backend/internal/platform/dynamodb/client"
	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/platform/dynamodb/repository"
	kmspkg "github.com/hirosato/go-mcp-scaffoldings/backend/internal/platform/kms"
)

var (
	oauthService *oauth.Service
	appConfig    *config.Config
)

func init() {
	// Load AWS configuration
	cfg, err := awsConfig.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Fatalf("Failed to load AWS config: %v", err)
	}

	// Initialize DynamoDB client
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}
	dbClient, err := ddbclient.NewDynamoDBClient(context.Background(), region)
	if err != nil {
		log.Fatalf("Failed to create DynamoDB client: %v", err)
	}

	// Initialize KMS and Secrets Manager clients
	kmsClient := kms.NewFromConfig(cfg)
	secretsClient := secretsmanager.NewFromConfig(cfg)

	// Get table name from environment
	tableName := os.Getenv("OAUTH_TABLE_NAME")
	if tableName == "" {
		panic("OAUTH_TABLE_NAME not set")
	}

	// Initialize repositories
	clientRepo := repository.NewOAuthClientRepository(dbClient, tableName)
	codeRepo := repository.NewOAuthCodeRepository(dbClient, tableName)
	tokenRepo := repository.NewOAuthTokenRepository(dbClient, tableName)
	jwksRepo := kmspkg.NewJWKSRepository(kmsClient, secretsClient)
	securityRepo := repository.NewSecurityEventRepository(dbClient, tableName)
	authAttemptRepo := repository.NewAuthAttemptRepository(dbClient, tableName)

	appConfig, err = config.LoadFromEnv()
	if err != nil {
		os.Exit(1)
	}

	// Initialize OAuth service
	oauthService = oauth.NewService(clientRepo, codeRepo, tokenRepo, jwksRepo, securityRepo, authAttemptRepo)
}

// handler is the Lambda function handler for API Gateway REST API Request Authorizer
func handler(ctx context.Context, request events.APIGatewayCustomAuthorizerRequestTypeRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
	// Extract token from Authorization header
	authHeader := request.Headers["Authorization"]
	if authHeader == "" {
		authHeader = request.Headers["authorization"] // Case-insensitive fallback
	}

	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		log.Printf("Missing or invalid Authorization header")
		return generatePolicy("user", "Deny", request.MethodArn, nil), nil
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	slog.Info("authorizer - Memory Status", "MB", m.Alloc/1024/1024)

	if !appConfig.IsProd() {
		slog.Info("Token Body", "token", token, "authorization header", authHeader)
	}

	// Validate token
	claims, err := oauthService.ValidateToken(ctx, token)
	if err != nil {
		log.Printf("Token validation failed: %v", err)
		return generatePolicy("user", "Deny", request.MethodArn, nil), nil
	}

	// Build context for the API Gateway
	authContext := map[string]interface{}{
		"clientId": claims.ClientID,
		"scope":    claims.Scope,
		"jti":      claims.JTI,
		"sub":      claims.Subject,
		"iss":      claims.Issuer,
		"exp":      fmt.Sprintf("%d", claims.ExpiresAt),
	} //arn:aws:execute-api:{regionId}:{accountId}:{apiId}/{stage}/{httpVerb}/[{resource}/[{child-resources}]]"
	arn := fmt.Sprintf("arn:aws:execute-api:%s:%s:%s/%s/%s",
		"*", // Region
		request.RequestContext.AccountID,
		request.RequestContext.APIID,
		request.RequestContext.Stage,
		"*", //HTTP Method
	)

	// Return allow response with context
	return generatePolicy(claims.ClientID, "Allow", arn, authContext), nil
}

// generatePolicy generates an IAM policy for the authorizer response
func generatePolicy(principalID, effect, resource string, context map[string]interface{}) events.APIGatewayCustomAuthorizerResponse {
	authResponse := events.APIGatewayCustomAuthorizerResponse{
		PrincipalID: principalID,
	}

	if effect != "" && resource != "" {
		authResponse.PolicyDocument = events.APIGatewayCustomAuthorizerPolicy{
			Version: "2012-10-17",
			Statement: []events.IAMPolicyStatement{
				{
					Action:   []string{"execute-api:Invoke"},
					Effect:   effect,
					Resource: []string{resource},
				},
			},
		}
	}

	if context != nil {
		authResponse.Context = context
	}

	// Optional: Add usage identifier for API Gateway usage plans
	authResponse.UsageIdentifierKey = principalID

	return authResponse
}

// main is the entry point for the Lambda function
func main() {
	lambda.Start(handler)
}
