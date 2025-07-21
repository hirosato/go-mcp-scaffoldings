package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/api/handlers"
	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/api/response"

	envconfig "github.com/hirosato/go-mcp-scaffoldings/backend/internal/common/config"
	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/domain/oauth"
	ddbclient "github.com/hirosato/go-mcp-scaffoldings/backend/internal/platform/dynamodb/client"
	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/platform/dynamodb/repository"
	kmspkg "github.com/hirosato/go-mcp-scaffoldings/backend/internal/platform/kms"
)

var (
	oauthHandler *handlers.OAuthHandler
	logger       *slog.Logger
	config       *envconfig.Config
)

func init() {
	// Initialize logger
	logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	var err error = nil
	config, err = envconfig.LoadFromEnv()
	if err != nil {
		log.Fatalf("Failed to load Env config: %v", err)
	}

	// Load AWS configuration
	awscfg, err := awsconfig.LoadDefaultConfig(context.Background())
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
	kmsClient := kms.NewFromConfig(awscfg)
	secretsClient := secretsmanager.NewFromConfig(awscfg)

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

	// Initialize OAuth service
	oauthService := oauth.NewService(clientRepo, codeRepo, tokenRepo, jwksRepo, securityRepo, authAttemptRepo)

	// Initialize OAuth handler
	oauthHandler = handlers.NewOAuthHandler(oauthService)
}

func handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Handle CORS preflight
	if request.HTTPMethod == "OPTIONS" {
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusOK,
			Headers:    response.DefaultHeaders(),
		}, nil
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	slog.Info("oauth - Memory Status", "MB", m.Alloc/1024/1024)

	if config.Environment == "dev" {
		slog.Info("Request Details",
			"path", request.Path,
			"method", request.HTTPMethod,
			"body", request.Body,
			"origin", request.Headers["Origin"],
			"referer", request.Headers["Referer"],
			"userAgent", request.Headers["User-Agent"],
			"requestId", request.RequestContext.RequestID,
			"sourceIP", request.RequestContext.Identity.SourceIP,
			"queryParams", request.QueryStringParameters,
			"headers", request.Headers,
		)
	}

	// Route the request
	path := request.Path
	method := request.HTTPMethod

	// Remove base path if present
	path = strings.TrimPrefix(path, "/oauth")

	switch {
	case path == "/":
		return oauthHandler.GetRoot(ctx, logger, request)
	case path == "/.well-known/oauth-authorization-server" && method == "GET":
		return oauthHandler.GetMetadata(ctx, logger, request)
	case path == "/.well-known/oauth-protected-resource" && method == "GET":
		return oauthHandler.GetProtectedResourceMetadata(ctx, logger, request)
	case path == "/authorize/callback" && method == "POST":
		return oauthHandler.GenerateCode(ctx, logger, request)
	case path == "/token" && method == "POST":
		return oauthHandler.Token(ctx, logger, request)
	case path == "/register" && method == "POST":
		return oauthHandler.Register(ctx, logger, request)
	case path == "/validate" && method == "GET":
		return oauthHandler.ValidateToken(ctx, logger, request)
	case path == "/.well-known/jwks.json" && method == "GET":
		return oauthHandler.GetJWKS(ctx, logger, request)
	default:
		return response.NotFound("Endpoint not found"), nil
	}
}

func main() {
	lambda.Start(handler)
}
