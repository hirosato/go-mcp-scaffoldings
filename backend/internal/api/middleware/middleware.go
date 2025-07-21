package middleware

import (
	"context"
	"log/slog"

	"github.com/aws/aws-lambda-go/events"
)

// APIGatewayHandler is a function that handles API Gateway requests
type APIGatewayHandler func(context.Context, *slog.Logger, events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error)
