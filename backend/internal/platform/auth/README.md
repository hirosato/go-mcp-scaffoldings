# Auth Platform

This package contains the concrete implementations of the auth service interface defined in the domain layer.

## Architecture

The auth platform layer follows clean architecture principles:

- **Platform Layer**: Contains concrete implementations of domain interfaces
  - `/auth`: Contains factory methods to create auth services
  - `/cognito`: Contains AWS Cognito implementation of the auth.Service interface

## Implementations

Currently, the following auth providers are implemented:

- **Cognito**: AWS Cognito implementation
  - Uses AWS Cognito Identity Provider for authentication
  - Stores additional user data in DynamoDB
  - Implements JWT validation using JWKS

## Usage

To use authentication in your application:

```go
import (
    "github.com/hirosato/go-mcp-scaffoldings/backend/internal/domain/auth"
    authPlatform "github.com/hirosato/go-mcp-scaffoldings/backend/internal/platform/auth"
)

func main() {
    // Get the auth service from the factory
    authService, err := authPlatform.NewService(cfg, log)
    if err != nil {
        // Handle error
    }
    
    // Use the service through its interface
    user, err := authService.ValidateToken(ctx, token)
}
```