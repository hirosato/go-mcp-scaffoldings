# Cognito Auth Implementation

This package contains the AWS Cognito implementation of the auth.Service interface defined in the domain layer.

## Components

- `client.go`: Creates and configures the AWS Cognito client
- `service.go`: Implements the auth.Service interface using AWS Cognito
- `repository.go`: Implements the Repository interface for storing additional auth data
- `types.go`: Defines types specific to the Cognito implementation

## Architecture

The implementation follows clean architecture and dependency inversion principles:

1. The service depends on the domain interfaces, not the other way around
2. AWS Cognito specific code is isolated in this package
3. Repository implementations for persisting additional data are injected

## Testing

The implementation is designed to be testable:

1. The AWS Cognito client can be mocked for unit testing
2. The repository can be mocked or replaced with an in-memory implementation
3. The service implementation can be tested independently of AWS services