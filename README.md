# MCP OAuth Scaffolding

This repository contains OAuth and MCP (Model Context Protocol) implementation code, providing a foundation for building secure MCP servers with OAuth 2.1 authentication.

## Architecture Overview

The scaffolding includes:

- **OAuth 2.1 Authorization Server** - Complete OAuth implementation with PKCE support
- **MCP Server** - Full Model Context Protocol server implementation
- **AWS Infrastructure** - CDK templates for serverless deployment
- **Testing Scripts** - Comprehensive test suites for both OAuth and MCP functionality

## Directory Structure

```
mcp-scaffolding/
├── backend/                     # Go backend implementation
│   ├── cmd/
│   │   ├── oauth/              # OAuth server main
│   │   └── mcp/                # MCP server main
│   ├── internal/
│   │   ├── api/                # HTTP handlers and middleware
│   │   ├── domain/             # Business logic (OAuth, MCP, etc.)
│   │   └── platform/           # Infrastructure layer
│   ├── pkg/                    # Shared packages
│   └── scripts/                # Build and test scripts
├── cdk/                        # AWS CDK infrastructure
│   ├── lib/
│   │   ├── backend-stack.ts    # Main infrastructure stack
│   │   └── front-stack.ts      # Frontend infrastructure
│   └── bin/                    # CDK app entry point
├── docs/                       # Documentation
│   ├── OAuth.md               # OAuth architecture docs
│   ├── OAuth-IntegrationGuide.md
│   └── *.md                   # MCP reports and guides
└── scripts/                   # Test and deployment scripts
    ├── oauth-flow-test.sh     # OAuth flow testing
    └── test-mcp.sh           # MCP server testing
```

## Features

### OAuth 2.1 Authorization Server

- **Standards Compliant**: Full OAuth 2.1 with mandatory PKCE
- **Multiple Grant Types**: Authorization code with PKCE, client credentials, refresh tokens
- **Security Features**: JWT signing with AWS KMS, rate limiting, bcrypt hashing
- **MCP Integration**: Resource indicators support for MCP compliance
- **AWS Native**: DynamoDB storage, Lambda functions, API Gateway

### MCP Server

- **Protocol Support**: Complete JSON-RPC 2.0 implementation
- **Tools**: Journal entry creation, extensible tool framework
- **Resources**: Journal entries access, extensible resource framework
- **Authentication**: OAuth-protected endpoints with proper scoping
- **Error Handling**: MCP-specific error codes and responses

## Prerequisites

- Go 1.21+
- Node.js 18+ (for CDK)
- AWS CLI configured
- AWS CDK v2 installed (`npm install -g aws-cdk`)

## Quick Start

### 1. Backend Setup

```bash
cd backend
go mod download
go build ./cmd/oauth
go build ./cmd/mcp
```

### 2. Infrastructure Deployment

```bash
cd cdk
npm install
cdk bootstrap  # First time only
cdk deploy
```

### 3. Testing

```bash
# Test OAuth flow
./scripts/oauth-flow-test.sh

# Test MCP server
./scripts/test-mcp.sh
```

## OAuth Configuration

The OAuth server supports the following endpoints:

- `GET /.well-known/oauth-authorization-server` - OAuth metadata
- `GET /.well-known/jwks.json` - JWT public keys
- `POST /oauth/register` - Client registration
- `POST /oauth/authorize/callback` - Authorization code generation
- `POST /oauth/token` - Token exchange
- `GET /oauth/validate` - Token validation

## MCP Configuration

The MCP server implements:

- **Initialize**: Server capabilities negotiation
- **Resources**: List and read journal entries
- **Tools**: Create journal entries with validation
- **Authentication**: OAuth token validation

## Environment Variables

### OAuth Server
```bash
REGION=us-east-1
ENV=dev
```

### MCP Server
```bash
REGION=us-east-1
ENV=dev
```

## Documentation

Detailed documentation is available in the `docs/` directory:

- **OAuth.md**: Complete OAuth architecture and implementation details
- **OAuth-IntegrationGuide.md**: Step-by-step integration guide
- **2025-07-12-mcp-server-design.md**: MCP server design decisions
- **2025-06-20-mcp-oauth-compliance.md**: OAuth compliance for MCP

## Testing

### OAuth Flow Testing

The `oauth-flow-test.sh` script tests the complete OAuth 2.1 flow:

1. Client registration
2. Authorization with PKCE
3. Token exchange
4. Token validation
5. Token refresh

### MCP Testing

The `test-mcp.sh` script validates MCP functionality:

1. Server initialization
2. Resource listing and reading
3. Tool execution
4. Error handling

## Development

### Adding New MCP Tools

1. Create a new tool handler in `backend/internal/api/mcp/tools/`
2. Register the tool in `backend/internal/domain/mcp/handlers.go`
3. Add tests in the corresponding `_test.go` file

### Adding New MCP Resources

1. Create a new resource handler in `backend/internal/api/mcp/resources/`
2. Register the resource in `backend/internal/domain/mcp/handlers.go`
3. Add tests and documentation

## Security Considerations

- JWT tokens are signed with AWS KMS keys (auto-rotation in production)
- Client secrets are hashed with bcrypt
- Rate limiting prevents brute force attacks
- DynamoDB TTL automatically expires tokens
- WAF protection against DDoS attacks

## Deployment

The CDK stack creates:

- **Lambda Functions**: OAuth and MCP servers
- **DynamoDB Tables**: OAuth tokens, journal entries, accounts
- **API Gateway**: REST APIs with caching
- **KMS Keys**: JWT signing keys
- **IAM Roles**: Least privilege access
