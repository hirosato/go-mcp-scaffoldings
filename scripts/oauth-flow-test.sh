#!/bin/bash

# OAuth 2.1 Flow Test Script with Frontend Integration
# This script tests the complete OAuth flow using the dev frontend
# for user authorization instead of direct API Gateway calls.
#
# Prerequisites:
# 1. Backend deployed and accessible at BASE_URL
# 3. User account in Cognito for authentication

# Configuration
BASE_URL="https://mcp.dev.myapp.io"
FRONTEND_URL="http://dev.myapp.io"
REDIRECT_URI="http://example.com/callback"
CODE_VERIFIER="JeWxvqFi2x17sIAKWUfIZIJ-_6RhTyIbHMhPQdnMiWY"
CODE_CHALLENGE="MUPJ_zAjCQ2CYEbtDtPoObmP-lf-NhV_yxAM60eC71g"

dig mcp.dev.myapp.io

echo "=== OAuth 2.1 Flow Test ==="
echo "Backend URL: $BASE_URL"
echo "Frontend URL: $FRONTEND_URL"

echo ""
echo "=== Step 1: Register OAuth Client ==="
echo "Making request to: $BASE_URL/oauth/register"

REGISTER_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$BASE_URL/oauth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Test OAuth Client",
    "redirect_uris": ["'$REDIRECT_URI'"],
    "grant_types": ["authorization_code", "refresh_token"],
    "scopes": ["openid", "profile", "email"]
  }')

echo "Full Registration Response:"
echo "$REGISTER_RESPONSE"
echo ""

# Extract HTTP code and response body
HTTP_CODE=$(echo "$REGISTER_RESPONSE" | tail -1 | sed 's/HTTP_CODE://')
RESPONSE_BODY=$(echo "$REGISTER_RESPONSE" | sed '$d')

echo "HTTP Code: $HTTP_CODE"
echo "Response Body: $RESPONSE_BODY"

if [ "$HTTP_CODE" != "201" ] && [ "$HTTP_CODE" != "200" ]; then
    echo ""
    echo "❌ ERROR: Client registration failed with HTTP code $HTTP_CODE"
    
    echo "Response: $RESPONSE_BODY"
    exit 1
fi

# Check if jq is available
if ! command -v jq &> /dev/null; then
    echo "⚠️  WARNING: jq is not installed. Install with: brew install jq"
    echo "Raw response: $RESPONSE_BODY"
    echo ""
    echo "Please manually extract client_id and client_secret from the response above"
    echo "and use the manual curl commands in oauth-curl-commands.md"
    exit 1
fi

CLIENT_ID=$(echo "$RESPONSE_BODY" | jq -r '.client_id')
CLIENT_SECRET=$(echo "$RESPONSE_BODY" | jq -r '.client_secret')

echo "✅ Client ID: $CLIENT_ID"
echo "✅ Client Secret: $CLIENT_SECRET"

if [ "$CLIENT_ID" = "null" ] || [ "$CLIENT_SECRET" = "null" ]; then
    echo "❌ ERROR: Failed to get client credentials from response"
    echo "Response: $RESPONSE_BODY"
    exit 1
fi

echo ""
read -n 1 -p "Press any key to continue to Step 2..."
echo "=== Step 2: Authorization URL ==="
echo ""

# Use localhost:3000 for authorization (frontend)
AUTH_URL="${FRONTEND_URL}/authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&scope=openid%20profile&state=test-state&code_challenge=${CODE_CHALLENGE}&code_challenge_method=S256"

echo "🌐 Open this URL in your browser:"
echo ""
echo "$AUTH_URL"
echo ""
echo "📋 Steps to follow:"
echo "1. The browser will open the frontend authorization page"
echo "2. Sign in with your account if not already logged in"
echo "3. Review the requested permissions and click 'Authorize'"
echo "4. The browser will redirect to localhost with the authorization code"
echo "5. Copy the 'code' parameter from the redirect URL"
echo ""
echo "Example redirect: http://localhost:3000/callback?code=ABC123&state=test-state&iss=..."
echo ""

read -p "📝 Enter the authorization code from the redirect URL: " AUTH_CODE

if [ -z "$AUTH_CODE" ]; then
    echo "❌ ERROR: No authorization code provided"
    exit 1
fi

echo ""
read -n 1 -p "Press any key to continue to Step 3..."
echo "=== Step 3: Exchange Authorization Code for Tokens ==="
echo "Request parameters:"
echo "- Grant Type: authorization_code"
echo "- Auth Code: ${AUTH_CODE:0:10}..."
echo "- Client ID: $CLIENT_ID"
echo "- Redirect URI: $REDIRECT_URI"
echo "- Code Verifier: ${CODE_VERIFIER:0:10}..."
echo ""

TOKEN_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$BASE_URL/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=$AUTH_CODE&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&code_verifier=$CODE_VERIFIER")

TOKEN_HTTP_CODE=$(echo "$TOKEN_RESPONSE" | tail -1 | sed 's/HTTP_CODE://')
TOKEN_BODY=$(echo "$TOKEN_RESPONSE" | sed '$d')

echo "Token HTTP Code: $TOKEN_HTTP_CODE"
echo "Token Response: $TOKEN_BODY"

if [ "$TOKEN_HTTP_CODE" != "200" ]; then
    echo "❌ ERROR: Token exchange failed with HTTP code $TOKEN_HTTP_CODE" 
    exit 1
fi

ACCESS_TOKEN=$(echo "$TOKEN_BODY" | jq -r '.access_token')
REFRESH_TOKEN=$(echo "$TOKEN_BODY" | jq -r '.refresh_token')

echo "✅ Access Token: ${ACCESS_TOKEN:0:20}..."
echo "✅ Refresh Token: ${REFRESH_TOKEN:0:20}..."

# Debug: Check for any whitespace issues
echo "DEBUG: Access token length: ${#ACCESS_TOKEN}"
echo "DEBUG: First 5 bytes: $(echo -n "$ACCESS_TOKEN" | od -An -tx1 -N5)"

echo ""
read -n 1 -p "Press any key to continue to Step 4..."
echo "=== Step 4: Validate Access Token ==="
echo ""
VALIDATE_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X GET "$BASE_URL/oauth/validate" \
  -H "Authorization: Bearer $ACCESS_TOKEN")

VALIDATE_HTTP_CODE=$(echo "$VALIDATE_RESPONSE" | tail -1 | sed 's/HTTP_CODE://')
VALIDATE_BODY=$(echo "$VALIDATE_RESPONSE" | sed '$d')

echo "Validate HTTP Code: $VALIDATE_HTTP_CODE"
if [ "$VALIDATE_HTTP_CODE" = "200" ]; then
    echo "✅ Token validation successful:"
    echo "$VALIDATE_BODY" | jq
else
    echo "❌ Token validation failed:"
    echo "$VALIDATE_BODY"
fi

echo ""
read -n 1 -p "Press any key to continue to Step 5..."
echo "=== Step 5: Refresh Token ==="
REFRESH_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$BASE_URL/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=$REFRESH_TOKEN&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET")

REFRESH_HTTP_CODE=$(echo "$REFRESH_RESPONSE" | tail -1 | sed 's/HTTP_CODE://')
REFRESH_BODY=$(echo "$REFRESH_RESPONSE" | sed '$d')

echo "Refresh HTTP Code: $REFRESH_HTTP_CODE"
if [ "$REFRESH_HTTP_CODE" = "200" ]; then
    echo "✅ Token refresh successful:"
    echo "$REFRESH_BODY" | jq
else
    echo "❌ Token refresh failed:"
    echo "$REFRESH_BODY"
fi


echo ""
read -n 1 -p "Press any key to continue to Step 6..."
echo "=== Step 6: Test Client Credentials Grant ==="
CLIENT_CRED_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$BASE_URL/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&scope=api:read")

CLIENT_CRED_HTTP_CODE=$(echo "$CLIENT_CRED_RESPONSE" | tail -1 | sed 's/HTTP_CODE://')
CLIENT_CRED_BODY=$(echo "$CLIENT_CRED_RESPONSE" | sed '$d')

echo "Client Credentials HTTP Code: $CLIENT_CRED_HTTP_CODE"
if [ "$CLIENT_CRED_HTTP_CODE" = "200" ]; then
    echo "✅ Client credentials grant successful:"
    echo "$CLIENT_CRED_BODY" | jq
else
    echo "❌ Client credentials grant failed:"
    echo "$CLIENT_CRED_BODY"
fi

echo ""
echo "🎉 OAuth Flow Test Complete!"
echo ""
echo "📊 Summary:"
echo "- Client Registration: $([ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ] && echo "✅ Success" || echo "❌ Failed")"
echo "- Token Exchange: $([ "$TOKEN_HTTP_CODE" = "200" ] && echo "✅ Success" || echo "❌ Failed")"
echo "- Token Validation: $([ "$VALIDATE_HTTP_CODE" = "200" ] && echo "✅ Success" || echo "❌ Failed")"
echo "- Token Refresh: $([ "$REFRESH_HTTP_CODE" = "200" ] && echo "✅ Success" || echo "❌ Failed")"
echo "- Client Credentials: $([ "$CLIENT_CRED_HTTP_CODE" = "200" ] && echo "✅ Success" || echo "❌ Failed")"