package response

import (
	"fmt"
	"os"

	"github.com/aws/aws-lambda-go/events"
)

// AddWWWAuthenticateHeader adds WWW-Authenticate header to a response
func AddWWWAuthenticateHeader(resp *events.APIGatewayProxyResponse, realm string) {
	if resp.Headers == nil {
		resp.Headers = make(map[string]string)
	}

	// Include the authorization server URL in the WWW-Authenticate header
	authServerURL := os.Getenv("BASE_URL")
	if authServerURL == "" {
		authServerURL = "https://api.myapp.io"
	}

	// Format: Bearer realm="<realm>", authorization_uri="<auth_server_url>/.well-known/oauth-authorization-server"
	resp.Headers["WWW-Authenticate"] = fmt.Sprintf(`Bearer realm="%s", authorization_uri="%s/.well-known/oauth-authorization-server"`, realm, authServerURL)
}

// UnauthorizedWithWWWAuthenticate creates a 401 response with WWW-Authenticate header
func UnauthorizedWithWWWAuthenticate(message string, requestID string, realm string) events.APIGatewayProxyResponse {
	resp := Unauthorized(message, requestID)
	AddWWWAuthenticateHeader(&resp, realm)
	return resp
}
