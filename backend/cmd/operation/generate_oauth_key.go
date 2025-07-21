package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/golang-jwt/jwt/v5"
	jwksrepo "github.com/hirosato/go-mcp-scaffoldings/backend/internal/platform/kms"
)

// Example: AWS_DEFAULT_PROFILE=myapp-dev AWS_REGION=ap-northeast-1 go run generate_oauth_key.go generate-oauth-key
func main() {
	// Check if this is being called directly
	if len(os.Args) > 1 && os.Args[1] == "generate-oauth-key" {
		generateOAuthKey()
		os.Exit(0)
	}

	// Check if this is being called directly for testing
	if len(os.Args) > 1 && os.Args[1] == "test-oauth-key" {
		testOAuthKey()
		os.Exit(0)
	}
}

// run like AWS_PROFILE=myapp-dev AWS_REGION=ap-northeast-1 go run . generate-oauth-key
func generateOAuthKey() {
	// Set environment for dev
	os.Setenv("OAUTH_SIGNING_KEY_SECRET", "myapp/oauth/signing-key/dev")

	// Load AWS config
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("Failed to load AWS config: %v", err)
	}

	// Create clients
	kmsClient := kms.NewFromConfig(cfg)
	secretsClient := secretsmanager.NewFromConfig(cfg)

	// Create JWKS repository
	repo := jwksrepo.NewJWKSRepository(kmsClient, secretsClient)

	// Generate the signing key
	fmt.Println("🔑 Generating OAuth signing key...")
	err = repo.RotateSigningKey(context.Background())
	if err != nil {
		log.Fatalf("❌ Failed to generate signing key: %v", err)
	}

	fmt.Println("✅ Successfully generated OAuth signing key!")

	// Test that we can retrieve it
	fmt.Println("🔍 Testing key retrieval...")
	_, keyID, err := repo.GetSigningKey(context.Background())
	if err != nil {
		log.Fatalf("❌ Failed to retrieve signing key: %v", err)
	}

	fmt.Printf("✅ Key retrieved successfully with ID: %s\n", keyID)

	// Test JWKS endpoint
	fmt.Println("🔒 Testing JWKS generation...")
	_, err = repo.GetPublicKeySet(context.Background())
	if err != nil {
		log.Fatalf("❌ Failed to generate JWKS: %v", err)
	}

	fmt.Printf("✅ JWKS generated successfully!\n")
	fmt.Println("🎉 OAuth signing key is ready for use!")
}

func testOAuthKey() {
	// Load AWS config
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("Failed to load AWS config: %v", err)
	}

	// Create clients
	kmsClient := kms.NewFromConfig(cfg)
	secretsClient := secretsmanager.NewFromConfig(cfg)

	// Create JWKS repository
	repo := jwksrepo.NewJWKSRepository(kmsClient, secretsClient)

	// Test key retrieval
	fmt.Println("Testing signing key retrieval and parsing...")
	signingKeyPEM, keyID, err := repo.GetSigningKey(context.Background())
	if err != nil {
		log.Fatalf("Failed to get signing key: %v", err)
	}

	fmt.Printf("Key ID: %s\n", keyID)
	fmt.Printf("Key length: %d bytes\n", len(signingKeyPEM))

	// Show first 200 chars of the key
	keyPreview := string(signingKeyPEM)
	if len(keyPreview) > 200 {
		keyPreview = keyPreview[:200] + "..."
	}
	fmt.Printf("Key preview:\n%s\n", keyPreview)

	// Test JWT parsing (this is what's failing in the OAuth service)
	fmt.Println("\nTesting JWT RSA key parsing...")
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(signingKeyPEM)
	if err != nil {
		log.Fatalf("❌ Failed to parse RSA private key: %v", err)
	}

	fmt.Printf("✅ Successfully parsed RSA private key with %d bits\n", privateKey.N.BitLen())

	// Test token generation
	fmt.Println("\nTesting JWT token generation...")
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "test",
		"iss": "test",
		"exp": 1234567890,
	})

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		log.Fatalf("❌ Failed to sign token: %v", err)
	}

	fmt.Printf("✅ Successfully generated JWT token: %s...\n", tokenString[:50])
	fmt.Println("\n🎉 All tests passed! The signing key is working correctly.")
}
