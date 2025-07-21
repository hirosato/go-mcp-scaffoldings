package kms

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-secretsmanager-caching-go/v2/secretcache"
	"github.com/google/uuid"
)

// secretCache will be initialized with proper AWS config in NewJWKSRepository

// JWKSRepository implements JWKS storage using AWS KMS and Secrets Manager
type JWKSRepository struct {
	kmsClient          *kms.Client
	secretsClient      *secretsmanager.Client
	secretCache        *secretcache.Cache
	signingKeyAlias    string
	signingKeySecretID string
	publicKeyCache     *publicKeyCache
	mu                 sync.RWMutex
}

type publicKeyCache struct {
	keyID     string
	publicKey interface{}
	expiresAt time.Time
}

// NewJWKSRepository creates a new JWKS repository
func NewJWKSRepository(kmsClient *kms.Client, secretsClient *secretsmanager.Client) *JWKSRepository {
	signingKeyAlias := os.Getenv("OAUTH_SIGNING_KEY_ALIAS")
	if signingKeyAlias == "" {
		signingKeyAlias = "alias/oauth-signing-key"
	}

	signingKeySecretID := os.Getenv("OAUTH_SIGNING_KEY_SECRET")
	if signingKeySecretID == "" {
		signingKeySecretID = "oauth/signing-key"
	}

	// Initialize secretCache with the configured secrets client
	secretCache, err := secretcache.New(
		func(c *secretcache.Cache) {
			c.Client = secretsClient
		},
	)
	if err != nil {
		// If secretCache initialization fails, log the error but continue
		// The repository will fall back to direct API calls
		fmt.Printf("Failed to initialize secretCache: %v\n", err)
	}

	return &JWKSRepository{
		kmsClient:          kmsClient,
		secretsClient:      secretsClient,
		secretCache:        secretCache,
		signingKeyAlias:    signingKeyAlias,
		signingKeySecretID: signingKeySecretID,
	}
}

// GetSigningKey retrieves the current signing key from Secrets Manager
func (r *JWKSRepository) GetSigningKey(ctx context.Context) ([]byte, string, error) {
	// Get the current signing key from Secrets Manager
	var secretString string
	var err error
	
	if r.secretCache != nil {
		secretString, err = r.secretCache.GetSecretString(r.signingKeySecretID)
	} else {
		// Fall back to direct API call if secretCache is not available
		result, apiErr := r.secretsClient.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
			SecretId: aws.String(r.signingKeySecretID),
		})
		if apiErr != nil {
			err = apiErr
		} else {
			secretString = *result.SecretString
		}
	}

	if err != nil {
		// If secret doesn't exist, create a new one
		if isSecretNotFoundError(err) {
			return r.createNewSigningKey(ctx)
		}
		return nil, "", fmt.Errorf("failed to get signing key: %w", err)
	}

	// Parse the secret value
	type signingKeyData struct {
		KeyID      string `json:"keyId"`
		PrivateKey string `json:"privateKey"`
		PublicKey  string `json:"publicKey"`
		CreatedAt  string `json:"createdAt"`
	}

	var keyData signingKeyData
	if err := json.Unmarshal([]byte(secretString), &keyData); err != nil {
		return nil, "", fmt.Errorf("failed to parse signing key data: %w", err)
	}

	// Decode the private key
	privateKeyPEM, err := base64.StdEncoding.DecodeString(keyData.PrivateKey)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode private key: %w", err)
	}

	// Return the PEM-encoded private key bytes
	return privateKeyPEM, keyData.KeyID, nil
}

// RotateSigningKey rotates the signing key
func (r *JWKSRepository) RotateSigningKey(ctx context.Context) error {
	// Create a new signing key
	_, _, err := r.createNewSigningKey(ctx)
	return err
}

// GetPublicKeySet retrieves the public key set for JWKS endpoint
func (r *JWKSRepository) GetPublicKeySet(ctx context.Context) (interface{}, error) {
	// Check cache
	r.mu.RLock()
	if r.publicKeyCache != nil && time.Now().Before(r.publicKeyCache.expiresAt) {
		defer r.mu.RUnlock()
		return r.buildJWKS(r.publicKeyCache.keyID, r.publicKeyCache.publicKey), nil
	}
	r.mu.RUnlock()

	// Get the current signing key
	result, err := r.secretsClient.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(r.signingKeySecretID),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get signing key: %w", err)
	}

	// Parse the secret value
	type signingKeyData struct {
		KeyID      string `json:"keyId"`
		PrivateKey string `json:"privateKey"`
		PublicKey  string `json:"publicKey"`
		CreatedAt  string `json:"createdAt"`
	}

	var keyData signingKeyData
	if err := json.Unmarshal([]byte(*result.SecretString), &keyData); err != nil {
		return nil, fmt.Errorf("failed to parse signing key data: %w", err)
	}

	// Decode the public key
	publicKeyPEM, err := base64.StdEncoding.DecodeString(keyData.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	// Parse the public key
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	// Update cache
	r.mu.Lock()
	r.publicKeyCache = &publicKeyCache{
		keyID:     keyData.KeyID,
		publicKey: publicKey,
		expiresAt: time.Now().Add(5 * time.Minute),
	}
	r.mu.Unlock()

	return r.buildJWKS(keyData.KeyID, publicKey), nil
}

// Private methods

func (r *JWKSRepository) createNewSigningKey(ctx context.Context) ([]byte, string, error) {
	// Generate a new RSA key pair using KMS
	keyID := uuid.New().String()

	// For this implementation, we'll generate a local RSA key pair
	// In production, you might want to use KMS data keys or external key management
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Encode private key to PEM
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Encode public key to PEM
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	// Store in Secrets Manager
	keyData := map[string]string{
		"keyId":      keyID,
		"privateKey": base64.StdEncoding.EncodeToString(privateKeyPEM),
		"publicKey":  base64.StdEncoding.EncodeToString(publicKeyPEM),
		"createdAt":  time.Now().Format(time.RFC3339),
	}

	keyDataJSON, err := json.Marshal(keyData)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal key data: %w", err)
	}

	// Try to update existing secret first
	_, err = r.secretsClient.UpdateSecret(ctx, &secretsmanager.UpdateSecretInput{
		SecretId:     aws.String(r.signingKeySecretID),
		SecretString: aws.String(string(keyDataJSON)),
	})

	if err != nil {
		// If update fails, try to create new secret
		_, err = r.secretsClient.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(r.signingKeySecretID),
			SecretString: aws.String(string(keyDataJSON)),
			Description:  aws.String("OAuth JWT signing key"),
		})
		if err != nil {
			return nil, "", fmt.Errorf("failed to store signing key: %w", err)
		}
	}

	// Clear cache
	r.mu.Lock()
	r.publicKeyCache = nil
	r.mu.Unlock()

	return privateKeyPEM, keyID, nil
}

func (r *JWKSRepository) buildJWKS(keyID string, publicKey interface{}) interface{} {
	rsaKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return map[string]interface{}{
			"keys": []interface{}{},
		}
	}

	// Build JWK
	jwk := map[string]interface{}{
		"kty": "RSA",
		"use": "sig",
		"kid": keyID,
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.E)).Bytes()),
	}

	return map[string]interface{}{
		"keys": []interface{}{jwk},
	}
}

func isSecretNotFoundError(err error) bool {
	// Check if the error is a ResourceNotFoundException
	return err != nil && contains(err.Error(), "ResourceNotFoundException")
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr || len(s) > len(substr) && containsHelper(s[1:], substr)
}

func containsHelper(s, substr string) bool {
	if len(s) < len(substr) {
		return false
	}
	if s[:len(substr)] == substr {
		return true
	}
	return containsHelper(s[1:], substr)
}