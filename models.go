package main

import (
	"time"
)

// CreateSecretRequest represents a request to create a new secret
type CreateSecretRequest struct {
	Ciphertext   string   `json:"ciphertext"`
	IV           string   `json:"iv"`
	ExpiresIn    int      `json:"expires_in"`
	MaxViews     int      `json:"max_views"`
	AllowedCIDRs []string `json:"allowed_cidrs,omitempty"`
	Password     string   `json:"password,omitempty"`
}

// GetSecretRequest represents a request to retrieve a secret
type GetSecretRequest struct {
	Password string `json:"password,omitempty"`
}

// CreateSecretResponse represents the response after creating a secret
type CreateSecretResponse struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// GetSecretResponse represents the response when retrieving a secret
type GetSecretResponse struct {
	Ciphertext string `json:"ciphertext"`
	IV         string `json:"iv"`
}

// Secret represents a secret stored in the database
type Secret struct {
	ID           string
	Ciphertext   string
	IV           string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	Views        int
	MaxViews     int
	AllowedCIDRs []string
	PasswordHash *string
}
