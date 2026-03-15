package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
)

// Context key type
type contextKey string

const requestIDKey contextKey = "requestID"

// WithRequestID adds request ID to context
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey, requestID)
}

// GetRequestID retrieves request ID from context
func GetRequestID(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDKey).(string); ok {
		return id
	}
	return ""
}

// hashString returns SHA256 hash of string (for sensitive data)
func hashString(s string) string {
	hash := sha256.Sum256([]byte(s))
	return hex.EncodeToString(hash[:])
}

// hashIP returns SHA256 hash of IP (for privacy)
func hashIP(ip string) string {
	return hashString(ip)
}
