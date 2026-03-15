package main

import (
	"context"
	"testing"
)

func TestRequestContext(t *testing.T) {
	ctx := WithRequestID(context.Background(), "test-id-123")
	if ctx == nil {
		t.Error("WithRequestID() returned nil")
		return
	}

	// Get request ID back
	id := GetRequestID(ctx)
	if id != "test-id-123" {
		t.Errorf("GetRequestID() = %v, want %v", id, "test-id-123")
	}
}

func TestGetRequestID_NoID(t *testing.T) {
	// Test GetRequestID with context that has no request ID
	ctx := context.Background()
	id := GetRequestID(ctx)
	if id != "" {
		t.Errorf("GetRequestID() = %v, want empty string", id)
	}
}

func TestHashString(t *testing.T) {
	// Test that hashing produces consistent results
	hash1 := hashString("test")
	hash2 := hashString("test")

	if hash1 != hash2 {
		t.Error("hashString() produced different hashes for same input")
	}

	// Test that different inputs produce different hashes
	hash3 := hashString("different")
	if hash1 == hash3 {
		t.Error("hashString() produced same hash for different inputs")
	}

	// Test hash format (should be 64 hex characters for SHA256)
	if len(hash1) != 64 {
		t.Errorf("hashString() returned hash of wrong length: got %d, want 64", len(hash1))
	}
}

func TestHashIP(t *testing.T) {
	// hashIP should use hashString internally
	hash1 := hashIP("192.168.1.1")
	hash2 := hashIP("192.168.1.1")

	if hash1 != hash2 {
		t.Error("hashIP() produced different hashes for same IP")
	}

	// Different IPs should have different hashes
	hash3 := hashIP("192.168.1.2")
	if hash1 == hash3 {
		t.Error("hashIP() produced same hash for different IPs")
	}
}
