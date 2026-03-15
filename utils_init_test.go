package main

import (
	"os"
	"testing"
)

func TestInitTrustedProxies_WithEnv(t *testing.T) {
	// Save original state
	originalProxies := trustedProxies
	originalEnv := os.Getenv("TRUSTED_PROXIES")
	defer func() {
		trustedProxies = originalProxies
		os.Setenv("TRUSTED_PROXIES", originalEnv)
	}()

	// Test with environment variable set
	os.Setenv("TRUSTED_PROXIES", "192.168.1.1, 10.0.0.0/8")
	trustedProxies = nil
	initTrustedProxies()

	if len(trustedProxies) != 2 {
		t.Errorf("Expected 2 proxies, got %d", len(trustedProxies))
	}

	if trustedProxies[0] != "192.168.1.1" {
		t.Errorf("Expected first proxy to be 192.168.1.1, got %s", trustedProxies[0])
	}

	if trustedProxies[1] != "10.0.0.0/8" {
		t.Errorf("Expected second proxy to be 10.0.0.0/8, got %s", trustedProxies[1])
	}
}

func TestInitTrustedProxies_NoEnv(t *testing.T) {
	// Save original state
	originalProxies := trustedProxies
	originalEnv := os.Getenv("TRUSTED_PROXIES")
	defer func() {
		trustedProxies = originalProxies
		if originalEnv != "" {
			os.Setenv("TRUSTED_PROXIES", originalEnv)
		} else {
			os.Unsetenv("TRUSTED_PROXIES")
		}
	}()

	// Test without environment variable - initTrustedProxies doesn't reset existing values
	os.Unsetenv("TRUSTED_PROXIES")
	trustedProxies = nil // Start with nil
	initTrustedProxies()

	// When env is not set, trustedProxies should remain nil (not initialized)
	if trustedProxies != nil {
		t.Errorf("Expected trustedProxies to be nil when env not set, got %v", trustedProxies)
	}
}
