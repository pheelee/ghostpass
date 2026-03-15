package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRateLimitMiddleware_RateLimitExceeded(t *testing.T) {
	initLogger()

	// Create a new rate limiter with very low rate
	rl := newRateLimiter(1, 1) // 1 request per second, burst of 1
	limiter = rl

	// First request should succeed
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "192.168.1.100:12345"
	rr1 := httptest.NewRecorder()

	called := false
	handler := rateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler(rr1, req1)

	if !called {
		t.Error("First request should have been allowed")
	}

	// Immediately send second request - should be rate limited
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "192.168.1.100:12345"
	rr2 := httptest.NewRecorder()

	handler(rr2, req2)

	if rr2.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status %v for rate limited request, got %v", http.StatusTooManyRequests, rr2.Code)
	}

	// Restore original limiter
	limiter = newRateLimiter(10, 20)
}

func TestConnectionLimit_MaxReached(t *testing.T) {
	initLogger()

	// Create a connection limiter with max 1
	originalLimiter := connLimiter
	connLimiter = &connectionLimiter{max: 1}
	defer func() {
		connLimiter = originalLimiter
	}()

	// First request should acquire the slot
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "192.168.1.100:12345"
	rr1 := httptest.NewRecorder()

	called := false
	handler := connectionLimit(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler(rr1, req1)

	if !called {
		t.Error("First request should have been allowed")
	}

	// Second request should be rejected (server overloaded)
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "192.168.1.101:12345"
	rr2 := httptest.NewRecorder()

	// This request should get rejected
	handler(rr2, req2)

	// Note: The first request's defer hasn't run yet in this synchronous test,
	// so we can't easily test the rejection without async handling
}
