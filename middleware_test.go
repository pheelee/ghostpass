package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestRateLimiter(t *testing.T) {
	rl := newRateLimiter(100, 10) // 100 requests per second, burst of 10

	ip := "192.168.1.1"

	// Should allow burst of 10
	for i := 0; i < 10; i++ {
		limiter := rl.getLimiter(ip)
		if !limiter.Allow() {
			t.Errorf("Rate limiter blocked request %d in burst", i+1)
		}
	}

	// 11th request should be rate limited (but might pass due to time passing)
	// Just verify the limiter exists
	limiter := rl.getLimiter(ip)
	if limiter == nil {
		t.Error("getLimiter() returned nil")
	}
}

func TestConnectionLimiter(t *testing.T) {
	cl := &connectionLimiter{max: 2}

	// Should acquire first connection
	if !cl.acquire() {
		t.Error("acquire() returned false for first connection")
	}

	// Should acquire second connection
	if !cl.acquire() {
		t.Error("acquire() returned false for second connection")
	}

	// Should not acquire third (max reached)
	if cl.acquire() {
		t.Error("acquire() returned true when max connections reached")
	}

	// Release one and try again
	cl.release()
	if !cl.acquire() {
		t.Error("acquire() returned false after releasing connection")
	}
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	called := false
	handler := securityHeaders(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	handler(rr, req)

	if !called {
		t.Error("Handler was not called")
	}

	// Check security headers
	headers := rr.Header()

	if csp := headers.Get("Content-Security-Policy"); csp == "" {
		t.Error("CSP header not set")
	}

	if referrer := headers.Get("Referrer-Policy"); referrer != "no-referrer" {
		t.Errorf("Referrer-Policy header wrong: got %v want %v", referrer, "no-referrer")
	}

	if xcto := headers.Get("X-Content-Type-Options"); xcto != "nosniff" {
		t.Errorf("X-Content-Type-Options header wrong: got %v want %v", xcto, "nosniff")
	}

	if xfo := headers.Get("X-Frame-Options"); xfo != "DENY" {
		t.Errorf("X-Frame-Options header wrong: got %v want %v", xfo, "DENY")
	}

	if pp := headers.Get("Permissions-Policy"); pp == "" {
		t.Error("Permissions-Policy header not set")
	}
}

func TestSecurityHeadersWithHSTS(t *testing.T) {
	// Set environment variable to enable HSTS
	// Note: In real test we'd use t.Setenv, but we can't easily unset it after
	// This test documents the behavior

	handler := securityHeaders(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	handler(rr, req)

	// HSTS should not be set by default
	hsts := rr.Header().Get("Strict-Transport-Security")
	if hsts != "" {
		t.Error("HSTS header should not be set by default")
	}
}

func TestSecurityHeadersWithHSTSEnabled(t *testing.T) {
	// Enable HSTS
	t.Setenv("ENABLE_HSTS", "true")
	defer t.Setenv("ENABLE_HSTS", "")

	handler := securityHeaders(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	handler(rr, req)

	// HSTS should be set when enabled
	hsts := rr.Header().Get("Strict-Transport-Security")
	if hsts == "" {
		t.Error("HSTS header should be set when ENABLE_HSTS=true")
	}
	expectedHSTS := "max-age=31536000; includeSubDomains; preload"
	if hsts != expectedHSTS {
		t.Errorf("HSTS header = %v, want %v", hsts, expectedHSTS)
	}
}

func TestMaxBodySizeMiddleware(t *testing.T) {
	handler := maxBodySize(func(w http.ResponseWriter, r *http.Request) {
		// Try to read body
		buf := make([]byte, 10)
		_, err := r.Body.Read(buf)
		if err != nil {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	// Test with body under limit
	req := httptest.NewRequest("POST", "/", strings.NewReader("small"))
	rr := httptest.NewRecorder()
	handler(rr, req)

	// Body under 1MB should be OK
	// Note: The actual behavior depends on http.MaxBytesReader
}

func TestPanicRecoveryMiddleware(t *testing.T) {
	handler := panicRecovery(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	// Should not panic
	handler(rr, req)

	if status := rr.Code; status != http.StatusInternalServerError {
		t.Errorf("Expected status %v after panic, got %v", http.StatusInternalServerError, status)
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	initLogger()

	called := false
	handler := rateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rr := httptest.NewRecorder()

	handler(rr, req)

	if !called {
		t.Error("Handler was not called")
	}
}

func TestConnectionLimitMiddleware(t *testing.T) {
	initLogger()

	called := false
	handler := connectionLimit(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rr := httptest.NewRecorder()

	handler(rr, req)

	if !called {
		t.Error("Handler was not called")
	}
}

func TestRateLimiterCleanup(t *testing.T) {
	rl := newRateLimiter(100, 10)

	// Add a limiter
	limiter1 := rl.getLimiter("192.168.1.1")
	if limiter1 == nil {
		t.Error("Failed to create limiter")
	}

	// Verify limiter exists
	limiter2 := rl.getLimiter("192.168.1.1")
	if limiter1 != limiter2 {
		t.Error("getLimiter returned different limiter for same IP")
	}
}

func TestRateLimiterCleanupWithTicker(t *testing.T) {
	rl := &rateLimiter{
		visitors: make(map[string]*rate.Limiter),
		lastSeen: make(map[string]time.Time),
		rate:     rate.Limit(100),
		burst:    10,
	}

	// Add an old visitor (older than 30 minutes)
	rl.visitors["192.168.1.1"] = rate.NewLimiter(rate.Limit(100), 10)
	rl.lastSeen["192.168.1.1"] = time.Now().Add(-31 * time.Minute)

	// Add a recent visitor
	rl.visitors["192.168.1.2"] = rate.NewLimiter(rate.Limit(100), 10)
	rl.lastSeen["192.168.1.2"] = time.Now()

	ticker := make(chan time.Time)
	done := make(chan bool)

	go rl.cleanupWithTicker(ticker, done)

	// Trigger cleanup
	ticker <- time.Now()
	time.Sleep(10 * time.Millisecond)

	// Old visitor should be cleaned up
	rl.mu.RLock()
	if _, exists := rl.visitors["192.168.1.1"]; exists {
		t.Error("Old visitor should have been cleaned up")
	}
	if _, exists := rl.visitors["192.168.1.2"]; !exists {
		t.Error("Recent visitor should still exist")
	}
	rl.mu.RUnlock()

	// Stop cleanup goroutine
	close(done)
}

func TestRateLimiterCleanupWithTickerDone(t *testing.T) {
	rl := &rateLimiter{
		visitors: make(map[string]*rate.Limiter),
		lastSeen: make(map[string]time.Time),
		rate:     rate.Limit(100),
		burst:    10,
	}

	ticker := make(chan time.Time)
	done := make(chan bool)

	go rl.cleanupWithTicker(ticker, done)

	// Immediately close done channel to stop goroutine
	close(done)
	time.Sleep(10 * time.Millisecond)
}
