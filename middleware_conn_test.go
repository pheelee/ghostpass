package main

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestConnectionLimit_Rejection(t *testing.T) {
	initLogger()

	// Create a connection limiter with max 1
	originalLimiter := connLimiter
	connLimiter = &connectionLimiter{max: 1}
	defer func() {
		connLimiter = originalLimiter
	}()

	var wg sync.WaitGroup
	wg.Add(1)

	// First request - blocks to hold the connection
	req1 := httptest.NewRequest("GET", "/", nil)
	rr1 := httptest.NewRecorder()

	handler := connectionLimit(func(w http.ResponseWriter, r *http.Request) {
		wg.Done()
		time.Sleep(100 * time.Millisecond) // Hold the connection
		w.WriteHeader(http.StatusOK)
	})

	// Start first request in goroutine
	go handler(rr1, req1)

	// Wait for first request to acquire the slot
	wg.Wait()

	// Second request should be rejected immediately
	req2 := httptest.NewRequest("GET", "/", nil)
	rr2 := httptest.NewRecorder()

	handler(rr2, req2)

	if rr2.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status %v, got %v", http.StatusServiceUnavailable, rr2.Code)
	}
}
