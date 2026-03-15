package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoggerMethods(t *testing.T) {
	initLogger()

	// Test Info
	logger.Info("test_info", map[string]interface{}{"key": "value"})

	// Test Warn
	logger.Warn("test_warn", map[string]interface{}{"key": "value"})

	// Test Error
	logger.Error("test_error", nil, map[string]interface{}{"key": "value"})

	// Test Error with actual error
	testErr := errors.New("test error")
	logger.Error("test_error_with_err", testErr, map[string]interface{}{"key": "value"})

	// Test Security
	logger.Security("test_security_event", map[string]interface{}{"key": "value"})
}

func TestLogSecretAccess(t *testing.T) {
	initLogger()

	// Test successful access log
	LogSecretAccess("test-secret-id", "create", true, "192.168.1.1", nil)

	// Test failed access log
	LogSecretAccess("test-secret-id", "retrieve", false, "192.168.1.1", nil)

	// Test access with error
	testErr := errors.New("test error")
	LogSecretAccess("test-secret-id", "retrieve", false, "192.168.1.1", testErr)
}

func TestLogRateLimit(t *testing.T) {
	initLogger()
	LogRateLimit("192.168.1.1", "/api/secrets")
}

func TestRequestLogger(t *testing.T) {
	initLogger()

	handler := RequestLogger(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("User-Agent", "test-agent")
	rr := httptest.NewRecorder()

	handler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Expected status %v, got %v", http.StatusOK, status)
	}
}

func TestRequestLogger_ErrorStatus(t *testing.T) {
	initLogger()

	handler := RequestLogger(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()

	handler(rr, req)

	if status := rr.Code; status != http.StatusInternalServerError {
		t.Errorf("Expected status %v, got %v", http.StatusInternalServerError, status)
	}
}

func TestRequestLogger_WarnStatus(t *testing.T) {
	initLogger()

	handler := RequestLogger(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()

	handler(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("Expected status %v, got %v", http.StatusBadRequest, status)
	}
}

func TestLogEntryStructure(t *testing.T) {
	entry := LogEntry{
		Timestamp:  "2026-03-14T10:00:00Z",
		Level:      "info",
		Message:    "test",
		RequestID:  "test-id",
		Method:     "GET",
		Path:       "/test",
		StatusCode: 200,
		ClientIP:   "hash",
		UserAgent:  "test",
		Duration:   "1ms",
		SecretID:   "secret-hash",
		Error:      "",
		Fields:     map[string]interface{}{"key": "value"},
	}

	// Verify JSON marshaling
	data, err := json.Marshal(entry)
	if err != nil {
		t.Errorf("Failed to marshal LogEntry: %v", err)
	}

	if !strings.Contains(string(data), "test") {
		t.Error("Marshaled JSON doesn't contain expected message")
	}
}

func TestLogger_SecurityWithNilFields(t *testing.T) {
	initLogger()
	// Test Security method with nil fields (should auto-create map)
	logger.Security("test_security", nil)
}

func TestLogger_LogWithEmptyLevel(t *testing.T) {
	initLogger()
	// Test that log method sets default level to "info" when empty
	entry := LogEntry{
		Level:   "",
		Message: "test_default_level",
	}
	logger.log(entry)
}
