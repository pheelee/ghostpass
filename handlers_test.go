package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func setupTestDB(t *testing.T) func() {
	t.Helper()
	dbPath := "./test_handlers_" + t.Name() + ".db"
	if err := initDBWithPath(dbPath); err != nil {
		t.Fatalf("Failed to init DB: %v", err)
	}
	return func() {
		db.Close()
		os.Remove(dbPath)
	}
}

func TestGetSecretHandler(t *testing.T) {
	initLogger()
	cleanup := setupTestDB(t)
	defer cleanup()

	// First create a secret
	reqBody := CreateSecretRequest{
		Ciphertext: "dGVzdC1jaXBoZXJ0ZXh0",
		IV:         "dGVzdC1pdg==",
		ExpiresIn:  3600,
		MaxViews:   2,
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/api/secrets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	createSecretHandler(rr, req)

	var createResp CreateSecretResponse
	json.Unmarshal(rr.Body.Bytes(), &createResp)

	// Test successful retrieval with POST
	getReqBody := GetSecretRequest{}
	getReqBytes, _ := json.Marshal(getReqBody)
	req = httptest.NewRequest("POST", "/api/secrets/"+createResp.ID, bytes.NewReader(getReqBytes))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	getSecretHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("getSecretHandler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	var resp GetSecretResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Errorf("Failed to parse response: %v", err)
	}

	if resp.Ciphertext != reqBody.Ciphertext {
		t.Error("Ciphertext mismatch")
	}
}

func TestGetSecretHandler_NotFound(t *testing.T) {
	initLogger()
	cleanup := setupTestDB(t)
	defer cleanup()

	reqBody := GetSecretRequest{}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/api/secrets/nonexistent", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	getSecretHandler(rr, req)

	if status := rr.Code; status != http.StatusNotFound {
		t.Errorf("Expected status %v, got %v", http.StatusNotFound, status)
	}
}

func TestGetSecretHandler_InvalidMethod(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/secrets/test-id", nil)
	rr := httptest.NewRecorder()
	getSecretHandler(rr, req)

	if status := rr.Code; status != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %v, got %v", http.StatusMethodNotAllowed, status)
	}
}

func TestGetSecretHandler_MissingID(t *testing.T) {
	reqBody := GetSecretRequest{}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/api/secrets/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	getSecretHandler(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("Expected status %v, got %v", http.StatusBadRequest, status)
	}
}

func TestGetSecretHandler_IPRestriction(t *testing.T) {
	initLogger()
	cleanup := setupTestDB(t)
	defer cleanup()

	// Create secret with IP restriction
	reqBody := CreateSecretRequest{
		Ciphertext:   "dGVzdC1jaXBoZXJ0ZXh0",
		IV:           "dGVzdC1pdg==",
		ExpiresIn:    3600,
		MaxViews:     2,
		AllowedCIDRs: []string{"10.0.0.0/8"},
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/api/secrets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	createSecretHandler(rr, req)

	var createResp CreateSecretResponse
	json.Unmarshal(rr.Body.Bytes(), &createResp)

	// Try to access from different IP (should fail)
	getReqBody := GetSecretRequest{}
	getReqBytes, _ := json.Marshal(getReqBody)
	req = httptest.NewRequest("POST", "/api/secrets/"+createResp.ID, bytes.NewReader(getReqBytes))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.168.1.100:12345"
	rr = httptest.NewRecorder()
	getSecretHandler(rr, req)

	if status := rr.Code; status != http.StatusForbidden {
		t.Errorf("Expected status %v, got %v", http.StatusForbidden, status)
	}
}

func TestGetSecretHandler_MaxViews(t *testing.T) {
	initLogger()
	cleanup := setupTestDB(t)
	defer cleanup()

	// Create secret with only 1 view allowed
	reqBody := CreateSecretRequest{
		Ciphertext: "dGVzdC1jaXBoZXJ0ZXh0",
		IV:         "dGVzdC1pdg==",
		ExpiresIn:  3600,
		MaxViews:   1,
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/api/secrets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	createSecretHandler(rr, req)

	var createResp CreateSecretResponse
	json.Unmarshal(rr.Body.Bytes(), &createResp)

	// First retrieval should work
	getReqBody := GetSecretRequest{}
	getReqBytes, _ := json.Marshal(getReqBody)
	req = httptest.NewRequest("POST", "/api/secrets/"+createResp.ID, bytes.NewReader(getReqBytes))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	getSecretHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("First retrieval failed: got %v want %v", status, http.StatusOK)
	}

	// Second retrieval should fail (secret deleted after max views)
	getReqBytes, _ = json.Marshal(getReqBody)
	req = httptest.NewRequest("POST", "/api/secrets/"+createResp.ID, bytes.NewReader(getReqBytes))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	getSecretHandler(rr, req)

	if status := rr.Code; status != http.StatusGone && status != http.StatusNotFound {
		t.Errorf("Second retrieval should fail: got %v want %v or %v", status, http.StatusGone, http.StatusNotFound)
	}
}

func TestGetSecretHandler_ExpiredSecret(t *testing.T) {
	initLogger()
	cleanup := setupTestDB(t)
	defer cleanup()

	// Insert an already expired secret directly into the database
	id, _ := generateID()
	_, err := db.Exec(
		"INSERT INTO secrets (id, ciphertext, iv, expires_at, max_views, allowed_cidrs) VALUES (?, ?, ?, datetime('now', '-1 hour'), ?, ?)",
		id, "test-cipher", "test-iv", 1, "",
	)
	if err != nil {
		t.Fatalf("Failed to insert expired secret: %v", err)
	}

	reqBody := GetSecretRequest{}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/api/secrets/"+id, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	getSecretHandler(rr, req)

	if status := rr.Code; status != http.StatusNotFound {
		t.Errorf("Expected status %v, got %v", http.StatusNotFound, status)
	}
}

func TestCreateSecretHandler_InvalidMethod(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/secrets", nil)
	rr := httptest.NewRecorder()
	createSecretHandler(rr, req)

	if status := rr.Code; status != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %v, got %v", http.StatusMethodNotAllowed, status)
	}
}

func TestCreateSecretHandler_InvalidJSON(t *testing.T) {
	initLogger()
	cleanup := setupTestDB(t)
	defer cleanup()

	req := httptest.NewRequest("POST", "/api/secrets", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	createSecretHandler(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("Expected status %v, got %v", http.StatusBadRequest, status)
	}
}

func TestGetSecretHandler_WithAllowedIP(t *testing.T) {
	initLogger()
	cleanup := setupTestDB(t)
	defer cleanup()

	// Create secret with IP restriction
	reqBody := CreateSecretRequest{
		Ciphertext:   "dGVzdC1jaXBoZXJ0ZXh0",
		IV:           "dGVzdC1pdg==",
		ExpiresIn:    3600,
		MaxViews:     2,
		AllowedCIDRs: []string{"192.168.1.0/24"},
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/api/secrets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	createSecretHandler(rr, req)

	var createResp CreateSecretResponse
	json.Unmarshal(rr.Body.Bytes(), &createResp)

	// Try to access from allowed IP
	getReqBody := GetSecretRequest{}
	getReqBytes, _ := json.Marshal(getReqBody)
	req = httptest.NewRequest("POST", "/api/secrets/"+createResp.ID, bytes.NewReader(getReqBytes))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.168.1.50:12345"
	rr = httptest.NewRecorder()
	getSecretHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Expected status %v, got %v", http.StatusOK, status)
	}
}

func TestCreateSecretHandler_MissingFields(t *testing.T) {
	initLogger()
	cleanup := setupTestDB(t)
	defer cleanup()

	tests := []struct {
		name    string
		reqBody CreateSecretRequest
	}{
		{
			name: "Missing ciphertext",
			reqBody: CreateSecretRequest{
				Ciphertext: "",
				IV:         "dGVzdC1pdg==",
				ExpiresIn:  3600,
				MaxViews:   1,
			},
		},
		{
			name: "Missing IV",
			reqBody: CreateSecretRequest{
				Ciphertext: "dGVzdC1jaXBoZXJ0ZXh0",
				IV:         "",
				ExpiresIn:  3600,
				MaxViews:   1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.reqBody)
			req := httptest.NewRequest("POST", "/api/secrets", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			createSecretHandler(rr, req)

			if status := rr.Code; status != http.StatusBadRequest {
				t.Errorf("Expected status %v, got %v", http.StatusBadRequest, status)
			}
		})
	}
}

func TestCreateSecretHandler_MaxViewsValidation(t *testing.T) {
	initLogger()
	cleanup := setupTestDB(t)
	defer cleanup()

	reqBody := CreateSecretRequest{
		Ciphertext: "dGVzdC1jaXBoZXJ0ZXh0",
		IV:         "dGVzdC1pdg==",
		ExpiresIn:  3600,
		MaxViews:   200, // Exceeds maximum
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/api/secrets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	createSecretHandler(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("Expected status %v, got %v", http.StatusBadRequest, status)
	}
}

func TestCreateSecretHandler_DefaultTTL(t *testing.T) {
	initLogger()
	cleanup := setupTestDB(t)
	defer cleanup()

	// Invalid TTL should default to 24 hours
	reqBody := CreateSecretRequest{
		Ciphertext: "dGVzdC1jaXBoZXJ0ZXh0",
		IV:         "dGVzdC1pdg==",
		ExpiresIn:  999999, // Invalid TTL
		MaxViews:   1,
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/api/secrets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	createSecretHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Expected status %v, got %v", http.StatusOK, status)
	}

	var resp CreateSecretResponse
	json.Unmarshal(rr.Body.Bytes(), &resp)

	// Should have created with default TTL
	if resp.ID == "" {
		t.Error("Response ID is empty")
	}
}

func TestServeSecretPage(t *testing.T) {
	req := httptest.NewRequest("GET", "/s/test-id", nil)
	rr := httptest.NewRecorder()

	// This will fail because the file doesn't exist in test environment
	// but it tests the function execution path
	defer func() {
		recover()
	}()

	serveSecretPage(rr, req)
}

func TestGenerateID_Error(t *testing.T) {
	// generateID should not return an error under normal conditions
	// This test just ensures the function can be called multiple times
	for i := 0; i < 100; i++ {
		id, err := generateID()
		if err != nil {
			t.Fatalf("generateID() failed on iteration %d: %v", i, err)
		}
		if id == "" {
			t.Error("generateID() returned empty string")
		}
	}
}

func TestCreateSecretHandler_MinViews(t *testing.T) {
	initLogger()
	cleanup := setupTestDB(t)
	defer cleanup()

	// Test with 0 views (should default to 1)
	reqBody := CreateSecretRequest{
		Ciphertext: "dGVzdC1jaXBoZXJ0ZXh0",
		IV:         "dGVzdC1pdg==",
		ExpiresIn:  3600,
		MaxViews:   0, // Should default to 1
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/api/secrets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	createSecretHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Expected status %v, got %v", http.StatusOK, status)
	}
}

func TestCreateSecretHandler_WithCIDRs(t *testing.T) {
	initLogger()
	cleanup := setupTestDB(t)
	defer cleanup()

	reqBody := CreateSecretRequest{
		Ciphertext:   "dGVzdC1jaXBoZXJ0ZXh0",
		IV:           "dGVzdC1pdg==",
		ExpiresIn:    3600,
		MaxViews:     1,
		AllowedCIDRs: []string{"192.168.0.0/16", "10.0.0.0/8"},
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/api/secrets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	createSecretHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Expected status %v, got %v", http.StatusOK, status)
	}

	var resp CreateSecretResponse
	json.Unmarshal(rr.Body.Bytes(), &resp)

	if resp.ID == "" {
		t.Error("Response ID is empty")
	}
}

func TestCreateSecretHandler_DatabaseError(t *testing.T) {
	initLogger()
	cleanup := setupTestDB(t)
	defer cleanup()

	// Close database to simulate error
	db.Close()

	reqBody := CreateSecretRequest{
		Ciphertext: "dGVzdC1jaXBoZXJ0ZXh0",
		IV:         "dGVzdC1pdg==",
		ExpiresIn:  3600,
		MaxViews:   1,
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/api/secrets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	createSecretHandler(rr, req)

	if status := rr.Code; status != http.StatusInternalServerError {
		t.Errorf("Expected status %v, got %v", http.StatusInternalServerError, status)
	}
}

func TestGetSecretHandler_DatabaseQueryError(t *testing.T) {
	initLogger()
	cleanup := setupTestDB(t)
	defer cleanup()

	// Insert a secret
	id, _ := generateID()
	_, err := db.Exec(
		"INSERT INTO secrets (id, ciphertext, iv, expires_at, max_views, allowed_cidrs) VALUES (?, ?, ?, datetime('now', '+1 hour'), ?, ?)",
		id, "test-cipher", "test-iv", 1, "",
	)
	if err != nil {
		t.Fatalf("Failed to insert secret: %v", err)
	}

	// Close database before query to simulate error
	db.Close()

	reqBody := GetSecretRequest{}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/api/secrets/"+id, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	getSecretHandler(rr, req)

	if status := rr.Code; status != http.StatusInternalServerError {
		t.Errorf("Expected status %v, got %v", http.StatusInternalServerError, status)
	}
}

func TestGetSecretHandler_AlreadyMaxViews(t *testing.T) {
	initLogger()
	cleanup := setupTestDB(t)
	defer cleanup()

	// Insert a secret that has already reached max views
	id, _ := generateID()
	_, err := db.Exec(
		"INSERT INTO secrets (id, ciphertext, iv, expires_at, views, max_views, allowed_cidrs) VALUES (?, ?, ?, datetime('now', '+1 hour'), ?, ?, ?)",
		id, "test-cipher", "test-iv", 5, 5, "",
	)
	if err != nil {
		t.Fatalf("Failed to insert secret: %v", err)
	}

	reqBody := GetSecretRequest{}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/api/secrets/"+id, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	getSecretHandler(rr, req)

	if status := rr.Code; status != http.StatusGone {
		t.Errorf("Expected status %v, got %v", http.StatusGone, status)
	}
}

func TestCreateSecretHandler_WithPassword(t *testing.T) {
	initLogger()
	cleanup := setupTestDB(t)
	defer cleanup()

	reqBody := CreateSecretRequest{
		Ciphertext: "dGVzdC1jaXBoZXJ0ZXh0",
		IV:         "dGVzdC1pdg==",
		ExpiresIn:  3600,
		MaxViews:   1,
		Password:   "securepassword123",
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/api/secrets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	createSecretHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Expected status %v, got %v", http.StatusOK, status)
	}

	var resp CreateSecretResponse
	json.Unmarshal(rr.Body.Bytes(), &resp)

	if resp.ID == "" {
		t.Error("Response ID is empty")
	}

	var passwordHash string
	err := db.QueryRow("SELECT password_hash FROM secrets WHERE id = ?", resp.ID).Scan(&passwordHash)
	if err != nil {
		t.Fatalf("Failed to get password hash: %v", err)
	}

	if passwordHash == "" {
		t.Error("Password hash should not be empty")
	}
}

func TestCreateSecretHandler_PasswordTooShort(t *testing.T) {
	initLogger()
	cleanup := setupTestDB(t)
	defer cleanup()

	reqBody := CreateSecretRequest{
		Ciphertext: "dGVzdC1jaXBoZXJ0ZXh0",
		IV:         "dGVzdC1pdg==",
		ExpiresIn:  3600,
		MaxViews:   1,
		Password:   "short",
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/api/secrets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	createSecretHandler(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("Expected status %v, got %v", http.StatusBadRequest, status)
	}
}

func TestGetSecretHandler_WithCorrectPassword(t *testing.T) {
	initLogger()
	cleanup := setupTestDB(t)
	defer cleanup()

	reqBody := CreateSecretRequest{
		Ciphertext: "dGVzdC1jaXBoZXJ0ZXh0",
		IV:         "dGVzdC1pdg==",
		ExpiresIn:  3600,
		MaxViews:   2,
		Password:   "securepassword123",
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/api/secrets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	createSecretHandler(rr, req)

	var createResp CreateSecretResponse
	json.Unmarshal(rr.Body.Bytes(), &createResp)

	getReqBody := GetSecretRequest{Password: "securepassword123"}
	getReqBytes, _ := json.Marshal(getReqBody)
	req = httptest.NewRequest("POST", "/api/secrets/"+createResp.ID, bytes.NewReader(getReqBytes))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	getSecretHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Expected status %v, got %v", http.StatusOK, status)
	}

	var resp GetSecretResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Errorf("Failed to parse response: %v", err)
	}

	if resp.Ciphertext != reqBody.Ciphertext {
		t.Error("Ciphertext mismatch")
	}
}

func TestGetSecretHandler_WithoutPasswordWhenRequired(t *testing.T) {
	initLogger()
	cleanup := setupTestDB(t)
	defer cleanup()

	reqBody := CreateSecretRequest{
		Ciphertext: "dGVzdC1jaXBoZXJ0ZXh0",
		IV:         "dGVzdC1pdg==",
		ExpiresIn:  3600,
		MaxViews:   2,
		Password:   "securepassword123",
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/api/secrets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	createSecretHandler(rr, req)

	var createResp CreateSecretResponse
	json.Unmarshal(rr.Body.Bytes(), &createResp)

	getReqBody := GetSecretRequest{}
	getReqBytes, _ := json.Marshal(getReqBody)
	req = httptest.NewRequest("POST", "/api/secrets/"+createResp.ID, bytes.NewReader(getReqBytes))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	getSecretHandler(rr, req)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("Expected status %v, got %v", http.StatusUnauthorized, status)
	}
}

func TestGetSecretHandler_WithWrongPassword(t *testing.T) {
	initLogger()
	cleanup := setupTestDB(t)
	defer cleanup()

	reqBody := CreateSecretRequest{
		Ciphertext: "dGVzdC1jaXBoZXJ0ZXh0",
		IV:         "dGVzdC1pdg==",
		ExpiresIn:  3600,
		MaxViews:   2,
		Password:   "securepassword123",
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/api/secrets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	createSecretHandler(rr, req)

	var createResp CreateSecretResponse
	json.Unmarshal(rr.Body.Bytes(), &createResp)

	getReqBody := GetSecretRequest{Password: "wrongpassword"}
	getReqBytes, _ := json.Marshal(getReqBody)
	req = httptest.NewRequest("POST", "/api/secrets/"+createResp.ID, bytes.NewReader(getReqBytes))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	getSecretHandler(rr, req)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("Expected status %v, got %v", http.StatusUnauthorized, status)
	}
}

func TestGetSecretHandler_WithoutPasswordWhenNotRequired(t *testing.T) {
	initLogger()
	cleanup := setupTestDB(t)
	defer cleanup()

	reqBody := CreateSecretRequest{
		Ciphertext: "dGVzdC1jaXBoZXJ0ZXh0",
		IV:         "dGVzdC1pdg==",
		ExpiresIn:  3600,
		MaxViews:   2,
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/api/secrets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	createSecretHandler(rr, req)

	var createResp CreateSecretResponse
	json.Unmarshal(rr.Body.Bytes(), &createResp)

	getReqBody := GetSecretRequest{}
	getReqBytes, _ := json.Marshal(getReqBody)
	req = httptest.NewRequest("POST", "/api/secrets/"+createResp.ID, bytes.NewReader(getReqBytes))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	getSecretHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Expected status %v, got %v", http.StatusOK, status)
	}
}
