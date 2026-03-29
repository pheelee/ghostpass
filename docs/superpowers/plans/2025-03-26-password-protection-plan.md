# Optional Password Protection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add optional password protection to secrets using Argon2id hashing. When a password is set during creation, users must provide it to retrieve the secret.

**Architecture:** Store Argon2id password hashes in a new `password_hash` column. Change secret retrieval from GET to POST to support password in request body. Frontend adds `?p=1` to URL when password is set.

**Tech Stack:** Go (golang.org/x/crypto/argon2), SQLite, vanilla JS

---

## File Structure

| File | Responsibility |
|------|----------------|
| `password.go` (new) | Argon2id hashing utilities |
| `password_test.go` (new) | Password hashing tests |
| `database.go` | Schema: add `password_hash` column |
| `models.go` | Add `Password` field to `CreateSecretRequest`, create `GetSecretRequest` struct |
| `handlers.go` | Hash password on create, verify on retrieve, change GET to POST |
| `handlers_test.go` | Update existing tests + add password-specific tests |
| `static/index.html` | Add password input to create form |
| `static/s/index.html` | Add password input to retrieve page, handle `?p=1` param |

---

## Task 1: Password Hashing Utilities

**Files:**
- Create: `password.go`
- Create: `password_test.go`

- [ ] **Step 1: Write failing tests for password hashing**

```go
// password_test.go
package main

import (
	"testing"
)

func TestHashPassword(t *testing.T) {
	password := "testpassword123"
	hash, err := hashPassword(password)
	if err != nil {
		t.Fatalf("hashPassword() error = %v", err)
	}
	if hash == "" {
		t.Error("hashPassword() returned empty string")
	}
	if hash == password {
		t.Error("hashPassword() should not return plaintext password")
	}
}

func TestHashPassword_DifferentHashes(t *testing.T) {
	password := "testpassword123"
	hash1, _ := hashPassword(password)
	hash2, _ := hashPassword(password)
	if hash1 == hash2 {
		t.Error("Two calls to hashPassword() should produce different hashes (due to random salt)")
	}
}

func TestVerifyPassword_Correct(t *testing.T) {
	password := "testpassword123"
	hash, _ := hashPassword(password)
	
	if !verifyPassword(password, hash) {
		t.Error("verifyPassword() should return true for correct password")
	}
}

func TestVerifyPassword_Incorrect(t *testing.T) {
	password := "testpassword123"
	hash, _ := hashPassword(password)
	
	if verifyPassword("wrongpassword", hash) {
		t.Error("verifyPassword() should return false for incorrect password")
	}
}

func TestHashPassword_MinLength(t *testing.T) {
	// Passwords less than 8 chars should fail
	_, err := hashPassword("short")
	if err == nil {
		t.Error("hashPassword() should reject passwords < 8 chars")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v -run "TestHashPassword|TestVerifyPassword" ./...`
Expected: FAIL - undefined functions `hashPassword`, `verifyPassword`

- [ ] **Step 3: Write minimal Argon2id implementation**

```go
// password.go
package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	minPasswordLength = 8
	saltLength       = 16
	keyLength        = 32
	timeCost         = 1
	memoryCost       = 64 * 1024 // 64 MB
	parallelism      = 4
)

var ErrPasswordTooShort = errors.New("password must be at least 8 characters")

func hashPassword(password string) (string, error) {
	if len(password) < minPasswordLength {
		return "", ErrPasswordTooShort
	}
	
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	
	hash := argon2.IDKey([]byte(password), salt, timeCost, memoryCost, parallelism, keyLength)
	
	// Encode salt:hash in a portable format
	// Format: $argon2id$v=19$m=65536,t=1,p=4$<base64-salt>$<base64-hash>
	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedHash := base64.RawStdEncoding.EncodeToString(hash)
	
	return strings.Join([]string{
		"$argon2id$v=19$m=65536,t=1,p=4",
		encodedSalt,
		encodedHash,
	}, "$"), nil
}

func verifyPassword(password, encodedHash string) bool {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 4 {
		return false
	}
	
	// Parse parameters (simplified - in production you'd validate more carefully)
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	
	storedHash, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	
	// Derive hash from provided password
	derivedHash := argon2.IDKey([]byte(password), salt, timeCost, memoryCost, parallelism, keyLength)
	
	// Constant-time comparison
	return subtle.ConstantTimeCompare(derivedHash, storedHash) == 1
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -v -run "TestHashPassword|TestVerifyPassword" ./...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add password.go password_test.go
git commit -m "feat: add Argon2id password hashing utilities"
```

---

## Task 2: Database Schema Update

**Files:**
- Modify: `database.go:22-34`

- [ ] **Step 1: Write failing test for password_hash column**

```go
// database_test.go (add to existing or create)
func TestInitDB_WithPasswordHashColumn(t *testing.T) {
	tmpFile := "./test_password_schema_" + t.Name() + ".db"
	defer os.Remove(tmpFile)
	
	if err := initDBWithPath(tmpFile); err != nil {
		t.Fatalf("initDBWithPath() error = %v", err)
	}
	defer db.Close()
	
	// Verify password_hash column exists
	var columnExists int
	err := db.QueryRow("SELECT 1 FROM pragma_table_info('secrets') WHERE name='password_hash'").Scan(&columnExists)
	if err != nil {
		t.Fatalf("Failed to check column existence: %v", err)
	}
	if columnExists != 1 {
		t.Error("password_hash column should exist in secrets table")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v -run TestInitDB_WithPasswordHashColumn ./...`
Expected: FAIL - column doesn't exist

- [ ] **Step 3: Update schema in database.go**

```go
schema := `
CREATE TABLE IF NOT EXISTS secrets (
    id TEXT PRIMARY KEY,
    ciphertext TEXT NOT NULL,
    iv TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    views INTEGER DEFAULT 0,
    max_views INTEGER DEFAULT 1,
    allowed_cidrs TEXT,
    password_hash TEXT
);
CREATE INDEX IF NOT EXISTS idx_expires_at ON secrets(expires_at);
`
```

Also update the INSERT statement in `createSecretHandler` to include `password_hash` column and add a migration that runs `ALTER TABLE secrets ADD COLUMN password_hash TEXT` if the column doesn't exist.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -v -run TestInitDB_WithPasswordHashColumn ./...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add database.go
git commit -m "feat: add password_hash column to secrets table"
```

---

## Task 3: Update Models

**Files:**
- Modify: `models.go`

- [ ] **Step 1: Update CreateSecretRequest to add Password field**

```go
// CreateSecretRequest represents a request to create a new secret
type CreateSecretRequest struct {
	Ciphertext   string   `json:"ciphertext"`
	IV           string   `json:"iv"`
	ExpiresIn    int      `json:"expires_in"`
	MaxViews     int      `json:"max_views"`
	AllowedCIDRs []string `json:"allowed_cidrs,omitempty"`
	Password     string   `json:"password,omitempty"` // NEW
}
```

- [ ] **Step 2: Add GetSecretRequest struct**

```go
// GetSecretRequest represents a request to retrieve a secret
type GetSecretRequest struct {
	Password string `json:"password,omitempty"`
}
```

- [ ] **Step 3: Update Secret struct to include PasswordHash**

```go
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
	PasswordHash *string // NEW: pointer to allow NULL (no password)
}
```

- [ ] **Step 4: Commit**

```bash
git add models.go
git commit -m "feat: add password fields to models"
```

---

## Task 4: Update createSecretHandler

**Files:**
- Modify: `handlers.go`

- [ ] **Step 1: Write failing test for create with password**

```go
func TestCreateSecretHandler_WithPassword(t *testing.T) {
	initLogger()
	cleanup := setupTestDB(t)
	defer cleanup()

	reqBody := CreateSecretRequest{
		Ciphertext: "dGVzdC1jaXBoZXJ0ZXh0",
		IV:         "dGVzdC1pdg==",
		ExpiresIn:  3600,
		MaxViews:   1,
		Password:   "testpassword123",
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

	// Verify password was stored by retrieving the secret
	var storedHash string
	err := db.QueryRow("SELECT password_hash FROM secrets WHERE id = ?", resp.ID).Scan(&storedHash)
	if err != nil {
		t.Fatalf("Failed to query password_hash: %v", err)
	}
	if storedHash == "" {
		t.Error("password_hash should be stored")
	}
	if !verifyPassword("testpassword123", storedHash) {
		t.Error("Stored hash should verify correct password")
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
		Password:   "short", // Less than 8 chars
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/api/secrets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	createSecretHandler(rr, req)

	// Should accept short passwords but just not hash them
	// OR reject them - spec says minimum 8 chars
	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("Expected status %v for short password, got %v", http.StatusBadRequest, status)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v -run "TestCreateSecretHandler_WithPassword|TestCreateSecretHandler_PasswordTooShort" ./...`
Expected: FAIL - Password field not handled

- [ ] **Step 3: Update createSecretHandler**

In `handlers.go`, after getting `cidrsStr`, add password hashing:

```go
var passwordHash *string
if req.Password != "" {
    if len(req.Password) < 8 {
        http.Error(w, "Password must be at least 8 characters", http.StatusBadRequest)
        return
    }
    hash, err := hashPassword(req.Password)
    if err != nil {
        logger.Error("password_hash_failed", err, nil)
        http.Error(w, "Failed to process password", http.StatusInternalServerError)
        return
    }
    passwordHash = &hash
}
```

Update the INSERT statement:
```go
_, err = db.Exec(
    "INSERT INTO secrets (id, ciphertext, iv, expires_at, max_views, allowed_cidrs, password_hash) VALUES (?, ?, ?, ?, ?, ?, ?)",
    id, req.Ciphertext, req.IV, expiresAt, req.MaxViews, cidrsStr, passwordHash,
)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -v -run "TestCreateSecretHandler_WithPassword|TestCreateSecretHandler_PasswordTooShort" ./...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add handlers.go
git commit -m "feat: hash and store password on secret creation"
```

---

## Task 5: Update getSecretHandler (GET to POST + Password Verification)

**Files:**
- Modify: `handlers.go`

- [ ] **Step 1: Write failing tests for password-protected retrieval**

```go
func TestGetSecretHandler_WithPassword_Success(t *testing.T) {
	initLogger()
	cleanup := setupTestDB(t)
	defer cleanup()

	// Create secret with password
	reqBody := CreateSecretRequest{
		Ciphertext: "dGVzdC1jaXBoZXJ0ZXh0",
		IV:         "dGVzdC1pdg==",
		ExpiresIn:  3600,
		MaxViews:   2,
		Password:   "testpassword123",
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/api/secrets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	createSecretHandler(rr, req)

	var createResp CreateSecretResponse
	json.Unmarshal(rr.Body.Bytes(), &createResp)

	// Retrieve with correct password
	getReqBody := GetSecretRequest{Password: "testpassword123"}
	getBody, _ := json.Marshal(getReqBody)
	getReq := httptest.NewRequest("POST", "/api/secrets/"+createResp.ID, bytes.NewReader(getBody))
	getReq.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	getSecretHandler(rr, getReq)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Expected status %v, got %v", http.StatusOK, status)
	}
}

func TestGetSecretHandler_WithPassword_Missing(t *testing.T) {
	initLogger()
	cleanup := setupTestDB(t)
	defer cleanup()

	// Create secret with password
	reqBody := CreateSecretRequest{
		Ciphertext: "dGVzdC1jaXBoZXJ0ZXh0",
		IV:         "dGVzdC1pdg==",
		ExpiresIn:  3600,
		MaxViews:   1,
		Password:   "testpassword123",
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/api/secrets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	createSecretHandler(rr, req)

	var createResp CreateSecretResponse
	json.Unmarshal(rr.Body.Bytes(), &createResp)

	// Retrieve WITHOUT password (should fail)
	getReq := httptest.NewRequest("POST", "/api/secrets/"+createResp.ID, bytes.NewReader([]byte("{}")))
	getReq.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	getSecretHandler(rr, getReq)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("Expected status %v, got %v", http.StatusUnauthorized, status)
	}
}

func TestGetSecretHandler_WithPassword_Wrong(t *testing.T) {
	initLogger()
	cleanup := setupTestDB(t)
	defer cleanup()

	// Create secret with password
	reqBody := CreateSecretRequest{
		Ciphertext: "dGVzdC1jaXBoZXJ0ZXh0",
		IV:         "dGVzdC1pdg==",
		ExpiresIn:  3600,
		MaxViews:   1,
		Password:   "testpassword123",
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/api/secrets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	createSecretHandler(rr, req)

	var createResp CreateSecretResponse
	json.Unmarshal(rr.Body.Bytes(), &createResp)

	// Retrieve with wrong password
	getReqBody := GetSecretRequest{Password: "wrongpassword"}
	getBody, _ := json.Marshal(getReqBody)
	getReq := httptest.NewRequest("POST", "/api/secrets/"+createResp.ID, bytes.NewReader(getBody))
	getReq.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	getSecretHandler(rr, getReq)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("Expected status %v, got %v", http.StatusUnauthorized, status)
	}
}

func TestGetSecretHandler_NoPassword_NotRequired(t *testing.T) {
	initLogger()
	cleanup := setupTestDB(t)
	defer cleanup()

	// Create secret WITHOUT password
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

	// Retrieve without password (should succeed)
	getReqBody := GetSecretRequest{}
	getBody, _ := json.Marshal(getReqBody)
	getReq := httptest.NewRequest("POST", "/api/secrets/"+createResp.ID, bytes.NewReader(getBody))
	getReq.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	getSecretHandler(rr, getReq)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Expected status %v, got %v", http.StatusOK, status)
	}
}

func TestGetSecretHandler_PostMethodRequired(t *testing.T) {
	initLogger()
	cleanup := setupTestDB(t)
	defer cleanup()

	// Create a secret
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

	// Try GET (should fail with Method Not Allowed)
	getReq := httptest.NewRequest("GET", "/api/secrets/"+createResp.ID, nil)
	rr = httptest.NewRecorder()
	getSecretHandler(rr, getReq)

	if status := rr.Code; status != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %v for GET, got %v", http.StatusMethodNotAllowed, status)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -v -run "TestGetSecretHandler_With|TestGetSecretHandler_PostMethod" ./...`
Expected: FAIL - method not allowed, unauthorized, etc.

- [ ] **Step 3: Update getSecretHandler**

Change the method check from GET to POST:
```go
func getSecretHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {  // Changed from GET
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    // ...
}
```

Update the query to also fetch `password_hash`:
```go
var secret Secret
var cidrsStr string
var passwordHash sql.NullString
err := db.QueryRow(
    "SELECT id, ciphertext, iv, created_at, expires_at, views, max_views, allowed_cidrs, password_hash FROM secrets WHERE id = ?",
    id,
).Scan(&secret.ID, &secret.Ciphertext, &secret.IV, &secret.CreatedAt, &secret.ExpiresAt, &secret.Views, &secret.MaxViews, &cidrsStr, &passwordHash)

if passwordHash.Valid {
    secret.PasswordHash = &passwordHash.String
}
```

Add password verification after the CIDR check:
```go
if secret.PasswordHash != nil && *secret.PasswordHash != "" {
    // Parse request body for password
    var getReq GetSecretRequest
    if err := json.NewDecoder(r.Body).Decode(&getReq); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }
    
    if getReq.Password == "" || !verifyPassword(getReq.Password, *secret.PasswordHash) {
        LogSecretAccess(id, "retrieve_password_failed", false, clientIP, nil)
        http.Error(w, "Invalid or missing password", http.StatusUnauthorized)
        return
    }
}
```

Note: We need to read the body before the existing checks, so restructure to decode body early:
```go
func getSecretHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    id := strings.TrimPrefix(r.URL.Path, "/api/secrets/")
    if id == "" {
        http.Error(w, "Missing secret ID", http.StatusBadRequest)
        return
    }

    clientIP := getClientIP(r)

    // Parse request body for password (if any)
    var getReq GetSecretRequest
    json.NewDecoder(r.Body).Decode(&getReq) // Ignore error, password is optional

    var secret Secret
    var cidrsStr string
    var passwordHash sql.NullString
    err := db.QueryRow(
        "SELECT id, ciphertext, iv, created_at, expires_at, views, max_views, allowed_cidrs, password_hash FROM secrets WHERE id = ?",
        id,
    ).Scan(&secret.ID, &secret.Ciphertext, &secret.IV, &secret.CreatedAt, &secret.ExpiresAt, &secret.Views, &secret.MaxViews, &cidrsStr, &passwordHash)
    
    // ... rest of handler with password verification after CIDR check
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -v -run "TestGetSecretHandler_With|TestGetSecretHandler_PostMethod" ./...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add handlers.go
git commit -m "feat: change retrieve to POST and add password verification"
```

---

## Task 6: Update Frontend - Create Page

**Files:**
- Modify: `static/index.html`

- [ ] **Step 1: Add password input field to create form**

Add after the CIDR section (around line 55):
```html
<div class="form-group">
    <label for="password">Password Protection (Optional)</label>
    <input type="password" id="password" placeholder="Minimum 8 characters" minlength="8">
    <p class="help-text">If set, recipients must enter this password to view</p>
</div>
```

- [ ] **Step 2: Update JavaScript to include password in request**

In the submit handler (around line 161), add:
```javascript
// Get password
const password = document.getElementById('password').value;

// Prepare request
const request = {
    ciphertext: CryptoUtils.arrayBufferToBase64(encrypted.ciphertext),
    iv: CryptoUtils.arrayBufferToBase64(encrypted.iv),
    expires_in: parseInt(document.getElementById('expiry').value),
    max_views: parseInt(document.getElementById('max-views').value),
    allowed_cidrs: cidrs.length > 0 ? cidrs : undefined,
    password: password || undefined  // Only include if provided
};
```

- [ ] **Step 3: Update link generation to include ?p=1 when password set**

Change the link generation section (around line 183):
```javascript
// Build link with key in fragment
const keyBase64 = CryptoUtils.arrayBufferToBase64(key);
let link = `${window.location.origin}/s/${result.id}#${keyBase64}`;
// Add password indicator if password was set
if (password) {
    link += '?p=1';
}
```

- [ ] **Step 4: Test locally**

Run: `go build -o ghostpass . && ./ghostpass` (in background)  
Visit http://localhost:8080, create secret with password, verify URL includes `?p=1`

- [ ] **Step 5: Commit**

```bash
git add static/index.html
git commit -m "feat: add password input to create page"
```

---

## Task 7: Update Frontend - Retrieve Page

**Files:**
- Modify: `static/s/index.html`

- [ ] **Step 1: Add password input UI**

Add after the nav (around line 19), before the card:
```html
<div id="password-section" class="hidden">
    <div class="form-group">
        <label for="secret-password">Password Required</label>
        <input type="password" id="secret-password" placeholder="Enter password" required>
        <p class="help-text">This secret is password protected</p>
    </div>
    <button class="btn" id="view-btn" onclick="submitWithPassword()">View Secret</button>
</div>
```

Also hide the original loading section and modify the flow.

- [ ] **Step 2: Update loadSecret function to check for ?p=1**

Modify the function to:
1. Check URL params for `p=1`
2. If `p=1`, show password section instead of auto-fetching
3. If no `p=1`, proceed with existing auto-fetch logic

```javascript
async function loadSecret() {
    // Extract ID from path and key from fragment
    const pathParts = window.location.pathname.split('/');
    const id = pathParts[pathParts.length - 1];
    const keyBase64 = window.location.hash.slice(1); // Remove #
    
    // Check if password required
    const urlParams = new URLSearchParams(window.location.search);
    const requiresPassword = urlParams.get('p') === '1';
    
    if (!id || !keyBase64) {
        showError('Invalid secret link');
        return;
    }
    
    if (requiresPassword) {
        // Show password input
        document.getElementById('loading-section').classList.add('hidden');
        document.getElementById('password-section').classList.remove('hidden');
        // Store id and keyBase64 for later
        window.pendingSecretId = id;
        window.pendingKeyBase64 = keyBase64;
        return;
    }
    
    // No password required, fetch directly
    await fetchSecret(id, keyBase64, null);
}

async function submitWithPassword() {
    const password = document.getElementById('secret-password').value;
    if (!password) {
        return;
    }
    
    await fetchSecret(window.pendingSecretId, window.pendingKeyBase64, password);
}

async function fetchSecret(id, keyBase64, password) {
    // ... existing fetch logic but with POST and body
}
```

- [ ] **Step 3: Update fetch to use POST and include password**

Replace the fetch call with POST and body:
```javascript
async function fetchSecret(id, keyBase64, password) {
    try {
        const fetchOptions = {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
        };
        
        if (password) {
            fetchOptions.body = JSON.stringify({ password: password });
        } else {
            fetchOptions.body = JSON.stringify({});
        }
        
        const response = await fetch(`/api/secrets/${id}`, fetchOptions);
        
        if (response.status === 401) {
            throw new Error('Invalid or missing password');
        }
        
        if (response.status === 404) {
            throw new Error('SECRET_NOT_FOUND');
        }
        
        if (response.status === 403) {
            throw new Error('Access denied - your IP is not allowed to view this secret');
        }
        
        if (response.status === 410) {
            throw new Error('SECRET_BURNED');
        }

        if (!response.ok) {
            throw new Error('Failed to retrieve secret');
        }

        const data = await response.json();

        // Decrypt
        const key = CryptoUtils.base64ToArrayBuffer(keyBase64);
        const ciphertext = CryptoUtils.base64ToArrayBuffer(data.ciphertext);
        const iv = CryptoUtils.base64ToArrayBuffer(data.iv);

        const plaintext = await CryptoUtils.decrypt(ciphertext, iv, key);

        // Show secret
        document.getElementById('password-section').classList.add('hidden');
        document.getElementById('secret-content').textContent = plaintext;
        document.getElementById('secret-section').classList.remove('hidden');

    } catch (err) {
        document.getElementById('password-section').classList.add('hidden');
        
        if (err.message === 'SECRET_NOT_FOUND' || err.message === 'SECRET_BURNED') {
            document.getElementById('burned-section').classList.remove('hidden');
        } else {
            document.getElementById('error-message').textContent = err.message;
            document.getElementById('error-section').classList.remove('hidden');
        }
    }
}
```

- [ ] **Step 4: Test locally**

Visit a secret URL with `?p=1`, verify password prompt appears, enter correct/wrong password

- [ ] **Step 5: Commit**

```bash
git add static/s/index.html
git commit -m "feat: add password input to retrieve page"
```

---

## Task 8: Run Full Test Suite

- [ ] **Step 1: Run all tests**

Run: `go test -v ./...`
Expected: All tests pass

- [ ] **Step 2: Run linter**

Run: `golangci-lint run`
Expected: No errors

- [ ] **Step 3: Run security scan**

Run: `gosec -conf .gosec.json ./...`
Expected: No high/critical issues

- [ ] **Step 4: Commit final**

```bash
git add -A
git commit -m "feat: implement optional password protection for secrets"
```

---

## Dependencies

Add to `go.mod`:
```
golang.org/x/crypto v0.31.0
```

Run: `go mod tidy`

---

## Verification

After implementation:
1. Create secret with password via web UI
2. Copy URL (should include `?p=1`)
3. Open URL in new tab - should prompt for password
4. Enter wrong password - should show error
5. Enter correct password - should reveal secret
6. Create secret without password
7. Open URL - should auto-fetch without password prompt
8. API tests: create with password, retrieve without → 401
9. API tests: create with password, retrieve with wrong → 401
10. API tests: create with password, retrieve with correct → 200
