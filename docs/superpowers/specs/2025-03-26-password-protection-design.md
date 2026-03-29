# Optional Password Protection for Secrets - Design Document

**Date:** 2025-03-26  
**Feature:** Optional Password Protection  
**Status:** Approved

---

## Overview

Add optional password protection to secrets. When a password is set during secret creation, users must provide the correct password to retrieve the secret. The password adds an additional layer of security beyond existing mechanisms (TTL, max views, CIDR restrictions).

---

## Goals

1. Allow users to optionally protect secrets with a password
2. Store passwords securely using modern hashing (Argon2id)
3. Require password verification before secret retrieval
4. Provide clear UI feedback for password-protected secrets

## Breaking Changes

**API Change:** The retrieve secret endpoint changes from `GET /api/secrets/{id}` to `POST /api/secrets/{id}`. This is a breaking change for API clients. The web UI is the primary client and will be updated accordingly.

---

## Non-Goals

1. Password recovery mechanism (secrets are meant to be ephemeral)
2. Password complexity requirements beyond minimum length
3. Rate limiting specifically for password attempts (general rate limiting applies)
4. Client-side password derivation

---

## Architecture

### Data Model Changes

**Database Schema Update:**
```sql
ALTER TABLE secrets ADD COLUMN password_hash TEXT;
```

- `password_hash`: Argon2id hash string (includes salt and parameters), NULL if no password

### API Changes

**1. Create Secret (POST /api/secrets)**

Request body additions:
```json
{
  "ciphertext": "...",
  "iv": "...",
  "expires_in": 3600,
  "max_views": 5,
  "allowed_cidrs": [],
  "password": "optional_password_here"  // NEW: optional, min 8 chars
}
```

Validation:
- If provided, password must be >= 8 characters
- Password is hashed with Argon2id before storage
- Plaintext password never stored or logged

**2. Retrieve Secret (POST /api/secrets/{id})**

*Note: Changed from GET to POST to support request body*

Request body:
```json
{
  "password": "user_entered_password"  // optional, required if secret has password
}
```

Response codes:
- `200 OK`: Secret retrieved successfully
- `400 Bad Request`: Invalid request body
- `401 Unauthorized`: Password required but not provided, or incorrect
- `404 Not Found`: Secret doesn't exist or has expired
- `403 Forbidden`: Client IP not in allowed CIDRs
- `410 Gone`: Secret has reached max views

Error message for 401: "Invalid or missing password" (same message for both cases to prevent user enumeration)

### Password Hashing

**Algorithm:** Argon2id (OWASP recommended)

**Parameters:**
- Time cost: 1
- Memory cost: 64 MB (65536 KB)
- Parallelism: 4 threads
- Salt length: 16 bytes
- Key length: 32 bytes
- Hash encoding: Argon2id standard format (includes all parameters)

**Functions:**
- `hashPassword(password string) (string, error)`: Generate new hash
- `verifyPassword(password, hash string) bool`: Verify password against hash

---

## Security Considerations

1. **Hash Storage**: Only Argon2id hashes stored, never plaintext
2. **Timing Attack Prevention**: Use constant-time comparison during verification
3. **User Enumeration Prevention**: Return same error for "no password" and "wrong password"
4. **Logging**: Never log passwords or password hashes
5. **Defense in Depth**: Password check happens AFTER CIDR validation
6. **Rate Limiting**: Existing rate limiting applies to password attempts

---

## Frontend Changes

### Create Page

**UI Elements:**
- Password input field (type="password")
- Label: "Password Protection (optional)"
- Helper text: "Minimum 8 characters. Recipients must enter this password to view."
- Client-side validation: Disable submit if password < 8 chars

**Behavior:**
- Password included in create request if provided
- If password set, show share URL with `?p=1` suffix

### Retrieve Page

**URL Format:**
- With password: `/s/{id}?p=1`
- Without password: `/s/{id}`

**UI Flow:**
1. Parse URL on page load
2. If `p=1` present:
   - Show password input field
   - Disable "View Secret" button until password entered
   - On submit, include password in POST body
3. If `p=1` not present:
   - Hide password field
   - POST without password field

**Error Handling:**
- 401 response: Show "Invalid or missing password" message (same as API to maintain consistent messaging)
- Other errors: Existing error handling

**Note on URL Parameter (`p=1`):**
The `?p=1` URL parameter indicates that a secret is password-protected. While this does leak the fact that a password is required (visible in browser history, logs, and referrers), this is an acceptable trade-off for better UX. The alternative would require an extra API call to check password status, which would add latency and complexity. The password itself is never exposed.

---

## Files Modified

### Backend

1. **database.go**: Add `password_hash` column to schema
2. **models.go**: Add `Password` field to `CreateSecretRequest`, create `GetSecretRequest`
3. **handlers.go**: 
   - Update `createSecretHandler` to handle password hashing
   - Change `getSecretHandler` from GET to POST, add password verification
4. **password.go** (new): Password hashing utilities

### Frontend

1. **static/index.html**: Add password input field
2. **static/js/app.js**: Update createSecret to send password
3. **static/s/index.html**: Add password input for retrieval
4. **static/js/retrieve.js**: Update getSecret to use POST and handle password

### Dependencies

Add to `go.mod`:
- `golang.org/x/crypto/argon2`

---

## Testing Strategy

### Unit Tests

1. **password_test.go**:
   - Test password hashing produces valid hash
   - Test password verification succeeds with correct password
   - Test password verification fails with wrong password
   - Test hash format is correct

2. **handlers_test.go**:
   - Test create secret with password
   - Test create secret without password (backward compatibility)
   - Test retrieve secret with correct password
   - Test retrieve secret with wrong password returns 401
   - Test retrieve secret without password when required returns 401
   - Test retrieve secret without password when not required succeeds
   - Test password minimum length validation

### Integration Tests

1. End-to-end flow: Create with password → Retrieve with correct password
2. End-to-end flow: Create with password → Retrieve with wrong password (fails)
3. Backward compatibility: Create without password → Retrieve (works)

---

## Migration Plan

1. **Schema Migration:** On application startup, `database.go` will execute `ALTER TABLE secrets ADD COLUMN password_hash TEXT;` if the column doesn't exist. This uses SQLite's ability to add nullable columns without data migration.
2. **Existing secrets:** Continue to work normally (password_hash will be NULL for existing rows)
3. **New secrets:** Can optionally have passwords set
4. **No data migration needed** - the nullable column defaults to NULL for existing rows

---

## Rollback Plan

1. Revert code to previous version
2. Column `password_hash` will be ignored by old code
3. Secrets created with password will be retrievable without password (degraded security but functional)

---

## Open Questions

None - design approved.

---

## Approval

Design reviewed and approved for implementation.
