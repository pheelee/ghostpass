package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

func generateID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func createSecretHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CreateSecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Ciphertext == "" || req.IV == "" {
		http.Error(w, "Missing ciphertext or IV", http.StatusBadRequest)
		return
	}

	if req.MaxViews < 1 {
		req.MaxViews = 1
	}

	if req.MaxViews > 100 {
		http.Error(w, "Max views cannot exceed 100", http.StatusBadRequest)
		return
	}

	if !allowedTTLs[req.ExpiresIn] {
		req.ExpiresIn = 86400 // default to 24 hours
	}

	id, err := generateID()
	if err != nil {
		logger.Error("id_generation_failed", err, nil)
		http.Error(w, "Failed to generate ID", http.StatusInternalServerError)
		return
	}

	expiresAt := time.Now().UTC().Add(time.Duration(req.ExpiresIn) * time.Second)

	var cidrsStr string
	if len(req.AllowedCIDRs) > 0 {
		cidrsBytes, _ := json.Marshal(req.AllowedCIDRs)
		cidrsStr = string(cidrsBytes)
	}

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

	_, err = db.Exec(
		"INSERT INTO secrets (id, ciphertext, iv, expires_at, max_views, allowed_cidrs, password_hash) VALUES (?, ?, ?, ?, ?, ?, ?)",
		id, req.Ciphertext, req.IV, expiresAt, req.MaxViews, cidrsStr, passwordHash,
	)
	if err != nil {
		logger.Error("secret_creation_failed", err, nil)
		http.Error(w, "Failed to store secret", http.StatusInternalServerError)
		return
	}

	LogSecretAccess(id, "create", true, getClientIP(r), nil)

	resp := CreateSecretResponse{
		ID:        id,
		ExpiresAt: expiresAt,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

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

	var getReq GetSecretRequest
	if err := json.NewDecoder(r.Body).Decode(&getReq); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	clientIP := getClientIP(r)

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

	if err == sql.ErrNoRows {
		LogSecretAccess(id, "retrieve", false, clientIP, nil)
		http.Error(w, "Secret not found", http.StatusNotFound)
		return
	}
	if err != nil {
		logger.Error("database_query_failed", err, map[string]interface{}{
			"secret_id_hash": hashString(id),
		})
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if time.Now().UTC().After(secret.ExpiresAt) {
		db.Exec("DELETE FROM secrets WHERE id = ?", id)
		LogSecretAccess(id, "retrieve_expired", false, clientIP, nil)
		http.Error(w, "Secret expired", http.StatusNotFound)
		return
	}

	if secret.Views >= secret.MaxViews {
		db.Exec("DELETE FROM secrets WHERE id = ?", id)
		LogSecretAccess(id, "retrieve_max_views", false, clientIP, nil)
		http.Error(w, "Secret already viewed", http.StatusGone)
		return
	}

	if cidrsStr != "" {
		json.Unmarshal([]byte(cidrsStr), &secret.AllowedCIDRs)
		if !checkCIDR(clientIP, secret.AllowedCIDRs) {
			LogSecretAccess(id, "retrieve_ip_denied", false, clientIP, nil)
			http.Error(w, "Access denied from this IP", http.StatusForbidden)
			return
		}
	}

	if secret.PasswordHash != nil && *secret.PasswordHash != "" {
		if getReq.Password == "" || !verifyPassword(getReq.Password, *secret.PasswordHash) {
			LogSecretAccess(id, "retrieve_password_failed", false, clientIP, nil)
			http.Error(w, "Invalid or missing password", http.StatusUnauthorized)
			return
		}
	}

	_, err = db.Exec("UPDATE secrets SET views = views + 1 WHERE id = ?", id)
	if err != nil {
		logger.Error("view_count_update_failed", err, map[string]interface{}{
			"secret_id_hash": hashString(id),
		})
		http.Error(w, "Failed to update view count", http.StatusInternalServerError)
		return
	}

	if secret.Views+1 >= secret.MaxViews {
		db.Exec("DELETE FROM secrets WHERE id = ?", id)
	}

	LogSecretAccess(id, "retrieve", true, clientIP, nil)

	resp := GetSecretResponse{
		Ciphertext: secret.Ciphertext,
		IV:         secret.IV,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func serveSecretPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/s/index.html")
}
