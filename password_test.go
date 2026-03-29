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
	hash1, err := hashPassword(password)
	if err != nil {
		t.Fatalf("hashPassword() error = %v", err)
	}
	hash2, err := hashPassword(password)
	if err != nil {
		t.Fatalf("hashPassword() error = %v", err)
	}
	if hash1 == hash2 {
		t.Error("Two calls to hashPassword() should produce different hashes (due to random salt)")
	}
}

func TestVerifyPassword_Correct(t *testing.T) {
	password := "testpassword123"
	hash, err := hashPassword(password)
	if err != nil {
		t.Fatalf("hashPassword() error = %v", err)
	}

	if !verifyPassword(password, hash) {
		t.Error("verifyPassword() should return true for correct password")
	}
}

func TestVerifyPassword_Incorrect(t *testing.T) {
	password := "testpassword123"
	hash, err := hashPassword(password)
	if err != nil {
		t.Fatalf("hashPassword() error = %v", err)
	}

	if verifyPassword("wrongpassword", hash) {
		t.Error("verifyPassword() should return false for incorrect password")
	}
}

func TestHashPassword_MinLength(t *testing.T) {
	_, err := hashPassword("short")
	if err == nil {
		t.Error("hashPassword() should reject passwords < 8 chars")
	}
}
