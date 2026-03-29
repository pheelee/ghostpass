package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	minPasswordLength = 8
	saltLength        = 16
	keyLength         = 32
	timeCost          = 1
	memoryCost        = 64 * 1024
	parallelism       = 4
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

	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedHash := base64.RawStdEncoding.EncodeToString(hash)

	format := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d", memoryCost, timeCost, parallelism)
	return strings.Join([]string{
		format,
		encodedSalt,
		encodedHash,
	}, "$"), nil
}

func verifyPassword(password, encodedHash string) bool {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}

	storedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}

	derivedHash := argon2.IDKey([]byte(password), salt, timeCost, memoryCost, parallelism, keyLength)

	return subtle.ConstantTimeCompare(derivedHash, storedHash) == 1
}
