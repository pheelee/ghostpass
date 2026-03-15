package main

import (
	"os"
	"testing"
	"time"
)

func TestCleanupExpiredSecretsWithTicker(t *testing.T) {
	initLogger()

	// Use temporary database file
	dbPath := "./test_cleanup_1.db"
	defer os.Remove(dbPath)

	if err := initDBWithPath(dbPath); err != nil {
		t.Fatalf("Failed to init DB: %v", err)
	}
	defer db.Close()

	// Insert an expired secret
	id, _ := generateID()
	_, err := db.Exec(
		"INSERT INTO secrets (id, ciphertext, iv, expires_at, max_views) VALUES (?, ?, ?, ?, ?)",
		id, "test-cipher", "test-iv", time.Now().Add(-time.Hour), 1,
	)
	if err != nil {
		t.Fatalf("Failed to insert expired secret: %v", err)
	}

	ticker := make(chan time.Time)
	done := make(chan bool)

	go cleanupExpiredSecretsWithTicker(ticker, done)

	// Trigger cleanup
	ticker <- time.Now()
	time.Sleep(50 * time.Millisecond)

	// Stop cleanup goroutine first
	close(done)
	time.Sleep(10 * time.Millisecond)

	// Now verify the expired secret was deleted
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM secrets WHERE id = ?", id).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query secrets: %v", err)
	}
	if count != 0 {
		t.Error("Expired secret should have been deleted")
	}
}

func TestCleanupExpiredSecretsWithTicker_MaxViews(t *testing.T) {
	initLogger()

	// Use temporary database file
	dbPath := "./test_cleanup_2.db"
	defer os.Remove(dbPath)

	if err := initDBWithPath(dbPath); err != nil {
		t.Fatalf("Failed to init DB: %v", err)
	}
	defer db.Close()

	// Insert a secret that has reached max views
	id, _ := generateID()
	_, err := db.Exec(
		"INSERT INTO secrets (id, ciphertext, iv, expires_at, views, max_views) VALUES (?, ?, ?, ?, ?, ?)",
		id, "test-cipher", "test-iv", time.Now().Add(time.Hour), 5, 5,
	)
	if err != nil {
		t.Fatalf("Failed to insert max views secret: %v", err)
	}

	ticker := make(chan time.Time)
	done := make(chan bool)

	go cleanupExpiredSecretsWithTicker(ticker, done)

	// Trigger cleanup
	ticker <- time.Now()
	time.Sleep(50 * time.Millisecond)

	// Stop cleanup goroutine first
	close(done)
	time.Sleep(10 * time.Millisecond)

	// Now verify the max views secret was deleted
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM secrets WHERE id = ?", id).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query secrets: %v", err)
	}
	if count != 0 {
		t.Error("Max views secret should have been deleted")
	}
}

func TestCleanupExpiredSecretsWithTickerDone(t *testing.T) {
	initLogger()

	// Use temporary database file
	dbPath := "./test_cleanup_3.db"
	defer os.Remove(dbPath)

	if err := initDBWithPath(dbPath); err != nil {
		t.Fatalf("Failed to init DB: %v", err)
	}
	defer db.Close()

	ticker := make(chan time.Time)
	done := make(chan bool)

	go cleanupExpiredSecretsWithTicker(ticker, done)

	// Immediately close done channel to stop goroutine
	close(done)
	time.Sleep(10 * time.Millisecond)
}

func TestCleanupExpiredSecretsWithTicker_CleanupError(t *testing.T) {
	initLogger()

	// Use temporary database file
	dbPath := "./test_cleanup_4.db"
	defer os.Remove(dbPath)

	if err := initDBWithPath(dbPath); err != nil {
		t.Fatalf("Failed to init DB: %v", err)
	}
	// Close the database to simulate an error
	db.Close()

	ticker := make(chan time.Time)
	done := make(chan bool)

	go cleanupExpiredSecretsWithTicker(ticker, done)

	// Trigger cleanup - should handle error gracefully
	ticker <- time.Now()
	time.Sleep(50 * time.Millisecond)

	// Stop cleanup goroutine
	close(done)
}
