package main

import (
	"database/sql"
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

func TestNewDatabaseHasPasswordHashColumn(t *testing.T) {
	initLogger()

	dbPath := "./test_new_db_" + t.Name() + ".db"
	defer os.Remove(dbPath)

	if err := initDBWithPath(dbPath); err != nil {
		t.Fatalf("Failed to init DB: %v", err)
	}
	defer db.Close()

	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('secrets') WHERE name='password_hash'").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to check column existence: %v", err)
	}
	if count != 1 {
		t.Error("New database should have password_hash column")
	}
}

func TestMigrationAddsPasswordHashColumn(t *testing.T) {
	initLogger()

	dbPath := "./test_migration_" + t.Name() + ".db"
	defer os.Remove(dbPath)

	sqlite, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}

	oldSchema := `
	CREATE TABLE IF NOT EXISTS secrets (
		id TEXT PRIMARY KEY,
		ciphertext TEXT NOT NULL,
		iv TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		expires_at TIMESTAMP NOT NULL,
		views INTEGER DEFAULT 0,
		max_views INTEGER DEFAULT 1,
		allowed_cidrs TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_expires_at ON secrets(expires_at);
	`
	_, err = sqlite.Exec(oldSchema)
	if err != nil {
		sqlite.Close()
		t.Fatalf("Failed to create old schema: %v", err)
	}
	sqlite.Close()

	if err := initDBWithPath(dbPath); err != nil {
		t.Fatalf("Failed to run migration: %v", err)
	}
	defer db.Close()

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('secrets') WHERE name='password_hash'").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to check column existence after migration: %v", err)
	}
	if count != 1 {
		t.Error("Migration should have added password_hash column")
	}
}
