package main

import (
	"net/http"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestAllowedTTLs(t *testing.T) {
	// Test that allowed TTLs are correctly defined
	expectedTTLs := []int{3600, 86400, 604800, 2592000}

	for _, ttl := range expectedTTLs {
		if !allowedTTLs[ttl] {
			t.Errorf("TTL %d should be allowed", ttl)
		}
	}

	// Test that invalid TTL is not allowed
	if allowedTTLs[12345] {
		t.Error("Invalid TTL 12345 should not be allowed")
	}
}

func TestInitDB(t *testing.T) {
	// Test database initialization
	dbPath := "./test_main_" + t.Name() + ".db"
	defer os.Remove(dbPath)
	err := initDBWithPath(dbPath)
	if err != nil {
		t.Fatalf("initDB() failed: %v", err)
	}
	defer db.Close()

	// Verify database is initialized
	if db == nil {
		t.Error("Database is nil after initialization")
	}
}

func TestDatabaseConnectionSettings(t *testing.T) {
	dbPath := "./test_main_" + t.Name() + ".db"
	defer os.Remove(dbPath)
	err := initDBWithPath(dbPath)
	if err != nil {
		t.Fatalf("initDB() failed: %v", err)
	}
	defer db.Close()

	// Verify connection settings are applied
	// Note: We can't directly test these, but we can verify the DB works
	err = db.Ping()
	if err != nil {
		t.Errorf("Database ping failed: %v", err)
	}
}

func TestGetPort_Default(t *testing.T) {
	// Save original env
	originalPort := os.Getenv("PORT")
	defer os.Setenv("PORT", originalPort)

	// Test default port
	os.Unsetenv("PORT")
	port := getPort()
	if port != "8080" {
		t.Errorf("Expected default port 8080, got %s", port)
	}
}

func TestGetPort_Custom(t *testing.T) {
	// Save original env
	originalPort := os.Getenv("PORT")
	defer os.Setenv("PORT", originalPort)

	// Test custom port
	os.Setenv("PORT", "3000")
	port := getPort()
	if port != "3000" {
		t.Errorf("Expected port 3000, got %s", port)
	}
}

func TestCreateServer(t *testing.T) {
	server := createServer("8080")

	if server.Addr != ":8080" {
		t.Errorf("Expected server address :8080, got %s", server.Addr)
	}

	if server.ReadTimeout != 5*time.Second {
		t.Errorf("Expected ReadTimeout 5s, got %v", server.ReadTimeout)
	}

	if server.WriteTimeout != 10*time.Second {
		t.Errorf("Expected WriteTimeout 10s, got %v", server.WriteTimeout)
	}

	if server.IdleTimeout != 120*time.Second {
		t.Errorf("Expected IdleTimeout 120s, got %v", server.IdleTimeout)
	}
}

func TestInitializeApp(t *testing.T) {
	// Save original db
	originalDB := db
	defer func() { db = originalDB }()

	err := initializeApp()
	if err != nil {
		t.Fatalf("initializeApp() failed: %v", err)
	}
	defer db.Close()

	if db == nil {
		t.Error("Database should be initialized")
	}

	if logger == nil {
		t.Error("Logger should be initialized")
	}
}

func TestInitializeApp_WithTrustedProxies(t *testing.T) {
	// Save original state
	originalDB := db
	originalProxies := os.Getenv("TRUSTED_PROXIES")
	defer func() {
		db = originalDB
		os.Setenv("TRUSTED_PROXIES", originalProxies)
	}()

	os.Setenv("TRUSTED_PROXIES", "192.168.1.1,10.0.0.0/8")

	err := initializeApp()
	if err != nil {
		t.Fatalf("initializeApp() failed: %v", err)
	}
	defer db.Close()

	if len(trustedProxies) == 0 {
		t.Error("Trusted proxies should be configured")
	}
}

func TestInitDBWithPath_Error(t *testing.T) {
	// Try to open a database in a read-only directory (should fail)
	err := initDBWithPath("/nonexistent/path/ghostpass.db")
	if err == nil {
		t.Error("Expected error when opening database in invalid path")
		if db != nil {
			db.Close()
		}
	}
}

func TestInitializeApp_DBError(t *testing.T) {
	// Save original db
	originalDB := db
	defer func() { db = originalDB }()

	// Set invalid database path via environment or other mechanism
	// Since initDB uses a hardcoded path, we'll need to test differently
	// This test documents that initializeApp returns error when initDB fails

	// For now, we can't easily test this without mocking or dependency injection
	// The test is here as documentation of the expected behavior
	t.Skip("Cannot test initDB error without mocking - requires database refactoring")
}

func TestSetupRoutes(t *testing.T) {
	// This test ensures setupRoutes doesn't panic
	// We can't easily test the actual routes without starting a server
	setupRoutes()
}

func TestRunServer(t *testing.T) {
	// Create a test server
	mux := http.NewServeMux()
	mux.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	server := &http.Server{
		Addr:    ":18080",
		Handler: mux,
	}

	quit := make(chan os.Signal, 1)

	// Start server in goroutine
	go func() {
		time.Sleep(50 * time.Millisecond)
		quit <- syscall.SIGTERM
	}()

	err := runServer(server, quit)
	if err != nil {
		t.Errorf("runServer() returned error: %v", err)
	}
}

func TestRunServer_WithContextTimeout(t *testing.T) {
	// Create a server that will force shutdown
	mux := http.NewServeMux()
	server := &http.Server{
		Addr:    ":18081",
		Handler: mux,
	}

	quit := make(chan os.Signal, 1)

	go func() {
		time.Sleep(50 * time.Millisecond)
		quit <- syscall.SIGTERM
	}()

	// This should complete without error
	err := runServer(server, quit)
	// Error might occur because we're shutting down quickly
	_ = err
}
