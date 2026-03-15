package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

var db *sql.DB
var allowedTTLs = map[int]bool{
	3600:    true, // 1 hour
	86400:   true, // 24 hours
	604800:  true, // 7 days
	2592000: true, // 30 days
}

func getPort() string {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	return port
}

func createServer(port string) *http.Server {
	return &http.Server{
		Addr:         ":" + port,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
}

func setupRoutes() {
	// Chain middleware for API handlers
	apiHandler := func(handler http.HandlerFunc) http.HandlerFunc {
		return RequestLogger(securityHeaders(rateLimitMiddleware(connectionLimit(panicRecovery(maxBodySize(handler))))))
	}

	fs := http.FileServer(http.Dir("static"))
	http.Handle("/", fs)
	http.HandleFunc("/s/", securityHeaders(serveSecretPage))
	http.HandleFunc("/api/secrets", apiHandler(createSecretHandler))
	http.HandleFunc("/api/secrets/", apiHandler(getSecretHandler))
	http.HandleFunc("/healthz", healthHandler)
}

func initializeApp() error {
	initLogger()

	if err := initDB(); err != nil {
		return err
	}

	initTrustedProxies()
	if len(trustedProxies) > 0 {
		log.Printf("Trusted proxies configured: %v", trustedProxies)
	} else {
		log.Printf("No trusted proxies configured - X-Forwarded-For headers will be ignored")
	}

	return nil
}

func runServer(server *http.Server, quit chan os.Signal) error {
	// Start server in goroutine
	go func() {
		log.Printf("Server starting on port %s", server.Addr[1:])
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	// Wait for interrupt signal for graceful shutdown
	<-quit

	log.Println("Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return server.Shutdown(ctx)
}

func main() {
	if err := initializeApp(); err != nil {
		log.Fatalf("Failed to initialize application: %v", err)
	}
	defer db.Close()

	go cleanupExpiredSecrets()

	setupRoutes()

	port := getPort()
	server := createServer(port)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	if err := runServer(server, quit); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	log.Println("Server gracefully stopped")
}
