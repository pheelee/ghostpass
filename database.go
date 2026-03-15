package main

import (
	"database/sql"
	"time"

	_ "modernc.org/sqlite"
)

func initDBWithPath(path string) error {
	var err error
	db, err = sql.Open("sqlite", path)
	if err != nil {
		return err
	}

	// Set connection limits
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	schema := `
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

	_, err = db.Exec(schema)
	return err
}

func initDB() error {
	return initDBWithPath("./ghostpass.db")
}

func cleanupExpiredSecretsWithTicker(ticker <-chan time.Time, done chan bool) {
	for {
		select {
		case <-ticker:
			result, err := db.Exec("DELETE FROM secrets WHERE expires_at < datetime('now') OR views >= max_views")
			if err != nil {
				logger.Error("cleanup_failed", err, nil)
				continue
			}
			affected, _ := result.RowsAffected()
			if affected > 0 {
				logger.Info("cleanup_completed", map[string]interface{}{
					"deleted_count": affected,
				})
			}
		case <-done:
			return
		}
	}
}

func cleanupExpiredSecrets() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	done := make(chan bool)
	// done channel will never be closed in production, runs forever
	// nolint:staticcheck
	cleanupExpiredSecretsWithTicker(ticker.C, done)
}
