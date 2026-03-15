package main

import (
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
)

// Logger provides structured logging
type Logger struct {
	jsonEncoder *json.Encoder
}

// LogEntry represents a structured log entry
type LogEntry struct {
	Timestamp  string                 `json:"timestamp"`
	Level      string                 `json:"level"`
	Message    string                 `json:"message"`
	RequestID  string                 `json:"request_id,omitempty"`
	Method     string                 `json:"method,omitempty"`
	Path       string                 `json:"path,omitempty"`
	StatusCode int                    `json:"status_code,omitempty"`
	ClientIP   string                 `json:"client_ip,omitempty"`
	UserAgent  string                 `json:"user_agent,omitempty"`
	Duration   string                 `json:"duration,omitempty"`
	SecretID   string                 `json:"secret_id,omitempty"`
	Error      string                 `json:"error,omitempty"`
	Fields     map[string]interface{} `json:"fields,omitempty"`
}

var logger *Logger

func initLogger() {
	logger = &Logger{
		jsonEncoder: json.NewEncoder(os.Stdout),
	}
}

func (l *Logger) log(entry LogEntry) {
	entry.Timestamp = time.Now().UTC().Format(time.RFC3339)
	if entry.Level == "" {
		entry.Level = "info"
	}
	l.jsonEncoder.Encode(entry)
}

func (l *Logger) Info(message string, fields map[string]interface{}) {
	l.log(LogEntry{Level: "info", Message: message, Fields: fields})
}

func (l *Logger) Warn(message string, fields map[string]interface{}) {
	l.log(LogEntry{Level: "warn", Message: message, Fields: fields})
}

func (l *Logger) Error(message string, err error, fields map[string]interface{}) {
	entry := LogEntry{Level: "error", Message: message, Fields: fields}
	if err != nil {
		entry.Error = err.Error()
	}
	l.log(entry)
}

func (l *Logger) Security(event string, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	fields["event_type"] = "security"
	l.log(LogEntry{Level: "warn", Message: event, Fields: fields})
}

// RequestLogger middleware logs all HTTP requests
func RequestLogger(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		requestID := uuid.New().String()

		// Add request ID to context
		ctx := WithRequestID(r.Context(), requestID)
		r = r.WithContext(ctx)

		// Wrap response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next(wrapped, r)

		duration := time.Since(start)

		entry := LogEntry{
			Timestamp:  time.Now().UTC().Format(time.RFC3339),
			Level:      "info",
			RequestID:  requestID,
			Method:     r.Method,
			Path:       r.URL.Path,
			StatusCode: wrapped.statusCode,
			ClientIP:   hashIP(getClientIP(r)),
			UserAgent:  r.UserAgent(),
			Duration:   duration.String(),
		}

		// Log based on status code
		if wrapped.statusCode >= 500 {
			entry.Level = "error"
			logger.log(entry)
		} else if wrapped.statusCode >= 400 {
			entry.Level = "warn"
			logger.log(entry)
		} else {
			logger.log(entry)
		}
	}
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// LogSecretAccess logs secret access attempts
func LogSecretAccess(secretID string, action string, success bool, clientIP string, err error) {
	fields := map[string]interface{}{
		"secret_id_hash": hashString(secretID),
		"action":         action,
		"success":        success,
		"client_ip":      hashIP(clientIP),
	}

	if err != nil {
		logger.Error("secret_access", err, fields)
	} else if success {
		logger.Info("secret_access", fields)
	} else {
		logger.Security("secret_access_denied", fields)
	}
}

// LogRateLimit logs rate limit violations
func LogRateLimit(clientIP string, path string) {
	logger.Security("rate_limit_exceeded", map[string]interface{}{
		"client_ip_hash": hashIP(clientIP),
		"path":           path,
	})
}
