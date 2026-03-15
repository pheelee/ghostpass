package main

import (
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Rate Limiter
type rateLimiter struct {
	visitors map[string]*rate.Limiter
	lastSeen map[string]time.Time
	mu       sync.RWMutex
	rate     rate.Limit
	burst    int
}

func newRateLimiter(r rate.Limit, b int) *rateLimiter {
	rl := &rateLimiter{
		visitors: make(map[string]*rate.Limiter),
		lastSeen: make(map[string]time.Time),
		rate:     r,
		burst:    b,
	}
	go rl.cleanup()
	return rl
}

func (rl *rateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	limiter, exists := rl.visitors[ip]
	if !exists {
		limiter = rate.NewLimiter(rl.rate, rl.burst)
		rl.visitors[ip] = limiter
	}
	rl.lastSeen[ip] = time.Now()
	return limiter
}

func (rl *rateLimiter) cleanupWithTicker(ticker <-chan time.Time, done chan bool) {
	for {
		select {
		case <-ticker:
			rl.mu.Lock()
			now := time.Now()
			for ip, lastSeen := range rl.lastSeen {
				if now.Sub(lastSeen) > 30*time.Minute {
					delete(rl.visitors, ip)
					delete(rl.lastSeen, ip)
				}
			}
			rl.mu.Unlock()
		case <-done:
			return
		}
	}
}

func (rl *rateLimiter) cleanup() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	done := make(chan bool)
	// done channel will never be closed in production, runs forever
	// nolint:staticcheck
	rl.cleanupWithTicker(ticker.C, done)
}

var limiter = newRateLimiter(10, 20)

// Middleware functions
func securityHeaders(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; media-src 'none'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Permissions-Policy", "accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), camera=(), cross-origin-isolated=(), display-capture=(), document-domain=(), encrypted-media=(), execution-while-not-rendered=(), execution-while-out-of-viewport=(), fullscreen=(), geolocation=(), gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(), navigation-override=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(), usb=(), web-share=(), xr-spatial-tracking=()")

		// Add HSTS only if explicitly enabled (should be set by reverse proxy in production)
		if os.Getenv("ENABLE_HSTS") == "true" {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}

		next(w, r)
	}
}

func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)
		limiter := limiter.getLimiter(ip)
		if !limiter.Allow() {
			LogRateLimit(ip, r.URL.Path)
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

func panicRecovery(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				logger.Error("panic_recovered", nil, map[string]interface{}{
					"error": err,
					"path":  r.URL.Path,
				})
				http.Error(w, "Internal server error", http.StatusInternalServerError)
			}
		}()
		next(w, r)
	}
}

func maxBodySize(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1024*1024) // 1MB limit
		next(w, r)
	}
}

// Connection Limiter
type connectionLimiter struct {
	count int64
	max   int64
	mu    sync.Mutex
}

var connLimiter = &connectionLimiter{max: 1000}

func (cl *connectionLimiter) acquire() bool {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if cl.count >= cl.max {
		return false
	}
	cl.count++
	return true
}

func (cl *connectionLimiter) release() {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if cl.count > 0 {
		cl.count--
	}
}

func connectionLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !connLimiter.acquire() {
			logger.Error("connection_limit_exceeded", nil, map[string]interface{}{
				"client_ip": hashIP(getClientIP(r)),
			})
			http.Error(w, "Server overloaded", http.StatusServiceUnavailable)
			return
		}
		defer connLimiter.release()
		next(w, r)
	}
}
