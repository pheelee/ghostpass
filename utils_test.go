package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthHandler(t *testing.T) {
	req := httptest.NewRequest("GET", "/healthz", nil)
	rr := httptest.NewRecorder()

	healthHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("healthHandler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	if body := rr.Body.String(); body != "OK" {
		t.Errorf("healthHandler returned wrong body: got %v want %v", body, "OK")
	}
}

func TestIsTrustedProxy(t *testing.T) {
	// Save and restore original state
	originalProxies := trustedProxies
	defer func() {
		trustedProxies = originalProxies
	}()

	tests := []struct {
		name           string
		trustedProxies []string
		clientIP       string
		want           bool
	}{
		{
			name:           "Exact IP match",
			trustedProxies: []string{"192.168.1.1"},
			clientIP:       "192.168.1.1",
			want:           true,
		},
		{
			name:           "IP not in list",
			trustedProxies: []string{"192.168.1.1"},
			clientIP:       "192.168.1.2",
			want:           false,
		},
		{
			name:           "IP in CIDR range",
			trustedProxies: []string{"192.168.0.0/16"},
			clientIP:       "192.168.5.100",
			want:           true,
		},
		{
			name:           "Empty trusted proxies",
			trustedProxies: []string{},
			clientIP:       "192.168.1.1",
			want:           false,
		},
		{
			name:           "Multiple proxies - match one",
			trustedProxies: []string{"10.0.0.1", "192.168.1.0/24"},
			clientIP:       "192.168.1.50",
			want:           true,
		},
		{
			name:           "Invalid CIDR in list",
			trustedProxies: []string{"invalid-cidr", "192.168.1.1"},
			clientIP:       "192.168.1.1",
			want:           true,
		},
		{
			name:           "CIDR not matching",
			trustedProxies: []string{"10.0.0.0/8"},
			clientIP:       "192.168.1.1",
			want:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trustedProxies = tt.trustedProxies
			got := isTrustedProxy(tt.clientIP)
			if got != tt.want {
				t.Errorf("isTrustedProxy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetClientIP(t *testing.T) {
	originalProxies := trustedProxies
	defer func() {
		trustedProxies = originalProxies
	}()

	tests := []struct {
		name           string
		trustedProxies []string
		remoteAddr     string
		headers        map[string]string
		want           string
	}{
		{
			name:           "Direct connection",
			trustedProxies: []string{},
			remoteAddr:     "192.168.1.100:12345",
			headers:        map[string]string{},
			want:           "192.168.1.100",
		},
		{
			name:           "Behind trusted proxy - X-Forwarded-For",
			trustedProxies: []string{"10.0.0.1"},
			remoteAddr:     "10.0.0.1:12345",
			headers: map[string]string{
				"X-Forwarded-For": "192.168.1.100, 10.0.0.2",
			},
			want: "192.168.1.100",
		},
		{
			name:           "Behind untrusted proxy - ignore headers",
			trustedProxies: []string{"10.0.0.1"},
			remoteAddr:     "192.168.1.50:12345",
			headers: map[string]string{
				"X-Forwarded-For": "1.2.3.4",
			},
			want: "192.168.1.50",
		},
		{
			name:           "Behind trusted proxy - X-Real-Ip",
			trustedProxies: []string{"10.0.0.1"},
			remoteAddr:     "10.0.0.1:12345",
			headers: map[string]string{
				"X-Real-Ip": "192.168.1.200",
			},
			want: "192.168.1.200",
		},
		{
			name:           "Invalid remote addr format",
			trustedProxies: []string{},
			remoteAddr:     "invalid",
			headers:        map[string]string{},
			want:           "invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trustedProxies = tt.trustedProxies

			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr

			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			got := getClientIP(req)
			if got != tt.want {
				t.Errorf("getClientIP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckCIDR(t *testing.T) {
	tests := []struct {
		name     string
		clientIP string
		cidrs    []string
		want     bool
	}{
		{
			name:     "IP in CIDR range",
			clientIP: "192.168.1.100",
			cidrs:    []string{"192.168.1.0/24"},
			want:     true,
		},
		{
			name:     "IP not in CIDR range",
			clientIP: "192.168.2.100",
			cidrs:    []string{"192.168.1.0/24"},
			want:     false,
		},
		{
			name:     "Multiple CIDRs - match second",
			clientIP: "10.0.0.50",
			cidrs:    []string{"192.168.1.0/24", "10.0.0.0/8"},
			want:     true,
		},
		{
			name:     "Invalid client IP",
			clientIP: "invalid",
			cidrs:    []string{"192.168.1.0/24"},
			want:     false,
		},
		{
			name:     "Invalid CIDR - skipped",
			clientIP: "192.168.1.100",
			cidrs:    []string{"invalid-cidr", "192.168.1.0/24"},
			want:     true,
		},
		{
			name:     "IPv6 address",
			clientIP: "2001:db8::1",
			cidrs:    []string{"2001:db8::/32"},
			want:     true,
		},
		{
			name:     "Empty CIDR list",
			clientIP: "192.168.1.100",
			cidrs:    []string{},
			want:     false,
		},
		{
			name:     "CIDR with invalid format",
			clientIP: "192.168.1.100",
			cidrs:    []string{"not-a-cidr"},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkCIDR(tt.clientIP, tt.cidrs)
			if got != tt.want {
				t.Errorf("checkCIDR() = %v, want %v", got, tt.want)
			}
		})
	}
}
