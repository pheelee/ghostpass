package main

import (
	"net"
	"net/http"
	"os"
	"strings"
)

var trustedProxies []string

func initTrustedProxies() {
	proxies := os.Getenv("TRUSTED_PROXIES")
	if proxies != "" {
		trustedProxies = strings.Split(proxies, ",")
		for i := range trustedProxies {
			trustedProxies[i] = strings.TrimSpace(trustedProxies[i])
		}
	}
}

func isTrustedProxy(ip string) bool {
	if len(trustedProxies) == 0 {
		return false
	}
	for _, proxy := range trustedProxies {
		if proxy == ip {
			return true
		}
		// Check if it's a CIDR range
		if strings.Contains(proxy, "/") {
			_, cidr, err := net.ParseCIDR(proxy)
			if err != nil {
				continue
			}
			clientIP := net.ParseIP(ip)
			if clientIP != nil && cidr.Contains(clientIP) {
				return true
			}
		}
	}
	return false
}

func getClientIP(r *http.Request) string {
	// Get the direct connection IP first
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	// Only trust X-Forwarded-For headers if the request comes from a trusted proxy
	if isTrustedProxy(host) {
		xff := r.Header.Get("X-Forwarded-For")
		if xff != "" {
			ips := strings.Split(xff, ",")
			return strings.TrimSpace(ips[0])
		}

		xri := r.Header.Get("X-Real-Ip")
		if xri != "" {
			return xri
		}
	}

	return host
}

func checkCIDR(clientIP string, cidrs []string) bool {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}

	for _, cidrStr := range cidrs {
		_, cidr, err := net.ParseCIDR(cidrStr)
		if err != nil {
			continue
		}
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}
