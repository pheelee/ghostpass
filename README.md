# GhostPass

[![Docker Build](https://github.com/pheelee/ghostpass/actions/workflows/release.yml/badge.svg)](https://github.com/pheelee/ghostpass/actions/workflows/release.yml)
[![codecov](https://codecov.io/gh/pheelee/ghostpass/branch/main/graph/badge.svg)](https://codecov.io/gh/pheelee/ghostpass)
[![Go Report Card](https://goreportcard.com/badge/github.com/pheelee/ghostpass)](https://goreportcard.com/report/github.com/pheelee/ghostpass)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/github/go-mod/go-version/pheelee/ghostpass)](https://go.dev/)

A minimal, privacy-focused service for sharing sensitive text (passwords, tokens, notes) via one-time, self-destructing, client-side-encrypted links.

## Features

- **Client-side encryption**: AES-GCM encryption in the browser before sending to server
- **One-time retrieval**: Secrets are deleted after first successful fetch
- **Self-destructing**: Automatic expiration (1h, 24h, 7d, 30d options)
- **IP restriction**: Optional CIDR-based access control
- **Zero knowledge**: Server never sees encryption keys or plaintext
- **Rate limiting**: Per-IP rate limiting to prevent abuse
- **Connection limiting**: Maximum concurrent connections to prevent overload
- **Security headers**: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy
- **Trusted proxy support**: Configurable trusted proxy validation for X-Forwarded-For headers
- **Structured logging**: JSON logging with privacy-preserving hashed identifiers
- **Graceful shutdown**: Clean shutdown on SIGINT/SIGTERM signals
- **Comprehensive testing**: 91.3% test coverage with automated CI/CD

## Security

GhostPass implements defense-in-depth security with a comprehensive security validation report available in [SECURITY.md](SECURITY.md).

The [SECURITY.md](SECURITY.md) document provides a detailed OWASP Top 10:2025 security validation report covering:

- **A01: Broken Access Control** - CIDR-based IP restrictions, rate limiting, trusted proxy validation
- **A02: Security Misconfiguration** - Comprehensive security headers, request size limits, generic error messages
- **A03: Software Supply Chain** - Minimal dependencies, Renovate for automated updates, no external assets
- **A04: Cryptographic Failures** - AES-GCM with 256-bit keys, 128-bit IVs, proper key management
- **A05: Injection** - Parameterized queries throughout, no SQL injection vulnerabilities
- **A06: Insecure Design** - Zero-knowledge architecture, one-time use design, defense in depth
- **A07: Authentication Failures** - High-entropy random IDs (128-bit), rate limiting prevents enumeration
- **A08: Software/Data Integrity** - AES-GCM authenticated encryption, tamper detection via GCM tags
- **A09: Security Logging** - Structured JSON logging with privacy-preserving hashed identifiers
- **A10: Exceptional Conditions** - Panic recovery, timeouts, connection limits, graceful shutdown

**Overall Security Posture: GOOD** - All OWASP Top 10:2025 categories properly addressed with production-ready security controls.

## Quick Start

### Local Development

```bash
# Clone the repository
git clone https://github.com/pheelee/ghostpass.git
cd ghostpass

# Build
go build -o ghostpass .

# Run
./ghostpass
```

The server will start on port 8080 by default. Visit http://localhost:8080

### Docker

```bash
# Build
docker build -t ghostpass .

# Run
docker run -p 8080:8080 -v $(pwd)/data:/app/data ghostpass
```

## API Endpoints

### POST `/api/secrets`

Create a new encrypted secret.

**Request:**
```json
{
  "ciphertext": "base64url_encoded_encrypted_data",
  "iv": "base64url_encoded_iv",
  "expires_in": 86400,
  "max_views": 1,
  "allowed_cidrs": ["192.168.1.0/24"]
}
```

**Parameters:**
- `ciphertext` (required): Base64URL-encoded encrypted data
- `iv` (required): Base64URL-encoded initialization vector
- `expires_in` (optional): TTL in seconds (3600, 86400, 604800, 2592000). Defaults to 86400 (24h)
- `max_views` (optional): Maximum number of views (1-100). Defaults to 1
- `allowed_cidrs` (optional): Array of CIDR ranges allowed to access the secret

**Response:**
```json
{
  "id": "abc123xyz",
  "expires_at": "2026-03-13T15:00:00Z"
}
```

### GET `/api/secrets/:id`

Retrieve ciphertext for decryption.

**Response:**
```json
{
  "ciphertext": "base64url_encoded_encrypted_data",
  "iv": "base64url_encoded_iv"
}
```

**Error Responses:**
- `404 Not Found`: Secret doesn't exist or has expired
- `410 Gone`: Secret has already been viewed (max views reached)
- `403 Forbidden`: Client IP not in allowed CIDR ranges
- `429 Too Many Requests`: Rate limit exceeded
- `503 Service Unavailable`: Server at connection capacity

### GET `/healthz`

Health check endpoint.

**Response:** `OK` (200 status)

## How It Works

1. **Encryption**: When creating a secret, the browser generates a random 256-bit key and encrypts the plaintext using AES-GCM
2. **Storage**: Only the encrypted ciphertext and IV are sent to the server
3. **Key Storage**: The encryption key is appended to the URL as a fragment (`#key`), which browsers never send to the server
4. **Retrieval**: When viewing a secret, the browser extracts the key from the URL fragment, fetches the encrypted data, and decrypts it locally
5. **Destruction**: After viewing, the secret is permanently deleted from the server

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | `8080` |
| `TRUSTED_PROXIES` | Comma-separated list of trusted proxy IPs/CIDRs (e.g., `10.0.0.1,192.168.0.0/16`) | none |
| `ENABLE_HSTS` | Enable HSTS header (set to `true` if not using reverse proxy) | `false` |

## Development

### Running Tests

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run with detailed coverage report
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
go tool cover -html=coverage.out
```

Current test coverage: **91.3%**

### Project Structure

```
ghostpass/
├── main.go              # Application entry point, server setup
├── handlers.go          # HTTP request handlers (API endpoints)
├── middleware.go        # HTTP middleware (rate limiting, security headers, etc.)
├── database.go          # Database initialization and cleanup
├── models.go            # Data structures and types
├── logger.go            # Structured logging infrastructure
├── context.go           # Request context utilities
├── utils.go             # IP validation and CIDR checking utilities
├── static/              # Static web assets (HTML, CSS, JS)
│   ├── index.html       # Main application page
│   ├── about.html       # About page
│   ├── s/               # Secret viewing page
│   ├── css/
│   └── js/
│       └── crypto.js    # Client-side encryption implementation
├── *_test.go            # Unit tests for each module
├── SECURITY.md          # Comprehensive security validation report
├── Dockerfile           # Docker image definition
└── go.mod               # Go module dependencies
```

### Architecture

The application follows a clean, modular architecture:

- **Zero-knowledge design**: Server never has access to encryption keys or plaintext
- **Defense in depth**: Multiple layers of security (encryption, rate limiting, IP restrictions)
- **Ephemeral data**: Secrets exist only temporarily and are permanently deleted after use
- **Privacy-first logging**: All sensitive identifiers are hashed before logging
- **Resource protection**: Connection limits, timeouts, and size limits prevent abuse

### Testing Strategy

- **Unit tests**: Comprehensive coverage of all handlers, middleware, and utilities
- **Isolated test databases**: Each test uses temporary SQLite databases to avoid conflicts
- **Error path testing**: Tests for database errors, invalid input, and edge cases
- **Mock-friendly design**: Key functions extracted for easier testing

## Deployment

### Recommended Setup

1. **Run behind a reverse proxy** (nginx, traefik, etc.) for:
   - TLS termination
   - HSTS header configuration
   - Additional rate limiting

2. **Configure trusted proxies** when running behind a load balancer:
   ```bash
   export TRUSTED_PROXIES="10.0.0.0/8,172.16.0.0/12"
   ```

3. **Enable HSTS** only if not using a reverse proxy:
   ```bash
   export ENABLE_HSTS=true
   ```

### Docker Compose Example

```yaml
version: '3'
services:
  ghostpass:
    image: pheelee/ghostpass:latest
    ports:
      - "8080:8080"
    environment:
      - PORT=8080
      - TRUSTED_PROXIES=10.0.0.0/8
    volumes:
      - ./data:/app/data
    restart: unless-stopped
```

## Security Considerations

- Always use HTTPS in production (TLS 1.2+)
- Configure `TRUSTED_PROXIES` when behind a load balancer to prevent IP spoofing
- Enable HSTS at the reverse proxy level or via `ENABLE_HSTS=true`
- The server stores only encrypted data and has no access to decryption keys
- Secrets are automatically cleaned up after expiration or max views
- All logs use hashed identifiers to protect privacy

## License

MIT License - see [LICENSE](LICENSE) file for details

## Acknowledgments

- Inspired by [transfer.pw](https://transfer.pw) - this is an independent reimplementation
- Uses [modernc.org/sqlite](https://gitlab.com/cznic/sqlite) for pure Go SQLite support
- Uses [golang.org/x/time/rate](https://pkg.go.dev/golang.org/x/time/rate) for rate limiting

---


**Note**: This is a security-focused application. Please review the [SECURITY.md](SECURITY.md) document for detailed security information and the [LICENSE](LICENSE) file for usage terms.
