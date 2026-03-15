# Build stage
FROM golang:1.26-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o ghostpass .

# Runtime stage
FROM alpine:latest

RUN apk add --no-cache ca-certificates wget

WORKDIR /app

COPY --from=builder /app/ghostpass .
COPY --from=builder /app/static ./static

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/healthz || exit 1

VOLUME ["/app/data"]

CMD ["./ghostpass"]