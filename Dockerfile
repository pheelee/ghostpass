# Build stage
FROM golang:1.27-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN apk add --no-cache ca-certificates wget

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o ghostpass .

# Runtime stage
FROM scratch


WORKDIR /app

COPY --from=builder /app/ghostpass .
COPY --from=builder /app/static ./static
COPY --from=builder /usr/share/ca-certificates/ /usr/share/ca-certificates/

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/app/ghostpass", "healthz"]

VOLUME ["/app/data"]

CMD ["./ghostpass"]