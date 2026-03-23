# ── build stage ───────────────────────────────────────────────────────────────
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy module files first for layer caching
COPY go.mod ./
RUN go mod download

# Copy source (data is embedded at compile time via embed.go)
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o server .

# ── runtime stage ─────────────────────────────────────────────────────────────
FROM scratch

COPY --from=builder /app/server /server

EXPOSE 8080

ENTRYPOINT ["/server"]
