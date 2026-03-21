# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /build

# Copy module files first for layer caching (stdlib-only, no dependencies).
COPY go.mod ./

# Copy all source.
COPY . .

# Build a fully static binary (no CGO, no libc dependency).
RUN CGO_ENABLED=0 GOOS=linux go build \
      -ldflags="-w -s -extldflags '-static'" \
      -o unifideck \
      ./cmd/unifideck

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
# Use Alpine (not scratch) so we have: ca-certificates (TLS to UDM Pro),
# tzdata (scheduler timezone support), and a shell for debugging.
FROM alpine:3.19

RUN apk --no-cache add ca-certificates tzdata && \
    addgroup -S unifideck && adduser -S unifideck -G unifideck

WORKDIR /app

COPY --from=builder /build/unifideck .

# data/ is a volume mount – this just ensures the directory exists at startup.
RUN mkdir -p /app/data && chown -R unifideck:unifideck /app

USER unifideck

EXPOSE 8099

# DATA_DIR is an absolute path so the binary always stores data here
# regardless of which working directory the process is started in.
# Mount /app/data as a volume to persist data across container upgrades:
#   docker run -v /your/host/path:/app/data ...
#   docker compose (see docker-compose.yml) mounts this automatically.
ENV PORT=8099
ENV DATA_DIR=/app/data

ENTRYPOINT ["/app/unifideck"]
