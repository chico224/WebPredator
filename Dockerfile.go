FROM golang:1.21-alpine as builder

WORKDIR /app

# Copy project files
COPY go.mod go.sum .
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o domainhunter .

# -----------------------------
# Stage 2: runtime
# -----------------------------
FROM alpine:3.19

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/domainhunter .

# Copy configuration files
COPY config.toml .

# Create directories
RUN mkdir -p plugins database templates exec reports logs

# Set permissions
RUN chmod +x domainhunter

# Default execution
ENTRYPOINT ["./domainhunter"]

# Metadata
LABEL org.opencontainers.image.title="DomainHunter Pro"
LABEL org.opencontainers.image.version="4.2.0"
LABEL org.opencontainers.image.description="Advanced subdomain discovery tool"
LABEL org.opencontainers.image.authors="Your Name <you@example.com>"
LABEL org.opencontainers.image.licenses="Commercial"

# Expose ports
EXPOSE 8080 8443
