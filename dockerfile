# =============================================================================
# Builder Stage
# =============================================================================
FROM --platform=${BUILDPLATFORM} golang:1.25-alpine AS builder

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=2.1.0
ARG BUILD_DATE
ARG VCS_REF

WORKDIR /app

# Build dependencies
RUN apk add --no-cache git ca-certificates

# Copy source
COPY main.go .

# Initialize module and build
RUN go mod init dyndns && \
    go mod tidy && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.BuildDate=${BUILD_DATE}" \
    -trimpath \
    -o dyndns main.go

# Verify binary
RUN chmod +x dyndns && \
    (file dyndns || true) && \
    (./dyndns --help 2>&1 || true)

# =============================================================================
# Runtime Stage
# =============================================================================
FROM alpine:3.22

# Install runtime dependencies and security updates
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    curl \
    tini && \
    apk upgrade --no-cache

# Metadata
LABEL org.opencontainers.image.title="IONOS-DDNS-Go" \
      org.opencontainers.image.description="Leichtgewichtiger DynDNS-Client für IONOS mit Dual-Stack Support" \
      org.opencontainers.image.authors="CrazyUs3r" \
      org.opencontainers.image.source="https://github.com/CrazyUs3r/IONOS-DDNS" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}"

# Environment defaults
ENV DOMAINS="example.com" \
    TZ=Europe/Berlin \
    IP_MODE="BOTH" \
    INTERFACE="eth0" \
    INTERVAL=300 \
    HEALTH_PORT=8080 \
    LANG=de \
    CONFIG_DIR=/config \
    API_PREFIX="" \
    API_SECRET="" \
    DRY_RUN=false \
    DEBUG=false \
    DEBUG_HTTP_RAW=false \
    DNS_SERVERS="1.1.1.1:53,8.8.8.8:53" \
    LOG_MAX_LINES=5000 \
    HOURLY_RATE_LIMIT=1200 \
    MAX_CONCURRENT=5

WORKDIR /app

# Create user and directories
RUN addgroup -S -g 1000 dyndns && \
    adduser -S -u 1000 -G dyndns -h /home/dyndns dyndns && \
    mkdir -p /config/logs /config/lang && \
    chown -R dyndns:dyndns /config /app

# Copy artifacts
COPY --from=builder --chown=dyndns:dyndns /app/dyndns /app/
COPY --chown=dyndns:dyndns lang/*.json /app/lang/
COPY --chown=dyndns:dyndns docker-entrypoint.sh /app/

# Set permissions
RUN chmod +x /app/dyndns /app/docker-entrypoint.sh

# Switch to non-root
USER dyndns

# Volume for persistent data
VOLUME ["/config"]

# Expose health port
EXPOSE ${HEALTH_PORT}

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f -s http://localhost:${HEALTH_PORT}/health || exit 1

# Use tini as init system
ENTRYPOINT ["/sbin/tini", "--", "/app/docker-entrypoint.sh"]
CMD ["./dyndns"]
