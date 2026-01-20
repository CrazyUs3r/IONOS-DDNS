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

RUN apk add --no-cache git ca-certificates

# Mod-Dateien zuerst für effizientes Caching
COPY go.mod go.sum ./
RUN go mod download

# Quellcode kopieren (Stelle sicher, dass maintest2.go bereits in main.go umbenannt wurde)
COPY main.go .

# Build ausführen
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.BuildDate=${BUILD_DATE}" \
    -trimpath \
    -o dyndns main.go

# =============================================================================
# Runtime Stage
# =============================================================================
FROM alpine:3.22

ARG VERSION=2.1.0
ARG BUILD_DATE
ARG VCS_REF

RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    curl \
    tini && \
    apk upgrade --no-cache

LABEL org.opencontainers.image.title="Go-DynDNS" \
      org.opencontainers.image.description="Multi-Provider DynDNS-Client (IONOS, Cloudflare, IPv64)" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}"

# --- Alle ENV Variablen aus der main.go ---
ENV PROVIDER="IONOS" \
    DOMAINS="example.com" \
    API_PREFIX="" \
    API_SECRET="" \
    CLOUDFLARE_TOKEN="" \
    CLOUDFLARE_ZONE_ID="" \
    IPV64_TOKEN="" \
    IPV64_DOMAIN_TOKEN="" \
    IP_MODE="BOTH" \
    INTERVAL=300 \
    HEALTH_PORT=8080 \
    LANG="de" \
    CONFIG_DIR="/config" \
    DRY_RUN=false \
    DEBUG=false \
    DEBUG_HTTP_RAW=false \
    DNS_SERVERS="1.1.1.1:53,8.8.8.8:53" \
    LOG_MAX_LINES=5000 \
    HOURLY_RATE_LIMIT=1200 \
    MAX_CONCURRENT=7 \
    TZ="Europe/Berlin"

WORKDIR /app

# User und Verzeichnisse
RUN addgroup -S -g 1000 dyndns && \
    adduser -S -u 1000 -G dyndns -h /home/dyndns dyndns && \
    mkdir -p /config/logs /config/lang && \
    chown -R dyndns:dyndns /config /app

# Artefakte kopieren
COPY --from=builder --chown=dyndns:dyndns /app/dyndns /app/
COPY --chown=dyndns:dyndns lang/*.json /app/lang/
COPY --chown=dyndns:dyndns docker-entrypoint.sh /app/

RUN chmod +x /app/dyndns /app/docker-entrypoint.sh

USER dyndns
VOLUME ["/config"]
EXPOSE ${HEALTH_PORT}

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f -s http://localhost:${HEALTH_PORT}/health || exit 1

ENTRYPOINT ["/sbin/tini", "--", "/app/docker-entrypoint.sh"]
CMD ["./dyndns"]
