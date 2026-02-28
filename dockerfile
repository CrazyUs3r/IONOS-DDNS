# =============================================================================
# Builder Stage
# =============================================================================
FROM --platform=${BUILDPLATFORM} golang:1.26-alpine AS builder

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=2.3.0
ARG BUILD_DATE
ARG VCS_REF

WORKDIR /app

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY *.go .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.BuildDate=${BUILD_DATE}" \
    -trimpath \
    -o dyndns .

# =============================================================================
# Runtime Stage
# =============================================================================
FROM alpine:3.23

ARG VERSION=2.3.0
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
    HEALTH_PORT="" \
    LANG="de" \
    CONFIG_DIR="/config" \
    DRY_RUN=false \
    DEBUG=false \
    DEBUG_HTTP_RAW=false \
    DNS_SERVERS="1.1.1.1:53,8.8.8.8:53" \
    LOG_MAX_LINES=5000 \
    HOURLY_RATE_LIMIT=1200 \
    MAX_CONCURRENT=7 \
    MAX_API_RETRIES=3 \
    TZ="Europe/Berlin" \
    TELEGRAM_BOT_TOKEN="" \
    TELEGRAM_CHAT_ID="" \
    GOTIFY_URL="" \
    GOTIFY_TOKEN="" \
    NOTIFY_ON="UPDATE,CREATE,ERROR"

WORKDIR /app

RUN addgroup -S -g 1000 dyndns && \
    adduser -S -u 1000 -G dyndns -h /home/dyndns dyndns && \
    mkdir -p /config/logs /config/lang && \
    chown -R dyndns:dyndns /config /app

COPY --from=builder --chown=dyndns:dyndns /app/dyndns /app/
COPY --chown=dyndns:dyndns lang/*.json /app/lang/
COPY --chown=dyndns:dyndns docker-entrypoint.sh /app/

RUN chmod +x /app/dyndns /app/docker-entrypoint.sh

USER dyndns
VOLUME ["/config"]
EXPOSE ${HEALTH_PORT}

HEALTHCHECK --interval=300s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f -s http://localhost:${HEALTH_PORT}/health || exit 1

ENTRYPOINT ["/sbin/tini", "--", "/app/docker-entrypoint.sh"]
CMD ["./dyndns"]

