# =============================================================================
# Builder Stage
# =============================================================================
FROM --platform=${BUILDPLATFORM} golang:1.26.2-alpine AS builder

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=2.3.8
ARG BUILD_DATE
ARG VCS_REF

WORKDIR /app

RUN echo "dyndns:x:1000:1000::/:" > /etc/passwd && \
    echo "dyndns:x:1000:" > /etc/group

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./
COPY http/* ./http/
COPY lang/*.json ./lang/

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
    -tags timetzdata \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.BuildDate=${BUILD_DATE}" \
    -trimpath \
    -o dyndns .

# =============================================================================
# Runtime Stage
# =============================================================================
FROM busybox:stable-musl

ARG VERSION=2.3.8
ARG BUILD_DATE
ARG VCS_REF

LABEL org.opencontainers.image.title="Go-DynDNS" \
      org.opencontainers.image.description="Multi-Provider DynDNS-Client (IONOS, Cloudflare, IPv64)" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/crazyus3r/ionos-ddns" \
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
    HEALTH_PORT="8080" \
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

RUN adduser -D -H -u 1000 -s /sbin/nologin dyndns

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder --chown=dyndns:dyndns /app/dyndns /app/

USER dyndns

VOLUME ["/config"]
EXPOSE ${HEALTH_PORT}

HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD wget -qO- "http://localhost:${HEALTH_PORT}/health" || exit 1

ENTRYPOINT ["/app/dyndns"]