# =============================================================================
# Builder Stage
# =============================================================================
FROM --platform=${BUILDPLATFORM} golang:1.26.4-alpine AS builder

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=2.5.0
ARG BUILD_DATE
ARG VCS_REF

WORKDIR /app

RUN echo "dyndns:x:1000:1000::/:" > /etc/passwd && \
    echo "dyndns:x:1000:" > /etc/group

RUN apk add --no-cache git ca-certificates tzdata

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY *.go ./
COPY templates/ ./templates/
COPY lang/*.json ./lang/

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
      -tags timetzdata \
      -trimpath \
      -ldflags="-s -w -X main.Version=${VERSION} -X main.BuildDate=${BUILD_DATE} -X main.VCSRef=${VCS_REF}" \
      -o /out/dyndns .

# =============================================================================
# Runtime Stage
# =============================================================================
FROM busybox:stable-musl

ARG VERSION=2.5.0
ARG BUILD_DATE

LABEL org.opencontainers.image.title="Go-DynDNS" \
      org.opencontainers.image.description="Multi-Provider DynDNS-Client (IONOS, Cloudflare, IPv64)" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/crazyus3r/ionos-ddns" \
      org.opencontainers.image.created="${BUILD_DATE}"

ENV CONFIG_DIR="/config" \
    HEALTH_PORT="8080" \
    LANG="de" \
    DEBUG=false \
    DEBUG_HTTP_RAW=false \
    TZ="Europe/Berlin"

WORKDIR /app

RUN adduser -D -H -u 1000 -s /bin/sh dyndns

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder --chown=dyndns:dyndns /out/dyndns /app/dyndns

COPY docker-entrypoint.sh /docker-entrypoint.sh

RUN chmod +x /docker-entrypoint.sh /app/dyndns

VOLUME ["/config"]

EXPOSE 8080

HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD wget -qO- "http://localhost:${HEALTH_PORT}/health" || exit 1

ENTRYPOINT ["/docker-entrypoint.sh"]
