# =============================================================================
# Builder Stage
# =============================================================================
FROM --platform=${BUILDPLATFORM} golang:1.26.4-alpine AS builder

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=2.5.1
ARG BUILD_DATE
ARG VCS_REF

WORKDIR /src

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./

RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    go mod download

COPY *.go ./
COPY templates/ ./templates/
COPY lang/*.json ./lang/

RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/.cache/go-build,sharing=locked \
    mkdir -p /out && \
    CGO_ENABLED=0 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH} \
    go build \
    -tags timetzdata \
    -trimpath \
    -ldflags="-s -w \
    -X main.Version=${VERSION} \
    -X main.BuildDate=${BUILD_DATE} \
    -X main.VCSRef=${VCS_REF}" \
    -o /out/dyndns .


# =============================================================================
# Runtime tools for target platform
# =============================================================================
FROM --platform=${TARGETPLATFORM} alpine:3.23 AS runtime-tools

RUN apk add --no-cache ca-certificates tzdata su-exec


# =============================================================================
# Runtime Stage
# =============================================================================
FROM busybox:stable-musl

ARG VERSION=2.5.1
ARG BUILD_DATE
ARG VCS_REF

LABEL org.opencontainers.image.title="Go-DynDNS" \
    org.opencontainers.image.description="Multi-Provider DynDNS-Client (IONOS, Cloudflare, IPv64)" \
    org.opencontainers.image.version="${VERSION}" \
    org.opencontainers.image.source="https://github.com/crazyus3r/ionos-ddns" \
    org.opencontainers.image.revision="${VCS_REF}" \
    org.opencontainers.image.created="${BUILD_DATE}"

ENV CONFIG_DIR="/config" \
    HEALTH_PORT="8080" \
    LANG="de" \
    DEBUG="false" \
    DEBUG_HTTP_RAW="false" \
    TZ="Europe/Berlin"

WORKDIR /app

RUN mkdir -p /app /config && \
    echo 'dyndns:x:1000:1000:dyndns:/nonexistent:/sbin/nologin' >> /etc/passwd && \
    echo 'dyndns:x:1000:' >> /etc/group && \
    chown -R 1000:1000 /app /config

COPY --from=runtime-tools /sbin/su-exec /sbin/su-exec
COPY --from=runtime-tools /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=runtime-tools /usr/share/zoneinfo /usr/share/zoneinfo

COPY --from=builder --chown=1000:1000 /out/dyndns /app/dyndns
COPY --chmod=755 docker-entrypoint.sh /docker-entrypoint.sh

VOLUME ["/config"]
EXPOSE 8080

HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD wget -qO- "http://localhost:${HEALTH_PORT}/health" || exit 1

ENTRYPOINT ["/docker-entrypoint.sh"]
