# =============================================================================
# Builder Stage
# =============================================================================
FROM --platform=${BUILDPLATFORM} golang:1.26.5-alpine AS builder

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=2.5.6
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
FROM alpine:3.24.1 AS runtime-tools

ARG SU_EXEC_COMMIT=89c016e6e08749d583efdeda04b9f73e1218e253

RUN apk add --no-cache \
    build-base \
    ca-certificates \
    git \
    tzdata && \
    git clone https://github.com/ncopa/su-exec.git /tmp/su-exec && \
    cd /tmp/su-exec && \
    git checkout "${SU_EXEC_COMMIT}" && \
    make su-exec-static && \
    strip su-exec-static && \
    mkdir -p /out && \
    cp su-exec-static /out/su-exec

# =============================================================================
# Runtime Stage
# =============================================================================
FROM busybox:stable-musl

ARG VERSION=2.5.6
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
    DASHBOARD_HTTPS_PORT="8443" \
    LANG="de" \
    DEBUG="false" \
    DEBUG_HTTP_RAW="false" \
    TZ="Europe/Berlin"

WORKDIR /app

RUN mkdir -p /app /config && \
    echo 'dyndns:x:1000:' >> /etc/group && \
    echo 'dyndns:x:1000:1000:dyndns:/nonexistent:/bin/false' >> /etc/passwd && \
    chown -R 1000:1000 /app /config

COPY --from=runtime-tools \
    --chmod=0755 \
    /out/su-exec /sbin/su-exec

COPY --from=runtime-tools \
    /etc/ssl/certs/ca-certificates.crt \
    /etc/ssl/certs/ca-certificates.crt

COPY --from=runtime-tools \
    /usr/share/zoneinfo \
    /usr/share/zoneinfo

COPY --from=builder \
    --chown=1000:1000 \
    --chmod=0755 \
    /out/dyndns /app/dyndns

COPY --chown=0:0 \
    --chmod=0755 \
    docker-entrypoint.sh /docker-entrypoint.sh

VOLUME ["/config"]

EXPOSE 8080 8443

HEALTHCHECK \
    --interval=60s \
    --timeout=10s \
    --start-period=30s \
    --retries=3 \
    CMD wget -q -O /dev/null "http://127.0.0.1:${HEALTH_PORT}/health" || exit 1

ENTRYPOINT ["/docker-entrypoint.sh"]
