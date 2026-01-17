FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY main.go .
RUN go mod init dyndns && go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -o dyndns main.go

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata curl

LABEL org.opencontainers.image.title="IONOS-DDNS-Go" \
      org.opencontainers.image.description="Leichtgewichtiger DynDNS-Client fuer IONOS mit Dual-Stack Support" \
      org.opencontainers.image.authors="CrazyUs3r" \
      org.opencontainers.image.source="https://github.com/CrazyUs3r/IONOS-DDNS" \
      org.opencontainers.image.version="2.1.0"

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
    LOG_MAX_LINES=5000

WORKDIR /app

RUN addgroup -S dyndns && adduser -S dyndns -G dyndns && \
    mkdir -p /config/logs /config/lang && \
    chown -R dyndns:dyndns /config

COPY --from=builder --chown=dyndns:dyndns /app/dyndns .
COPY --chown=dyndns:dyndns lang/*.json /app/lang/
COPY --chown=dyndns:dyndns docker-entrypoint.sh /app/
RUN chmod +x /app/docker-entrypoint.sh

USER dyndns

VOLUME ["/config"]


HEALTHCHECK --interval=1m --timeout=5s --retries=3 \
  CMD curl -f http://localhost:${HEALTH_PORT}/health || exit 1

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["./dyndns"]
