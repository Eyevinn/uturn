# Build stage
FROM rust:1.99-alpine3.24 AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release

# Runtime stage
FROM alpine:3.24

RUN apk add --no-cache ca-certificates \
    && addgroup -S uturn \
    && adduser -S -G uturn -H -s /sbin/nologin uturn

COPY --from=builder /build/target/release/uturn /usr/local/bin/uturn

# Default port (>1024 so unprivileged user can bind). If a port <1024 is
# needed, grant CAP_NET_BIND_SERVICE at runtime or override USER.
# 3478/udp: TURN, the public port. 8081/tcp: the health endpoint (GET /healthz)
# for orchestrator probes and load balancer health checks, internal network only.
EXPOSE 3478/udp 8081/tcp

# The binary's own health default is loopback; in a container it has to listen
# on all interfaces to be reachable. Set UTURN_HEALTH=off to disable it.
ENV UTURN_HEALTH=0.0.0.0:8081

# Optional: UTURN_EXTERNAL_IP (auto-detected via STUN if unset;
#   UTURN_STUN_SERVERS overrides the servers used)
# Auth (one required, or UTURN_ALLOW_ANONYMOUS=true):
#   UTURN_USERS (user:pass,...) and/or UTURN_AUTH_SECRET (TURN REST API secret)
# Optional: UTURN_PORT, UTURN_REALM, UTURN_LOG_LEVEL

USER uturn
ENTRYPOINT ["/usr/local/bin/uturn"]
