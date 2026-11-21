# syntax=docker/dockerfile:1

# Etap 1: frontend (React + Vite). Cache npm przez BuildKit.
FROM node:20-alpine AS frontend
WORKDIR /frontend
COPY frontend/package*.json ./
RUN --mount=type=cache,target=/root/.npm \
    if [ -f package-lock.json ]; then npm ci --no-audit --no-fund; else npm install --no-audit --no-fund; fi
COPY frontend/ ./
RUN npm run build

# Etap 2: backend (Rust, statyczna binarka musl). Cache rejestru crate'ów i katalogu target przez BuildKit.
FROM rust:1-alpine AS backend
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
COPY migrations ./migrations
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release \
 && cp /src/target/release/asi /usr/local/bin/asi

# Etap 3: obraz uruchomieniowy (Alpine: nmap + certyfikaty, healthcheck przez wget z busyboxa)
FROM alpine:3.20
RUN apk add --no-cache nmap ca-certificates \
 && adduser -S -D -H -u 10001 -h /app -s /sbin/nologin asi \
 && mkdir -p /app/data \
 && chown -R asi /app

WORKDIR /app
COPY --from=backend /usr/local/bin/asi /usr/local/bin/asi
COPY --from=frontend /frontend/dist ./frontend/dist
COPY --chmod=755 docker/entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY config ./config
COPY signatures ./signatures
COPY examples ./examples
RUN sed -i 's/\r$//' /usr/local/bin/docker-entrypoint.sh

ENV ASI_BIND=0.0.0.0:8080 \
    RUST_LOG=info,sqlx=warn

# Bez uprawnień roota nmap używa skanu connect(), co wystarcza do discovery.
# SYN scan i ICMP wymagają roota oraz cap_add NET_RAW/NET_ADMIN (patrz README).
USER asi
VOLUME ["/app/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/api/health || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["serve"]
