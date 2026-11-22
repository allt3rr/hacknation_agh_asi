# syntax=docker/dockerfile:1
# Obraz ASI: backend (backend/, PostgreSQL) ze skanerem nmap i zbudowanym interfejsem z tego samego originu.

# Etap 1: interfejs (React + Vite) z lockfile.
FROM node:24-alpine@sha256:116b800c3754b440ee0aa3ed2f20f5bf3d99a554bfd9adeea09ea8017f6e85f5 AS frontend
WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# Etap 2: backend (Rust, statyczna binarka musl) z wersjonowanego Cargo.lock.
FROM rust:1-alpine3.22@sha256:f8ddfd4b265d9a9e7fd7c36821af4a55771aee2ac3894294687a66c709319be9 AS backend
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY backend/ ./
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p asi \
 && cp /src/target/release/asi /usr/local/bin/asi

# Etap 3: nuclei (MIT) do weryfikacji aktywnej podatności. Wersja przypięta, integralność modułów
# sprawdza sum.golang.org; szablony to migawka z tagu (bez aktualizacji w czasie działania).
FROM golang:1.23-alpine AS nuclei
ARG NUCLEI_VERSION=v3.3.7
ARG NUCLEI_TEMPLATES_VERSION=v10.1.0
RUN apk add --no-cache git \
 && CGO_ENABLED=0 go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION} \
 && git clone --depth 1 --branch ${NUCLEI_TEMPLATES_VERSION} https://github.com/projectdiscovery/nuclei-templates /nuclei-templates \
 && rm -rf /nuclei-templates/.git

# Etap 4: obraz uruchomieniowy na wspieranym Alpine, bez roota.
FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f
# nmap-nselibs + nmap-scripts: -sV inicjuje silnik NSE (nse_main.lua i katalog scripts);
# skryptów nie uruchamiamy (brak --script), więc to nie zwiększa intensywności skanu
RUN apk add --no-cache "zlib>=1.4-r0" nmap nmap-nselibs nmap-scripts ca-certificates \
 && adduser -S -D -H -u 10001 -h /app -s /sbin/nologin asi
WORKDIR /app
COPY --from=backend /usr/local/bin/asi /usr/local/bin/asi
# nuclei szuka szablonów w $HOME/nuclei-templates i zapisuje konfigurację w $HOME/.config (HOME=/app)
COPY --from=nuclei /go/bin/nuclei /usr/local/bin/nuclei
COPY --from=nuclei /nuclei-templates /app/nuclei-templates
RUN mkdir -p /app/.config /app/.cache && chown asi /app/.config /app/.cache
COPY --from=frontend /frontend/dist ./ui
COPY signatures ./signatures
COPY backend/config/scan.toml ./config/scan.toml

ENV ASI_BIND=0.0.0.0:8080 \
    ASI_STATIC_DIR=/app/ui \
    ASI_SIGNATURES_DIR=/app/signatures \
    ASI_SCAN_CONFIG=/app/config/scan.toml \
    RUST_LOG=info,sqlx=warn

# Bez roota nmap używa skanu connect(), co wystarcza do discovery.
# SYN scan i ICMP wymagają roota oraz cap_add NET_RAW/NET_ADMIN (README).
USER asi
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/api/health || exit 1

ENTRYPOINT ["asi"]
CMD ["serve"]
