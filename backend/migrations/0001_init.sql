-- ASI: schemat bazowy (PostgreSQL 16). Kolumny *_enc to bytea pod szyfrowanie pól (§15).
-- Statusy jako text + CHECK, żeby dodanie stanu nie wymagało ALTER TYPE.

-- Tożsamość i dostęp ---------------------------------------------------------

CREATE TABLE users (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username           text NOT NULL UNIQUE,
    email_enc          bytea,
    password_hash      text NOT NULL,
    disabled           boolean NOT NULL DEFAULT false,
    -- zwiększana przy zmianie hasła / wyłączeniu konta: unieważnia wszystkie sesje
    credential_version integer NOT NULL DEFAULT 1,
    created_at         timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE roles (
    id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name    text NOT NULL UNIQUE,
    builtin boolean NOT NULL DEFAULT false
);

CREATE TABLE permissions (
    code text PRIMARY KEY
);

CREATE TABLE role_permissions (
    role_id    uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission text NOT NULL REFERENCES permissions(code) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission)
);

CREATE TABLE user_roles (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- Sesje: w bazie tylko SHA-256 tokenu z cookie.
CREATE TABLE sessions (
    id_hash            bytea PRIMARY KEY,
    user_id            uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_version integer NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    expires_at         timestamptz NOT NULL,
    ip                 inet,
    user_agent         text
);
CREATE INDEX sessions_user_idx ON sessions (user_id);

-- Cele i assety --------------------------------------------------------------

CREATE TABLE targets (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind       text NOT NULL CHECK (kind IN ('ip', 'cidr', 'range', 'domain')),
    value      text NOT NULL,
    source     text NOT NULL CHECK (source IN ('manual', 'csv', 'json', 'passive', 'import')),
    excluded   boolean NOT NULL DEFAULT false,
    tags       text[] NOT NULL DEFAULT '{}',
    note_enc   bytea,
    created_by uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (kind, value)
);

CREATE TABLE assets (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ip                 inet NOT NULL UNIQUE,
    hostnames          text[] NOT NULL DEFAULT '{}',
    first_seen         timestamptz NOT NULL DEFAULT now(),
    last_seen          timestamptz NOT NULL DEFAULT now(),
    state              text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'unstable', 'inactive')),
    miss_streak        integer NOT NULL DEFAULT 0,
    availability_ratio real,
    interest_score     integer NOT NULL DEFAULT 0,
    tags               text[] NOT NULL DEFAULT '{}'
);

-- Przebiegi ------------------------------------------------------------------

CREATE TABLE scan_runs (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    status           text NOT NULL DEFAULT 'queued'
                     CHECK (status IN ('queued', 'running', 'pausing', 'paused', 'done', 'partial', 'failed', 'cancelled')),
    profile_snapshot jsonb NOT NULL DEFAULT '{}',
    started_at       timestamptz,
    finished_at      timestamptz,
    duration_ms      bigint,
    hosts_total      integer NOT NULL DEFAULT 0,
    hosts_done       integer NOT NULL DEFAULT 0,
    triggered_by     uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at       timestamptz NOT NULL DEFAULT now()
);

-- Cele podgrupy jako text[]: mogą to być adresy IP albo domeny.
CREATE TABLE scan_chunks (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id      uuid NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    stage       text NOT NULL CHECK (stage IN ('discovery', 'ports', 'services', 'http')),
    targets     text[] NOT NULL,
    status      text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'done', 'failed')),
    attempt     integer NOT NULL DEFAULT 0,
    started_at  timestamptz,
    finished_at timestamptz,
    duration_ms bigint,
    worker_id   text,
    error       text
);
CREATE INDEX scan_chunks_run_status_idx ON scan_chunks (run_id, status);

-- Wyniki ---------------------------------------------------------------------

CREATE TABLE services (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id       uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    run_id         uuid REFERENCES scan_runs(id) ON DELETE SET NULL,
    proto          text NOT NULL CHECK (proto IN ('tcp', 'udp')),
    port           integer NOT NULL CHECK (port BETWEEN 0 AND 65535),
    state          text NOT NULL,
    service        text,
    product        text,
    version        text,
    cpe            text[] NOT NULL DEFAULT '{}',
    banner_enc     bytea,
    first_seen     timestamptz NOT NULL DEFAULT now(),
    last_seen      timestamptz NOT NULL DEFAULT now(),
    miss_streak    integer NOT NULL DEFAULT 0,
    interest_score integer NOT NULL DEFAULT 0,
    UNIQUE (asset_id, proto, port)
);

CREATE TABLE http_info (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    service_id   uuid NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    run_id       uuid NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    vhost        text,
    scheme       text NOT NULL CHECK (scheme IN ('http', 'https')),
    status       integer,
    title        text,
    redirects    jsonb NOT NULL DEFAULT '[]',
    headers_enc  bytea,
    cookies_meta jsonb NOT NULL DEFAULT '[]',
    cookies_enc  bytea,
    tls          jsonb,
    favicon_mmh3 integer,
    body_sha256  bytea,
    response_ms  integer,
    observed_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX http_info_service_idx ON http_info (service_id);

-- Analityk i reguły ----------------------------------------------------------

CREATE TABLE overrides (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_type text NOT NULL,
    entity_key  text NOT NULL,
    field       text NOT NULL,
    value_enc   bytea,
    reason      text,
    author      uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    revoked_at  timestamptz
);
CREATE INDEX overrides_active_idx ON overrides (entity_type, entity_key) WHERE revoked_at IS NULL;

-- Odpowiednik `signatures` z §16 (sygnatury YAML, wersjonowane).
CREATE TABLE rules (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    slug       text NOT NULL,
    version    integer NOT NULL DEFAULT 1,
    yaml       text NOT NULL,
    enabled    boolean NOT NULL DEFAULT true,
    builtin    boolean NOT NULL DEFAULT false,
    author     uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (slug, version)
);

-- Audyt ----------------------------------------------------------------------

CREATE TABLE audit_log (
    id        bigserial PRIMARY KEY,
    user_id   uuid REFERENCES users(id) ON DELETE SET NULL,
    username  text,
    action    text NOT NULL,
    entity    text,
    entity_id text,
    details   jsonb NOT NULL DEFAULT '{}',
    ip        inet,
    at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_log_at_idx ON audit_log (at);
