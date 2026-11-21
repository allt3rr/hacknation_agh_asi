-- Pola oznaczone *_enc są szyfrowane AES-256-GCM po stronie aplikacji (encryption at rest).

CREATE TABLE users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL,
    created_at    TEXT NOT NULL
);

-- Cele wprowadzone ręcznie / z pliku. Edycje użytkownika są tu trwałe
-- i nie są nadpisywane przez kolejne skany ani ponowny import.
CREATE TABLE targets (
    id         TEXT PRIMARY KEY,
    value      TEXT NOT NULL UNIQUE,
    kind       TEXT NOT NULL,
    tags       TEXT NOT NULL DEFAULT '',
    note_enc   TEXT,
    enabled    INTEGER NOT NULL DEFAULT 1,
    source     TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE scan_runs (
    id            TEXT PRIMARY KEY,
    source        TEXT NOT NULL,
    status        TEXT NOT NULL,          -- running | completed | partial | aborted | failed
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    duration_secs REAL,
    stats_json    TEXT,
    pending_json  TEXT                    -- adresy niezeskanowane przez koniec okna
);

CREATE TABLE observations (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id   TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    ip       TEXT NOT NULL,
    port     INTEGER NOT NULL,
    proto    TEXT NOT NULL,
    service  TEXT,
    data_enc TEXT NOT NULL                -- pełna obserwacja (nagłówki, ciasteczka, cert, bannery)
);
CREATE INDEX idx_observations_run ON observations(run_id);
CREATE INDEX idx_observations_ip ON observations(ip);

-- Stan hosta w czasie: active | unstable | inactive
CREATE TABLE host_state (
    ip            TEXT PRIMARY KEY,
    status        TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    last_seen_run TEXT NOT NULL,
    miss_count    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE changes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id     TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,
    key        TEXT NOT NULL,
    ip         TEXT NOT NULL,
    field      TEXT,
    before_enc TEXT,
    after_enc  TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX idx_changes_run ON changes(run_id);

-- Ręczne adnotacje analityków do usług (klucz ip:port/proto). Przetrwają kolejne skany.
CREATE TABLE annotations (
    key        TEXT PRIMARY KEY,
    tags       TEXT NOT NULL DEFAULT '',
    note_enc   TEXT,
    severity   TEXT,
    updated_by TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Własne sygnatury dodane przez użytkowników (YAML).
CREATE TABLE signatures (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    yaml       TEXT NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
