-- Przebiegi skanu: rezerwacja z dzierżawą, rodzaj, pokrycie; obserwacje append-only i zmiany.

ALTER TABLE scan_runs
    ADD COLUMN kind        text NOT NULL DEFAULT 'scan' CHECK (kind IN ('scan', 'import')),
    ADD COLUMN lease_owner text,
    ADD COLUMN lease_until timestamptz,
    ADD COLUMN coverage    jsonb NOT NULL DEFAULT '{}',
    ADD COLUMN reason      text;

-- Najwyżej jeden trwający skan na bazę: drugi INSERT kończy się naruszeniem unikalności.
CREATE UNIQUE INDEX scan_runs_one_running ON scan_runs ((true)) WHERE status = 'running' AND kind = 'scan';
CREATE INDEX scan_runs_kind_created_idx ON scan_runs (kind, created_at DESC);

ALTER TABLE scan_chunks DROP CONSTRAINT scan_chunks_status_check;
ALTER TABLE scan_chunks ADD CONSTRAINT scan_chunks_status_check
    CHECK (status IN ('pending', 'running', 'done', 'failed', 'abandoned'));

-- Jedna usługa w jednym przebiegu. Kolumny jawne służą do filtrowania i liczników;
-- pełna obserwacja (nagłówki, wartości ciasteczek, certyfikat) jest w `data_enc`.
CREATE TABLE observations (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id       uuid NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    ip           inet NOT NULL,
    port         integer NOT NULL,
    proto        text NOT NULL,
    state        text NOT NULL,
    service      text,
    product      text,
    version      text,
    hostname     text,
    http_status  integer,
    http_title   text,
    technologies text[] NOT NULL DEFAULT '{}',
    cookie_names text[] NOT NULL DEFAULT '{}',
    data_enc     bytea NOT NULL,
    observed_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX observations_run_idx ON observations (run_id);
CREATE INDEX observations_key_idx ON observations (ip, port, proto);

-- Ostatnia obserwacja usługi = punkt odniesienia porównań.
ALTER TABLE services ADD COLUMN last_observation_id uuid REFERENCES observations(id) ON DELETE SET NULL;

CREATE TABLE changes (
    id         bigserial PRIMARY KEY,
    run_id     uuid NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    kind       text NOT NULL,
    entity_key text NOT NULL,
    ip         inet NOT NULL,
    field      text,
    before     text,
    after      text,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX changes_run_idx ON changes (run_id);
