-- Podatności: stan sprawdzania przebiegu, podatności usług (append-only per przebieg) i cache CVE z NVD.
-- CPE usługi jest częścią zaszyfrowanej obserwacji (`observations.data_enc`), więc nie ma osobnej kolumny.

ALTER TABLE scan_runs
    ADD COLUMN vuln_state   text NOT NULL DEFAULT 'none'
        CHECK (vuln_state IN ('none', 'pending_decision', 'running', 'done', 'failed', 'skipped')),
    ADD COLUMN vuln_reason  text,
    ADD COLUMN vuln_summary jsonb NOT NULL DEFAULT '{}';

CREATE TABLE vulnerabilities (
    id          bigserial PRIMARY KEY,
    run_id      uuid NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    ip          inet NOT NULL,
    port        integer NOT NULL,
    proto       text NOT NULL,
    cve_id      text NOT NULL,
    cvss_score  double precision,
    cvss_vector text,
    severity    text NOT NULL CHECK (severity IN ('Critical', 'High', 'Medium', 'Low', 'Info')),
    evidence    text NOT NULL CHECK (evidence IN ('version_match', 'confirmed')),
    component   text NOT NULL,
    version     text NOT NULL,
    description text NOT NULL DEFAULT '',
    published   text,
    UNIQUE (run_id, ip, port, proto, cve_id)
);
CREATE INDEX vulnerabilities_run_idx ON vulnerabilities (run_id, severity);

CREATE TABLE cve_cache (
    cpe        text PRIMARY KEY,
    payload    jsonb NOT NULL,
    fetched_at timestamptz NOT NULL DEFAULT now()
);
