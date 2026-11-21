-- Ustawienia zmieniane z interfejsu (harmonogram, tempo skanu). Nadpisują config/asi.toml.
CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Notatka analityka do przebiegu skanu (szyfrowana, edytowalna po zakończeniu skanu).
ALTER TABLE scan_runs ADD COLUMN note_enc TEXT;
