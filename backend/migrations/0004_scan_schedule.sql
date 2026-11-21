-- Harmonogram automatycznych skanów ustawiany z interfejsu (okna czasowe i częstotliwość).
-- Jeden wiersz; gdy istnieje, zastępuje sekcję [schedule] z pliku konfiguracji skanu.
CREATE TABLE scan_schedule (
    id         boolean PRIMARY KEY DEFAULT true CHECK (id),
    value      jsonb NOT NULL,
    updated_by uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
