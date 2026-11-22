-- Wynik ostatniej wysyłki przebiegu do DefectDojo (automatycznej albo ręcznej): czas, zakres, liczby, błąd.
-- Interfejs pokazuje powiadomienie, gdy wartość się zmieni.
ALTER TABLE scan_runs ADD COLUMN dd_export jsonb;
