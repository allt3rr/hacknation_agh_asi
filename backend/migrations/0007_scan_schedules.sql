-- Pozycje harmonogramu: każda ma własne cele, częstotliwość, okna i tryb sprawdzania podatności.
-- Zastępuje jednowierszowy scan_schedule; zapisany harmonogram staje się jedną pozycją z celami
-- niewykluczonymi w chwili migracji. Przebiegi wskazują pozycję w profile_snapshot.schedule_id.
CREATE TABLE scan_schedules (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    enabled     boolean NOT NULL DEFAULT true,
    every_hours integer NOT NULL CHECK (every_hours BETWEEN 1 AND 720),
    windows     jsonb NOT NULL DEFAULT '[]',
    target_ids  uuid[] NOT NULL,
    vuln_check  text NOT NULL DEFAULT 'ask' CHECK (vuln_check IN ('auto', 'ask', 'off')),
    created_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

INSERT INTO scan_schedules (name, enabled, every_hours, windows, target_ids, created_by, updated_by)
SELECT 'Harmonogram',
       COALESCE((value->>'enabled')::boolean, false),
       LEAST(GREATEST(COALESCE((value->>'every_hours')::integer, 24), 1), 720),
       COALESCE(value->'windows', '[]'),
       ARRAY(SELECT id FROM targets WHERE NOT excluded ORDER BY created_at),
       updated_by,
       updated_by
FROM scan_schedule;

DROP TABLE scan_schedule;
