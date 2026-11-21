-- Sesje logowania. Cookie `asi_session` zawiera losowy token; tutaj trzymamy
-- tylko jego SHA-256, więc wyciek bazy nie daje gotowych sesji.
-- Rola jest czytana z `users` przy każdym żądaniu, a usunięcie użytkownika kasuje jego sesje.

CREATE TABLE sessions (
    id_hash    TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    expires_at INTEGER NOT NULL          -- unix timestamp (sekundy)
);
CREATE INDEX idx_sessions_user ON sessions(user_id);
