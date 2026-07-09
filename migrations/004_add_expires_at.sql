-- TTL opcional: links sem expires_at são permanentes; com valor, o redirect
-- responde 410 Gone após a data.
ALTER TABLE urls ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
