ALTER TABLE urls ADD COLUMN IF NOT EXISTS url_hash CHAR(64);

CREATE INDEX IF NOT EXISTS idx_urls_url_hash ON urls (url_hash);
