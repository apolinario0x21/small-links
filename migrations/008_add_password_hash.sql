-- Links protegidos por senha (autorização por posse do segredo, sem contas).
-- password_hash: bcrypt da senha; a senha em claro nunca é persistida nem
-- devolvida. NULL = link público. Links protegidos ficam fora do dedup por
-- url_hash (ver internal/storage.FindByURLHash).
ALTER TABLE urls ADD COLUMN IF NOT EXISTS password_hash TEXT;
