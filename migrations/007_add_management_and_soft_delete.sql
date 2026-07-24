-- Gerenciamento de links por token (autorização por posse) e soft delete.
-- management_token_hash: SHA-256 do token secreto; o token em claro nunca é
-- persistido. deleted_at: marca de soft delete (o registro permanece, então
-- o short_id nunca é reciclado como alias novo).
ALTER TABLE urls ADD COLUMN IF NOT EXISTS management_token_hash CHAR(64);
ALTER TABLE urls ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
