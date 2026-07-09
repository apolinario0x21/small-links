-- Eventos de clique para analytics. Sem FK para urls: o registro de evento
-- é assíncrono e não pode falhar/travar o caminho quente do redirect.
CREATE TABLE IF NOT EXISTS click_events (
	id BIGSERIAL PRIMARY KEY,
	short_id VARCHAR(10) NOT NULL,
	occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	referrer TEXT,
	user_agent TEXT,
	ip_hash CHAR(64)
);

CREATE INDEX IF NOT EXISTS idx_click_events_short_id_occurred_at
	ON click_events (short_id, occurred_at DESC);
