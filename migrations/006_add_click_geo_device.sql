-- Geolocalização (nível país) e detecção de dispositivo nos eventos de clique.
-- Apenas o código do país é persistido; o IP nunca é gravado (ver LGPD).
ALTER TABLE click_events ADD COLUMN IF NOT EXISTS country CHAR(2);
ALTER TABLE click_events ADD COLUMN IF NOT EXISTS device VARCHAR(20);
ALTER TABLE click_events ADD COLUMN IF NOT EXISTS os VARCHAR(20);
ALTER TABLE click_events ADD COLUMN IF NOT EXISTS is_bot BOOLEAN NOT NULL DEFAULT false;
