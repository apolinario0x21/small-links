-- Alinha a largura de short_id ao aliasRegex (até 30 chars). Antes, urls
-- estava VARCHAR(6) e click_events VARCHAR(10): aliases longos falhavam o
-- insert com "value too long" (string_data_right_truncation), caindo no 500.
ALTER TABLE urls ALTER COLUMN short_id TYPE VARCHAR(30);
ALTER TABLE click_events ALTER COLUMN short_id TYPE VARCHAR(30);
