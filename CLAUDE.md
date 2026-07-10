# CLAUDE.md — small-links

Encurtador de URLs em Go (Gin) com PostgreSQL, criptografia AES-GCM e Docker. Deploy no Railway.

## Comandos

- Rodar local: `go run ./cmd/server` (exige `ENCRYPTION_KEY` de 32 chars e `DATABASE_URL`)
- Subir tudo: `docker compose up --build`
- Observabilidade local (dev): `docker compose -f docker-compose.observability.yml up -d`
- Testes: `go test ./...`
- Verificações: `gofmt -l .` e `go vet ./...`
- Dependências: `go mod tidy`

## Variáveis de ambiente

| Variável       | Obrigatória | Descrição                                  |
|----------------|-------------|--------------------------------------------|
| ENCRYPTION_KEY | Sim         | Exatamente 32 caracteres (AES-256)         |
| DATABASE_URL   | Sim         | String de conexão PostgreSQL               |
| PORT           | Não         | Padrão 8080                                |
| GIN_MODE       | Não         | debug/release (padrão release)             |

## Arquitetura

```
cmd/server/          → bootstrap (config, injeção de dependências, graceful shutdown, slog)
internal/config/     → leitura e validação de env vars
internal/crypto/     → AES-256-GCM (nonce prefixado) + Hash HMAC-SHA256 p/ dedup e ip_hash
internal/storage/    → interface Repository + implementação Postgres (context + timeout)
internal/analytics/  → Recorder de cliques assíncrono (canal buffered + worker)
internal/metrics/    → coletores Prometheus (counters + histograma de latência)
internal/http/       → handlers via struct, middleware CORS/métricas, rate limiting por IP, rotas
migrations/          → SQL versionado, aplicado via go:embed na inicialização
```

## Convenções

- Go idiomático: erros retornados para o chamador; falha fatal apenas no bootstrap; sem panic em handler.
- Handlers recebem dependências via struct — sem variáveis globais.
- `context.Context` com timeout em toda query de banco.
- Logging estruturado com `log/slog`.
- Commits em português, padrão Conventional Commits (`feat:`, `fix:`, `refactor:`), pequenos e focados.
- Antes de refatorar comportamento existente, manter os testes de caracterização verdes.
- Nunca commitar `.env` nem chaves.

## Decisões registradas

- **AES-GCM (item 4)**: cifragem autenticada; o fallback de leitura CTR existiu apenas
  durante a transição e foi removido. Pelo Caminho A (jul/2026), os registros CTR legados
  são descartados via `TRUNCATE` no deploy final, então o backfill (`cmd/migrate-gcm`) foi
  removido como código morto. Ciphertext adulterado agora falha a autenticação com erro.
- **Dedup por HMAC (item 5)**: coluna `url_hash CHAR(64)` nullable com índice não-único
  (migration 002), preenchida no create e pelo backfill. HMAC-SHA256 com a `ENCRYPTION_KEY`
  permite lookup determinístico sem decifrar (o nonce aleatório impede busca pelo ciphertext).
  URL repetida devolve o `short_id` existente com HTTP 200 e `"existing": true`.
  Correção pós-TTL: a busca por `url_hash` ignora registros expirados
  (`expires_at IS NULL OR expires_at > now()`) — dedup não devolve link morto; se o único
  match estiver expirado, um link novo é criado normalmente.
- **Unicidade de short_id**: sem `SELECT EXISTS` prévio; o insert confia na constraint UNIQUE,
  com até 3 tentativas em colisão (`storage.ErrDuplicate`).
- **Rate limiting**: 10 req/min por IP (burst 10) nos endpoints de criação, HTTP 429.
  `SetTrustedProxies` restrito a faixas privadas para `ClientIP()` funcionar atrás do proxy
  do Railway sem spoofing.
- **GET /shorten** mantido por compatibilidade (200), delegando à mesma lógica do POST.
- **Analytics de clique (item 6)**: tabela `click_events` (migration 003) sem FK para `urls` —
  o insert é assíncrono e não pode travar o redirect. `internal/analytics.Recorder` usa canal
  buffered (cap 1000) + worker; buffer cheio descarta o evento com log warn. O `redirectHandler`
  publica o evento após o 302. Flush no graceful shutdown (`Recorder.Close()` antes do `db.Close()`).
- **LGPD**: o IP do acesso é gravado apenas como HMAC-SHA256 (`ip_hash`), nunca em claro.
- **Stats expandido**: `/stats/:shortId` agrega `total_clicks`, `clicks_per_day` (30 dias) e
  `top_referrers` (top 5), mantendo os campos antigos. Fatias vazias serializam como `[]`.
- **Métricas (item 6)**: `/metrics` via promhttp; counters `smalllinks_redirects_total`,
  `smalllinks_shortens_total`, `smalllinks_rate_limited_total` e histograma de latência por
  método/rota/status. Coletores no registry default (`internal/metrics`).
- **Alias customizado (item 6)**: `custom_alias` opcional no POST, validado por
  `^[a-zA-Z0-9_-]{3,30}$`; colisão com `short_id` existente ou rota reservada (`health`,
  `shorten`, `stats`, `api`, `metrics`, `qr`) devolve 409. Alias explícito ignora o dedup e
  não usa o retry de 3 tentativas (o alias é fixo).
- **Largura de short_id (bug corrigido)**: o `aliasRegex` aceita até 30 chars, mas o schema
  nasceu com `urls.short_id VARCHAR(6)` e `click_events.short_id VARCHAR(10)`. Aliases longos
  falhavam o insert com `string_data_right_truncation`, que não é `unique_violation` e caía no
  500 genérico. Migration 005 alinha ambas as colunas em `VARCHAR(30)`. Defesa em profundidade:
  o storage mapeia `string_data_right_truncation` para `ErrValueTooLong` e o handler responde
  400 (não 500) se validação e schema divergirem de novo.
  **Lição**: limites de tamanho devem ter uma única fonte de verdade compartilhada entre a
  validação da aplicação e o schema do banco.
- **Expiração/TTL (item 6)**: `expires_in_days` (>0) no POST; migration 004 adiciona
  `urls.expires_at TIMESTAMPTZ` nullable. Redirect de link expirado responde 410 Gone (antes
  de incrementar `access_count`). Sem `expires_at`, o link é permanente.
- **QR code (item 6)**: `GET /qr/:shortId` gera PNG (`image/png`) do short_url via
  `skip2/go-qrcode`, após confirmar que o short link existe (404 caso contrário).
- **Go 1.25**: exigido pelo `golang.org/x/time`; CI lê a versão do `go.mod`, Dockerfile usa
  `golang:1.25-alpine`.
- **Observabilidade local (dev)**: `docker-compose.observability.yml` sobe Prometheus (9090) +
  Grafana (3000), conectados à rede `small-links-net` (external) da stack principal. Configs em
  `observability/`: scrape de `app:8080/metrics` (15s) e provisionamento do Grafana (datasource
  Prometheus com `uid: prometheus`, referenciado pelos painéis do dashboard, e o dashboard
  *Small Links — Overview*). É ambiente de desenvolvimento — **não** faz parte do deploy; a app
  e o `docker-compose.yml` principal não foram alterados.

## Pendências de deploy

1. **TRUNCATE no deploy final**: rodar `TRUNCATE TABLE urls;` no banco do Railway antes de
   qualquer teste — os registros CTR legados foram deliberadamente descartados (Caminho A,
   jul/2026). Até lá, links antigos em produção estão quebrados: comportamento conhecido e aceito.
2. ~~**`cmd/migrate-gcm` é código morto** com essa decisão — remover em commit futuro.~~ ✅ removido.
3. **Commits marcados como "aplicar após operação manual"** devem ficar em PR separado.

## Backlog priorizado

1. ~~**Higiene**~~ ✅ (PR #1)
2. ~~**Testes de caracterização** + CI~~ ✅ (PR #2)
3. ~~**Refatoração estrutural** para a arquitetura alvo~~ ✅ (PR #2)
4. ~~**Segurança**: AES-GCM, POST /api/shorten, validação, rate limiting, Dockerfile~~ ✅ (PR #3)
5. ~~**Dedup**: url_hash HMAC-SHA256 indexado~~ ✅
   - Pelo Caminho A (jul/2026), os registros CTR legados são descartados via `TRUNCATE` no
     deploy final; o fallback `decryptLegacyCTR` e o backfill `cmd/migrate-gcm` foram removidos.
6. ~~**Features**: eventos de clique + registro assíncrono, stats expandido, `/metrics`
   Prometheus, alias customizado, expiração/TTL, QR code~~ ✅
7. **Extras**: cache Redis para redirects quentes, frontend em Next.js.
