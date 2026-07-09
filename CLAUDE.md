# CLAUDE.md — small-links

Encurtador de URLs em Go (Gin) com PostgreSQL, criptografia AES-GCM e Docker. Deploy no Railway.

## Comandos

- Rodar local: `go run ./cmd/server` (exige `ENCRYPTION_KEY` de 32 chars e `DATABASE_URL`)
- Backfill GCM/url_hash: `go run ./cmd/migrate-gcm` (idempotente; mesmas env vars)
- Subir tudo: `docker compose up --build`
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
cmd/migrate-gcm/     → backfill: re-cifra registros CTR legados em GCM e preenche url_hash
internal/config/     → leitura e validação de env vars
internal/crypto/     → AES-256-GCM (nonce prefixado) + Hash HMAC-SHA256 p/ dedup
internal/storage/    → interface Repository + implementação Postgres (context + timeout)
internal/http/       → handlers via struct, middleware CORS, rate limiting por IP, rotas
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

- **AES-GCM com fallback CTR (item 4)**: `Decrypt` tenta GCM e cai para o CTR legado se a
  autenticação falhar. Enquanto o fallback existir, ciphertext adulterado degrada para lixo CTR
  em vez de erro. Após rodar `cmd/migrate-gcm` em produção, remover `decryptLegacyCTR`
  (commit dedicado, aplicar só depois do backfill).
- **Dedup por HMAC (item 5)**: coluna `url_hash CHAR(64)` nullable com índice não-único
  (migration 002), preenchida no create e pelo backfill. HMAC-SHA256 com a `ENCRYPTION_KEY`
  permite lookup determinístico sem decifrar (o nonce aleatório impede busca pelo ciphertext).
  URL repetida devolve o `short_id` existente com HTTP 200 e `"existing": true`.
- **Unicidade de short_id**: sem `SELECT EXISTS` prévio; o insert confia na constraint UNIQUE,
  com até 3 tentativas em colisão (`storage.ErrDuplicate`).
- **Rate limiting**: 10 req/min por IP (burst 10) nos endpoints de criação, HTTP 429.
  `SetTrustedProxies` restrito a faixas privadas para `ClientIP()` funcionar atrás do proxy
  do Railway sem spoofing.
- **GET /shorten** mantido por compatibilidade (200), delegando à mesma lógica do POST.
- **Go 1.25**: exigido pelo `golang.org/x/time`; CI lê a versão do `go.mod`, Dockerfile usa
  `golang:1.25-alpine`.

## Backlog priorizado

1. ~~**Higiene**~~ ✅ (PR #1)
2. ~~**Testes de caracterização** + CI~~ ✅ (PR #2)
3. ~~**Refatoração estrutural** para a arquitetura alvo~~ ✅ (PR #2)
4. ~~**Segurança**: AES-GCM, POST /api/shorten, validação, rate limiting, Dockerfile~~ ✅ (PR #3)
5. ~~**Dedup**: url_hash HMAC-SHA256 indexado + backfill~~ ✅
   - Pendência operacional: rodar `go run ./cmd/migrate-gcm` em produção e só então aplicar
     o commit que remove `decryptLegacyCTR`.
6. **Features**: alias customizado, expiração/TTL, QR code, tabela de eventos de clique
   (timestamp, referrer, user-agent), endpoint `/metrics` Prometheus.
7. **Extras**: cache Redis para redirects quentes, frontend em Next.js.
