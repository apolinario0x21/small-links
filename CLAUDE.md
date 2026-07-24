# CLAUDE.md — small-links

Encurtador de URLs em Go (Gin) com PostgreSQL, criptografia AES-GCM e Docker. Em produção no
Render (app, auto-deploy da `main`) + Neon (PostgreSQL): <https://small-links.onrender.com>.

## Comandos

- Rodar local: `go run ./cmd/server` (exige `ENCRYPTION_KEY` de 32 chars e `DATABASE_URL`)
- Subir tudo: `docker compose up --build`
- Observabilidade local (dev): `docker compose -f docker-compose.observability.yml up -d`
- Testes: `go test ./...` (unidade; os de integração se auto-pulam sem banco)
- Testes de integração (Postgres real): `make test-integration
  SMALL_LINKS_TEST_DATABASE_URL='postgres://...'` — roda com `-p 1 -count=1`
- Verificações: `gofmt -l .` e `go vet ./...`
- Segurança: `make security-check` (govulncheck + gosec); corrida: `make race` (`go test -race`)
- Dependências: `go mod tidy`
- Regenerar docs OpenAPI: `swag init -g cmd/server/main.go --parseInternal -o docs` (após mudar anotações)
- **Sem Go instalado na máquina local** — rodar a sequência do CI via Docker antes de commitar:
  `docker run --rm --user $(id -u):$(id -g) -v $PWD:/app -w /app golang:1.25-alpine sh -c "gofmt -l . && go vet ./... && go build ./... && go test ./..."`
  (o CI para no primeiro step que falha: um erro de gofmt **mascara** erros de vet/build/test —
  já escondeu um import não usado que só apareceu depois de formatar; nunca commitar sem a
  sequência completa verde)

## Variáveis de ambiente

| Variável       | Obrigatória | Descrição                                  |
|----------------|-------------|--------------------------------------------|
| ENCRYPTION_KEY | Sim         | Exatamente 32 caracteres (AES-256)         |
| DATABASE_URL   | Sim         | String de conexão PostgreSQL               |
| PORT           | Não         | Padrão 8080                                |
| GIN_MODE       | Não         | debug/release (padrão release)             |
| SWAGGER_ENABLED| Não         | UI Swagger em /swagger (padrão on; `false` desabilita) |
| SAFE_BROWSING_API_KEY | Não  | Chave da Google Safe Browsing; vazia desabilita a verificação |
| GEOIP_DB_PATH  | Não         | Base MMDB DB-IP Lite (padrão /app/dbip-country-lite.mmdb); ausente = sem geo |
| TRUSTED_PLATFORM | Não       | Fonte do IP do cliente: vazio = proxies de faixa privada (local); `cloudflare` = header CF-Connecting-IP (Render/produção) |
| CORS_ALLOWED_ORIGINS | Não  | Allowlist de origens cross-origin, separada por vírgula; vazia = só a própria origem da aplicação |

## Arquitetura

```
cmd/server/          → bootstrap (config, injeção de dependências, graceful shutdown, slog)
internal/config/     → leitura e validação de env vars
internal/crypto/     → AES-256-GCM (nonce prefixado) + Hash HMAC-SHA256 p/ dedup e ip_hash
internal/storage/    → interface Repository + implementação Postgres (context + timeout)
internal/analytics/  → Recorder de cliques assíncrono (canal buffered + worker)
internal/safebrowsing/→ cliente Google Safe Browsing (Lookup v4) p/ URLs maliciosas
internal/geo/        → resolução IP→país via MMDB local (DB-IP Lite)
internal/metrics/    → coletores Prometheus (counters + histograma de latência)
internal/http/       → handlers via struct, middleware CORS/métricas, rate limiting por IP, rotas
internal/http/static/→ landing page (index.html) embutida via go:embed, servida em GET /
internal/logging/     → RedactURL: redação de query params sensíveis antes de logar URLs
internal/http/static/→ password.html: tela de senha (template) de link protegido, também embutida
docs/                → OpenAPI gerado pelo swag (docs.go/swagger.json/yaml); importado no main
migrations/          → SQL versionado, aplicado via go:embed na inicialização
```

## Convenções

- Go idiomático: erros retornados para o chamador; falha fatal apenas no bootstrap; sem panic em handler.
- Handlers recebem dependências via struct — sem variáveis globais.
- `context.Context` com timeout em toda query de banco.
- Logging estruturado com `log/slog`.
- **Antes de qualquer commit, rodar `make check`** (`gofmt -w .`, `go vet ./...`, `go test ./...`) —
  os três, nessa ordem. O CI para no primeiro step que falha, então um erro de gofmt mascara
  erros de vet/test (já escondeu um import não usado).
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
- **Geo + dispositivo no clique (migration 006)**: o `Recorder` enriquece o evento no worker —
  resolve o país do IP **antes** de gerar o `ip_hash` e descarta o IP (nunca persistido, nunca
  sai do processo); classifica device/os/is_bot via `mileusna/useragent`. **Decisões**:
  (a) **país, não cidade** — cidade é dado sensível demais e explode a cardinalidade da métrica
  `smalllinks_clicks_total{country,device}` (labels Prometheus devem ter domínio pequeno;
  ~250 países × 5 devices é aceitável, cidades não); (b) **base MMDB local (DB-IP Lite), não API
  externa** — o IP não pode sair do processo (LGPD) e o lookup local não adiciona latência nem
  dependência de rede. Base baixada no build do Dockerfile (CC BY 4.0, atribuição no README);
  ausente = warn e app segue sem geo. Bots (`is_bot`) ficam fora das agregações de stats.
  `cmd/backfill-devices` retroage device/os/is_bot pelo user_agent gravado (geo não é
  retroagível — não há IP).
- **Stats expandido**: `/stats/:shortId` agrega `total_clicks`, `clicks_per_day` (30 dias),
  `top_referrers` (top 5), `top_countries` e `devices`, mantendo os campos antigos. Fatias
  vazias serializam como `[]`.
- **Agregações compartilham critério de exclusão (bug corrigido)**: todas as agregações de um
  mesmo payload de stats aplicam o **mesmo critério de exclusão** — só `is_bot=true` é excluído,
  uniformemente, de `total_clicks`, `clicks_per_day`, `top_countries` e `devices`. Cliques com
  país/device não classificado (gravados como `NULL` via `NULLIF(...,'')` no insert) entram como
  categoria `"unknown"` via `COALESCE(col, 'unknown')`, **nunca omitidos**. `top_countries`
  deixou de ter `LIMIT 5` para garantir `soma(top_countries) == soma(devices) == total_clicks`
  (o `LIMIT 5` permanece só em `top_referrers`, que não entra nessa regra — referrer ausente é
  legítimo). **Bug original**: `top_countries`/`devices` filtravam `AND col IS NOT NULL`,
  descartando silenciosamente os não classificados, enquanto `total_clicks` os contava — as
  somas divergiam (ex.: total=7, devices=6). Teste de integração em
  `internal/storage/clickstats_integration_test.go` (Postgres real, gated por
  `SMALL_LINKS_TEST_DATABASE_URL`) verifica a invariante das somas. **Lição**: filtrar
  `IS NOT NULL` numa agregação e não em outra do mesmo payload quebra a soma; categorias devem
  virar `"unknown"`, não sumir.
- **IP do cliente atrás da Cloudflare (bug de geo em prod, corrigido)**: em produção todo clique
  era geolocalizado como **US**. Causa raiz: no Render a cadeia é
  visitante → **Cloudflare** → proxy interno (10.x) → app. Só as faixas privadas estavam nos
  trusted proxies, então o Gin devolvia o IP da **borda Cloudflare** (104.23.x, 172.71.x) como
  cliente. Correção: env `TRUSTED_PLATFORM`; com `=cloudflare` o router usa
  `gin.PlatformCloudflare` (lê `CF-Connecting-IP`). **Decisão de segurança**: o header é injetado
  pela borda (sobrescrevendo o que o visitante enviar) e, nessa topologia, nenhum tráfego externo
  alcança o app sem passar por ela — logo não é forjável ali. Fora dela seria trivialmente
  forjável (spoof de rate limit e de geo), por isso é **opt-in por env e nunca o default**; vazio
  mantém `SetTrustedProxies` com faixas privadas (Compose local). A confiança vive num único
  ponto (`Router()`): rate limiter e `Recorder` (geo + ip_hash) consomem todos o mesmo
  `c.ClientIP()` — nada usa `RemoteIP()`/`RemoteAddr`. Métrica
  `smalllinks_geo_unresolved_total` acusa cliques sem país (um salto sugere IP resolvido errado).
- **Postgres 18**: o `docker-compose.yml` local usa `postgres:18-alpine` para alinhar com a versão
  do Neon em produção — divergência de major entre dev e prod esconde diferenças de comportamento.
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
- **Swagger/OpenAPI**: anotações `swag` nos handlers (`internal/http/`) e infos gerais em
  `cmd/server/main.go`; artefatos gerados em `docs/` (versionados) e importados via blank import
  no main para registrar a spec. UI servida em `GET /swagger/*any` com `gin-swagger`. A rota é
  desabilitável por `SWAGGER_ENABLED=false` (produção) e `"swagger"` entrou nas rotas reservadas
  (não colide com short_id). Modelos de resposta só-de-documentação em `internal/http/api_docs.go`
  (os handlers continuam usando `gin.H` — comportamento inalterado). Atenção: a versão da lib
  `swaggo/swag` no `go.mod` deve casar com a do CLI que gerou `docs/` (senão o build quebra em
  campos como `LeftDelim`).
- **Verificação de URL maliciosa (Safe Browsing)**: `internal/safebrowsing` consulta a Google
  Safe Browsing API (Lookup v4, `threatMatches:find`) com os tipos MALWARE, SOCIAL_ENGINEERING,
  UNWANTED_SOFTWARE e POTENTIALLY_HARMFUL_APPLICATION, timeout de 2s. A checagem roda no `create`
  (POST e GET legado) **antes** do dedup e do insert; URL sinalizada recusa com **422**. Chave
  via `SAFE_BROWSING_API_KEY`: vazia = verificação desabilitada (warn no boot, `checker` nil).
  **Decisão — fail-open**: erro/timeout da API **permite** a criação (log warn +
  `smalllinks_safebrowsing_errors_total`), pois disponibilidade do encurtador > checagem; URLs
  bloqueadas incrementam `smalllinks_safebrowsing_blocked_total`. Injetado como interface
  `URLChecker` no `Server` (nil-safe, testável com mock). O bloqueio responde **422** com
  mensagem específica citando phishing/malware; a landing trata o 422 com texto próprio, final
  (sem sugerir nova tentativa). **Lição**: mensagens de erro devem distinguir **falha temporária**
  (5xx/rede → "tente de novo") de **bloqueio permanente e deliberado** (422 → "não pode ser
  encurtado") — reusar a genérica de retry para um bloqueio engana o usuário.
- **Landing page (rota `/`)**: `index.html` único, com CSS/JS inline e sem assets externos,
  embutido no binário via `go:embed` (`internal/http/static/`) e servido em `GET /`. **Decisão**:
  embutir mantém o **deploy de binário único** — nenhuma etapa de build de front nem assets a
  hospedar. A rota `/` (estática) coexiste com o catch-all `/:shortId` sem conflito; o
  `metricsMiddleware` a rotula como `route="/"`. O front chama `POST /api/shorten` via `fetch` e
  preenche o resultado só com `textContent`/atributos (nunca `innerHTML`) para evitar XSS
  refletido via `original_url`.
- **Gerenciamento por token + soft delete (migration 007)**: a criação gera um token de 32
  bytes (`crypto/rand`, 64 hex) e persiste **só o SHA-256** em `management_token_hash`; o token
  em claro volta **uma única vez** no response (`management_token`), nunca no reaproveitamento
  por dedup (só o criador original o tem). `DELETE /api/links/:shortId` autoriza por posse do
  segredo (Bearer), comparando o SHA-256 com `subtle.ConstantTimeCompare` (comparação normal
  vaza por timing). **Decisões**: (a) **soft delete** (`deleted_at`) em vez de remover a linha —
  preserva o analytics e, sobretudo, impede que o `short_id` seja **reciclado** como alias novo
  (a constraint UNIQUE continua valendo sobre a linha soft-deletada → golpe de reciclagem
  bloqueado); (b) **autorização por posse de segredo, sem identidade** — nenhuma conta/sessão,
  coerente com a postura de privacidade; (c) **links antigos (hash NULL) são não-gerenciáveis** —
  documentado honestamente. **Segurança**: resposta **403 uniforme** para qualquer não-autorização
  (token ausente, errado, link inexistente ou não-gerenciável) — não vaza se o `short_id` existe;
  comparação em tempo constante inclusive contra um hash dummy quando o link não existe. Efeitos
  do soft delete: redirect/QR de deletado → **410**; dedup ignora deletados (mesmo critério dos
  expirados); `/stats` permanece acessível. Métrica `smalllinks_links_deleted_total`; rate limit
  do DELETE igual ao da criação. **Nota sobre o 404**: os requisitos listavam 404 para short_id
  inexistente, mas isso colide com o requisito crítico de não vazar existência via token inválido
  — optou-se por **403 uniforme** (os testes cobrem exatamente isso; não há teste de 404).
- **Links protegidos por senha (migration 008)**: `password` opcional no POST (mín. 4 chars) vira
  **bcrypt custo 12** em `urls.password_hash`; a senha em claro nunca é persistida, logada nem
  devolvida — o cliente recebe apenas `has_password`. **Decisões**: (a) **bcrypt custo 12** (e não
  o default 10): a senha de link é curta e é o único segredo que protege o destino, então
  encarecer cada verificação (~200ms) é a defesa para o caso de o hash vazar; o custo é aceitável
  num fluxo interativo, mas obriga os testes a gerar **um** hash reaproveitado. (b) **Protegidos
  ficam fora do dedup nos DOIS sentidos** — criar com senha nunca reaproveita um link existente
  (todo link reaproveitável é público: devolvê-lo entregaria um link **desprotegido** a quem pediu
  proteção) e `FindByURLHash` filtra `password_hash IS NULL` (senão quem encurta **sem** senha
  receberia um link que **não conseguiria abrir**). É o mesmo critério de exclusão já aplicado a
  expirados e deletados. (c) **Cookie assinado de 1h**, não sessão em banco: `HMAC-SHA256` com a
  `ENCRYPTION_KEY` sobre `<short_id em base64>.<exp unix>`, verificado com
  `subtle.ConstantTimeCompare`. O **short_id vai dentro do payload assinado** — sem isso o cookie
  de um link abriria outro. `HttpOnly`, `Secure` em release, `SameSite=Lax` e `Path=/<shortId>`
  (o navegador nem envia o cookie para outros links). Sem estado no servidor, coerente com a
  postura de "autorização por posse de segredo, sem contas" do token de gerenciamento.
  (d) **Precedência: expiração e soft delete ANTES da senha** — link morto responde 410 sem nunca
  exibir a tela de senha (pedir senha de algo que não vai abrir é ruído e vaza que o link existiu
  em estado utilizável). A ordem vive num único ponto, `loadRedirectTarget`, compartilhado por
  GET e POST. (e) **A tela de senha jamais contém a URL de destino** — é um `html/template`
  embutido (`static/password.html`) que recebe só nonce, action e mensagem de erro; há teste
  assertando a ausência do destino no HTML. (f) **Negociação por Accept**: `text/html` → tela;
  qualquer outro → `401 {"error":"link protegido por senha"}`. (g) **Rate limit por SHORT_ID**
  (5/min), não por IP: força bruta contra um link é distribuível entre IPs, então o alvo é a
  chave certa — o `ipRateLimiter` virou `keyRateLimiter` com `byIP()` e `byShortID()`. Métricas
  `smalllinks_password_attempts_total` e `smalllinks_password_failures_total`.
  (h) **Analytics só no redirect concluído**: exibir a tela de senha não gera clique
  (`completeRedirect` é o único ponto que registra).
  **Armadilha nos testes**: o custo 12 torna cada verificação lenta (segundos sob `-race`), e um
  teste que fazia N tentativas erradas para provar o 429 **falhava intermitentemente** — as
  tentativas demoravam tanto que o limiter recarregava tokens no meio do laço. O teste passou a
  usar um short_id inexistente (o limiter roda antes do handler, sem custo de bcrypt).
  **Lição**: asserção sobre rate limit não pode depender de operações lentas dentro da janela.
- **Histórico de links (client-side)**: a landing guarda os links criados no `localStorage`
  (`small-links:history`, máx. 20, dedup por `short_id`, mais recente no topo) e enriquece cada
  item com a contagem de cliques via `GET /stats/:shortId` (404/410 esmaece o item; erro de rede
  não trava os demais). **Decisão — histórico no cliente por privacidade**: o servidor
  **permanece sem saber quem criou o quê** (nenhuma tabela de usuários/sessões), reforçando a
  postura de privacidade do projeto. **Sem alteração de backend** — só o `index.html` embutido;
  toda inserção de dados da API/localStorage no DOM é via `textContent`/atributos (nunca
  `innerHTML`).
- **CORS restritivo (endurecimento)**: o `Access-Control-Allow-Origin: *` foi substituído por
  allowlist via `CORS_ALLOWED_ORIGINS` (separada por vírgula; `*` é ignorado). **Decisões**:
  (a) **sem a env, só a própria origem** (scheme + Host da requisição) — cobre a landing embutida
  sem autorizar terceiros e não exige configuração no deploy atual; (b) **origem fora da lista não
  é bloqueada**, apenas não recebe headers CORS — quem impõe a restrição é o navegador, e abortar
  aqui quebraria curl/server-to-server sem ganho de segurança; (c) `Authorization` entra em
  `Allow-Headers` (e `DELETE` em `Allow-Methods`) **só para origens permitidas**, porque
  `DELETE /api/links/:shortId` usa Bearer — sem isso o botão "excluir" da landing morre no
  preflight; (d) `Vary: Origin`, senão um cache compartilhado serve os headers de uma origem para
  outra. A config do servidor virou a struct `http.Options` (o `New` já tinha 7 parâmetros).
- **Headers de segurança + CSP com nonce**: `securityHeadersMiddleware` aplica `nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin` e CSP em toda
  resposta; `Strict-Transport-Security` só em `ReleaseMode` (em dev sobre http ele travaria o
  navegador do desenvolvedor). **Decisão — nonce, não 'unsafe-inline'**: a landing é HTML embutido
  com CSS/JS inline; liberar `'unsafe-inline'` reabriria XSS refletido, então o middleware gera um
  nonce por requisição (16 bytes, `crypto/rand`), publica no contexto (`cspNonceKey`) e o
  `landingHandler` carimba `<style>`/`<script>` com o mesmo valor (cópia de ~30 KB por requisição,
  custo irrelevante). **Exceção**: `/swagger` recebe política relaxada — o inline vem de lib de
  terceiros e não é carimbável (rota desabilitável em produção).
- **`form-action 'self'` quebrava o link protegido por senha (bug corrigido)**: ao enviar a senha
  correta, o cookie era gravado mas o usuário **ficava parado na tela** — só o acesso seguinte
  funcionava. Causa raiz: o navegador valida `form-action` contra o documento que contém o
  formulário **e a cada hop da cadeia de redirects daquele envio**; como o destino de um short link
  é uma URL externa por definição, o Chromium abortava a navegação
  (`Sending form data to ... violates ... form-action 'self'`). O `Set-Cookie` já tinha sido
  processado, daí o sintoma enganoso. **Trocar 302 por 303 para a própria rota NÃO resolve** —
  verificado em Chromium real: o 303 é aceito, mas o GET seguinte, ainda parte da mesma cadeia,
  é barrado igual. Correção: `passwordPageCSP` serve a tela de senha **sem** a diretiva
  `form-action` (todo o resto do endurecimento permanece), e o handler voltou ao **302 direto ao
  destino** para navegador e API. Relaxar ali é seguro porque a página não tem nenhum conteúdo
  controlável por terceiros: template embutido cujas variáveis são só nonce, action (short_id já
  validado) e uma mensagem de erro constante. **Lição**: `form-action` é incompatível com qualquer
  rota cuja função seja levar o usuário para fora do site — e o efeito colateral aparece como bug
  de sessão/cookie, não de CSP. Testes em `TestPasswordPageCSPAllowsFormAction` (ausência da
  diretiva), `TestFormActionKeptOnOtherRoutes` (as demais rotas seguem restritas) e
  `TestPasswordSubmitCorrectRedirectsWithCookie` (302 + Location + cookie na MESMA resposta).
- **QR da landing: falha silenciosa (corrigido) e hipóteses descartadas**. Investigação com
  Chromium real em quatro cenários (contexto limpo, histórico com 20 itens, conexão ociosa além do
  `IdleTimeout`, backend lento): **nenhuma falha dura foi reproduzida**. Descartado que
  `GET /qr/:shortId` compartilhe rate limiter — a rota **não tem limiter algum** (o `createLimiter`
  cobre só criação e DELETE); 12 criações seguidas deram QR 200 em todas, e o 429 só apareceu na
  *criação*. Também não há corrida criação↔imagem: o insert commita antes do 201. O defeito real é
  **(c) a falha era 100% silenciosa** — o `<img>` não tinha `onerror`, então qualquer falha
  transitória (rede, free tier do Render hibernando, link excluído noutra aba → 410) deixava um
  espaço vazio permanente, sem aviso e sem como tentar de novo. Correção no front: `onerror` →
  mensagem discreta + botão de retry **com cache-buster** (`?r=N`, pois o navegador memoriza o
  resultado negativo de uma imagem e reatribuir a mesma URL não dispararia nova requisição), e
  `fetchpriority="high"` no `<img>` — observou-se que a requisição do QR era despachada **depois**
  das até 21 chamadas a `/stats` que o histórico dispara logo em seguida.
- **Redação de URL em log (`internal/logging.RedactURL`)**: valores dos query params `token`,
  `auth`, `password`, `api_key`, `secret`, `access_token` (case-insensitive) viram `REDACTED`
  antes de qualquer URL original ir para o logger. URL inparseável vira `[unparseable-url]` e
  query malformada é redigida por inteiro — **não conseguindo localizar o segredo, prefere-se
  perder informação a vazá-lo**. Nenhum corpo de requisição é logado.
- **Ferramentas de segurança no CI**: job `security` separado com `golangci-lint`, `govulncheck`
  e `gosec` (`-exclude-dir=docs`, gerado pelo swag), além de `go test -race` no job de build.
  `.golangci.yml` (v2) habilita errcheck/staticcheck/bodyclose/ineffassign/unused, com
  `exclude-functions` para `Close`/`Write` em defer — checá-los só gera ruído. `make check` passou
  a incluir `security-check`. **Correção do gosec**: `G112` — o `http.Server` não tinha
  `ReadHeaderTimeout`, então uma conexão enviando headers byte a byte segurava um worker
  indefinidamente (Slowloris); adicionados Read/Write/Idle/ReadHeader timeouts.
- **Auditoria de dependências (jul/2026)**: `go get -u ./...` + `go mod tidy` subiram gin 1.10.1→
  1.12.0, lib/pq 1.10.9→1.12.3, prometheus/client_golang 1.23.2→1.24.0 e as indiretas.
  `govulncheck`: **0 vulnerabilidades chamadas pelo código** (1 vulnerabilidade em módulo
  requerido, sem símbolo alcançável). `gosec`: 1 achado (G112, corrigido acima) — hoje limpo.
  `swaggo/swag` foi mantido em v1.16.6 de propósito: a versão da lib precisa casar com a do CLI
  que gerou `docs/`.
  **Patch do toolchain importa tanto quanto as libs (bug de CI corrigido)**: com
  `go-version-file: go.mod` o runner instalava **exatamente go1.25.0**, e o govulncheck acusou
  **29 CVEs da stdlib** — todos já corrigidos até o go1.25.12 (o container `golang:1.25-alpine`
  usado localmente já vinha patchado, por isso o local passava e o CI não). Correção: `go.mod`
  ganhou `toolchain go1.25.12` e o CI usa `go-version: 1.25.x` + `check-latest: true`, para o
  patch mais recente entrar sozinho. **Lição**: fixar a linha `go` não é o mesmo que fixar o
  toolchain — a stdlib é uma dependência como qualquer outra.
- **golangci-lint no CI**: usar `golangci/golangci-lint-action@v8` (linha v2 do linter, versão
  pinada). A `@v6` resolve `latest` para a v1, que não lê o `.golangci.yml` em `version: "2"` e
  é compilada com Go 1.24 — abaixo do `go.mod`, o que aborta o carregamento da config.
- **Duas camadas de teste**: unidade (handlers com `go-sqlmock`, cifragem, cookie, CORS,
  redação, rate limiting) e **integração contra Postgres real** — `internal/storage/
  postgres_integration_test.go` (repositório) e `internal/http/api_integration_test.go` (API
  ponta a ponta, com `httptest.Server` sobre o router de produção, repositório real e Recorder
  real). **Decisões**: (a) **integração de verdade, não sqlmock, para o que vive no SQL** — o
  critério de exclusão do dedup, o `NULLIF`, o mapeamento de `unique_violation`/
  `string_data_right_truncation` e o soft delete que impede reciclagem de short_id só podem ser
  confirmados por um banco; contra mock, o teste apenas repetiria a string da query que eu mesmo
  escrevi. (b) **Auto-skip por `SMALL_LINKS_TEST_DATABASE_URL`** — `go test ./...` continua verde
  sem banco (e o job padrão do CI segue rápido); o job `integration` do CI provê o Postgres como
  service. (c) **`-p 1` obrigatório na integração**: os dois pacotes dão `TRUNCATE` nas mesmas
  tabelas e o Go paraleliza pacotes por padrão. Sem `-p 1` passou nas execuções que fiz, mas o
  isolamento não é garantido — é corrida latente, e serializar custa segundos. (d) **`-count=1`**:
  cache de teste não enxerga mudança de estado no banco. (e) **Analytics é assíncrono**, então a
  asserção sobre cliques só vem depois de `Recorder.Close()` (flush) — sem isso o teste seria
  uma corrida com o worker. Cobertura total foi de **67,2% → 88,8%** (`internal/storage` saiu de
  0%, pois só tinha caminho de banco). (f) **Clientes de teste com `DisableKeepAlives`**:
  `httptest.Server.Close()` bloqueia enquanto houver conexão aberta, e cada cliente deixava a sua
  ociosa no pool — o pacote gastava **~40s de espera pura no teardown**, sem teste algum rodando
  (4,3s depois da correção). (g) **Asserção de rate limit não fixa o número da tentativa**: sob
  `-race` o bcrypt custa segundos e o limiter recarrega no meio do laço, então o teste tenta até
  20 vezes e exige que o 429 apareça — o consumo é mais rápido que a recarga, logo é inevitável,
  mas *em qual* tentativa depende da máquina. Mesma lição já registrada nos testes de unidade:
  **asserção sobre rate limit não pode depender de operação lenta dentro da janela**.
- **Go 1.25**: exigido pelo `golang.org/x/time`; CI lê a versão do `go.mod`, Dockerfile usa
  `golang:1.25-alpine`.
- **Observabilidade local (dev)**: `docker-compose.observability.yml` sobe Prometheus (9090) +
  Grafana (3000), conectados à rede `small-links-net` (external) da stack principal. Configs em
  `observability/`: provisionamento do Grafana (datasource Prometheus com `uid: prometheus`,
  referenciado pelos painéis, e o dashboard *Small Links — Overview*). É ambiente de
  desenvolvimento — **não** faz parte do deploy; a app e o `docker-compose.yml` principal não
  foram alterados. O Prometheus raspa **dois jobs**: `small-links` (local `app:8080`, 15s) e
  `small-links-prod` (produção `https://small-links.onrender.com`, 60s). O dashboard tem a
  variável de template `job` (custom: `small-links`/`small-links-prod`) e todas as queries
  filtram por `{job="$job"}`, permitindo alternar local↔produção sem quebrar os painéis. O free
  tier do Render hiberna quando ocioso: o alvo prod aparece **DOWN** em períodos sem tráfego
  (esperado).
- **Docker: rede com nome fixo + override local**: a rede `small-links-net` tem
  `name: small-links-net` explícito no `docker-compose.yml` — sem isso o Compose a criava com
  prefixo do diretório do projeto (`small-links_small-links-net`), quebrando o
  `docker-compose.observability.yml` (que a referencia como `external`) em clones com outro
  nome de pasta. **Regra**: ajustes por máquina (ex.: porta do Postgres remapeada para 5433
  quando a 5432 do host está ocupada) vão no `docker-compose.override.yml` — fundido
  automaticamente pelo Compose, **gitignored**, documentado no
  `docker-compose.override.yml.example` versionado — **nunca** como modificação local do
  arquivo versionado (gerava conflito em todo pull). Para substituir (e não somar) uma lista
  como `ports` no override, usar a tag YAML `!override`.
- **Dashboard provisionado sem dados (bug corrigido)**: dashboards provisionados exigem um `uid`
  de datasource **fixo e explícito**, referenciado igual em todos os painéis *e* em cada target.
  Isso já estava correto nos arquivos, mas o volume `grafana_data` podia persistir um datasource
  "Prometheus" antigo com uid aleatório — provisionar por nome não troca o uid, então os painéis
  (uid `prometheus`) ficavam órfãos e vazios. Correção: `deleteDatasources` no provisioning
  remove o datasource antes de recriá-lo com o uid fixo, tornando o vínculo determinístico mesmo
  com volume persistido; o dashboard ganhou `id: null`/`version`. **Lição**: com provisionamento,
  o uid do datasource é o contrato entre datasource e painéis — fixe-o dos dois lados e garanta
  que estado persistido não sobreponha um uid divergente.

## Deploy

**✅ Concluído (11/07/2026)** — app no **Render** (auto-deploy da `main`) + **PostgreSQL no Neon**:
<https://small-links.onrender.com>.

1. ~~**TRUNCATE no deploy final** (Caminho A): descartar os registros CTR legados antes de testar.~~
   **Não se aplica mais**: o banco do Neon nasceu **novo e vazio**, sem registros CTR legados —
   não há `TRUNCATE` a rodar.
2. ~~**`cmd/migrate-gcm` é código morto** com essa decisão — remover em commit futuro.~~ ✅ removido.
3. **Auto-deploy contínuo**: todo merge na `main` vai automaticamente para produção. O **CI verde**
   (`gofmt`, `go vet`, `go build`, `go test`) é o **portão de qualidade** antes do merge.
4. **Commits que exigem operação manual** continuam devendo ficar em PR separado (política mantida).

## Backlog priorizado

1. ~~**Higiene**~~ ✅ (PR #1)
2. ~~**Testes de caracterização** + CI~~ ✅ (PR #2)
3. ~~**Refatoração estrutural** para a arquitetura alvo~~ ✅ (PR #2)
4. ~~**Segurança**: AES-GCM, POST /api/shorten, validação, rate limiting, Dockerfile~~ ✅ (PR #3)
5. ~~**Dedup**: url_hash HMAC-SHA256 indexado~~ ✅
   - Pelo Caminho A (jul/2026), o fallback `decryptLegacyCTR` e o backfill `cmd/migrate-gcm`
     foram removidos. Na prática o banco de produção (Neon) nasceu vazio, então não houve
     `TRUNCATE` a rodar — ver seção **Deploy**.
6. ~~**Features**: eventos de clique + registro assíncrono, stats expandido, `/metrics`
   Prometheus, alias customizado, expiração/TTL, QR code~~ ✅
7. ~~**Landing page na rota `/`**: página inicial (formulário + branding) embutida via
   `go:embed`, sem colidir com o catch-all `/:shortId`~~ ✅
8. **Extras**: cache Redis para redirects quentes, frontend em Next.js.
