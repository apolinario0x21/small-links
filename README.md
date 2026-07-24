# Small Links

> Encurtador de URLs em Go com criptografia autenticada, analytics de clique e observabilidade Prometheus.

[![CI](https://github.com/apolinario0x21/small-links/actions/workflows/ci.yml/badge.svg)](https://github.com/apolinario0x21/small-links/actions/workflows/ci.yml)
![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)

Serviço HTTP que encurta URLs e as devolve por um `short_id`, redirecionando o acesso para o
destino original. As URLs são cifradas em repouso (AES-256-GCM), acessos repetidos reaproveitam
o mesmo link (dedup por HMAC), e cada clique alimenta estatísticas agregadas — tudo instrumentado
com métricas Prometheus. Arquitetura em camadas, dependências injetadas por struct e testes de
caracterização cobrindo os endpoints.

🔗 **Demo em produção:** **[small-links.onrender.com](https://small-links.onrender.com)** — app no Render (auto-deploy da `main`), PostgreSQL no Neon.

---

## ✨ Features

- **Encurtamento seguro** — a URL original é cifrada com **AES-256-GCM** (cifragem autenticada,
  nonce aleatório prefixado) antes de ir para o banco; nunca é gravada em claro.
- **Deduplicação por HMAC** — a mesma URL devolve o `short_id` existente. O lookup usa
  **HMAC-SHA256** da URL (o nonce aleatório impede busca pelo ciphertext), ignorando links já
  expirados.
- **Alias customizado** — `custom_alias` opcional (`^[a-zA-Z0-9_-]{3,30}$`), com proteção contra
  colisão e rotas reservadas.
- **Expiração / TTL** — `expires_in_days` opcional; links expirados respondem **410 Gone**.
- **Link protegido por senha** — `password` opcional na criação (mín. 4 caracteres, **bcrypt**);
  abrir o link exige a senha, que libera um cookie assinado de 1h. Links protegidos ficam fora da
  deduplicação e a senha nunca sai em resposta alguma.
- **QR code** — `GET /qr/{short_id}` devolve o PNG do short link.
- **Analytics de clique** — cada acesso gera um evento (referrer, user-agent, `ip_hash`, país,
  dispositivo) gravado de forma **assíncrona** (canal buffered + worker), sem adicionar latência
  ao redirect. Geolocalização por país resolvida localmente (DB-IP Lite) e detecção de
  dispositivo/bot pelo user-agent; bots ficam fora das estatísticas.
- **Rate limiting por IP** — 10 req/min nos endpoints de criação (HTTP 429), com `ClientIP`
  confiável atrás de proxy.
- **Verificação de URL maliciosa** — checagem opcional via **Google Safe Browsing** antes de
  encurtar; URLs sinalizadas são recusadas com **422**. Timeout curto e *fail-open* (falha da
  API nunca trava o encurtamento).
- **Observabilidade** — endpoint `/metrics` no formato Prometheus e stack local de Grafana
  provisionada.
- **Documentação interativa** — OpenAPI/Swagger UI em `/swagger` (desabilitável por env var).
- **Landing page** — página inicial em `/` (HTML embutido no binário via `go:embed`) com
  formulário de encurtamento, cópia do link, QR code e mensagens de erro amigáveis.
- **Histórico local** — os links criados ficam salvos no `localStorage` do navegador (últimos
  20, com contagem de cliques via `/stats`); **client-side por privacidade** — o servidor não
  registra quem criou o quê.
- **Gerenciamento por token** — cada criação devolve um `management_token` secreto (uma única
  vez); com ele, `DELETE /api/links/{short_id}` desativa o link (**soft delete**). Autorização
  por posse do segredo, sem contas. Analytics é preservado; o `short_id` nunca é reciclado.

## 🧰 Stack técnica

| Camada | Tecnologia |
|--------|-----------|
| Linguagem | Go 1.25 |
| Web framework | Gin |
| Banco de dados | PostgreSQL (`lib/pq`) |
| Criptografia | `crypto/aes` (AES-256-GCM) + `crypto/hmac` (HMAC-SHA256) |
| Rate limiting | `golang.org/x/time/rate` |
| Métricas | Prometheus (`client_golang`) |
| QR code | `skip2/go-qrcode` |
| Documentação | OpenAPI/Swagger (`swaggo/swag` + `gin-swagger`) |
| Empacotamento | Docker + Docker Compose |
| CI | GitHub Actions (`gofmt`, `go vet`, `go build`, `go test`, `-race`, integração com Postgres, `golangci-lint`, `govulncheck`, `gosec`) |
| Deploy | Render (app, auto-deploy da `main`) + Neon (PostgreSQL) |

## 🏗️ Arquitetura

Bootstrap em `cmd/`, regras de negócio isoladas em `internal/`, schema versionado em `migrations/`.
Handlers recebem dependências via struct (sem globais) e toda query de banco usa `context.Context`
com timeout.

```
cmd/server/          → bootstrap: config, injeção de dependências, graceful shutdown, slog
internal/config/     → leitura e validação das variáveis de ambiente
internal/crypto/     → AES-256-GCM (cifragem das URLs) + HMAC-SHA256 (dedup e ip_hash)
internal/storage/    → interface Repository + implementação PostgreSQL (context + timeout)
internal/analytics/  → Recorder de cliques assíncrono (canal buffered + worker goroutine)
internal/metrics/    → coletores Prometheus (counters + histograma de latência)
internal/http/       → handlers, middleware (CORS, métricas, rate limiting) e rotas
migrations/          → SQL versionado, aplicado via go:embed na inicialização
```

## 📬 API

| Método | Rota | Descrição |
|--------|------|-----------|
| `GET`  | `/` | Landing page (HTML) com formulário de encurtamento. |
| `POST` | `/api/shorten` | Cria um short link a partir de um body JSON. Campos opcionais: `custom_alias`, `expires_in_days`, `password`. **201** para novo (inclui `management_token`); **200** com `"existing": true` se a URL já existia (sem token); **409** em colisão de alias; **422** se a URL for maliciosa; **400** para entrada inválida. |
| `DELETE` | `/api/links/{short_id}` | Desativa (soft delete) o link. Requer `Authorization: Bearer <management_token>`. **204** sucesso; **403** uniforme se o token faltar/for inválido (não revela se o `short_id` existe). |
| `GET`  | `/shorten?url=` | Variante legada de criação (**200**), delegando à mesma lógica. |
| `GET`  | `/{short_id}` | Redireciona para a URL original (**302**); **404** se inexistente; **410 Gone** se expirado/desativado; **tela de senha** (ou **401** JSON) se protegido e sem cookie de acesso. |
| `POST` | `/{short_id}` | Envia a senha de um link protegido (`password` no form ou header `X-Password`). Correta: cookie de acesso (1h) + **302**. Errada: **401**. Máximo de **5 tentativas/min por link** (**429**). |
| `GET`  | `/stats/{short_id}` | Estatísticas: `access_count`, `total_clicks`, `clicks_per_day` (30 dias), `top_referrers` (top 5), `top_countries` (top 5) e `devices` — bots excluídos. |
| `GET`  | `/qr/{short_id}` | QR code do short link em PNG (`image/png`). |
| `GET`  | `/health` | Health check (`status`, `total_urls`, `timestamp`). |
| `GET`  | `/metrics` | Métricas no formato Prometheus. |
| `GET`  | `/swagger/*` | Documentação interativa da API (Swagger UI). Desabilitável por env var. |

### Exemplo — criar um short link

**Request**

```bash
curl -X POST "https://small-links.onrender.com/api/shorten" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.exemplo.com/pagina", "custom_alias": "promo", "expires_in_days": 30}'
```

**Response** `201 Created`

```json
{
  "short_id": "promo",
  "short_url": "https://small-links.onrender.com/promo",
  "original_url": "https://www.exemplo.com/pagina",
  "created_at": "2026-07-10T12:00:00Z",
  "expires_at": "2026-08-09T12:00:00Z"
}
```

Se a URL já tiver sido encurtada, a resposta é `200 OK` com o `short_id` existente e
`"existing": true`.

### Exemplo — link protegido por senha

```bash
curl -X POST http://localhost:8080/api/shorten \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://exemplo.com/relatorio.pdf","password":"segredo123"}'
```

```json
{
  "short_id": "aB3xY9",
  "short_url": "http://localhost:8080/aB3xY9",
  "original_url": "https://exemplo.com/relatorio.pdf",
  "created_at": "2026-07-23T12:00:00Z",
  "management_token": "…",
  "has_password": true
}
```

Abrir sem a senha responde **401** (ou a tela de senha, no navegador). Com a senha:

```bash
curl -i -X POST http://localhost:8080/aB3xY9 -H 'X-Password: segredo123'
# HTTP/1.1 302 Found
# Set-Cookie: sl_access=…; Path=/aB3xY9; HttpOnly; SameSite=Lax
# Location: https://exemplo.com/relatorio.pdf
```

### Exemplo — estatísticas

**Request**

```bash
curl "https://small-links.onrender.com/stats/promo"
```

**Response** `200 OK`

```json
{
  "short_id": "promo",
  "original_url": "https://www.exemplo.com/pagina",
  "created_at": "2026-07-10T12:00:00Z",
  "access_count": 42,
  "total_clicks": 42,
  "clicks_per_day": [
    { "day": "2026-07-09", "count": 30 },
    { "day": "2026-07-10", "count": 12 }
  ],
  "top_referrers": [
    { "referrer": "https://news.exemplo.com", "count": 20 }
  ]
}
```

### Exemplo — QR code

```bash
curl "https://small-links.onrender.com/qr/promo" --output qr.png
```

### Exemplo — excluir um link (token de gerenciamento)

A criação devolve `management_token` **uma única vez** — guarde-o. Ele é o segredo que autoriza
a exclusão (não há contas; a autorização é por posse do token):

```bash
# 1) criar → a resposta traz "management_token": "a1b2...64hex"
# 2) excluir com o token:
curl -X DELETE "https://small-links.onrender.com/api/links/promo" \
  -H "Authorization: Bearer a1b2c3...64hex"     # → 204 No Content
```

Após a exclusão, o redirect e o QR do link respondem **410 Gone**; as estatísticas continuam
acessíveis (analytics preservado) e o `short_id` nunca é reaproveitado. Um token ausente ou
inválido responde **403 uniforme** — deliberadamente sem revelar se o `short_id` existe.

> **Links criados antes desta feature não são gerenciáveis** (não têm token): não há como
> excluí-los pela API. Só links criados a partir de agora recebem `management_token`.

### 📖 Documentação interativa (Swagger)

A API é documentada via OpenAPI e servida com uma UI interativa (Swagger UI):

```
http://localhost:8080/swagger/index.html
```

Em produção (enquanto habilitada): <https://small-links.onrender.com/swagger/index.html>.

Lá é possível ver todos os endpoints, schemas de request/response e disparar chamadas de teste.
A UI fica ligada por padrão; em produção defina `SWAGGER_ENABLED=false` para desabilitá-la.

> As anotações ficam nos handlers (`internal/http/`) e nas infos gerais em `cmd/server/main.go`.
> Após alterá-las, regenere os artefatos em `docs/` com
> [`swag`](https://github.com/swaggo/swag): `swag init -g cmd/server/main.go --parseInternal -o docs`.

## 🔧 Variáveis de ambiente

| Variável | Obrigatória | Padrão | Descrição |
|----------|-------------|--------|-----------|
| `ENCRYPTION_KEY` | Sim | — | Chave AES-256, exatamente **32 caracteres**. |
| `DATABASE_URL` | Sim | — | String de conexão PostgreSQL. |
| `PORT` | Não | `8080` | Porta do servidor HTTP. |
| `GIN_MODE` | Não | `release` | Modo do Gin (`debug`/`release`). |
| `SWAGGER_ENABLED` | Não | `true` | UI do Swagger em `/swagger`. Defina `false` para desabilitar (ex.: produção). |
| `SAFE_BROWSING_API_KEY` | Não | — | Chave da Google Safe Browsing API. Vazia desabilita a verificação de URL maliciosa. |
| `GEOIP_DB_PATH` | Não | `/app/dbip-country-lite.mmdb` | Caminho da base MMDB (DB-IP Lite) para geolocalização por país. Ausente/inválida: app roda sem geo. |
| `TRUSTED_PLATFORM` | Não | — | Fonte do IP do cliente. Vazio: confia só em proxies de faixa privada (Docker Compose local). `cloudflare`: lê `CF-Connecting-IP` — usar **apenas** onde a borda Cloudflare é obrigatória (produção no Render). |
| `CORS_ALLOWED_ORIGINS` | Não | — | Allowlist de origens cross-origin, separada por vírgula (ex.: `https://app.exemplo.com,https://admin.exemplo.com`). Vazia: só a **própria origem** da aplicação é autorizada. O curinga `*` é ignorado. |

## 🚀 Rodando localmente

A forma mais simples é subir aplicação + PostgreSQL com Docker Compose:

```bash
docker compose up --build
```

O serviço fica em `http://localhost:8080` e o schema é criado/migrado automaticamente na
inicialização. Abra `http://localhost:8080/` no navegador para a **landing page** (ou use a de
produção em <https://small-links.onrender.com>).

**Ajustes locais (portas ocupadas etc.):** ajustes específicos da sua máquina — como remapear
a porta do Postgres quando a 5432 do host já estiver em uso — vão em um
`docker-compose.override.yml`, que o Compose funde automaticamente com o arquivo principal e
que está no `.gitignore` (nunca é commitado). Copie o exemplo versionado e adapte:

```bash
cp docker-compose.override.yml.example docker-compose.override.yml
```

<details>
<summary>Rodar sem Docker (Go + Postgres local)</summary>

```bash
git clone https://github.com/apolinario0x21/small-links.git
cd small-links

export ENCRYPTION_KEY=uma_chave_de_exatamente_32_chars_
export DATABASE_URL=postgres://usuario:senha@localhost:5432/smalllinks?sslmode=disable

go run ./cmd/server
```

</details>

## 🧪 Testes

A suíte tem duas camadas, e as duas rodam no CI:

| Camada | O que cobre | Como roda |
|--------|-------------|-----------|
| **Unidade** | Handlers com o banco mockado (`go-sqlmock`), cifragem, HMAC, bcrypt/cookie de acesso, CORS e headers de segurança, redação de URL, rate limiting, geo, Safe Browsing, parsing de env. | `make test` — sem dependência externa. |
| **Integração** | Repositório e API **ponta a ponta** contra um **Postgres real**: migrations, dedup, expiração, soft delete, links protegidos, analytics assíncrono, stats agregado, QR, health. | `make test-integration` — exige banco. |

```bash
make check             # gofmt -w . && go vet ./... && go test ./... && security-check
make test-integration  # sobe nada: usa SMALL_LINKS_TEST_DATABASE_URL
make race              # go test -race ./...
```

Os testes de integração **se auto-pulam** quando `SMALL_LINKS_TEST_DATABASE_URL` não está
definida — por isso `go test ./...` continua verde numa máquina sem banco. Para rodá-los:

```bash
docker run -d --name sl-test-pg -p 5433:5432 \
  -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=smalllinks_test \
  postgres:18-alpine

make test-integration \
  SMALL_LINKS_TEST_DATABASE_URL='postgres://postgres:postgres@localhost:5433/smalllinks_test?sslmode=disable'
```

> ⚠️ Use um **banco descartável**: os testes dão `TRUNCATE` em `urls` e `click_events`. Eles
> rodam com `-p 1` porque os dois pacotes de integração compartilham essas tabelas.

## 📈 Observabilidade local

Ambiente **de desenvolvimento** com Prometheus + Grafana para visualizar as métricas
expostas em `/metrics`. É **separado do deploy** — não faz parte do `docker-compose.yml`
principal nem do ambiente de produção (Render); serve só para inspecionar o serviço
rodando localmente.

![Dashboard Grafana — ambiente local monitorando também a instância de produção no Render](docs/grafana-dashboard.png)

> _Dashboard **Small Links — Overview**: o Prometheus local raspa tanto a instância local quanto
> a de produção (Render); a variável **Instância** no topo alterna entre elas._

Pré-requisito: a stack principal precisa estar no ar, pois o compose de observabilidade se
conecta à rede `small-links-net` (declarada como `external`):

```bash
docker compose up -d          # sobe app + banco e cria a rede small-links-net
```

Subir Prometheus e Grafana:

```bash
docker compose -f docker-compose.observability.yml up -d
```

- **Grafana**: http://localhost:3000 (login inicial `admin` / `admin`). O datasource
  Prometheus e o dashboard *Small Links — Overview* já vêm provisionados — nenhum clique
  de configuração é necessário.
- **Prometheus**: http://localhost:9090. Raspa dois alvos:
  - `small-links` — instância local (`app:8080/metrics`, a cada 15s);
  - `small-links-prod` — **produção** no Render (`small-links.onrender.com/metrics`, a cada 60s).

O dashboard tem uma variável **Instância** (`job`) no topo para alternar entre `small-links`
(local) e `small-links-prod` sem editar os painéis.

> ⚠️ O free tier do Render **hiberna** o serviço quando ocioso. Nesses períodos o alvo
> `small-links-prod` aparece **DOWN** no Prometheus e os painéis de produção ficam sem dados
> até o serviço acordar (o primeiro acesso o desperta). É esperado — não é falha do scrape.

Derrubar (com `-v` para também apagar os volumes de dados):

```bash
docker compose -f docker-compose.observability.yml down       # mantém os dados
docker compose -f docker-compose.observability.yml down -v    # remove os volumes
```

> Se a rede `small-links-net` não existir, o compose de observabilidade falha ao subir.
> Ela é criada automaticamente pelo `docker compose up` da stack principal — com nome fixo
> (`name: small-links-net` no `docker-compose.yml`), sem o prefixo de projeto que o Compose
> aplicaria por padrão. Para subir a observabilidade sem a stack principal, crie a rede
> manualmente com `docker network create small-links-net`.

O dashboard traz: taxa de redirects/s, latência p50/p95/p99 do redirect, requisições por
status (2xx/3xx/4xx/5xx), totais de shortens e rate-limited, URLs bloqueadas pelo Safe Browsing
(total + taxa), e memória residente/goroutines do processo.

### Dashboard sem dados / painéis vazios

Se o datasource funciona no **Explore** mas o dashboard provisionado aparece vazio, o volume
`grafana_data` provavelmente guarda um datasource "Prometheus" de uma execução anterior com
**uid diferente** de `prometheus` — os painéis referenciam `uid: prometheus` e ficam órfãos.
O provisionamento agora remove e recria o datasource com o uid fixo (`deleteDatasources`),
mas se o estado antigo persistir, recrie do zero:

```bash
docker compose -f docker-compose.observability.yml down -v
docker compose -f docker-compose.observability.yml up -d
```

Painéis de latência (p50/p95/p99) só mostram dados **depois** de haver tráfego de redirect —
gere alguns acessos a short links para populá-los.

## 🛡️ Segurança

- **CORS restritivo**: cross-origin é autorizado apenas para as origens de `CORS_ALLOWED_ORIGINS`
  (sem a env, somente a própria origem da aplicação). Origem ausente ou fora da lista **não é
  bloqueada** — apenas não recebe headers CORS, já que quem impõe a restrição é o navegador e
  bloquear aqui quebraria clientes não-browser legítimos. `Authorization` consta de
  `Access-Control-Allow-Headers` para as origens permitidas, porque
  `DELETE /api/links/:shortId` autoriza por Bearer token.
- **Headers de segurança** em todas as respostas: `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin` e
  `Content-Security-Policy`. Em modo release soma-se
  `Strict-Transport-Security: max-age=31536000; includeSubDomains`.
- **CSP com nonce**: a landing embutida usa CSS e JS inline; em vez de liberar `'unsafe-inline'`,
  cada resposta recebe um nonce novo, carimbado nas tags `<style>`/`<script>`. Só as rotas
  `/swagger` usam política relaxada (inline de terceiros, desabilitável com
  `SWAGGER_ENABLED=false`).
- **Links protegidos por senha**: `password` opcional na criação (mín. 4 caracteres), guardado
  como **bcrypt custo 12**. A senha e o hash nunca aparecem em resposta alguma — o cliente recebe
  só `has_password`. Abrir o link exige a senha (tela HTML no navegador, `401` JSON para clientes
  de API); acertando, o servidor emite um cookie **assinado (HMAC-SHA256), válido por 1h**,
  `HttpOnly`, `Secure` em produção, `SameSite=Lax` e restrito ao `Path` do próprio link.
  Tentativas são limitadas a **5 por minuto por link** (429). Links com senha ficam **fora da
  deduplicação** nos dois sentidos, e expiração/exclusão têm precedência sobre a senha (link
  morto responde `410` sem exibir a tela).
- **Redação de URLs em log**: `internal/logging.RedactURL` substitui por `REDACTED` o valor dos
  query params `token`, `auth`, `password`, `api_key`, `secret` e `access_token` (case-insensitive)
  antes de qualquer URL original chegar ao logger.
- **Ferramentas no CI**: `go test -race`, `golangci-lint`, `govulncheck` e `gosec`. Localmente,
  `make check` (que inclui `make security-check`) e `make race`.

## 🔒 Privacidade (LGPD)

- O endereço IP dos acessos **nunca** é armazenado em claro: grava-se apenas o **HMAC-SHA256 do
  IP** (`ip_hash`) na tabela `click_events`, o suficiente para contagem sem expor o IP.
- **Geolocalização resolvida localmente no instante do clique, antes do hash; apenas o código do
  país é armazenado; o IP nunca sai do processo nem é persistido.** A resolução usa uma base
  MMDB local (DB-IP Lite) — nenhuma API externa recebe o IP.
- Os eventos de clique guardam também referrer, user-agent e a classificação de dispositivo,
  usados exclusivamente nas estatísticas agregadas de `/stats/{short_id}`.
- As URLs originais são cifradas com AES-256-GCM antes do armazenamento.

> Este produto inclui dados IP→país de [DB-IP](https://db-ip.com) (IP Geolocation by DB-IP),
> licenciados sob [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

## 🚢 Deploy

Em produção o app roda no **Render** com **auto-deploy da branch `main`** e banco **PostgreSQL
no Neon**. Cada merge na `main` com o CI verde vai automaticamente para produção; o schema é
migrado na inicialização.

Para hospedar a sua própria instância (Render, Railway, Fly.io ou similar):

1. Provisione um PostgreSQL (Neon, Render, etc.) e obtenha a `DATABASE_URL`.
2. Configure as variáveis `ENCRYPTION_KEY` (32 caracteres) e `DATABASE_URL`.
3. Aponte o serviço para este repositório; o build compila `./cmd/server` e as migrations
   rodam sozinhas no start.

## 📄 Licença

Distribuído sob a licença MIT. Veja [LICENSE](LICENSE) para detalhes.
