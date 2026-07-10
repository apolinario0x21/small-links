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

🔗 **Demo:** `https://[SEU-DOMINIO]` _(substituir pelo link de produção do Railway)_

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
- **QR code** — `GET /qr/{short_id}` devolve o PNG do short link.
- **Analytics de clique** — cada acesso gera um evento (referrer, user-agent, `ip_hash`) gravado
  de forma **assíncrona** (canal buffered + worker), sem adicionar latência ao redirect.
- **Rate limiting por IP** — 10 req/min nos endpoints de criação (HTTP 429), com `ClientIP`
  confiável atrás de proxy.
- **Observabilidade** — endpoint `/metrics` no formato Prometheus e stack local de Grafana
  provisionada.

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
| Empacotamento | Docker + Docker Compose |
| CI | GitHub Actions (`gofmt`, `go vet`, `go build`, `go test`) |
| Deploy | Railway |

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
| `POST` | `/api/shorten` | Cria um short link a partir de um body JSON. Campos opcionais: `custom_alias`, `expires_in_days`. **201** para novo; **200** com `"existing": true` se a URL já existia; **409** em colisão de alias; **400** para entrada inválida. |
| `GET`  | `/shorten?url=` | Variante legada de criação (**200**), delegando à mesma lógica. |
| `GET`  | `/{short_id}` | Redireciona para a URL original (**302**); **404** se inexistente; **410 Gone** se expirado. |
| `GET`  | `/stats/{short_id}` | Estatísticas: `access_count`, `total_clicks`, `clicks_per_day` (30 dias), `top_referrers` (top 5). |
| `GET`  | `/qr/{short_id}` | QR code do short link em PNG (`image/png`). |
| `GET`  | `/health` | Health check (`status`, `total_urls`, `timestamp`). |
| `GET`  | `/metrics` | Métricas no formato Prometheus. |

### Exemplo — criar um short link

**Request**

```bash
curl -X POST "https://[SEU-DOMINIO]/api/shorten" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.exemplo.com/pagina", "custom_alias": "promo", "expires_in_days": 30}'
```

**Response** `201 Created`

```json
{
  "short_id": "promo",
  "short_url": "https://[SEU-DOMINIO]/promo",
  "original_url": "https://www.exemplo.com/pagina",
  "created_at": "2026-07-10T12:00:00Z",
  "expires_at": "2026-08-09T12:00:00Z"
}
```

Se a URL já tiver sido encurtada, a resposta é `200 OK` com o `short_id` existente e
`"existing": true`.

### Exemplo — estatísticas

**Request**

```bash
curl "https://[SEU-DOMINIO]/stats/promo"
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
curl "https://[SEU-DOMINIO]/qr/promo" --output qr.png
```

## 🔧 Variáveis de ambiente

| Variável | Obrigatória | Padrão | Descrição |
|----------|-------------|--------|-----------|
| `ENCRYPTION_KEY` | Sim | — | Chave AES-256, exatamente **32 caracteres**. |
| `DATABASE_URL` | Sim | — | String de conexão PostgreSQL. |
| `PORT` | Não | `8080` | Porta do servidor HTTP. |
| `GIN_MODE` | Não | `release` | Modo do Gin (`debug`/`release`). |

## 🚀 Rodando localmente

A forma mais simples é subir aplicação + PostgreSQL com Docker Compose:

```bash
docker compose up --build
```

O serviço fica em `http://localhost:8080` e o schema é criado/migrado automaticamente na
inicialização.

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

**Testes e verificações:**

```bash
go test ./...      # suíte completa
gofmt -l .         # formatação
go vet ./...       # análise estática
```

## 📈 Observabilidade local

Ambiente **de desenvolvimento** com Prometheus + Grafana para visualizar as métricas
expostas em `/metrics`. É **separado do deploy** — não faz parte do `docker-compose.yml`
principal nem do Railway; serve só para inspecionar o serviço rodando localmente.

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
- **Prometheus**: http://localhost:9090 (faz scrape de `app:8080/metrics` a cada 15s).

Derrubar (com `-v` para também apagar os volumes de dados):

```bash
docker compose -f docker-compose.observability.yml down       # mantém os dados
docker compose -f docker-compose.observability.yml down -v    # remove os volumes
```

> Se a rede `small-links-net` não existir, o compose de observabilidade falha ao subir.
> Ela é criada automaticamente pelo `docker compose up` da stack principal; caso o Compose
> a tenha criado com prefixo de projeto (ex.: `small-links_small-links-net`), ajuste o campo
> `name:` da rede externa no `docker-compose.observability.yml` ou crie uma rede compartilhada
> com `docker network create small-links-net`.

O dashboard traz: taxa de redirects/s, latência p50/p95/p99 do redirect, requisições por
status (2xx/3xx/4xx/5xx), totais de shortens e rate-limited, e memória residente/goroutines
do processo.

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

## 🔒 Privacidade (LGPD)

- O endereço IP dos acessos **nunca** é armazenado em claro: grava-se apenas o **HMAC-SHA256 do
  IP** (`ip_hash`) na tabela `click_events`, o suficiente para contagem sem expor o IP.
- Os eventos de clique guardam também referrer e user-agent, usados exclusivamente nas
  estatísticas agregadas de `/stats/{short_id}`.
- As URLs originais são cifradas com AES-256-GCM antes do armazenamento.

## 🚢 Deploy (Railway)

1. Faça um fork deste repositório e conecte sua conta do Railway ao GitHub.
2. Crie um projeto a partir do fork e adicione um banco **PostgreSQL** (o Railway injeta
   `DATABASE_URL` automaticamente).
3. Configure a variável `ENCRYPTION_KEY` (32 caracteres).
4. O deploy roda a cada push; o schema é migrado na inicialização.

## 📄 Licença

Distribuído sob a licença MIT. Veja [LICENSE](LICENSE) para detalhes.
