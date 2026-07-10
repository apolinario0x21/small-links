# Small Links

![Go](https://img.shields.io/badge/Go-1.25-blue.svg)
![Framework](https://img.shields.io/badge/Framework-Gin--v1.10.1-blueviolet.svg)
[![Framework](https://img.shields.io/badge/Gin-v1.10.1-blueviolet.svg)](https://gin-gonic.com/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue?logo=docker&logoColor=white)](https://www.docker.com/)
[![railway](https://img.shields.io/badge/Deploy-Railway-purple.svg)](https://railway.app/)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

Um serviço de encurtador de URLs seguro e de alta performance, construído com Go e o framework Gin. 
Oferecendo funcionalidades essenciais como criptografia robusta, armazenamento persistente e rastreamento de acessos.

## ⚙️ Funcionalidades

- 🔐 Criptografia Segura: URLs são criptografadas usando AES-256 antes do armazenamento
- 💾 Armazenamento Persistente: PostgreSQL com criação automática do schema na inicialização
- 📊 Análise de Dados: Rastreamento de contagem de acessos e timestamps de criação para cada URL
- 🚀 Pronto para Produção: Health checks, tratamento de erros e otimizado para deploy no Railway
- 🌐 Detecção Inteligente de Protocolo: Detecção automática de HTTPS/HTTP baseada no ambiente de deploy
- 🔄 Suporte CORS: Suporte integrado para Cross-Origin Resource Sharing


## 🚀 Tecnologias utilizadas
- Go 1.25+
- Gin Web Framework
- PostgreSQL (driver lib/pq)
- Criptografia AES (pacote crypto/aes)
- Métricas Prometheus (client_golang) e QR code (skip2/go-qrcode)
- Docker e Docker Compose
- Railway para deploy (opcional)

## 📦 Instalação e uso local

1. Clone o repositório
   ```bash
   git clone https://github.com/apolinario0x21/small-links.git
   cd small-links
   ```
2. Defina as variáveis de ambiente
   ```bash
   export ENCRYPTION_KEY=sua_chave_de_criptografia   # exatamente 32 caracteres
   export DATABASE_URL=postgres://usuario:senha@localhost:5432/smalllinks?sslmode=disable
   ```

3. Instale as dependências
   ```
   go mod tidy
   ```
4. Rode a aplicação
   ```
   go run ./cmd/server
   ```

Alternativamente, suba tudo (aplicação + PostgreSQL) com Docker:
   ```bash
   docker compose up --build
   ```

## 📬 Endpoints disponíveis

| Método | Rota      | Descrição                             |
|--------|-----------|---------------------------------------|
| POST   | `/api/shorten` | Gera uma URL curta (body JSON `{"url": "https://..."}`, responde 201; se a URL já foi encurtada, responde 200 com `"existing": true` e o `short_id` existente). Campos opcionais: `custom_alias` e `expires_in_days` |
| GET    | `/shorten?url={url_original}` | Gera uma URL curta (legado, responde 200) |
| GET    | `/{short_id}` | Redireciona para a URL original (302; 410 Gone se expirado) |
| GET    | `/stats/{short_id}`  | Estatísticas da URL: `access_count`, `total_clicks`, `clicks_per_day` (últimos 30 dias) e `top_referrers` (top 5) |
| GET    | `/qr/{short_id}`  | QR code do short link em PNG (`image/png`) |
| GET    | `/health`  | Verificação de Saúde  |
| GET    | `/metrics`  | Métricas Prometheus (counters de redirects/shortens/rate-limited e histograma de latência) |

### Campos opcionais do `POST /api/shorten`

- `custom_alias` — alias customizado (`^[a-zA-Z0-9_-]{3,30}$`). Colisão com um `short_id`
  existente ou com uma rota reservada (`health`, `shorten`, `stats`, `api`, `metrics`, `qr`)
  responde **409 Conflict**. Ausente, o `short_id` é gerado aleatoriamente.
- `expires_in_days` — inteiro positivo; o link expira após N dias e o redirect passa a
  responder **410 Gone**. Ausente, o link é permanente.


## 🔧 Configuração

| Variável | Descrição      | Padrão                             | Obrigatório |
|--------|-----------|---------------------------------------|-------------|
| ENCRYPTION_KEY    | `Chave de criptografia AES de 32 caracteres` | — | Sim |
| DATABASE_URL    | String de conexão PostgreSQL | — | Sim |
| PORT    | Porta do servidor | 8080 | Não         |
| GIN_MODE    | Modo do framework Gin `(debug/release)`  | release | Não |

## Considerações de Segurança

- Sempre defina uma ENCRYPTION_KEY personalizada em produção
- A chave de criptografia deve ter exatamente 32 caracteres
- URLs são criptografadas antes do armazenamento para proteger a privacidade do usuário 
- IDs curtos são gerados usando números aleatórios criptograficamente seguros
- Criação de URLs limitada a 10 requisições por minuto por IP (HTTP 429 ao exceder)

### 🔒 Privacidade (LGPD)

- Endereços IP dos acessos **nunca** são armazenados em claro: apenas o HMAC-SHA256 do IP
  (`ip_hash`) é gravado na tabela `click_events`, para contagem/deduplicação sem expor o IP.
- Os eventos de clique guardam também referrer e user-agent, usados apenas para as estatísticas
  agregadas expostas em `/stats/{short_id}`.

## 📊 Exemplos de Uso
### Usando cURL

```bash
### Criar uma URL encurtada
curl -X POST "https://seu-dominio.com/api/shorten" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.google.com"}'

### Criar com alias customizado e expiração em 30 dias
curl -X POST "https://seu-dominio.com/api/shorten" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.google.com", "custom_alias": "google", "expires_in_days": 30}'

### Criar uma URL encurtada (endpoint legado)
curl "https://seu-dominio.com/shorten?url=https://www.google.com"

### Obter estatísticas
curl "https://seu-dominio.com/stats/aB3xY2"

### Baixar o QR code (PNG)
curl "https://seu-dominio.com/qr/aB3xY2" --output qr.png

### Verificação de saúde
curl "https://seu-dominio.com/health"
```

## Usando JavaScript (Fetch API)

```javascript
// Criar URL encurtada
const response = await fetch('https://seu-dominio.com/shorten?url=https://www.exemplo.com');
const data = await response.json();
console.log('URL encurtada:', data.short_url);

// Obter estatísticas
const stats = await fetch(`https://seu-dominio.com/stats/${shortId}`);
const statsData = await stats.json();
console.log('Contagem de acessos:', statsData.access_count);
```
## Componentes Principais

- Camada de Criptografia: Criptografia AES-256-GCM autenticada
- Engine de Armazenamento: Persistência em PostgreSQL com short_id único indexado
- Geração de ID: Identificadores de 6 caracteres criptograficamente seguros, ou alias customizado
- Expiração: TTL opcional por link (`expires_in_days`); links expirados respondem 410 Gone
- QR code: PNG do short link em `/qr/{short_id}`
- Analytics: Eventos de clique gravados de forma assíncrona (buffer + worker), sem travar o redirect
- Monitoramento: Health checks, estatísticas de acesso e métricas Prometheus em `/metrics`

## 🚢 Deploy
Railway (Recomendado)

- Faça um fork deste repositório
- Conecte sua conta do Railway ao GitHub
- Crie um novo projeto a partir do seu fork
- Adicione um banco PostgreSQL ao projeto (o Railway define `DATABASE_URL` automaticamente)
- Configure a variável de ambiente ENCRYPTION_KEY
- Deploy automático no push


## 🔍 Monitoramento
### Endpoint de Saúde

O endpoint `/health` fornece:
- Status do serviço
- Número total de URLs armazenadas
- Timestamp atual

### Endpoint de Métricas

O endpoint `/metrics` expõe métricas no formato Prometheus:
- `smalllinks_redirects_total` — redirects bem-sucedidos
- `smalllinks_shortens_total` — URLs encurtadas
- `smalllinks_rate_limited_total` — requisições barradas pelo rate limiting
- `smalllinks_http_request_duration_seconds` — histograma de latência por método, rota e status

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

## Logs
A aplicação registra:

- Informações de inicialização
- Conexão e migração do banco de dados
- Condições de erro
- Avisos de segurança

## 🤝 Contribuindo

- Faça um fork do repositório
- Crie uma branch de feature (`git checkout -b feature/funcionalidade-incrivel`)
- Faça commit das suas mudanças (`git commit -m 'Adiciona funcionalidade incrível`')
- Faça push para a branch (`git push origin feature/funcionalidade-incrivel`)
- Abra um Pull Request

## 📄 Licença

Este projeto está sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

