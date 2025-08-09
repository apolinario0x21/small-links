# Small Links

![Go](https://img.shields.io/badge/Go-1.22.3-blue.svg)
![Framework](https://img.shields.io/badge/Framework-Gin--v1.10.1-blueviolet.svg)
[![Framework](https://img.shields.io/badge/Gin-v1.10.1-blueviolet.svg)](https://gin-gonic.com/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue?logo=docker&logoColor=white)](https://www.docker.com/)
[![railway](https://img.shields.io/badge/Deploy-Railway-purple.svg)](https://railway.app/)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

Um serviço de encurtador de URLs seguro e de alta performance, construído com Go e o framework Gin. 
Oferecendo funcionalidades essenciais como criptografia robusta, armazenamento persistente e rastreamento de acessos.

## ⚙️ Funcionalidades

- 🔐 Criptografia Segura: URLs são criptografadas usando AES-256 antes do armazenamento
- 💾 Armazenamento Persistente: Armazenamento baseado em arquivo JSON com backup automático
- 📊 Análise de Dados: Rastreamento de contagem de acessos e timestamps de criação para cada URL
- 🚀 Pronto para Produção: Health checks, tratamento de erros e otimizado para deploy no Railway
- 🌐 Detecção Inteligente de Protocolo: Detecção automática de HTTPS/HTTP baseada no ambiente de deploy
- ⚡ Alta Performance: Operações thread-safe com estruturas de dados eficientes
- 🔄 Suporte CORS: Suporte integrado para Cross-Origin Resource Sharing


## 🚀 Tecnologias utilizadas
- Go 1.21+
- Gin Web Framework
- Criptografia AES (pacote crypto/aes)
- .env para variáveis de ambiente
- Railway para deploy (opcional)

## 📦 Instalação e uso local

1. Clone o repositório
   ```bash
   git clone https://github.com/apolinario0x21/go-gin-short-url.git
   cd seu-repositorio
   ```
2. Crie um arquivo .env
   ```bash
   ENCRYPTION_KEY=sua_chave_de_criptografia
   ```
   Obs: A chave precisa ter 32 caracteres.


3. Instale as dependências
   ```
   go mod tidy
   ```
4. Rode a aplicação
   ```
   go run main.go
   ```

## 📬 Endpoints disponíveis

| Método | Rota      | Descrição                             |
|--------|-----------|---------------------------------------|
| GET    | `/shorten?url={url_original}` | Gera uma URL curta |
| GET    | `/{short_id}` | Redireciona para a URL original (AES) |
| GET    | `/stats/{short_id}`  | Obter Estatísticas da URL |
| GET    | `/health`  | Verificação de Saúde  |


## 🔧 Configuração

| Variável | Descrição      | Padrão                             | Obrigatório |
|--------|-----------|---------------------------------------|-------------|
| ENCRYPTION_KEY    | `Chave de criptografia AES de 32 caracteres` | sua_chave_de_criptografia | Recomendado |
| PORT    | Porta do servidor | 8080 | Não         |
| GIN_MODE    | Modo do framework Gin `(debug/release)`  | release | Não |

## Considerações de Segurança

- Sempre defina uma ENCRYPTION_KEY personalizada em produção
- A chave de criptografia deve ter exatamente 32 caracteres
- URLs são criptografadas antes do armazenamento para proteger a privacidade do usuário 
- IDs curtos são gerados usando números aleatórios criptograficamente seguros

## 📊 Exemplos de Uso
### Usando cURL

```bash
### Criar uma URL encurtada
curl "https://seu-dominio.com/shorten?url=https://www.google.com"

### Obter estatísticas
curl "https://seu-dominio.com/stats/aB3xY2"

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

- Camada de Criptografia: Criptografia AES-256-CTR para proteção de URLs
- Engine de Armazenamento: Persistência baseada em arquivo JSON com escritas atômicas
- Geração de ID: Identificadores de 6 caracteres criptograficamente seguros
- Concorrência: Operações thread-safe usando RWMutex
- Monitoramento: Health checks integrados e análise de acessos 

## 🚢 Deploy
Railway (Recomendado)

- Faça um fork deste repositório
- Conecte sua conta do Railway ao GitHub
- Crie um novo projeto a partir do seu fork
- Configure a variável de ambiente ENCRYPTION_KEY
- Deploy automático no push


## 🔍 Monitoramento
### Endpoint de Saúd

O endpoint `/health` fornece:
- Status do serviço
- Número total de URLs armazenadas
- Timestamp atual

## Logs
A aplicação registra:

- Informações de inicialização
- Operações de carregamento/salvamento de dados
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

