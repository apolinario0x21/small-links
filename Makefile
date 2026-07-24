.PHONY: check fmt vet test test-integration race security-check govulncheck gosec lint

# Obrigatório antes de qualquer commit: o CI para no primeiro step que falha,
# então um erro de gofmt mascara erros de vet/test.
check: fmt vet test security-check

fmt:
	gofmt -w .

vet:
	go vet ./...

test:
	go test ./...

# Testes de integração contra um Postgres REAL (repositório + API ponta a
# ponta). Sem SMALL_LINKS_TEST_DATABASE_URL eles se auto-pulam, e é por isso
# que `make test` continua valendo sem banco.
#
# -p 1: os dois pacotes de integração dão TRUNCATE nas MESMAS tabelas, e o Go
# roda pacotes em paralelo por padrão. Na prática costuma passar (um termina
# antes do outro começar a limpar), mas o isolamento não é garantido — é uma
# corrida latente, então serializamos em vez de contar com a sorte.
# -count=1 evita cache de resultado, que não enxerga mudanças no banco.
SMALL_LINKS_TEST_DATABASE_URL ?= postgres://postgres:postgres@localhost:5432/smalllinks_test?sslmode=disable

test-integration:
	SMALL_LINKS_TEST_DATABASE_URL="$(SMALL_LINKS_TEST_DATABASE_URL)" go test -p 1 -count=1 ./...

# Detector de corrida: o Recorder de cliques roda em worker próprio, então
# concorrência é caminho quente aqui.
race:
	go test -race ./...

lint:
	golangci-lint run ./...

# Ferramentas de segurança: vulnerabilidades conhecidas nas dependências
# (govulncheck) e padrões inseguros no código (gosec).
security-check: govulncheck gosec

govulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

gosec:
	go run github.com/securego/gosec/v2/cmd/gosec@latest -exclude-dir=docs ./...
