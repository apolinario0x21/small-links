.PHONY: check fmt vet test race security-check govulncheck gosec lint

# Obrigatório antes de qualquer commit: o CI para no primeiro step que falha,
# então um erro de gofmt mascara erros de vet/test.
check: fmt vet test security-check

fmt:
	gofmt -w .

vet:
	go vet ./...

test:
	go test ./...

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
