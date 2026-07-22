.PHONY: check fmt vet test build

# Portão de qualidade: formatação, análise estática e testes.
check: fmt vet test

fmt:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt: arquivos fora do padrão:"; echo "$$unformatted"; exit 1; \
	fi

vet:
	go vet ./...

test:
	go test ./...

build:
	go build ./...
