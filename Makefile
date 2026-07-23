.PHONY: check fmt vet test

# Obrigatório antes de qualquer commit: o CI para no primeiro step que falha,
# então um erro de gofmt mascara erros de vet/test.
check: fmt vet test

fmt:
	gofmt -w .

vet:
	go vet ./...

test:
	go test ./...
