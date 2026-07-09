# Etapa 1: build da aplicação
FROM golang:1.25-alpine AS builder
WORKDIR /app

# Copiar os manifests primeiro para aproveitar o cache de camadas:
# o download das dependências só roda de novo se go.mod/go.sum mudarem.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o main ./cmd/server

# Etapa 2: imagem final Alpine
FROM alpine:latest

# Instalar certificados SSL
RUN apk --no-cache add ca-certificates

RUN addgroup -S app && adduser -S -G app app
WORKDIR /app

COPY --from=builder /app/main .

USER app

EXPOSE 8080
CMD ["./main"]
