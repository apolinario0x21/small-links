# Etapa 1: build da aplicação
FROM golang:1.22.3-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o main .

# Etapa 2: imagem final Alpine
FROM alpine:latest

# Instalar certificados SSL
RUN apk --no-cache add ca-certificates
WORKDIR /app

COPY --from=builder /app/main .

EXPOSE 8080
CMD ["./main"]