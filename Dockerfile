# Etapa 1: build da aplicação
FROM golang:1.23 AS builder
WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o main .

# Etapa 2: imagem final mínima
FROM debian:bullseye-slim
WORKDIR /app
COPY --from=builder /app/main .

EXPOSE 8080
CMD ["./main"]
