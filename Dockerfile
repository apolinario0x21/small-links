# Etapa 1: build da aplicação
FROM golang:1.25-alpine AS builder
WORKDIR /app

# Copiar os manifests primeiro para aproveitar o cache de camadas:
# o download das dependências só roda de novo se go.mod/go.sum mudarem.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o main ./cmd/server

# Base DB-IP Lite country (CC BY 4.0) para geolocalização local — não é
# commitada; baixada no build. A URL é mensal: tenta o mês corrente e cai
# para o anterior. Se ambos falharem, o app sobe sem geo (warn no boot).
RUN set -e; \
    for m in "$(date +%Y-%m)" "$(date -d '-1 month' +%Y-%m 2>/dev/null || date -v-1m +%Y-%m)"; do \
      if wget -q "https://download.db-ip.com/free/dbip-country-lite-${m}.mmdb.gz" -O /tmp/geo.mmdb.gz; then \
        gunzip -c /tmp/geo.mmdb.gz > /app/dbip-country-lite.mmdb && break; \
      fi; \
    done; \
    if [ ! -s /app/dbip-country-lite.mmdb ]; then \
      echo "AVISO: base GeoIP não baixada; app seguirá sem geolocalização"; \
      touch /app/dbip-country-lite.mmdb; \
    fi

# Etapa 2: imagem final Alpine
FROM alpine:latest

# Instalar certificados SSL
RUN apk --no-cache add ca-certificates

RUN addgroup -S app && adduser -S -G app app
WORKDIR /app

COPY --from=builder /app/main .
COPY --from=builder /app/dbip-country-lite.mmdb .

USER app

EXPOSE 8080
CMD ["./main"]
