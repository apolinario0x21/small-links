// Package logging reúne utilidades de log — em especial a redação de dados
// sensíveis antes de qualquer URL chegar a um logger.
package logging

import (
	"net/url"
	"strings"
)

// redactedValue substitui o valor de um parâmetro sensível.
const redactedValue = "REDACTED"

// unparseableURL é o que se registra quando a URL não pode ser interpretada:
// devolver a string bruta arriscaria vazar justamente o segredo que não
// conseguimos localizar.
const unparseableURL = "[unparseable-url]"

// sensitiveParams são os nomes de query param cujo valor nunca pode ir para
// o log. Comparação case-insensitive (chaves já normalizadas em minúsculas).
var sensitiveParams = map[string]bool{
	"token":        true,
	"auth":         true,
	"password":     true,
	"api_key":      true,
	"secret":       true,
	"access_token": true,
}

// RedactURL devolve a URL com os valores dos query params sensíveis
// substituídos por REDACTED, preservando o restante (scheme, host, path e
// demais params) para que o log continue útil no diagnóstico.
//
// URLs encurtadas frequentemente carregam segredos na query; toda URL
// original que for parar em log deve passar por aqui.
func RedactURL(raw string) string {
	if raw == "" {
		return ""
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return unparseableURL
	}

	// Query inválida ainda pode conter pares recuperáveis: ParseQuery
	// devolve o que conseguiu junto com o erro, e é sobre esse conjunto
	// que reescrevemos — o resto da query é descartado, não vazado.
	values, err := url.ParseQuery(parsed.RawQuery)
	if err != nil && len(values) == 0 {
		if parsed.RawQuery != "" {
			parsed.RawQuery = redactedValue
		}
		return parsed.String()
	}

	changed := err != nil
	for key := range values {
		if !sensitiveParams[strings.ToLower(key)] {
			continue
		}
		for i := range values[key] {
			values[key][i] = redactedValue
		}
		changed = true
	}

	if !changed {
		return parsed.String()
	}

	parsed.RawQuery = values.Encode()
	return parsed.String()
}
