package logging

import (
	"strings"
	"testing"
)

func TestRedactURL(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "sem query",
			raw:  "https://exemplo.com/pagina",
			want: "https://exemplo.com/pagina",
		},
		{
			name: "query sem params sensíveis",
			raw:  "https://exemplo.com/busca?q=golang&page=2",
			want: "https://exemplo.com/busca?q=golang&page=2",
		},
		{
			name: "token",
			raw:  "https://exemplo.com/reset?token=abc123",
			want: "https://exemplo.com/reset?token=REDACTED",
		},
		{
			name: "case-insensitive",
			raw:  "https://exemplo.com/x?Token=abc&API_KEY=xyz",
			want: "https://exemplo.com/x?API_KEY=REDACTED&Token=REDACTED",
		},
		{
			name: "preserva os params não sensíveis",
			raw:  "https://exemplo.com/callback?code=ok&access_token=segredo",
			want: "https://exemplo.com/callback?access_token=REDACTED&code=ok",
		},
		{
			name: "todos os nomes sensíveis",
			raw:  "https://e.com/?auth=a&password=b&secret=c&api_key=d&access_token=e&token=f",
			want: "https://e.com/?access_token=REDACTED&api_key=REDACTED&auth=REDACTED&password=REDACTED&secret=REDACTED&token=REDACTED",
		},
		{
			name: "valor repetido no mesmo param",
			raw:  "https://e.com/?token=um&token=dois",
			want: "https://e.com/?token=REDACTED&token=REDACTED",
		},
		{
			name: "fragmento preservado",
			raw:  "https://e.com/doc?secret=s#secao",
			want: "https://e.com/doc?secret=REDACTED#secao",
		},
		{
			name: "vazia",
			raw:  "",
			want: "",
		},
		{
			name: "inparseável não vaza o bruto",
			raw:  "://exemplo.com?token=abc",
			want: unparseableURL,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := RedactURL(tc.raw); got != tc.want {
				t.Errorf("RedactURL(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

// Query malformada é redigida por inteiro: não conseguindo separar os pares
// com segurança, prefere-se perder informação a vazar um segredo.
func TestRedactURLMalformedQuery(t *testing.T) {
	got := RedactURL("https://e.com/x?%zz=1&token=segredo")
	if got == "https://e.com/x?%zz=1&token=segredo" {
		t.Errorf("RedactURL manteve a query malformada intacta: %q", got)
	}
	if strings.Contains(got, "segredo") {
		t.Errorf("RedactURL vazou o segredo: %q", got)
	}
}
