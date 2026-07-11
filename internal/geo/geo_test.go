package geo

import "testing"

func TestOpenMissingFile(t *testing.T) {
	if _, err := Open("/caminho/inexistente.mmdb"); err == nil {
		t.Error("Open deve falhar para arquivo inexistente")
	}
}

// IPs privados/inválidos retornam "" antes de qualquer consulta à base —
// válido mesmo sem MMDB carregada (resolver com db nil).
func TestCountryCodeSkipsPrivateAndInvalidIPs(t *testing.T) {
	r := &Resolver{}
	for _, ip := range []string{
		"", "não-é-ip", "10.0.0.1", "172.16.5.5", "192.168.1.1",
		"127.0.0.1", "::1", "0.0.0.0", "169.254.1.1", "fe80::1",
	} {
		if got := r.CountryCode(ip); got != "" {
			t.Errorf("CountryCode(%q) = %q, want \"\"", ip, got)
		}
	}
}

func TestCountryCodeNilResolverIsSafe(t *testing.T) {
	var r *Resolver
	if got := r.CountryCode("203.0.113.5"); got != "" {
		t.Errorf("resolver nil deve devolver \"\", got %q", got)
	}
}
