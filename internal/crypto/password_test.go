package crypto

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestHashAndCheckPassword(t *testing.T) {
	hash, err := HashPassword("segredo123")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if strings.Contains(hash, "segredo123") {
		t.Error("o hash não pode conter a senha em claro")
	}
	if !CheckPassword(hash, "segredo123") {
		t.Error("CheckPassword recusou a senha correta")
	}
	if CheckPassword(hash, "outra-senha") {
		t.Error("CheckPassword aceitou a senha errada")
	}
	if CheckPassword("", "segredo123") || CheckPassword(hash, "") {
		t.Error("CheckPassword deve recusar hash ou senha vazios")
	}
}

// Dois hashes da mesma senha diferem (salt), então o hash não denuncia
// senhas iguais entre links diferentes.
func TestHashPasswordIsSalted(t *testing.T) {
	first, _ := HashPassword("segredo123")
	second, _ := HashPassword("segredo123")
	if first == second {
		t.Error("hashes idênticos: bcrypt deveria salgar cada um")
	}
}

func TestHashPasswordTooShort(t *testing.T) {
	if _, err := HashPassword("abc"); !errors.Is(err, ErrPasswordTooShort) {
		t.Errorf("err = %v, want ErrPasswordTooShort", err)
	}
}

func TestAccessTokenRoundTrip(t *testing.T) {
	c, err := New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	now := time.Now()
	token := c.SignAccessToken("abc123", now.Add(time.Hour))

	if err := c.VerifyAccessToken(token, "abc123", now); err != nil {
		t.Errorf("token válido recusado: %v", err)
	}

	tests := []struct {
		name    string
		token   string
		shortID string
		now     time.Time
	}{
		{"outro short_id", token, "outro1", now},
		{"expirado", c.SignAccessToken("abc123", now.Add(-time.Second)), "abc123", now},
		{"assinatura adulterada", token[:strings.LastIndex(token, ".")] + ".deadbeef", "abc123", now},
		{"payload adulterado", "AAAA." + strings.SplitN(token, ".", 2)[1], "abc123", now},
		{"formato inválido", "nao-e-um-token", "abc123", now},
		{"vazio", "", "abc123", now},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := c.VerifyAccessToken(tc.token, tc.shortID, tc.now); !errors.Is(err, ErrInvalidAccessToken) {
				t.Errorf("err = %v, want ErrInvalidAccessToken", err)
			}
		})
	}
}

// Token assinado com outra chave não vale: a assinatura é o único vínculo
// de confiança do cookie.
func TestAccessTokenRejectsOtherKey(t *testing.T) {
	mine, _ := New([]byte("0123456789abcdef0123456789abcdef"))
	theirs, _ := New([]byte("ffffffffffffffff0123456789abcdef"))

	token := theirs.SignAccessToken("abc123", time.Now().Add(time.Hour))
	if err := mine.VerifyAccessToken(token, "abc123", time.Now()); !errors.Is(err, ErrInvalidAccessToken) {
		t.Errorf("err = %v, want ErrInvalidAccessToken", err)
	}
}
