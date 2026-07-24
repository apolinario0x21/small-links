package crypto

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// PasswordCost é o custo do bcrypt para senhas de link. 12 (contra o default
// 10) porque a senha do link tende a ser curta e é o único segredo que
// protege o destino: encarecer cada tentativa é a defesa contra quem vier a
// obter o hash. ~100-250ms por verificação é aceitável num fluxo interativo.
const PasswordCost = 12

// MinPasswordLength é o mínimo aceito na criação do link.
const MinPasswordLength = 4

var ErrPasswordTooShort = errors.New("password must be at least 4 characters long")

// HashPassword devolve o bcrypt da senha. Só o hash é persistido.
func HashPassword(password string) (string, error) {
	if len(password) < MinPasswordLength {
		return "", ErrPasswordTooShort
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), PasswordCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// CheckPassword informa se a senha corresponde ao hash. O bcrypt já compara
// em tempo constante em relação ao conteúdo do hash.
func CheckPassword(hash, password string) bool {
	if hash == "" || password == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// --- Cookie de acesso a link protegido ---

// AccessTokenTTL é a validade do cookie emitido após acertar a senha.
// Curto o bastante para limitar o estrago de um cookie vazado, longo o
// bastante para o visitante não redigitar a senha a cada acesso.
const AccessTokenTTL = time.Hour

var ErrInvalidAccessToken = errors.New("invalid access token")

// SignAccessToken emite um token assinado autorizando o acesso a um
// short_id até expiresAt. Formato "<shortID>.<expUnix>.<HMAC>", com o HMAC
// calculado sobre o payload usando a ENCRYPTION_KEY (mesmo mecanismo do
// Hash de dedup). O short_id vai DENTRO do payload assinado: sem isso, um
// cookie de um link serviria para outro.
func (c *Cipher) SignAccessToken(shortID string, expiresAt time.Time) string {
	payload := accessPayload(shortID, expiresAt.Unix())
	return payload + "." + c.Hash(payload)
}

// VerifyAccessToken valida assinatura, vínculo com o short_id e expiração.
// Qualquer divergência devolve ErrInvalidAccessToken — um token forjado é
// indistinguível de um expirado para quem chama.
func (c *Cipher) VerifyAccessToken(token, shortID string, now time.Time) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ErrInvalidAccessToken
	}

	payload := parts[0] + "." + parts[1]
	expected := c.Hash(payload)
	// Comparação em tempo constante: a normal vaza a assinatura por timing.
	if subtle.ConstantTimeCompare([]byte(parts[2]), []byte(expected)) != 1 {
		return ErrInvalidAccessToken
	}

	rawShortID, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || string(rawShortID) != shortID {
		return ErrInvalidAccessToken
	}

	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || now.Unix() >= exp {
		return ErrInvalidAccessToken
	}

	return nil
}

// accessPayload monta a parte assinada. O short_id vai em base64 url-safe
// para que nenhum caractere colida com o separador ".".
func accessPayload(shortID string, expUnix int64) string {
	return base64.RawURLEncoding.EncodeToString([]byte(shortID)) + "." + strconv.FormatInt(expUnix, 10)
}
