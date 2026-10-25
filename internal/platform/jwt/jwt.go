package jwt

import (
	"context"
	lib "github.com/golang-jwt/jwt/v5"
	"net/http"
	"strconv"
	"time"
)

type Validator interface {
	Sign(int64, string, string) (string, error)
	Parse(string) (lib.MapClaims, error)
}
type HS256 struct {
	secret []byte
	ttl    time.Duration
}

func NewHS256(secret []byte, ttl time.Duration) *HS256 { return &HS256{secret: secret, ttl: ttl} }
func (h *HS256) Sign(id int64, email, role string) (string, error) {
	now := time.Now()
	return lib.NewWithClaims(lib.SigningMethodHS256, lib.MapClaims{"sub": strconv.FormatInt(id, 10), "email": email, "role": role, "iat": now.Unix(), "exp": now.Add(h.ttl).Unix(), "iss": "pz10-auth", "aud": "pz10-clients"}).SignedString(h.secret)
}
func (h *HS256) Parse(raw string) (lib.MapClaims, error) {
	t, e := lib.Parse(raw, func(t *lib.Token) (any, error) { return h.secret, nil }, lib.WithValidMethods([]string{"HS256"}), lib.WithIssuer("pz10-auth"), lib.WithAudience("pz10-clients"), lib.WithExpirationRequired())
	if e != nil {
		return nil, e
	}
	return t.Claims.(lib.MapClaims), nil
}

type claimsKey struct{}

func WithClaims(ctx context.Context, c lib.MapClaims) context.Context {
	return context.WithValue(ctx, claimsKey{}, c)
}
func Claims(r *http.Request) lib.MapClaims {
	c, _ := r.Context().Value(claimsKey{}).(lib.MapClaims)
	return c
}
