package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	lib "github.com/golang-jwt/jwt/v5"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

type Validator interface {
	Parse(string) (lib.MapClaims, error)
}
type Pair struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
	Token   string `json:"token"`
}
type Manager struct {
	keys                  map[string]*rsa.PrivateKey
	active                string
	accessTTL, refreshTTL time.Duration
	mu                    sync.Mutex
	revoked               map[string]time.Time
}

func GenerateKeys(dir string) error {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	for _, kid := range []string{"key1", "key2"} {
		path := filepath.Join(dir, kid+".pem")
		if _, e := os.Stat(path); e == nil {
			continue
		}
		key, e := rsa.GenerateKey(rand.Reader, 2048)
		if e != nil {
			return e
		}
		if e = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600); e != nil {
			return e
		}
		if e = os.WriteFile(filepath.Join(dir, kid+".pub.pem"), pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey)}), 0644); e != nil {
			return e
		}
	}
	return nil
}
func NewManager(dir, active string, accessTTL, refreshTTL time.Duration) (*Manager, error) {
	m := &Manager{keys: make(map[string]*rsa.PrivateKey), active: active, accessTTL: accessTTL, refreshTTL: refreshTTL, revoked: make(map[string]time.Time)}
	for _, kid := range []string{"key1", "key2"} {
		data, e := os.ReadFile(filepath.Join(dir, kid+".pem"))
		if e != nil {
			return nil, e
		}
		key, e := lib.ParseRSAPrivateKeyFromPEM(data)
		if e != nil {
			return nil, e
		}
		m.keys[kid] = key
	}
	if m.keys[active] == nil {
		return nil, fmt.Errorf("unknown active kid")
	}
	return m, nil
}
func (m *Manager) sign(id int64, email, role, kind string, ttl time.Duration) (string, error) {
	idBytes := make([]byte, 16)
	if _, e := rand.Read(idBytes); e != nil {
		return "", e
	}
	now := time.Now()
	t := lib.NewWithClaims(lib.SigningMethodRS256, lib.MapClaims{"sub": strconv.FormatInt(id, 10), "email": email, "role": role, "kind": kind, "jti": hex.EncodeToString(idBytes), "iat": now.Unix(), "exp": now.Add(ttl).Unix(), "iss": "pz10-auth", "aud": "pz10-clients"})
	t.Header["kid"] = m.active
	return t.SignedString(m.keys[m.active])
}
func (m *Manager) NewPair(id int64, email, role string) (Pair, error) {
	a, e := m.sign(id, email, role, "access", m.accessTTL)
	if e != nil {
		return Pair{}, e
	}
	r, e := m.sign(id, email, role, "refresh", m.refreshTTL)
	return Pair{Access: a, Refresh: r, Token: a}, e
}
func (m *Manager) Parse(raw string) (lib.MapClaims, error) {
	t, e := lib.Parse(raw, func(t *lib.Token) (any, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok || m.keys[kid] == nil {
			return nil, fmt.Errorf("unknown kid")
		}
		return &m.keys[kid].PublicKey, nil
	}, lib.WithValidMethods([]string{"RS256"}), lib.WithIssuer("pz10-auth"), lib.WithAudience("pz10-clients"), lib.WithExpirationRequired())
	if e != nil {
		return nil, e
	}
	return t.Claims.(lib.MapClaims), nil
}
func (m *Manager) Rotate(raw string) (Pair, error) {
	c, e := m.Parse(raw)
	if e != nil || c["kind"] != "refresh" {
		return Pair{}, fmt.Errorf("invalid refresh")
	}
	jti, ok := c["jti"].(string)
	if !ok || jti == "" {
		return Pair{}, fmt.Errorf("missing jti")
	}
	exp, e := c.GetExpirationTime()
	if e != nil || exp == nil {
		return Pair{}, fmt.Errorf("missing expiration")
	}
	subject, e := c.GetSubject()
	if e != nil {
		return Pair{}, e
	}
	id, e := strconv.ParseInt(subject, 10, 64)
	if e != nil {
		return Pair{}, e
	}
	email, ok := c["email"].(string)
	if !ok {
		return Pair{}, fmt.Errorf("bad email")
	}
	role, ok := c["role"].(string)
	if !ok {
		return Pair{}, fmt.Errorf("bad role")
	}
	m.mu.Lock()
	for key, until := range m.revoked {
		if time.Now().After(until) {
			delete(m.revoked, key)
		}
	}
	if _, exists := m.revoked[jti]; exists {
		m.mu.Unlock()
		return Pair{}, fmt.Errorf("refresh revoked")
	}
	m.revoked[jti] = exp.Time
	m.mu.Unlock()
	return m.NewPair(id, email, role)
}

type claimsKey struct{}

func WithClaims(ctx context.Context, c lib.MapClaims) context.Context {
	return context.WithValue(ctx, claimsKey{}, c)
}
func Claims(r *http.Request) lib.MapClaims {
	c, _ := r.Context().Value(claimsKey{}).(lib.MapClaims)
	return c
}
