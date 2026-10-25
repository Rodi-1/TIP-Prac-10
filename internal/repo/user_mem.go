package repo

import (
	"errors"
	"example.com/pz10-auth/internal/core"
	"golang.org/x/crypto/bcrypt"
	"strings"
)

type record struct {
	User core.User
	Hash []byte
}
type UserMem struct{ users map[string]record }

var ErrBadCredentials = errors.New("invalid credentials")

func NewUserMem() *UserMem {
	r := &UserMem{users: make(map[string]record)}
	for i, email := range []string{"admin@example.com", "user@example.com"} {
		hash, e := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.DefaultCost)
		if e != nil {
			panic(e)
		}
		role := "user"
		if i == 0 {
			role = "admin"
		}
		r.users[email] = record{User: core.User{ID: int64(i + 1), Email: email, Role: role}, Hash: hash}
	}
	return r
}
func (r *UserMem) CheckPassword(email, password string) (core.User, error) {
	u, ok := r.users[strings.ToLower(strings.TrimSpace(email))]
	if !ok || bcrypt.CompareHashAndPassword(u.Hash, []byte(password)) != nil {
		return core.User{}, ErrBadCredentials
	}
	return u.User, nil
}
