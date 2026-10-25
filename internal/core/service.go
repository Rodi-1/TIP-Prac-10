package core

import (
	"encoding/json"
	"example.com/pz10-auth/internal/platform/jwt"
	"net/http"
)

type userRepo interface {
	CheckPassword(string, string) (User, error)
}
type signer interface {
	Sign(int64, string, string) (string, error)
}
type Service struct {
	repo userRepo
	jwt  signer
}

func NewService(r userRepo, j signer) *Service { return &Service{repo: r, jwt: j} }
func (s *Service) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.Email == "" || in.Password == "" {
		fail(w, 400, "invalid_credentials")
		return
	}
	u, e := s.repo.CheckPassword(in.Email, in.Password)
	if e != nil {
		fail(w, 401, "invalid_credentials")
		return
	}
	token, e := s.jwt.Sign(u.ID, u.Email, u.Role)
	if e != nil {
		fail(w, 500, "token_error")
		return
	}
	ok(w, map[string]string{"token": token})
}
func (s *Service) MeHandler(w http.ResponseWriter, r *http.Request) {
	c := jwt.Claims(r)
	ok(w, map[string]any{"id": c["sub"], "email": c["email"], "role": c["role"]})
}
func (s *Service) AdminStats(w http.ResponseWriter, r *http.Request) {
	ok(w, map[string]any{"users": 2, "version": "1.0"})
}
func ok(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": message, "details": nil})
}
