package core

import (
	"encoding/json"
	"example.com/pz10-auth/internal/platform/jwt"
	"github.com/go-chi/chi/v5"
	"net/http"
	"strconv"
)

type userRepo interface {
	CheckPassword(string, string) (User, error)
	ByID(int64) (User, error)
}
type tokens interface {
	NewPair(int64, string, string) (jwt.Pair, error)
	Rotate(string) (jwt.Pair, error)
}
type Service struct {
	repo userRepo
	jwt  tokens
}

func NewService(r userRepo, j tokens) *Service { return &Service{repo: r, jwt: j} }
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
	pair, e := s.jwt.NewPair(u.ID, u.Email, u.Role)
	if e != nil {
		fail(w, 500, "token_error")
		return
	}
	ok(w, pair)
}
func (s *Service) RefreshHandler(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Refresh string `json:"refresh"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.Refresh == "" {
		fail(w, 400, "refresh_required")
		return
	}
	pair, e := s.jwt.Rotate(in.Refresh)
	if e != nil {
		fail(w, 401, "invalid_refresh")
		return
	}
	ok(w, pair)
}
func (s *Service) MeHandler(w http.ResponseWriter, r *http.Request) {
	c := jwt.Claims(r)
	ok(w, map[string]any{"id": c["sub"], "email": c["email"], "role": c["role"]})
}
func (s *Service) AdminStats(w http.ResponseWriter, r *http.Request) {
	ok(w, map[string]any{"users": 2, "version": "1.0"})
}
func (s *Service) UserHandler(w http.ResponseWriter, r *http.Request) {
	id, e := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if e != nil || id <= 0 {
		fail(w, 400, "invalid_id")
		return
	}
	c := jwt.Claims(r)
	sub, _ := c.GetSubject()
	if c["role"] == "user" && sub != strconv.FormatInt(id, 10) {
		fail(w, 403, "forbidden")
		return
	}
	u, e := s.repo.ByID(id)
	if e != nil {
		fail(w, 404, "not_found")
		return
	}
	ok(w, u)
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
