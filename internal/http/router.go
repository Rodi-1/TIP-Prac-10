package router

import (
	"example.com/pz10-auth/internal/core"
	"example.com/pz10-auth/internal/http/middleware"
	"example.com/pz10-auth/internal/platform/config"
	"example.com/pz10-auth/internal/platform/jwt"
	"example.com/pz10-auth/internal/repo"
	"fmt"
	"github.com/go-chi/chi/v5"
	"net/http"
	"time"
)

func Build(cfg config.Config) (http.Handler, error) {
	r := chi.NewRouter()
	v, e := jwt.NewManager(cfg.KeyDir, cfg.ActiveKID, cfg.JWTTTL, cfg.RefreshTTL)
	if e != nil {
		return nil, fmt.Errorf("keys: %w (run go run ./cmd/keygen)", e)
	}
	svc := core.NewService(repo.NewUserMem(), v)
	r.Use(middleware.Logging)
	r.NotFound(func(w http.ResponseWriter, r *http.Request) { middleware.Error(w, 404, "not_found") })
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) { middleware.Error(w, 405, "method_not_allowed") })
	r.With(middleware.LoginLimit(5, 5*time.Minute)).Post("/api/v1/login", svc.LoginHandler)
	r.Post("/api/v1/refresh", svc.RefreshHandler)
	r.Group(func(p chi.Router) {
		p.Use(middleware.AuthN(v))
		p.Use(middleware.AuthZRoles("user", "admin"))
		p.Get("/api/v1/me", svc.MeHandler)
		p.Get("/api/v1/users/{id}", svc.UserHandler)
	})
	r.Group(func(a chi.Router) {
		a.Use(middleware.AuthN(v))
		a.Use(middleware.AuthZRoles("admin"))
		a.Get("/api/v1/admin/stats", svc.AdminStats)
	})
	return r, nil
}
