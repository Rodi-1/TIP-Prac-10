package router

import (
	"example.com/pz10-auth/internal/core"
	"example.com/pz10-auth/internal/http/middleware"
	"example.com/pz10-auth/internal/platform/config"
	"example.com/pz10-auth/internal/platform/jwt"
	"example.com/pz10-auth/internal/repo"
	"github.com/go-chi/chi/v5"
	"net/http"
)

func Build(cfg config.Config) http.Handler {
	r := chi.NewRouter()
	v := jwt.NewHS256(cfg.JWTSecret, cfg.JWTTTL)
	svc := core.NewService(repo.NewUserMem(), v)
	r.Post("/api/v1/login", svc.LoginHandler)
	r.Group(func(p chi.Router) {
		p.Use(middleware.AuthN(v))
		p.Use(middleware.AuthZRoles("user", "admin"))
		p.Get("/api/v1/me", svc.MeHandler)
	})
	r.Group(func(a chi.Router) {
		a.Use(middleware.AuthN(v))
		a.Use(middleware.AuthZRoles("admin"))
		a.Get("/api/v1/admin/stats", svc.AdminStats)
	})
	return r
}
