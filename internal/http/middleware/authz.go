package middleware

import (
	"example.com/pz10-auth/internal/platform/jwt"
	"net/http"
)

func AuthZRoles(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role, _ := jwt.Claims(r)["role"].(string)
			for _, allow := range roles {
				if role == allow {
					next.ServeHTTP(w, r)
					return
				}
			}
			Error(w, 403, "forbidden")
		})
	}
}
