package middleware

import (
	"encoding/json"
	"example.com/pz10-auth/internal/platform/jwt"
	"net/http"
	"strings"
)

func Error(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": message, "details": nil})
}
func AuthN(v jwt.Validator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			parts := strings.Fields(r.Header.Get("Authorization"))
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
				Error(w, 401, "unauthorized")
				return
			}
			c, e := v.Parse(parts[1])
			if e != nil {
				Error(w, 401, "unauthorized")
				return
			}
			next.ServeHTTP(w, r.WithContext(jwt.WithClaims(r.Context(), c)))
		})
	}
}
