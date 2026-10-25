package middleware

import (
	"log"
	"net/http"
	"time"
)

type response struct {
	http.ResponseWriter
	status int
}

func (w *response) WriteHeader(status int) { w.status = status; w.ResponseWriter.WriteHeader(status) }
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		out := &response{ResponseWriter: w, status: 200}
		next.ServeHTTP(out, r)
		log.Printf("method=%s path=%s status=%d elapsed=%s", r.Method, r.URL.Path, out.status, time.Since(start))
	})
}
