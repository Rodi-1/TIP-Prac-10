package middleware

import (
	"net"
	"net/http"
	"sync"
	"time"
)

type attempt struct {
	count int
	until time.Time
}

func LoginLimit(limit int, window time.Duration) func(http.Handler) http.Handler {
	var mu sync.Mutex
	attempts := make(map[string]attempt)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip, _, e := net.SplitHostPort(r.RemoteAddr)
			if e != nil {
				ip = r.RemoteAddr
			}
			now := time.Now()
			mu.Lock()
			for k, v := range attempts {
				if !now.Before(v.until) {
					delete(attempts, k)
				}
			}
			v := attempts[ip]
			if v.until.IsZero() {
				v.until = now.Add(window)
			}
			if v.count >= limit {
				mu.Unlock()
				Error(w, 429, "too_many_attempts")
				return
			}
			v.count++
			attempts[ip] = v
			mu.Unlock()
			next.ServeHTTP(w, r)
		})
	}
}
