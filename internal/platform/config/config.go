package config

import (
	"fmt"
	"os"
	"time"
)

type Config struct {
	Port      string
	JWTSecret []byte
	JWTTTL    time.Duration
}

func Load() (Config, error) {
	port := os.Getenv("APP_PORT")
	if port == "" {
		port = "8080"
	}
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return Config{}, fmt.Errorf("JWT_SECRET is required")
	}
	ttl := os.Getenv("JWT_TTL")
	if ttl == "" {
		ttl = "15m"
	}
	duration, e := time.ParseDuration(ttl)
	if e != nil || duration <= 0 {
		return Config{}, fmt.Errorf("bad JWT_TTL")
	}
	return Config{Port: ":" + port, JWTSecret: []byte(secret), JWTTTL: duration}, nil
}
