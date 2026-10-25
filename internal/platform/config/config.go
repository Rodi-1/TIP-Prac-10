package config

import (
	"fmt"
	"os"
	"time"
)

type Config struct {
	Port, KeyDir, ActiveKID string
	JWTTTL, RefreshTTL      time.Duration
}

func Load() (Config, error) {
	c := Config{Port: os.Getenv("APP_PORT"), KeyDir: os.Getenv("JWT_KEY_DIR"), ActiveKID: os.Getenv("JWT_ACTIVE_KID")}
	if c.Port == "" {
		c.Port = "8080"
	}
	c.Port = ":" + c.Port
	if c.KeyDir == "" {
		c.KeyDir = ".keys"
	}
	if c.ActiveKID == "" {
		c.ActiveKID = "key2"
	}
	var e error
	c.JWTTTL, e = duration("JWT_TTL", 15*time.Minute)
	if e != nil {
		return c, e
	}
	c.RefreshTTL, e = duration("JWT_REFRESH_TTL", 7*24*time.Hour)
	if e != nil {
		return c, e
	}
	if c.RefreshTTL <= c.JWTTTL {
		return c, fmt.Errorf("refresh TTL must exceed access TTL")
	}
	return c, nil
}
func duration(key string, fallback time.Duration) (time.Duration, error) {
	s := os.Getenv(key)
	if s == "" {
		return fallback, nil
	}
	d, e := time.ParseDuration(s)
	if e != nil || d <= 0 {
		return 0, fmt.Errorf("invalid %s", key)
	}
	return d, nil
}
