package main

import (
	router "example.com/pz10-auth/internal/http"
	"example.com/pz10-auth/internal/platform/config"
	"log"
	"net/http"
)

func main() {
	cfg, e := config.Load()
	if e != nil {
		log.Fatal(e)
	}
	log.Println("listening on", cfg.Port)
	log.Fatal(http.ListenAndServe(cfg.Port, router.Build(cfg)))
}
