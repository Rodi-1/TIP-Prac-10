package main

import (
	"example.com/pz10-auth/internal/platform/jwt"
	"log"
	"os"
)

func main() {
	dir := os.Getenv("JWT_KEY_DIR")
	if dir == "" {
		dir = ".keys"
	}
	if e := jwt.GenerateKeys(dir); e != nil {
		log.Fatal(e)
	}
	log.Println("two RSA key pairs ready in", dir)
}
