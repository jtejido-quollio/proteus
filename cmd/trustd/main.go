package main

import (
	"log"

	"proteus/internal/config"
	"proteus/internal/infra/db"
	httpinfra "proteus/internal/infra/http"
)

func main() {
	cfg := config.FromEnv()

	store, err := db.NewStore(cfg)
	if err != nil {
		log.Fatalf("failed to init store: %v", err)
	}

	srv := httpinfra.NewServer(cfg, store)
	if err := srv.Run(); err != nil {
		log.Fatalf("server exited: %v", err)
	}
}
