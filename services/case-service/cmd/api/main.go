package main

import (
	"log"

	"proteus/case-service/internal/config"
	httpapi "proteus/case-service/internal/http"
	"proteus/case-service/internal/repo/postgres"
)

func main() {
	cfg := config.FromEnv()
	store, err := postgres.NewStore(cfg)
	if err != nil {
		log.Fatalf("failed to init store: %v", err)
	}
	defer store.Close()

	srv := httpapi.NewServer(cfg, store)
	if err := srv.Run(); err != nil {
		log.Fatalf("server exited: %v", err)
	}
}
