package db

import (
	"fmt"
	"log"

	"proteus/internal/config"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Store struct {
	DB *gorm.DB
	// Repos will hang off this store in Phase 1.
}

func NewStore(cfg config.Config) (*Store, error) {
	if cfg.PostgresDSN == "" {
		log.Printf("POSTGRES_DSN not set; starting in no-db mode (Phase 0).")
		return &Store{DB: nil}, nil
	}

	gdb, err := gorm.Open(postgres.Open(cfg.PostgresDSN), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}

	return &Store{DB: gdb}, nil
}
