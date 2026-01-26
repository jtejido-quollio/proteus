package postgres

import (
	"testing"

	"proteus/case-service/internal/config"
)

func TestNewStoreRequiresDSN(t *testing.T) {
	_, err := NewStore(config.Config{})
	if err == nil {
		t.Fatalf("expected error for missing POSTGRES_DSN")
	}
}
