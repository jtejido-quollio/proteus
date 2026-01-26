package testdb

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const defaultDSN = "postgres://proteus:proteus@localhost:5432/proteus?sslmode=disable"

func NewDatabase(t *testing.T) (*pgxpool.Pool, func()) {
	t.Helper()
	adminDSN := os.Getenv("POSTGRES_ADMIN_DSN")
	baseDSN := os.Getenv("POSTGRES_DSN")
	if baseDSN == "" {
		baseDSN = defaultDSN
	}
	if adminDSN == "" {
		adminDSN = withDatabase(baseDSN, "postgres")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	adminConn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect admin db: %v", err)
	}

	dbName := "case_service_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := adminConn.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{dbName}.Sanitize()); err != nil {
		t.Fatalf("create database: %v", err)
	}

	pool, err := pgxpool.New(ctx, withDatabase(baseDSN, dbName))
	if err != nil {
		_ = dropDatabase(ctx, adminConn, dbName)
		t.Fatalf("connect test db: %v", err)
	}

	applyMigrations(t, pool)

	cleanup := func() {
		pool.Close()
		_ = dropDatabase(context.Background(), adminConn, dbName)
		_ = adminConn.Close(context.Background())
	}
	return pool, cleanup
}

func applyMigrations(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	migrationsDir := trustdMigrationsDir(t)
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		files = append(files, filepath.Join(migrationsDir, entry.Name()))
	}
	sort.Strings(files)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, file := range files {
		payload, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read migration %s: %v", file, err)
		}
		if len(strings.TrimSpace(string(payload))) == 0 {
			continue
		}
		if _, err := pool.Exec(ctx, string(payload)); err != nil {
			t.Fatalf("apply migration %s: %v", file, err)
		}
	}
}

func trustdMigrationsDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("resolve testdb path")
	}
	base := filepath.Dir(filename)
	path := filepath.Clean(filepath.Join(base, "..", "..", "..", "..", "..", "trustd", "migrations"))
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("migrations dir not found: %v", err)
	}
	return path
}

func withDatabase(dsn string, dbName string) string {
	parsed, err := url.Parse(dsn)
	if err != nil {
		return dsn
	}
	parsed.Path = "/" + dbName
	return parsed.String()
}

func dropDatabase(ctx context.Context, conn *pgx.Conn, name string) error {
	_, err := conn.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize())
	return err
}
