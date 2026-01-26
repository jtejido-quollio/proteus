package config

import "os"

type Config struct {
	HTTPAddr    string
	PostgresDSN string
	AuthMode    string
	LogLevel    string
}

func FromEnv() Config {
	addr := os.Getenv("HTTP_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	return Config{
		HTTPAddr:    addr,
		PostgresDSN: os.Getenv("POSTGRES_DSN"),
		AuthMode:    os.Getenv("AUTH_MODE"),
		LogLevel:    envDefault("LOG_LEVEL", "info"),
	}
}

func envDefault(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}
