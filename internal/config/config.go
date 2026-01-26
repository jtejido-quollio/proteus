package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	HTTPAddr    string
	PostgresDSN string
	LogLevel    string

	AuthMode          string
	OIDCIssuerURL     string
	OIDCAudience      string
	OIDCJWKSURL       string
	OIDCClockSkewSecs int

	AdminAPIKey     string
	ProteusEnv      string
	KeyRotationDays int

	LogPrivateKeyBase64      string
	LogPrivateKeySeedHex     string
	SigningPrivateKeyBase64  string
	SigningPrivateKeySeedHex string

	VaultAddr  string
	VaultToken string

	AWSRegion                 string
	AWSAccessKeyID            string
	AWSSecretAccessKey        string
	AWSSessionToken           string
	AWSSecretsManagerEndpoint string
	GCPProjectID              string
	GCPAccessToken            string
	GCPSecretManagerEndpoint  string

	RateLimitRequests       int
	RateLimitWindowSeconds  int
	RateLimitIncludeSubject bool
	RateLimitFailClosed     bool
	RateLimitMaxKeys        int
	RateLimitSubjectMaxLen  int
	RateLimitSubjectHash    bool

	RedisAddr     string
	RedisPassword string
	RedisDB       int
}

func FromEnv() Config {
	addr := os.Getenv("HTTP_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	return Config{
		HTTPAddr:                  addr,
		PostgresDSN:               os.Getenv("POSTGRES_DSN"),
		LogLevel:                  envDefault("LOG_LEVEL", "info"),
		AuthMode:                  os.Getenv("AUTH_MODE"),
		OIDCIssuerURL:             os.Getenv("OIDC_ISSUER_URL"),
		OIDCAudience:              os.Getenv("OIDC_AUDIENCE"),
		OIDCJWKSURL:               os.Getenv("OIDC_JWKS_URL"),
		OIDCClockSkewSecs:         envIntDefault("OIDC_CLOCK_SKEW_SECONDS", 60),
		AdminAPIKey:               os.Getenv("ADMIN_API_KEY"),
		ProteusEnv:                os.Getenv("PROTEUS_ENV"),
		KeyRotationDays:           envIntDefault("KEY_ROTATION_DAYS", 90),
		LogPrivateKeyBase64:       os.Getenv("LOG_PRIVATE_KEY_BASE64"),
		LogPrivateKeySeedHex:      os.Getenv("LOG_PRIVATE_KEY_SEED_HEX"),
		SigningPrivateKeyBase64:   os.Getenv("SIGNING_PRIVATE_KEY_BASE64"),
		SigningPrivateKeySeedHex:  os.Getenv("SIGNING_PRIVATE_KEY_SEED_HEX"),
		VaultAddr:                 os.Getenv("VAULT_ADDR"),
		VaultToken:                os.Getenv("VAULT_TOKEN"),
		AWSRegion:                 os.Getenv("AWS_REGION"),
		AWSAccessKeyID:            os.Getenv("AWS_ACCESS_KEY_ID"),
		AWSSecretAccessKey:        os.Getenv("AWS_SECRET_ACCESS_KEY"),
		AWSSessionToken:           os.Getenv("AWS_SESSION_TOKEN"),
		AWSSecretsManagerEndpoint: os.Getenv("AWS_SECRETS_MANAGER_ENDPOINT"),
		GCPProjectID:              os.Getenv("GCP_PROJECT_ID"),
		GCPAccessToken:            os.Getenv("GCP_ACCESS_TOKEN"),
		GCPSecretManagerEndpoint:  os.Getenv("GCP_SECRET_MANAGER_ENDPOINT"),
		RateLimitRequests:         envIntDefault("RATE_LIMIT_REQUESTS", 0),
		RateLimitWindowSeconds:    envIntDefault("RATE_LIMIT_WINDOW_SECONDS", 60),
		RateLimitIncludeSubject:   envBoolDefault("RATE_LIMIT_INCLUDE_SUBJECT", false),
		RateLimitFailClosed:       envBoolDefault("RATE_LIMIT_FAIL_CLOSED", false),
		RateLimitMaxKeys:          envIntDefault("RATE_LIMIT_MAX_KEYS", 10000),
		RateLimitSubjectMaxLen:    envIntDefault("RATE_LIMIT_SUBJECT_MAX_LEN", 128),
		RateLimitSubjectHash:      envBoolDefault("RATE_LIMIT_SUBJECT_HASH", false),
		RedisAddr:                 os.Getenv("REDIS_ADDR"),
		RedisPassword:             os.Getenv("REDIS_PASSWORD"),
		RedisDB:                   envIntDefault("REDIS_DB", 0),
	}
}

func envDefault(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

func envIntDefault(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	parsed, err := strconv.Atoi(v)
	if err != nil || parsed <= 0 {
		return def
	}
	return parsed
}

func envBoolDefault(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	switch v {
	case "1", "true", "TRUE", "True", "yes", "YES", "Yes":
		return true
	case "0", "false", "FALSE", "False", "no", "NO", "No":
		return false
	default:
		return def
	}
}

func (c Config) KeyRotationInterval() time.Duration {
	if c.KeyRotationDays <= 0 {
		return 0
	}
	return time.Duration(c.KeyRotationDays) * 24 * time.Hour
}
