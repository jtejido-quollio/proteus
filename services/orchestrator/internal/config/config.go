package config

import "os"

type Config struct {
	TemporalAddress    string
	TemporalNamespace  string
	TaskQueue          string
	CaseServiceBaseURL string
	ServiceSubject     string
	ServiceScopes      string
	HealthAddr         string
}

func FromEnv() Config {
	return Config{
		TemporalAddress:    envDefault("TEMPORAL_ADDRESS", "localhost:7233"),
		TemporalNamespace:  envDefault("TEMPORAL_NAMESPACE", "default"),
		TaskQueue:          envDefault("TEMPORAL_TASK_QUEUE", "case-orchestrator"),
		CaseServiceBaseURL: envDefault("CASE_SERVICE_BASE_URL", "http://localhost:8080"),
		ServiceSubject:     envDefault("ORCHESTRATOR_SUBJECT", "orchestrator"),
		ServiceScopes:      envDefault("ORCHESTRATOR_SCOPES", "case:event"),
		HealthAddr:         envDefault("HEALTH_ADDR", ":8090"),
	}
}

func envDefault(key, def string) string {
	value := os.Getenv(key)
	if value == "" {
		return def
	}
	return value
}
