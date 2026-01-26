package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"proteus/api/clients/cases"
	"proteus/orchestrator/internal/activities"
	"proteus/orchestrator/internal/config"
	"proteus/orchestrator/internal/workflows"

	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
)

func main() {
	cfg := config.FromEnv()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	healthSrv := startHealthServer(cfg.HealthAddr)
	defer func() {
		_ = healthSrv.Shutdown(context.Background())
	}()

	temporalClient, err := client.NewClient(client.Options{
		HostPort:  cfg.TemporalAddress,
		Namespace: cfg.TemporalNamespace,
	})
	if err != nil {
		log.Fatalf("failed to create temporal client: %v", err)
	}
	defer temporalClient.Close()

	principal := cases.Principal{
		Subject: cfg.ServiceSubject,
		Scopes:  splitCSV(cfg.ServiceScopes),
	}
	caseClient := cases.NewClient(cfg.CaseServiceBaseURL, cases.WithPrincipal(principal))

	acts := activities.New(caseClient)
	workerOptions := worker.Options{}
	w := worker.New(temporalClient, cfg.TaskQueue, workerOptions)
	w.RegisterWorkflow(workflows.CaseWorkflow)
	w.RegisterActivityWithOptions(acts.EmitCaseEvent, activity.RegisterOptions{Name: activities.EmitCaseEventActivityName})
	w.RegisterActivityWithOptions(acts.Notify, activity.RegisterOptions{Name: activities.NotifyActivityName})
	w.RegisterActivityWithOptions(acts.Ticketing, activity.RegisterOptions{Name: activities.TicketingActivityName})

	go func() {
		<-ctx.Done()
		w.Stop()
	}()

	log.Printf("orchestrator worker listening on task queue %s", cfg.TaskQueue)
	if err := w.Run(worker.InterruptCh()); err != nil {
		log.Fatalf("worker exited: %v", err)
	}
}

func startHealthServer(addr string) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("health server error: %v", err)
		}
	}()
	return srv
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}
