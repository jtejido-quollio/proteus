//go:build integration
// +build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"proteus/api/clients/cases"
	"proteus/orchestrator/internal/activities"
	"proteus/orchestrator/internal/workflows"

	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
)

type recordedEvent struct {
	CaseID    string
	EventType string
	RequestID string
}

func TestWorkflowIntegrationWithTemporal(t *testing.T) {
	temporalAddr := os.Getenv("TEMPORAL_ADDRESS")
	if temporalAddr == "" {
		temporalAddr = "localhost:7233"
	}

	var (
		mu     sync.Mutex
		events []recordedEvent
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		requestID := r.Header.Get("X-Request-ID")
		var payload struct {
			EventType string `json:"event_type"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		events = append(events, recordedEvent{CaseID: "case-1", EventType: payload.EventType, RequestID: requestID})
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	clientOptions := client.Options{HostPort: temporalAddr}
	c, err := client.NewClient(clientOptions)
	if err != nil {
		t.Skipf("temporal not available at %s: %v", temporalAddr, err)
	}
	defer c.Close()

	caseClient := cases.NewClient(server.URL, cases.WithPrincipal(cases.Principal{Subject: "orchestrator", Scopes: []string{"case:event"}}))
	acts := activities.New(caseClient)

	taskQueue := "case-orchestrator-integration"
	w := worker.New(c, taskQueue, worker.Options{})
	w.RegisterWorkflow(workflows.CaseWorkflow)
	w.RegisterActivityWithOptions(acts.EmitCaseEvent, activity.RegisterOptions{Name: activities.EmitCaseEventActivityName})
	w.RegisterActivityWithOptions(acts.Notify, activity.RegisterOptions{Name: activities.NotifyActivityName})
	w.RegisterActivityWithOptions(acts.Ticketing, activity.RegisterOptions{Name: activities.TicketingActivityName})

	if err := w.Start(); err != nil {
		t.Fatalf("start worker: %v", err)
	}
	defer w.Stop()

	workflowID := workflows.WorkflowID("tenant-1", "case-1") + ":integration"
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	we, err := c.ExecuteWorkflow(ctx, client.StartWorkflowOptions{ID: workflowID, TaskQueue: taskQueue}, workflows.CaseWorkflow, workflows.CaseWorkflowInput{
		TenantID: "tenant-1",
		CaseID:   "case-1",
		SLA: workflows.SLAConfig{
			BreachAfter:  10 * time.Hour,
			ReminderLead: 2 * time.Hour,
		},
	})
	if err != nil {
		t.Fatalf("start workflow: %v", err)
	}

	sigErr := c.SignalWorkflow(ctx, workflowID, we.GetRunID(), workflows.SignalResolve, workflows.ResolveSignal{Resolution: "done", RequestID: "req-resolve"})
	if sigErr != nil {
		t.Fatalf("signal workflow: %v", sigErr)
	}

	if err := we.Get(ctx, nil); err != nil {
		t.Fatalf("workflow run: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(events) == 0 {
		t.Fatalf("expected at least one event")
	}
	found := false
	for _, ev := range events {
		if ev.EventType == workflows.EventResolved && ev.RequestID == "req-resolve" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected resolved event with request id, got %+v", events)
	}
}
