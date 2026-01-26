package workflows

import (
	"context"
	"testing"
	"time"

	"proteus/orchestrator/internal/activities"

	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/testsuite"
)

func TestCaseWorkflowEmitsReminderAndBreach(t *testing.T) {
	suite := &testsuite.WorkflowTestSuite{}
	env := suite.NewTestWorkflowEnvironment()

	events := make([]string, 0)
	emit := func(_ context.Context, input activities.EmitCaseEventInput) error {
		events = append(events, input.EventType)
		return nil
	}
	env.RegisterActivityWithOptions(emit, activity.RegisterOptions{Name: activities.EmitCaseEventActivityName})
	env.RegisterActivityWithOptions(func(context.Context, activities.NotifyInput) error { return nil }, activity.RegisterOptions{Name: activities.NotifyActivityName})

	input := CaseWorkflowInput{
		TenantID: "tenant-1",
		CaseID:   "case-1",
		SLA: SLAConfig{
			BreachAfter:  2 * time.Hour,
			ReminderLead: 1 * time.Hour,
		},
	}

	env.RegisterDelayedCallback(func() {
		env.SignalWorkflow(SignalResolve, ResolveSignal{Resolution: "done", RequestID: "req-resolve"})
	}, 3*time.Hour)

	env.ExecuteWorkflow(CaseWorkflow, input)
	if !env.IsWorkflowCompleted() {
		t.Fatalf("workflow did not complete")
	}

	if !containsEvent(events, EventSLARemind) || !containsEvent(events, EventSLABreach) {
		t.Fatalf("expected reminder and breach events, got %v", events)
	}
}

func TestCaseWorkflowDedupesSignals(t *testing.T) {
	suite := &testsuite.WorkflowTestSuite{}
	env := suite.NewTestWorkflowEnvironment()

	assignedCount := 0
	emit := func(_ context.Context, input activities.EmitCaseEventInput) error {
		if input.EventType == EventAssigned {
			assignedCount++
		}
		return nil
	}
	env.RegisterActivityWithOptions(emit, activity.RegisterOptions{Name: activities.EmitCaseEventActivityName})
	env.RegisterActivityWithOptions(func(context.Context, activities.NotifyInput) error { return nil }, activity.RegisterOptions{Name: activities.NotifyActivityName})

	input := CaseWorkflowInput{
		TenantID: "tenant-1",
		CaseID:   "case-1",
		SLA: SLAConfig{
			BreachAfter:  10 * time.Hour,
			ReminderLead: 2 * time.Hour,
		},
	}

	env.RegisterDelayedCallback(func() {
		env.SignalWorkflow(SignalAssign, AssignSignal{OwnerID: "user-1", RequestID: "req-assign"})
	}, 5*time.Minute)
	env.RegisterDelayedCallback(func() {
		env.SignalWorkflow(SignalAssign, AssignSignal{OwnerID: "user-1", RequestID: "req-assign"})
	}, 10*time.Minute)
	env.RegisterDelayedCallback(func() {
		env.SignalWorkflow(SignalResolve, ResolveSignal{Resolution: "done", RequestID: "req-resolve"})
	}, 15*time.Minute)

	env.ExecuteWorkflow(CaseWorkflow, input)
	if assignedCount != 1 {
		t.Fatalf("expected 1 assigned event, got %d", assignedCount)
	}
}

func containsEvent(events []string, target string) bool {
	for _, ev := range events {
		if ev == target {
			return true
		}
	}
	return false
}
