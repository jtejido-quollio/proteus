package activities

import (
	"context"
	"fmt"

	"proteus/api/clients/cases"

	"go.temporal.io/sdk/activity"
)

const (
	EmitCaseEventActivityName = "EmitCaseEvent"
	NotifyActivityName        = "Notify"
	TicketingActivityName     = "Ticketing"
)

type Activities struct {
	CaseClient *cases.Client
}

type EmitCaseEventInput struct {
	TenantID  string
	CaseID    string
	EventType string
	RequestID string
	Payload   map[string]any
}

type NotifyInput struct {
	TenantID string
	CaseID   string
	Message  string
}

type TicketingInput struct {
	TenantID string
	CaseID   string
	Target   string
}

func New(caseClient *cases.Client) *Activities {
	return &Activities{CaseClient: caseClient}
}

func (a *Activities) EmitCaseEvent(ctx context.Context, input EmitCaseEventInput) error {
	if a == nil || a.CaseClient == nil {
		return fmt.Errorf("case client not configured")
	}
	return a.CaseClient.EmitEvent(ctx, cases.EmitEventInput{
		TenantID:  input.TenantID,
		CaseID:    input.CaseID,
		EventType: input.EventType,
		RequestID: input.RequestID,
		Payload:   input.Payload,
	})
}

func (a *Activities) Notify(ctx context.Context, input NotifyInput) error {
	logger := activity.GetLogger(ctx)
	logger.Info("notify stub", "tenant_id", input.TenantID, "case_id", input.CaseID, "message", input.Message)
	return nil
}

func (a *Activities) Ticketing(ctx context.Context, input TicketingInput) error {
	logger := activity.GetLogger(ctx)
	logger.Info("ticketing stub", "tenant_id", input.TenantID, "case_id", input.CaseID, "target", input.Target)
	return nil
}
