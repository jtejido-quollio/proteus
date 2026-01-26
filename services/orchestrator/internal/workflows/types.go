package workflows

import "time"

const (
	SignalAssign    = "assign"
	SignalHold      = "hold"
	SignalUnhold    = "unhold"
	SignalEscalate  = "escalate"
	SignalResolve   = "resolve"
	SignalComment   = "comment"
	EventAssigned   = "case.assigned"
	EventHoldPlaced = "case.hold_placed"
	EventHoldGone   = "case.hold_released"
	EventEscalated  = "case.escalated"
	EventResolved   = "case.resolved"
	EventCommented  = "case.comment_added"
	EventSLARemind  = "case.sla.reminder"
	EventSLABreach  = "case.sla.breached"
)

type SLAConfig struct {
	BreachAfter  time.Duration
	ReminderLead time.Duration
}

type CaseWorkflowInput struct {
	TenantID string
	CaseID   string
	QueueID  string
	Severity string
	SLA      SLAConfig
}

type AssignSignal struct {
	OwnerID   string
	RequestID string
}

type HoldSignal struct {
	HoldType  string
	Reason    string
	RequestID string
}

type UnholdSignal struct {
	Reason    string
	RequestID string
}

type EscalateSignal struct {
	FromQueueID string
	ToQueueID   string
	Reason      string
	RequestID   string
}

type ResolveSignal struct {
	Resolution string
	RequestID  string
}

type CommentSignal struct {
	Body      string
	RequestID string
}

func WorkflowID(tenantID, caseID string) string {
	return "case:" + tenantID + ":" + caseID
}
