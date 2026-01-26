package usecase

import (
	"context"
	"time"

	"proteus/case-service/internal/domain/cases"
)

type CaseRepository interface {
	CreateCase(ctx context.Context, header cases.CaseHeader) (cases.CaseHeader, bool, error)
	GetCase(ctx context.Context, tenantID, caseID string) (cases.CaseHeader, error)
	GetCaseBySource(ctx context.Context, tenantID, sourceType, sourceRefHash string) (cases.CaseHeader, error)
}

type EventRepository interface {
	Append(ctx context.Context, event cases.CaseEvent) (cases.CaseEvent, bool, error)
	ListByCase(ctx context.Context, tenantID, caseID string) ([]cases.CaseEvent, error)
}

type EvidenceRepository interface {
	Add(ctx context.Context, link cases.EvidenceLink) (bool, error)
	ListByCase(ctx context.Context, tenantID, caseID string) ([]cases.EvidenceLink, error)
}

type PolicySnapshotRepository interface {
	Get(ctx context.Context, tenantID, snapshotID string) (cases.PolicySnapshot, error)
}

type ProjectionRepository interface {
	GetCaseState(ctx context.Context, tenantID, caseID string) (cases.CaseStateProjection, error)
	ListCases(ctx context.Context, filter CaseListFilter) ([]CaseListItem, string, error)
	ListQueueCases(ctx context.Context, filter QueueListFilter) ([]QueueCaseItem, string, error)
}

type FactRepository interface {
	InsertHold(ctx context.Context, hold cases.Hold) error
	InsertEscalation(ctx context.Context, esc cases.Escalation) error
	InsertAssignment(ctx context.Context, asg cases.Assignment) error
	InsertComment(ctx context.Context, comment cases.Comment) error
	InsertExport(ctx context.Context, export cases.Export) error
}

type CaseListFilter struct {
	TenantID      string
	Status        string
	QueueID       string
	OwnerID       string
	Severity      string
	SLAState      string
	CreatedAfter  *time.Time
	CreatedBefore *time.Time
	Limit         int
	Cursor        string
}

type QueueListFilter struct {
	TenantID string
	QueueID  string
	Status   string
	Severity string
	OwnerID  string
	SLAState string
	Limit    int
	Cursor   string
}

type CaseListItem struct {
	CaseID    string
	TenantID  string
	Status    cases.CaseStatus
	Severity  string
	QueueID   string
	OwnerID   string
	SLAState  string
	SLADueAt  *time.Time
	CreatedAt time.Time
}

type QueueCaseItem struct {
	CaseID    string
	TenantID  string
	QueueID   string
	Status    cases.CaseStatus
	Severity  string
	OwnerID   string
	SLAState  string
	SLADueAt  *time.Time
	CreatedAt time.Time
}
