package cases

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

type SourceRefType string

const (
	SourceRefSubjectHash  SourceRefType = "subject_hash"
	SourceRefArtifactHash SourceRefType = "artifact_hash"
	SourceRefManifestID   SourceRefType = "manifest_id"
	SourceRefReceiptID    SourceRefType = "receipt_id"
	SourceRefExternal     SourceRefType = "external_ticket"
)

type CaseStatus string

const (
	StatusQueued    CaseStatus = "queued"
	StatusAssigned  CaseStatus = "assigned"
	StatusInReview  CaseStatus = "in_review"
	StatusOnHold    CaseStatus = "on_hold"
	StatusEscalated CaseStatus = "escalated"
	StatusResolved  CaseStatus = "resolved"
	StatusClosed    CaseStatus = "closed"
)

type EventType string

const (
	EventCaseCreated       EventType = "case.created"
	EventEvidenceAdded     EventType = "case.evidence_added"
	EventEvidenceRedacted  EventType = "case.evidence_redacted"
	EventEvidenceAccessed  EventType = "case.evidence_accessed"
	EventCommentAdded      EventType = "case.comment_added"
	EventAssigned          EventType = "case.assigned"
	EventUnassigned        EventType = "case.unassigned"
	EventReviewStarted     EventType = "case.review_started"
	EventHoldPlaced        EventType = "case.hold_placed"
	EventHoldReleased      EventType = "case.hold_released"
	EventEscalated         EventType = "case.escalated"
	EventDeescalated       EventType = "case.deescalated"
	EventDecided           EventType = "case.decided"
	EventReopened          EventType = "case.reopened"
	EventClosed            EventType = "case.closed"
	EventSLAReminder       EventType = "case.sla.reminder"
	EventSLABreached       EventType = "case.sla.breached"
	EventAssignmentExpired EventType = "case.assignment_expired"
	EventAutoEscalated     EventType = "case.auto_escalated"
	EventExportRequested   EventType = "case.export_requested"
	EventExportCompleted   EventType = "case.export_completed"
	EventExportFailed      EventType = "case.export_failed"
)

type Principal struct {
	Subject  string
	TenantID string
	Scopes   []string
	Roles    []string
}

type Authorizer interface {
	Require(principal Principal, tenantID string, permission string) error
}

type CaseHeader struct {
	ID            string
	TenantID      string
	SourceType    string
	SourceRefType SourceRefType
	SourceRefHash string
	SourceRefRaw  string
	CreatedAt     time.Time
}

type CaseEvent struct {
	ID        string
	TenantID  string
	CaseID    string
	EventType EventType
	ActorType string
	ActorID   string
	RequestID string
	CreatedAt time.Time
	Payload   map[string]any
}

type EvidenceLink struct {
	ID           string
	TenantID     string
	CaseID       string
	EvidenceType string
	EvidenceRef  string
	EvidenceHash string
	AddedBy      string
	AddedAt      time.Time
	Metadata     map[string]any
}

type PolicySnapshot struct {
	ID            string
	TenantID      string
	BundleID      string
	BundleHash    string
	BundleURI     string
	ActivatedAt   time.Time
	DeactivatedAt *time.Time
	ActorID       string
	CreatedAt     time.Time
}

type CaseStateProjection struct {
	CaseID            string
	TenantID          string
	Status            CaseStatus
	Severity          string
	QueueID           string
	OwnerType         string
	OwnerID           string
	SLAID             string
	SLAState          string
	SLADueAt          *time.Time
	UpdatedAt         time.Time
	ProjectionVersion int64
}

type CaseQueueProjection struct {
	CaseID            string
	TenantID          string
	QueueID           string
	Status            CaseStatus
	Severity          string
	OwnerID           string
	SLAState          string
	SLADueAt          *time.Time
	CaseCreatedAt     time.Time
	UpdatedAt         time.Time
	ProjectionVersion int64
}

type Hold struct {
	ID            string
	TenantID      string
	CaseID        string
	HoldType      string
	Reason        string
	Status        string
	PlacedBy      string
	PlacedAt      time.Time
	ReleasedAt    *time.Time
	ReleaseReason string
	HoldUntil     *time.Time
	RequestID     string
}

type Escalation struct {
	ID          string
	TenantID    string
	CaseID      string
	FromQueueID string
	ToQueueID   string
	Reason      string
	Status      string
	EscalatedBy string
	EscalatedAt time.Time
	ResolvedAt  *time.Time
	RequestID   string
}

type Assignment struct {
	ID           string
	TenantID     string
	CaseID       string
	AssigneeType string
	AssigneeID   string
	Status       string
	AssignedBy   string
	AssignedAt   time.Time
	UnassignedAt *time.Time
	RequestID    string
}

type Comment struct {
	ID         string
	TenantID   string
	CaseID     string
	AuthorType string
	AuthorID   string
	Body       string
	CreatedAt  time.Time
	RequestID  string
}

type Export struct {
	ID          string
	TenantID    string
	CaseID      string
	Status      string
	Format      string
	RequestedBy string
	RequestedAt time.Time
	CompletedAt *time.Time
	ExportURI   string
	ExportHash  string
	ErrorCode   string
	Metadata    map[string]any
	RequestID   string
}

var (
	ErrUnauthorized    = errors.New("unauthorized")
	ErrForbidden       = errors.New("forbidden")
	ErrNotFound        = errors.New("not found")
	ErrConflict        = errors.New("conflict")
	ErrInvalidArgument = errors.New("invalid argument")
	ErrInternal        = errors.New("internal error")
)

func CanonicalizeSourceRef(refType SourceRefType, raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", ErrInvalidArgument
	}
	switch refType {
	case SourceRefSubjectHash, SourceRefArtifactHash:
		canonical := strings.ToLower(trimmed)
		if len(canonical) != 64 || !isHex(canonical) {
			return "", ErrInvalidArgument
		}
		return canonical, nil
	case SourceRefManifestID:
		canonical := strings.ToLower(trimmed)
		if _, err := uuid.Parse(canonical); err != nil {
			return "", ErrInvalidArgument
		}
		return canonical, nil
	case SourceRefReceiptID:
		return strings.ToLower(trimmed), nil
	case SourceRefExternal:
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) != 2 {
			return "", ErrInvalidArgument
		}
		vendor := strings.ToLower(strings.TrimSpace(parts[0]))
		ref := strings.ToLower(strings.TrimSpace(parts[1]))
		if vendor == "" || ref == "" {
			return "", ErrInvalidArgument
		}
		return vendor + ":" + ref, nil
	default:
		return "", ErrInvalidArgument
	}
}

func HashSourceRef(canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

func DeriveStatus(events []CaseEvent) CaseStatus {
	status := StatusQueued
	for _, ev := range events {
		switch ev.EventType {
		case EventCaseCreated:
			status = StatusQueued
		case EventAssigned:
			status = StatusAssigned
		case EventReviewStarted:
			status = StatusInReview
		case EventHoldPlaced:
			status = StatusOnHold
		case EventHoldReleased:
			status = StatusInReview
		case EventEscalated:
			status = StatusEscalated
		case EventDeescalated:
			status = StatusInReview
		case EventDecided:
			status = StatusResolved
		case EventClosed:
			status = StatusClosed
		case EventReopened:
			status = StatusQueued
		}
	}
	return status
}

func isHex(value string) bool {
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
