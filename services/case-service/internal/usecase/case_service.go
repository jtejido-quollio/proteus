package usecase

import (
	"context"
	"strings"
	"time"

	"proteus/case-service/internal/domain/cases"
)

type CaseService struct {
	Cases           CaseRepository
	Events          EventRepository
	Evidence        EvidenceRepository
	Projections     ProjectionRepository
	PolicySnapshots PolicySnapshotRepository
	Clock           func() time.Time
}

type Actor struct {
	Type string
	ID   string
}

type CreateCaseInput struct {
	TenantID      string
	SourceType    string
	SourceRefType cases.SourceRefType
	SourceRefRaw  string
	Severity      string
	QueueID       string
	RequestID     string
	Actor         Actor
}

type CaseView struct {
	Header   cases.CaseHeader
	Status   cases.CaseStatus
	Severity string
	QueueID  string
	OwnerID  string
	SLAState string
	SLADueAt *time.Time
}

type EvidenceInput struct {
	TenantID     string
	CaseID       string
	EvidenceType string
	EvidenceRef  string
	EvidenceHash string
	Metadata     map[string]any
	RequestID    string
	Actor        Actor
}

type CommentInput struct {
	TenantID  string
	CaseID    string
	Body      string
	RequestID string
	Actor     Actor
}

type AssignInput struct {
	TenantID     string
	CaseID       string
	AssigneeType string
	AssigneeID   string
	RequestID    string
	Actor        Actor
}

type HoldInput struct {
	TenantID  string
	CaseID    string
	Reason    string
	HoldType  string
	RequestID string
	Actor     Actor
}

type EscalateInput struct {
	TenantID  string
	CaseID    string
	FromQueue string
	ToQueue   string
	Reason    string
	RequestID string
	Actor     Actor
}

type DecideInput struct {
	TenantID         string
	CaseID           string
	Decision         string
	PolicySnapshotID string
	BundleHash       string
	EvaluatorVersion string
	Rationale        string
	RequestID        string
	Actor            Actor
}

type ReopenInput struct {
	TenantID  string
	CaseID    string
	Reason    string
	RequestID string
	Actor     Actor
}

type ExportInput struct {
	TenantID  string
	CaseID    string
	Format    string
	RequestID string
	Actor     Actor
}

func NewCaseService(cases CaseRepository, events EventRepository, evidence EvidenceRepository, projections ProjectionRepository, snapshots PolicySnapshotRepository) *CaseService {
	return &CaseService{
		Cases:           cases,
		Events:          events,
		Evidence:        evidence,
		Projections:     projections,
		PolicySnapshots: snapshots,
		Clock:           time.Now,
	}
}

func requireRequestID(requestID string) error {
	if strings.TrimSpace(requestID) == "" {
		return cases.ErrInvalidArgument
	}
	return nil
}

func (s *CaseService) CreateCase(ctx context.Context, input CreateCaseInput) (CaseView, bool, error) {
	if err := requireRequestID(input.RequestID); err != nil {
		return CaseView{}, false, err
	}
	canonical, err := cases.CanonicalizeSourceRef(input.SourceRefType, input.SourceRefRaw)
	if err != nil {
		return CaseView{}, false, cases.ErrInvalidArgument
	}
	sourceHash := cases.HashSourceRef(canonical)
	header := cases.CaseHeader{
		TenantID:      input.TenantID,
		SourceType:    input.SourceType,
		SourceRefType: input.SourceRefType,
		SourceRefHash: sourceHash,
		SourceRefRaw:  input.SourceRefRaw,
	}
	createdHeader, created, err := s.Cases.CreateCase(ctx, header)
	if err != nil {
		return CaseView{}, false, err
	}
	if created {
		payload := map[string]any{
			"source_type":     input.SourceType,
			"source_ref_type": input.SourceRefType,
			"source_ref_hash": sourceHash,
			"source_ref_raw":  input.SourceRefRaw,
			"severity":        input.Severity,
			"queue_id":        input.QueueID,
		}
		_, _, err = s.Events.Append(ctx, cases.CaseEvent{
			TenantID:  input.TenantID,
			CaseID:    createdHeader.ID,
			EventType: cases.EventCaseCreated,
			ActorType: input.Actor.Type,
			ActorID:   input.Actor.ID,
			RequestID: input.RequestID,
			Payload:   payload,
		})
		if err != nil {
			return CaseView{}, false, err
		}
	}
	view, err := s.GetCase(ctx, input.TenantID, createdHeader.ID)
	return view, created, err
}

func (s *CaseService) GetCase(ctx context.Context, tenantID, caseID string) (CaseView, error) {
	header, err := s.Cases.GetCase(ctx, tenantID, caseID)
	if err != nil {
		return CaseView{}, err
	}
	events, err := s.Events.ListByCase(ctx, tenantID, caseID)
	if err != nil {
		return CaseView{}, err
	}
	state := deriveStateFromEvents(tenantID, caseID, events)
	projection, projErr := s.Projections.GetCaseState(ctx, tenantID, caseID)
	if projErr != nil && projErr != cases.ErrNotFound {
		return CaseView{}, projErr
	}
	if projErr == nil {
		state.Severity = projection.Severity
		state.QueueID = projection.QueueID
		state.OwnerID = projection.OwnerID
		state.SLAState = projection.SLAState
		state.SLADueAt = projection.SLADueAt
	}
	return CaseView{
		Header:   header,
		Status:   state.Status,
		Severity: state.Severity,
		QueueID:  state.QueueID,
		OwnerID:  state.OwnerID,
		SLAState: state.SLAState,
		SLADueAt: state.SLADueAt,
	}, nil
}

func (s *CaseService) ListCases(ctx context.Context, filter CaseListFilter) ([]CaseListItem, string, error) {
	return s.Projections.ListCases(ctx, filter)
}

func (s *CaseService) ListQueueCases(ctx context.Context, filter QueueListFilter) ([]QueueCaseItem, string, error) {
	return s.Projections.ListQueueCases(ctx, filter)
}

func (s *CaseService) ListEvents(ctx context.Context, tenantID, caseID string) ([]cases.CaseEvent, error) {
	return s.Events.ListByCase(ctx, tenantID, caseID)
}

func (s *CaseService) AddEvidence(ctx context.Context, input EvidenceInput) error {
	if err := requireRequestID(input.RequestID); err != nil {
		return err
	}
	inserted, err := s.Evidence.Add(ctx, cases.EvidenceLink{
		TenantID:     input.TenantID,
		CaseID:       input.CaseID,
		EvidenceType: input.EvidenceType,
		EvidenceRef:  input.EvidenceRef,
		EvidenceHash: input.EvidenceHash,
		AddedBy:      input.Actor.ID,
		Metadata:     input.Metadata,
	})
	if err != nil {
		return err
	}
	if !inserted {
		return nil
	}
	payload := map[string]any{
		"evidence_type": input.EvidenceType,
		"evidence_ref":  input.EvidenceRef,
		"evidence_hash": input.EvidenceHash,
	}
	_, _, err = s.Events.Append(ctx, cases.CaseEvent{
		TenantID:  input.TenantID,
		CaseID:    input.CaseID,
		EventType: cases.EventEvidenceAdded,
		ActorType: input.Actor.Type,
		ActorID:   input.Actor.ID,
		RequestID: input.RequestID,
		Payload:   payload,
	})
	return err
}

func (s *CaseService) AddComment(ctx context.Context, input CommentInput) error {
	if err := requireRequestID(input.RequestID); err != nil {
		return err
	}
	payload := map[string]any{
		"body": input.Body,
	}
	_, _, err := s.Events.Append(ctx, cases.CaseEvent{
		TenantID:  input.TenantID,
		CaseID:    input.CaseID,
		EventType: cases.EventCommentAdded,
		ActorType: input.Actor.Type,
		ActorID:   input.Actor.ID,
		RequestID: input.RequestID,
		Payload:   payload,
	})
	return err
}

func (s *CaseService) Assign(ctx context.Context, input AssignInput) error {
	if err := requireRequestID(input.RequestID); err != nil {
		return err
	}
	payload := map[string]any{
		"assignee_type": input.AssigneeType,
		"assignee_id":   input.AssigneeID,
	}
	_, _, err := s.Events.Append(ctx, cases.CaseEvent{
		TenantID:  input.TenantID,
		CaseID:    input.CaseID,
		EventType: cases.EventAssigned,
		ActorType: input.Actor.Type,
		ActorID:   input.Actor.ID,
		RequestID: input.RequestID,
		Payload:   payload,
	})
	return err
}

func (s *CaseService) Unassign(ctx context.Context, tenantID, caseID, requestID string, actor Actor) error {
	if err := requireRequestID(requestID); err != nil {
		return err
	}
	_, _, err := s.Events.Append(ctx, cases.CaseEvent{
		TenantID:  tenantID,
		CaseID:    caseID,
		EventType: cases.EventUnassigned,
		ActorType: actor.Type,
		ActorID:   actor.ID,
		RequestID: requestID,
	})
	return err
}

func (s *CaseService) Hold(ctx context.Context, input HoldInput) error {
	if err := requireRequestID(input.RequestID); err != nil {
		return err
	}
	payload := map[string]any{
		"reason":    input.Reason,
		"hold_type": input.HoldType,
	}
	_, _, err := s.Events.Append(ctx, cases.CaseEvent{
		TenantID:  input.TenantID,
		CaseID:    input.CaseID,
		EventType: cases.EventHoldPlaced,
		ActorType: input.Actor.Type,
		ActorID:   input.Actor.ID,
		RequestID: input.RequestID,
		Payload:   payload,
	})
	return err
}

func (s *CaseService) Unhold(ctx context.Context, tenantID, caseID, requestID string, actor Actor) error {
	if err := requireRequestID(requestID); err != nil {
		return err
	}
	_, _, err := s.Events.Append(ctx, cases.CaseEvent{
		TenantID:  tenantID,
		CaseID:    caseID,
		EventType: cases.EventHoldReleased,
		ActorType: actor.Type,
		ActorID:   actor.ID,
		RequestID: requestID,
	})
	return err
}

func (s *CaseService) Escalate(ctx context.Context, input EscalateInput) error {
	if err := requireRequestID(input.RequestID); err != nil {
		return err
	}
	payload := map[string]any{
		"from_queue_id": input.FromQueue,
		"to_queue_id":   input.ToQueue,
		"reason":        input.Reason,
	}
	_, _, err := s.Events.Append(ctx, cases.CaseEvent{
		TenantID:  input.TenantID,
		CaseID:    input.CaseID,
		EventType: cases.EventEscalated,
		ActorType: input.Actor.Type,
		ActorID:   input.Actor.ID,
		RequestID: input.RequestID,
		Payload:   payload,
	})
	return err
}

func (s *CaseService) Deescalate(ctx context.Context, tenantID, caseID, requestID string, actor Actor) error {
	if err := requireRequestID(requestID); err != nil {
		return err
	}
	_, _, err := s.Events.Append(ctx, cases.CaseEvent{
		TenantID:  tenantID,
		CaseID:    caseID,
		EventType: cases.EventDeescalated,
		ActorType: actor.Type,
		ActorID:   actor.ID,
		RequestID: requestID,
	})
	return err
}

func (s *CaseService) Decide(ctx context.Context, input DecideInput) error {
	if err := requireRequestID(input.RequestID); err != nil {
		return err
	}
	if strings.TrimSpace(input.PolicySnapshotID) == "" {
		return cases.ErrInvalidArgument
	}
	if s.PolicySnapshots == nil {
		return cases.ErrInternal
	}
	if _, err := s.PolicySnapshots.Get(ctx, input.TenantID, input.PolicySnapshotID); err != nil {
		return err
	}
	payload := map[string]any{
		"decision":           input.Decision,
		"policy_snapshot_id": input.PolicySnapshotID,
		"bundle_hash":        input.BundleHash,
		"evaluator_version":  input.EvaluatorVersion,
		"rationale":          input.Rationale,
	}
	_, _, err := s.Events.Append(ctx, cases.CaseEvent{
		TenantID:  input.TenantID,
		CaseID:    input.CaseID,
		EventType: cases.EventDecided,
		ActorType: input.Actor.Type,
		ActorID:   input.Actor.ID,
		RequestID: input.RequestID,
		Payload:   payload,
	})
	return err
}

func (s *CaseService) Reopen(ctx context.Context, input ReopenInput) error {
	if err := requireRequestID(input.RequestID); err != nil {
		return err
	}
	payload := map[string]any{"reason": input.Reason}
	_, _, err := s.Events.Append(ctx, cases.CaseEvent{
		TenantID:  input.TenantID,
		CaseID:    input.CaseID,
		EventType: cases.EventReopened,
		ActorType: input.Actor.Type,
		ActorID:   input.Actor.ID,
		RequestID: input.RequestID,
		Payload:   payload,
	})
	return err
}

func (s *CaseService) Export(ctx context.Context, input ExportInput) error {
	if err := requireRequestID(input.RequestID); err != nil {
		return err
	}
	payload := map[string]any{"format": input.Format}
	_, _, err := s.Events.Append(ctx, cases.CaseEvent{
		TenantID:  input.TenantID,
		CaseID:    input.CaseID,
		EventType: cases.EventExportRequested,
		ActorType: input.Actor.Type,
		ActorID:   input.Actor.ID,
		RequestID: input.RequestID,
		Payload:   payload,
	})
	return err
}

func deriveStateFromEvents(tenantID, caseID string, events []cases.CaseEvent) cases.CaseStateProjection {
	state := cases.CaseStateProjection{
		TenantID: tenantID,
		CaseID:   caseID,
		Status:   cases.StatusQueued,
	}
	for _, ev := range events {
		switch ev.EventType {
		case cases.EventCaseCreated:
			state.Status = cases.StatusQueued
			if severity, ok := ev.Payload["severity"].(string); ok {
				state.Severity = severity
			}
			if queueID, ok := ev.Payload["queue_id"].(string); ok {
				state.QueueID = queueID
			}
		case cases.EventAssigned:
			state.Status = cases.StatusAssigned
			if ownerID, ok := ev.Payload["assignee_id"].(string); ok {
				state.OwnerID = ownerID
			}
		case cases.EventUnassigned:
			state.Status = cases.StatusQueued
			state.OwnerID = ""
		case cases.EventReviewStarted:
			state.Status = cases.StatusInReview
		case cases.EventHoldPlaced:
			state.Status = cases.StatusOnHold
		case cases.EventHoldReleased:
			state.Status = cases.StatusInReview
		case cases.EventEscalated:
			state.Status = cases.StatusEscalated
			if queueID, ok := ev.Payload["to_queue_id"].(string); ok {
				state.QueueID = queueID
			}
		case cases.EventDeescalated:
			state.Status = cases.StatusInReview
		case cases.EventDecided:
			state.Status = cases.StatusResolved
		case cases.EventClosed:
			state.Status = cases.StatusClosed
		case cases.EventReopened:
			state.Status = cases.StatusQueued
		}
	}
	return state
}
