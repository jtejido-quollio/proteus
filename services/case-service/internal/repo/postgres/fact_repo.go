package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"proteus/case-service/internal/domain/cases"

	"github.com/jackc/pgx/v5/pgxpool"
)

type FactRepo struct {
	Pool *pgxpool.Pool
}

func NewFactRepo(pool *pgxpool.Pool) *FactRepo {
	return &FactRepo{Pool: pool}
}

func (r *FactRepo) InsertHold(ctx context.Context, hold cases.Hold) error {
	if r == nil || r.Pool == nil {
		return fmt.Errorf("db not configured")
	}
	query := `
INSERT INTO holds (tenant_id, case_id, hold_type, reason, status, placed_by, placed_at, released_at, release_reason, hold_until, request_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`
	_, err := r.Pool.Exec(ctx, query,
		hold.TenantID,
		hold.CaseID,
		hold.HoldType,
		hold.Reason,
		hold.Status,
		hold.PlacedBy,
		hold.PlacedAt,
		hold.ReleasedAt,
		hold.ReleaseReason,
		hold.HoldUntil,
		hold.RequestID,
	)
	return err
}

func (r *FactRepo) InsertEscalation(ctx context.Context, esc cases.Escalation) error {
	if r == nil || r.Pool == nil {
		return fmt.Errorf("db not configured")
	}
	query := `
INSERT INTO escalations (tenant_id, case_id, from_queue_id, to_queue_id, reason, status, escalated_by, escalated_at, resolved_at, request_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`
	_, err := r.Pool.Exec(ctx, query,
		esc.TenantID,
		esc.CaseID,
		esc.FromQueueID,
		esc.ToQueueID,
		esc.Reason,
		esc.Status,
		esc.EscalatedBy,
		esc.EscalatedAt,
		esc.ResolvedAt,
		esc.RequestID,
	)
	return err
}

func (r *FactRepo) InsertAssignment(ctx context.Context, asg cases.Assignment) error {
	if r == nil || r.Pool == nil {
		return fmt.Errorf("db not configured")
	}
	query := `
INSERT INTO assignments (tenant_id, case_id, assignee_type, assignee_id, status, assigned_by, assigned_at, unassigned_at, request_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	_, err := r.Pool.Exec(ctx, query,
		asg.TenantID,
		asg.CaseID,
		asg.AssigneeType,
		asg.AssigneeID,
		asg.Status,
		asg.AssignedBy,
		asg.AssignedAt,
		asg.UnassignedAt,
		asg.RequestID,
	)
	return err
}

func (r *FactRepo) InsertComment(ctx context.Context, comment cases.Comment) error {
	if r == nil || r.Pool == nil {
		return fmt.Errorf("db not configured")
	}
	query := `
INSERT INTO comments (tenant_id, case_id, author_type, author_id, body, created_at, request_id)
VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := r.Pool.Exec(ctx, query,
		comment.TenantID,
		comment.CaseID,
		comment.AuthorType,
		comment.AuthorID,
		comment.Body,
		comment.CreatedAt,
		comment.RequestID,
	)
	return err
}

func (r *FactRepo) InsertExport(ctx context.Context, export cases.Export) error {
	if r == nil || r.Pool == nil {
		return fmt.Errorf("db not configured")
	}
	metadata, err := json.Marshal(export.Metadata)
	if err != nil {
		return err
	}
	query := `
INSERT INTO exports (tenant_id, case_id, status, format, requested_by, requested_at, completed_at, export_uri, export_hash, error_code, metadata_json, request_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`
	_, err = r.Pool.Exec(ctx, query,
		export.TenantID,
		export.CaseID,
		export.Status,
		export.Format,
		export.RequestedBy,
		export.RequestedAt,
		export.CompletedAt,
		export.ExportURI,
		export.ExportHash,
		export.ErrorCode,
		metadata,
		export.RequestID,
	)
	return err
}
