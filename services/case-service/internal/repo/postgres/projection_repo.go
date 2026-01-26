package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"proteus/case-service/internal/domain/cases"
	"proteus/case-service/internal/usecase"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ProjectionRepo struct {
	Pool *pgxpool.Pool
}

func NewProjectionRepo(pool *pgxpool.Pool) *ProjectionRepo {
	return &ProjectionRepo{Pool: pool}
}

func (r *ProjectionRepo) GetCaseState(ctx context.Context, tenantID, caseID string) (cases.CaseStateProjection, error) {
	if r == nil || r.Pool == nil {
		return cases.CaseStateProjection{}, fmt.Errorf("db not configured")
	}
	query := `
SELECT case_id, tenant_id, status, severity, queue_id, owner_type, owner_id, sla_id, sla_state, sla_due_at, updated_at, projection_version
FROM case_state_projection
WHERE tenant_id = $1 AND case_id = $2`
	row := r.Pool.QueryRow(ctx, query, tenantID, caseID)
	var state cases.CaseStateProjection
	var status string
	var queueID *string
	var ownerType *string
	var ownerID *string
	var slaID *string
	var slaState string
	var slaDueAt *time.Time
	if err := row.Scan(
		&state.CaseID,
		&state.TenantID,
		&status,
		&state.Severity,
		&queueID,
		&ownerType,
		&ownerID,
		&slaID,
		&slaState,
		&slaDueAt,
		&state.UpdatedAt,
		&state.ProjectionVersion,
	); err != nil {
		if err == pgx.ErrNoRows {
			return cases.CaseStateProjection{}, cases.ErrNotFound
		}
		return cases.CaseStateProjection{}, err
	}
	state.Status = cases.CaseStatus(status)
	if queueID != nil {
		state.QueueID = *queueID
	}
	if ownerType != nil {
		state.OwnerType = *ownerType
	}
	if ownerID != nil {
		state.OwnerID = *ownerID
	}
	if slaID != nil {
		state.SLAID = *slaID
	}
	state.SLAState = slaState
	state.SLADueAt = slaDueAt
	return state, nil
}

func (r *ProjectionRepo) ListCases(ctx context.Context, filter usecase.CaseListFilter) ([]usecase.CaseListItem, string, error) {
	if r == nil || r.Pool == nil {
		return nil, "", fmt.Errorf("db not configured")
	}
	limit := normalizeLimit(filter.Limit)
	args := []any{filter.TenantID}
	where := []string{"p.tenant_id = $1"}
	if filter.Status != "" {
		args = append(args, filter.Status)
		where = append(where, fmt.Sprintf("p.status = $%d", len(args)))
	}
	if filter.QueueID != "" {
		args = append(args, filter.QueueID)
		where = append(where, fmt.Sprintf("p.queue_id = $%d", len(args)))
	}
	if filter.OwnerID != "" {
		args = append(args, filter.OwnerID)
		where = append(where, fmt.Sprintf("p.owner_id = $%d", len(args)))
	}
	if filter.Severity != "" {
		args = append(args, filter.Severity)
		where = append(where, fmt.Sprintf("p.severity = $%d", len(args)))
	}
	if filter.SLAState != "" {
		args = append(args, filter.SLAState)
		where = append(where, fmt.Sprintf("p.sla_state = $%d", len(args)))
	}
	if filter.CreatedAfter != nil {
		args = append(args, *filter.CreatedAfter)
		where = append(where, fmt.Sprintf("c.created_at >= $%d", len(args)))
	}
	if filter.CreatedBefore != nil {
		args = append(args, *filter.CreatedBefore)
		where = append(where, fmt.Sprintf("c.created_at <= $%d", len(args)))
	}
	if filter.Cursor != "" {
		cursorTime, cursorID, err := decodeCursor(filter.Cursor)
		if err != nil {
			return nil, "", cases.ErrInvalidArgument
		}
		args = append(args, cursorTime, cursorID)
		where = append(where, fmt.Sprintf("(c.created_at, p.case_id) < ($%d, $%d)", len(args)-1, len(args)))
	}
	query := fmt.Sprintf(`
SELECT p.case_id, p.tenant_id, p.status, p.severity, p.queue_id, p.owner_id, p.sla_state, p.sla_due_at, c.created_at
FROM case_state_projection p
JOIN cases c ON c.id = p.case_id AND c.tenant_id = p.tenant_id
WHERE %s
ORDER BY c.created_at DESC, p.case_id DESC
LIMIT %d`, strings.Join(where, " AND "), limit+1)
	rows, err := r.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	items := make([]usecase.CaseListItem, 0, limit)
	for rows.Next() {
		var item usecase.CaseListItem
		var status string
		var queueID *string
		var ownerID *string
		var slaState string
		var slaDueAt *time.Time
		if err := rows.Scan(
			&item.CaseID,
			&item.TenantID,
			&status,
			&item.Severity,
			&queueID,
			&ownerID,
			&slaState,
			&slaDueAt,
			&item.CreatedAt,
		); err != nil {
			return nil, "", err
		}
		item.Status = cases.CaseStatus(status)
		if queueID != nil {
			item.QueueID = *queueID
		}
		if ownerID != nil {
			item.OwnerID = *ownerID
		}
		item.SLAState = slaState
		item.SLADueAt = slaDueAt
		items = append(items, item)
	}
	if rows.Err() != nil {
		return nil, "", rows.Err()
	}
	if len(items) > limit {
		last := items[limit-1]
		return items[:limit], encodeCursor(last.CreatedAt, last.CaseID), nil
	}
	return items, "", nil
}

func (r *ProjectionRepo) ListQueueCases(ctx context.Context, filter usecase.QueueListFilter) ([]usecase.QueueCaseItem, string, error) {
	if r == nil || r.Pool == nil {
		return nil, "", fmt.Errorf("db not configured")
	}
	limit := normalizeLimit(filter.Limit)
	args := []any{filter.TenantID, filter.QueueID}
	where := []string{"q.tenant_id = $1", "q.queue_id = $2"}
	if filter.Status != "" {
		args = append(args, filter.Status)
		where = append(where, fmt.Sprintf("q.status = $%d", len(args)))
	}
	if filter.OwnerID != "" {
		args = append(args, filter.OwnerID)
		where = append(where, fmt.Sprintf("q.owner_id = $%d", len(args)))
	}
	if filter.Severity != "" {
		args = append(args, filter.Severity)
		where = append(where, fmt.Sprintf("q.severity = $%d", len(args)))
	}
	if filter.SLAState != "" {
		args = append(args, filter.SLAState)
		where = append(where, fmt.Sprintf("q.sla_state = $%d", len(args)))
	}
	if filter.Cursor != "" {
		cursorTime, cursorID, err := decodeCursor(filter.Cursor)
		if err != nil {
			return nil, "", cases.ErrInvalidArgument
		}
		args = append(args, cursorTime, cursorID)
		where = append(where, fmt.Sprintf("(q.case_created_at, q.case_id) < ($%d, $%d)", len(args)-1, len(args)))
	}
	query := fmt.Sprintf(`
SELECT q.case_id, q.tenant_id, q.queue_id, q.status, q.severity, q.owner_id, q.sla_state, q.sla_due_at, q.case_created_at
FROM case_queue_projection q
WHERE %s
ORDER BY q.case_created_at DESC, q.case_id DESC
LIMIT %d`, strings.Join(where, " AND "), limit+1)
	rows, err := r.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	items := make([]usecase.QueueCaseItem, 0, limit)
	for rows.Next() {
		var item usecase.QueueCaseItem
		var status string
		var ownerID *string
		var slaState string
		var slaDueAt *time.Time
		if err := rows.Scan(
			&item.CaseID,
			&item.TenantID,
			&item.QueueID,
			&status,
			&item.Severity,
			&ownerID,
			&slaState,
			&slaDueAt,
			&item.CreatedAt,
		); err != nil {
			return nil, "", err
		}
		item.Status = cases.CaseStatus(status)
		if ownerID != nil {
			item.OwnerID = *ownerID
		}
		item.SLAState = slaState
		item.SLADueAt = slaDueAt
		items = append(items, item)
	}
	if rows.Err() != nil {
		return nil, "", rows.Err()
	}
	if len(items) > limit {
		last := items[limit-1]
		return items[:limit], encodeCursor(last.CreatedAt, last.CaseID), nil
	}
	return items, "", nil
}

func normalizeLimit(limit int) int {
	if limit <= 0 {
		return 50
	}
	if limit > 200 {
		return 200
	}
	return limit
}

func encodeCursor(createdAt time.Time, caseID string) string {
	return createdAt.UTC().Format(time.RFC3339Nano) + "|" + caseID
}

func decodeCursor(cursor string) (time.Time, string, error) {
	parts := strings.SplitN(cursor, "|", 2)
	if len(parts) != 2 {
		return time.Time{}, "", fmt.Errorf("invalid cursor")
	}
	parsed, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return time.Time{}, "", err
	}
	if parts[1] == "" {
		return time.Time{}, "", fmt.Errorf("invalid cursor")
	}
	return parsed, parts[1], nil
}
