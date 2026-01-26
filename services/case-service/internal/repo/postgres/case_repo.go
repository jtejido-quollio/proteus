package postgres

import (
	"context"
	"fmt"
	"time"

	"proteus/case-service/internal/domain/cases"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type CaseRepo struct {
	Pool *pgxpool.Pool
}

func NewCaseRepo(pool *pgxpool.Pool) *CaseRepo {
	return &CaseRepo{Pool: pool}
}

func (r *CaseRepo) CreateCase(ctx context.Context, header cases.CaseHeader) (cases.CaseHeader, bool, error) {
	if r == nil || r.Pool == nil {
		return cases.CaseHeader{}, false, fmt.Errorf("db not configured")
	}
	query := `
INSERT INTO cases (tenant_id, source_type, source_ref_type, source_ref_hash, source_ref_raw)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (tenant_id, source_type, source_ref_hash) DO NOTHING
RETURNING id, created_at`
	row := r.Pool.QueryRow(ctx, query,
		header.TenantID,
		header.SourceType,
		string(header.SourceRefType),
		header.SourceRefHash,
		header.SourceRefRaw,
	)
	var id string
	var createdAt time.Time
	err := row.Scan(&id, &createdAt)
	if err == pgx.ErrNoRows {
		existing, err := r.GetCaseBySource(ctx, header.TenantID, header.SourceType, header.SourceRefHash)
		return existing, false, err
	}
	if err != nil {
		return cases.CaseHeader{}, false, err
	}
	header.ID = id
	header.CreatedAt = createdAt
	return header, true, nil
}

func (r *CaseRepo) GetCase(ctx context.Context, tenantID, caseID string) (cases.CaseHeader, error) {
	if r == nil || r.Pool == nil {
		return cases.CaseHeader{}, fmt.Errorf("db not configured")
	}
	query := `
SELECT id, tenant_id, source_type, source_ref_type, source_ref_hash, source_ref_raw, created_at
FROM cases
WHERE tenant_id = $1 AND id = $2`
	row := r.Pool.QueryRow(ctx, query, tenantID, caseID)
	var header cases.CaseHeader
	var refType string
	if err := row.Scan(
		&header.ID,
		&header.TenantID,
		&header.SourceType,
		&refType,
		&header.SourceRefHash,
		&header.SourceRefRaw,
		&header.CreatedAt,
	); err != nil {
		if err == pgx.ErrNoRows {
			return cases.CaseHeader{}, cases.ErrNotFound
		}
		return cases.CaseHeader{}, err
	}
	header.SourceRefType = cases.SourceRefType(refType)
	return header, nil
}

func (r *CaseRepo) GetCaseBySource(ctx context.Context, tenantID, sourceType, sourceRefHash string) (cases.CaseHeader, error) {
	if r == nil || r.Pool == nil {
		return cases.CaseHeader{}, fmt.Errorf("db not configured")
	}
	query := `
SELECT id, tenant_id, source_type, source_ref_type, source_ref_hash, source_ref_raw, created_at
FROM cases
WHERE tenant_id = $1 AND source_type = $2 AND source_ref_hash = $3`
	row := r.Pool.QueryRow(ctx, query, tenantID, sourceType, sourceRefHash)
	var header cases.CaseHeader
	var refType string
	if err := row.Scan(
		&header.ID,
		&header.TenantID,
		&header.SourceType,
		&refType,
		&header.SourceRefHash,
		&header.SourceRefRaw,
		&header.CreatedAt,
	); err != nil {
		if err == pgx.ErrNoRows {
			return cases.CaseHeader{}, cases.ErrNotFound
		}
		return cases.CaseHeader{}, err
	}
	header.SourceRefType = cases.SourceRefType(refType)
	return header, nil
}
