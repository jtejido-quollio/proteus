package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"proteus/case-service/internal/domain/cases"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type EvidenceRepo struct {
	Pool *pgxpool.Pool
}

func NewEvidenceRepo(pool *pgxpool.Pool) *EvidenceRepo {
	return &EvidenceRepo{Pool: pool}
}

func (r *EvidenceRepo) Add(ctx context.Context, link cases.EvidenceLink) (bool, error) {
	if r == nil || r.Pool == nil {
		return false, fmt.Errorf("db not configured")
	}
	metadata, err := json.Marshal(link.Metadata)
	if err != nil {
		return false, err
	}
	query := `
INSERT INTO case_evidence_links (tenant_id, case_id, evidence_type, evidence_ref, evidence_hash, added_by, metadata_json)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (tenant_id, case_id, evidence_type, evidence_ref) DO NOTHING
RETURNING id, added_at`
	row := r.Pool.QueryRow(ctx, query,
		link.TenantID,
		link.CaseID,
		link.EvidenceType,
		link.EvidenceRef,
		link.EvidenceHash,
		link.AddedBy,
		metadata,
	)
	var id string
	var addedAt time.Time
	if err := row.Scan(&id, &addedAt); err != nil {
		if err == pgx.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	link.ID = id
	link.AddedAt = addedAt
	return true, nil
}

func (r *EvidenceRepo) ListByCase(ctx context.Context, tenantID, caseID string) ([]cases.EvidenceLink, error) {
	if r == nil || r.Pool == nil {
		return nil, fmt.Errorf("db not configured")
	}
	query := `
SELECT id, tenant_id, case_id, evidence_type, evidence_ref, evidence_hash, added_by, added_at, metadata_json
FROM case_evidence_links
WHERE tenant_id = $1 AND case_id = $2
ORDER BY added_at ASC, id ASC`
	rows, err := r.Pool.Query(ctx, query, tenantID, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []cases.EvidenceLink
	for rows.Next() {
		var link cases.EvidenceLink
		var metadataBytes []byte
		if err := rows.Scan(
			&link.ID,
			&link.TenantID,
			&link.CaseID,
			&link.EvidenceType,
			&link.EvidenceRef,
			&link.EvidenceHash,
			&link.AddedBy,
			&link.AddedAt,
			&metadataBytes,
		); err != nil {
			return nil, err
		}
		if len(metadataBytes) > 0 {
			_ = json.Unmarshal(metadataBytes, &link.Metadata)
		}
		out = append(out, link)
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	return out, nil
}
