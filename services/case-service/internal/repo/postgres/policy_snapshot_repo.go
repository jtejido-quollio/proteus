package postgres

import (
	"context"
	"fmt"
	"time"

	"proteus/case-service/internal/domain/cases"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PolicySnapshotRepo struct {
	Pool *pgxpool.Pool
}

func NewPolicySnapshotRepo(pool *pgxpool.Pool) *PolicySnapshotRepo {
	return &PolicySnapshotRepo{Pool: pool}
}

func (r *PolicySnapshotRepo) Get(ctx context.Context, tenantID, snapshotID string) (cases.PolicySnapshot, error) {
	if r == nil || r.Pool == nil {
		return cases.PolicySnapshot{}, fmt.Errorf("db not configured")
	}
	query := `
SELECT id, tenant_id, bundle_id, bundle_hash, bundle_uri, activated_at, deactivated_at, actor_id, created_at
FROM case_policy_snapshots
WHERE tenant_id = $1 AND id = $2`
	row := r.Pool.QueryRow(ctx, query, tenantID, snapshotID)
	var snap cases.PolicySnapshot
	var deactivatedAt *time.Time
	if err := row.Scan(
		&snap.ID,
		&snap.TenantID,
		&snap.BundleID,
		&snap.BundleHash,
		&snap.BundleURI,
		&snap.ActivatedAt,
		&deactivatedAt,
		&snap.ActorID,
		&snap.CreatedAt,
	); err != nil {
		if err == pgx.ErrNoRows {
			return cases.PolicySnapshot{}, cases.ErrNotFound
		}
		return cases.PolicySnapshot{}, err
	}
	snap.DeactivatedAt = deactivatedAt
	return snap, nil
}
