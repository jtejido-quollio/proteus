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

type EventRepo struct {
	Pool *pgxpool.Pool
}

func NewEventRepo(pool *pgxpool.Pool) *EventRepo {
	return &EventRepo{Pool: pool}
}

func (r *EventRepo) Append(ctx context.Context, event cases.CaseEvent) (cases.CaseEvent, bool, error) {
	if r == nil || r.Pool == nil {
		return cases.CaseEvent{}, false, fmt.Errorf("db not configured")
	}
	payload, err := json.Marshal(event.Payload)
	if err != nil {
		return cases.CaseEvent{}, false, err
	}
	query := `
INSERT INTO case_events (tenant_id, case_id, event_type, actor_type, actor_id, request_id, payload_json)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (tenant_id, case_id, request_id) DO NOTHING
RETURNING id, created_at`
	row := r.Pool.QueryRow(ctx, query,
		event.TenantID,
		event.CaseID,
		string(event.EventType),
		event.ActorType,
		event.ActorID,
		event.RequestID,
		payload,
	)
	var id string
	var createdAt time.Time
	if err := row.Scan(&id, &createdAt); err != nil {
		if err == pgx.ErrNoRows {
			return cases.CaseEvent{}, false, nil
		}
		return cases.CaseEvent{}, false, err
	}
	event.ID = id
	event.CreatedAt = createdAt
	return event, true, nil
}

func (r *EventRepo) ListByCase(ctx context.Context, tenantID, caseID string) ([]cases.CaseEvent, error) {
	if r == nil || r.Pool == nil {
		return nil, fmt.Errorf("db not configured")
	}
	query := `
SELECT id, tenant_id, case_id, event_type, actor_type, actor_id, request_id, created_at, payload_json
FROM case_events
WHERE tenant_id = $1 AND case_id = $2
ORDER BY event_index ASC, created_at ASC`
	rows, err := r.Pool.Query(ctx, query, tenantID, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []cases.CaseEvent
	for rows.Next() {
		var ev cases.CaseEvent
		var eventType string
		var payloadBytes []byte
		if err := rows.Scan(
			&ev.ID,
			&ev.TenantID,
			&ev.CaseID,
			&eventType,
			&ev.ActorType,
			&ev.ActorID,
			&ev.RequestID,
			&ev.CreatedAt,
			&payloadBytes,
		); err != nil {
			return nil, err
		}
		ev.EventType = cases.EventType(eventType)
		if len(payloadBytes) > 0 {
			_ = json.Unmarshal(payloadBytes, &ev.Payload)
		}
		out = append(out, ev)
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	return out, nil
}
