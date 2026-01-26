//go:build integration
// +build integration

package http

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"proteus/case-service/internal/config"
	"proteus/case-service/internal/repo/postgres"
	"proteus/case-service/internal/repo/postgres/testdb"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCaseCreateAndGet(t *testing.T) {
	pool, cleanup := testdb.NewDatabase(t)
	defer cleanup()

	tenantID := uuid.NewString()
	insertTenant(t, pool, tenantID)

	gin.SetMode(gin.TestMode)
	store := &postgres.Store{Pool: pool}
	srv := NewServer(config.Config{}, store)
	server := httptest.NewServer(srv.r)
	defer server.Close()

	body := map[string]any{
		"source_type":     "verify",
		"source_ref_type": "manifest_id",
		"source_ref_raw":  uuid.NewString(),
		"severity":        "high",
	}
	payload, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/cases", bytes.NewReader(payload))
	setAuthHeaders(req, tenantID, "req-1", "case:write,case:read,case:event")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create case: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
	var createResp struct {
		Case struct {
			ID string `json:"id"`
		} `json:"case"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&createResp); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if createResp.Case.ID == "" {
		t.Fatalf("missing case id")
	}

	getReq, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/cases/"+createResp.Case.ID, nil)
	setAuthHeaders(getReq, tenantID, "", "case:read")
	getResp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("get case: %v", err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected get status: %d", getResp.StatusCode)
	}

	eventsReq, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/cases/"+createResp.Case.ID+"/events", nil)
	setAuthHeaders(eventsReq, tenantID, "", "case:read")
	eventsResp, err := http.DefaultClient.Do(eventsReq)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	defer eventsResp.Body.Close()
	if eventsResp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected events status: %d", eventsResp.StatusCode)
	}
}

func TestQueuePagination(t *testing.T) {
	pool, cleanup := testdb.NewDatabase(t)
	defer cleanup()

	tenantID := uuid.NewString()
	queueID := uuid.NewString()
	insertTenant(t, pool, tenantID)
	insertQueue(t, pool, tenantID, queueID)

	cases := []struct {
		ID        string
		CreatedAt time.Time
	}{
		{uuid.NewString(), time.Now().Add(-3 * time.Hour)},
		{uuid.NewString(), time.Now().Add(-2 * time.Hour)},
		{uuid.NewString(), time.Now().Add(-1 * time.Hour)},
	}
	for _, item := range cases {
		insertCaseHeader(t, pool, tenantID, item.ID, item.CreatedAt)
		insertQueueProjection(t, pool, tenantID, queueID, item.ID, item.CreatedAt)
	}

	gin.SetMode(gin.TestMode)
	store := &postgres.Store{Pool: pool}
	srv := NewServer(config.Config{}, store)
	server := httptest.NewServer(srv.r)
	defer server.Close()

	req, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/queues/"+queueID+"/cases?limit=2", nil)
	setAuthHeaders(req, tenantID, "", "queue:read")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("queue list: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected queue list status: %d", resp.StatusCode)
	}
	var listResp struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
		NextCursor string `json:"next_cursor"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		t.Fatalf("decode queue list: %v", err)
	}
	if len(listResp.Items) != 2 || listResp.NextCursor == "" {
		t.Fatalf("expected 2 items and cursor")
	}

	req2, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/queues/"+queueID+"/cases?limit=2&cursor="+listResp.NextCursor, nil)
	setAuthHeaders(req2, tenantID, "", "queue:read")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("queue list page 2: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("unexpected queue list page 2 status: %d", resp2.StatusCode)
	}
	var listResp2 struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&listResp2); err != nil {
		t.Fatalf("decode queue list page 2: %v", err)
	}
	if len(listResp2.Items) != 1 {
		t.Fatalf("expected 1 item on page 2")
	}
}

func setAuthHeaders(req *http.Request, tenantID, requestID, scopes string) {
	req.Header.Set("X-Principal-Subject", "user-1")
	req.Header.Set("X-Principal-Tenant", tenantID)
	req.Header.Set("X-Principal-Scopes", scopes)
	if requestID != "" {
		req.Header.Set("X-Request-ID", requestID)
	}
	req.Header.Set("Content-Type", "application/json")
}

func insertTenant(t *testing.T, pool *pgxpool.Pool, tenantID string) {
	t.Helper()
	_, err := pool.Exec(context.Background(), "INSERT INTO tenants (id, name) VALUES ($1, $2)", tenantID, "tenant-"+tenantID)
	if err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
}

func insertQueue(t *testing.T, pool *pgxpool.Pool, tenantID, queueID string) {
	t.Helper()
	_, err := pool.Exec(context.Background(), "INSERT INTO queues (id, tenant_id, name, created_at, updated_at) VALUES ($1, $2, $3, now(), now())", queueID, tenantID, "queue-1")
	if err != nil {
		t.Fatalf("insert queue: %v", err)
	}
}

func insertCaseHeader(t *testing.T, pool *pgxpool.Pool, tenantID, caseID string, createdAt time.Time) {
	t.Helper()
	sourceHash := sha256Hex("case-" + caseID)
	_, err := pool.Exec(context.Background(), "INSERT INTO cases (id, tenant_id, source_type, source_ref_type, source_ref_hash, source_ref_raw, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)", caseID, tenantID, "verify", "manifest_id", sourceHash, caseID, createdAt)
	if err != nil {
		t.Fatalf("insert case: %v", err)
	}
}

func insertQueueProjection(t *testing.T, pool *pgxpool.Pool, tenantID, queueID, caseID string, createdAt time.Time) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
INSERT INTO case_queue_projection (case_id, tenant_id, queue_id, status, severity, owner_id, sla_state, sla_due_at, case_created_at, updated_at, projection_version)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		caseID, tenantID, queueID, "queued", "medium", "", "active", nil, createdAt, time.Now(), 1,
	)
	if err != nil {
		t.Fatalf("insert queue projection: %v", err)
	}
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
