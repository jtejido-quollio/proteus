package usecase

import (
	"context"
	"testing"

	"proteus/case-service/internal/domain/cases"
)

func TestRequestIDRequiredForActions(t *testing.T) {
	svc := &CaseService{}
	tenantID := "tenant-1"
	caseID := "case-1"
	actor := Actor{Type: "user", ID: "user-1"}

	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "CreateCase",
			run: func() error {
				_, _, err := svc.CreateCase(context.Background(), CreateCaseInput{
					TenantID:      tenantID,
					SourceType:    "verify",
					SourceRefType: cases.SourceRefManifestID,
					SourceRefRaw:  "1b4e28ba-2fa1-11d2-883f-0016d3cca427",
					RequestID:     "",
					Actor:         actor,
				})
				return err
			},
		},
		{
			name: "AddEvidence",
			run: func() error {
				return svc.AddEvidence(context.Background(), EvidenceInput{
					TenantID:  tenantID,
					CaseID:    caseID,
					RequestID: "",
					Actor:     actor,
				})
			},
		},
		{
			name: "AddComment",
			run: func() error {
				return svc.AddComment(context.Background(), CommentInput{
					TenantID:  tenantID,
					CaseID:    caseID,
					RequestID: "",
					Actor:     actor,
				})
			},
		},
		{
			name: "Assign",
			run: func() error {
				return svc.Assign(context.Background(), AssignInput{
					TenantID:  tenantID,
					CaseID:    caseID,
					RequestID: "",
					Actor:     actor,
				})
			},
		},
		{
			name: "Unassign",
			run: func() error {
				return svc.Unassign(context.Background(), tenantID, caseID, "", actor)
			},
		},
		{
			name: "Hold",
			run: func() error {
				return svc.Hold(context.Background(), HoldInput{
					TenantID:  tenantID,
					CaseID:    caseID,
					RequestID: "",
					Actor:     actor,
				})
			},
		},
		{
			name: "Unhold",
			run: func() error {
				return svc.Unhold(context.Background(), tenantID, caseID, "", actor)
			},
		},
		{
			name: "Escalate",
			run: func() error {
				return svc.Escalate(context.Background(), EscalateInput{
					TenantID:  tenantID,
					CaseID:    caseID,
					RequestID: "",
					Actor:     actor,
				})
			},
		},
		{
			name: "Deescalate",
			run: func() error {
				return svc.Deescalate(context.Background(), tenantID, caseID, "", actor)
			},
		},
		{
			name: "Decide",
			run: func() error {
				return svc.Decide(context.Background(), DecideInput{
					TenantID:  tenantID,
					CaseID:    caseID,
					RequestID: "",
					Actor:     actor,
				})
			},
		},
		{
			name: "Reopen",
			run: func() error {
				return svc.Reopen(context.Background(), ReopenInput{
					TenantID:  tenantID,
					CaseID:    caseID,
					RequestID: "",
					Actor:     actor,
				})
			},
		},
		{
			name: "Export",
			run: func() error {
				return svc.Export(context.Background(), ExportInput{
					TenantID:  tenantID,
					CaseID:    caseID,
					RequestID: "",
					Actor:     actor,
				})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.run(); err != cases.ErrInvalidArgument {
				t.Fatalf("expected ErrInvalidArgument, got %v", err)
			}
		})
	}
}

func TestDecideRequiresPolicySnapshot(t *testing.T) {
	svc := &CaseService{}
	err := svc.Decide(context.Background(), DecideInput{
		TenantID:  "tenant-1",
		CaseID:    "case-1",
		RequestID: "req-1",
		Actor:     Actor{Type: "user", ID: "user-1"},
	})
	if err != cases.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
}
