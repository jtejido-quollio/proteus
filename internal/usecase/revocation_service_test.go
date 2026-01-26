package usecase

import (
	"context"
	"errors"
	"testing"

	"proteus/internal/domain"
)

type stubRevocationRepo struct {
	calls int
	last  domain.Revocation
	err   error
}

func (r *stubRevocationRepo) Revoke(ctx context.Context, rev domain.Revocation) error {
	r.calls++
	r.last = rev
	return r.err
}

type stubEpochRepo struct {
	epoch int64
	calls int
}

func (r *stubEpochRepo) GetEpoch(ctx context.Context, tenantID string) (int64, error) {
	return r.epoch, nil
}

func (r *stubEpochRepo) BumpEpoch(ctx context.Context, tenantID string) (int64, error) {
	r.calls++
	r.epoch++
	return r.epoch, nil
}

func TestRevocationService_RevokeBumpsEpoch(t *testing.T) {
	revRepo := &stubRevocationRepo{}
	epochRepo := &stubEpochRepo{}
	svc := NewRevocationService(revRepo, epochRepo)

	rev := domain.Revocation{TenantID: "tenant-1", KID: "kid-1"}
	epoch, err := svc.Revoke(context.Background(), rev)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if epoch != 1 {
		t.Fatalf("expected epoch 1, got %d", epoch)
	}
	if epochRepo.calls != 1 {
		t.Fatalf("expected epoch bump to be called once")
	}

	epoch, err = svc.Revoke(context.Background(), rev)
	if err != nil {
		t.Fatalf("revoke again: %v", err)
	}
	if epoch != 2 {
		t.Fatalf("expected epoch 2, got %d", epoch)
	}
	if epochRepo.calls != 2 {
		t.Fatalf("expected epoch bump to be called twice")
	}
	if revRepo.calls != 2 {
		t.Fatalf("expected revocation repo called twice")
	}
}

func TestRevocationService_RevokeErrorSkipsEpoch(t *testing.T) {
	revRepo := &stubRevocationRepo{err: errors.New("fail")}
	epochRepo := &stubEpochRepo{}
	svc := NewRevocationService(revRepo, epochRepo)

	_, err := svc.Revoke(context.Background(), domain.Revocation{TenantID: "tenant-1", KID: "kid-1"})
	if err == nil {
		t.Fatalf("expected revoke error")
	}
	if epochRepo.calls != 0 {
		t.Fatalf("expected epoch bump to be skipped on revocation error")
	}
}
