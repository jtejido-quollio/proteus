package anchor

import (
	"context"
	"errors"
	"time"

	"proteus/internal/domain"
)

type Provider interface {
	ProviderName() string
	BundleID() string
	Anchor(ctx context.Context, payload Payload) domain.AnchorReceipt
}

type Service struct {
	providers          map[string]Provider
	defaultProviderIDs []string
	attempts           domain.AnchorAttemptRepository
	receipts           domain.AnchorReceiptRepository
}

func NewService(providers []Provider, defaultProviderIDs []string, attempts domain.AnchorAttemptRepository, receipts domain.AnchorReceiptRepository) (*Service, error) {
	index := make(map[string]Provider, len(providers))
	for _, provider := range providers {
		if provider == nil {
			return nil, errors.New("provider is nil")
		}
		id := provider.ProviderName()
		if id == "" {
			return nil, errors.New("provider id is required")
		}
		if _, exists := index[id]; exists {
			return nil, errors.New("duplicate provider id: " + id)
		}
		index[id] = provider
	}
	return &Service{
		providers:          index,
		defaultProviderIDs: defaultProviderIDs,
		attempts:           attempts,
		receipts:           receipts,
	}, nil
}

func (s *Service) AnchorSTH(ctx context.Context, tenantID string, sth domain.STH) ([]domain.AnchorReceipt, error) {
	if s == nil {
		return nil, errors.New("anchor service is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	payload, err := BuildPayload(tenantID, sth)
	if err != nil {
		return nil, err
	}
	ids := s.defaultProviderIDs
	if len(ids) == 0 {
		receipt := skippedReceipt(tenantID, sth.TreeSize, payload.HashHex, "anchor", "disabled")
		receipt = s.persistAttempt(ctx, receipt)
		return []domain.AnchorReceipt{receipt}, nil
	}

	receipts := make([]domain.AnchorReceipt, 0, len(ids))
	for _, id := range ids {
		provider, ok := s.providers[id]
		if !ok {
			receipt := failedConfigReceipt(tenantID, sth.TreeSize, payload.HashHex, id, "unknown")
			receipt = s.persistAttempt(ctx, receipt)
			receipts = append(receipts, receipt)
			continue
		}
		providerCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		receipt := provider.Anchor(providerCtx, payload)
		cancel()
		if receipt.Provider == "" {
			receipt.Provider = provider.ProviderName()
		}
		if receipt.BundleID == "" {
			receipt.BundleID = provider.BundleID()
		}
		if receipt.Status == "" {
			receipt.Status = domain.AnchorStatusAnchored
		}
		receipt.TenantID = tenantID
		receipt.TreeSize = sth.TreeSize
		receipt.PayloadHash = payload.HashHex
		if providerCtx.Err() == context.DeadlineExceeded {
			receipt.Status = domain.AnchorStatusFailed
			if receipt.ErrorCode == "" {
				receipt.ErrorCode = domain.AnchorErrorTimeout
			}
		}
		receipt = s.persistAttempt(ctx, receipt)
		if receipt.Status == domain.AnchorStatusAnchored {
			receipt = s.persistReceipt(ctx, receipt)
		}
		receipts = append(receipts, receipt)
	}
	return receipts, nil
}

func (s *Service) persistAttempt(ctx context.Context, receipt domain.AnchorReceipt) domain.AnchorReceipt {
	if s.attempts == nil {
		return receipt
	}
	attempt := domain.AnchorAttempt{
		TenantID:                 receipt.TenantID,
		Provider:                 receipt.Provider,
		BundleID:                 receipt.BundleID,
		Status:                   receipt.Status,
		ErrorCode:                receipt.ErrorCode,
		PayloadHash:              receipt.PayloadHash,
		TreeSize:                 receipt.TreeSize,
		ProviderReceiptJSON:      cloneBytes(receipt.ProviderReceiptJSON),
		ProviderReceiptTruncated: receipt.ProviderReceiptTruncated,
		ProviderReceiptSizeBytes: receipt.ProviderReceiptSizeBytes,
	}
	if err := s.attempts.Append(ctx, attempt); err != nil {
		receipt.Status = domain.AnchorStatusFailed
		receipt.ErrorCode = domain.AnchorErrorPersistence
	}
	return receipt
}

func (s *Service) persistReceipt(ctx context.Context, receipt domain.AnchorReceipt) domain.AnchorReceipt {
	if s.receipts == nil {
		return receipt
	}
	if err := s.receipts.AppendAnchored(ctx, receipt); err != nil {
		receipt.Status = domain.AnchorStatusFailed
		receipt.ErrorCode = domain.AnchorErrorPersistence
	}
	return receipt
}

func failedConfigReceipt(tenantID string, treeSize int64, payloadHash, provider, bundleID string) domain.AnchorReceipt {
	if bundleID == "" {
		bundleID = "unknown"
	}
	return domain.AnchorReceipt{
		TenantID:    tenantID,
		Provider:    provider,
		BundleID:    bundleID,
		Status:      domain.AnchorStatusFailed,
		ErrorCode:   domain.AnchorErrorBadConfig,
		PayloadHash: payloadHash,
		TreeSize:    treeSize,
	}
}

func skippedReceipt(tenantID string, treeSize int64, payloadHash, provider, bundleID string) domain.AnchorReceipt {
	if bundleID == "" {
		bundleID = "disabled"
	}
	return domain.AnchorReceipt{
		TenantID:    tenantID,
		Provider:    provider,
		BundleID:    bundleID,
		Status:      domain.AnchorStatusSkipped,
		PayloadHash: payloadHash,
		TreeSize:    treeSize,
	}
}

func cloneBytes(in []byte) []byte {
	if len(in) == 0 {
		return nil
	}
	out := make([]byte, len(in))
	copy(out, in)
	return out
}
