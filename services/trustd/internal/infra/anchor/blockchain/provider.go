package blockchain

import (
	"context"

	"proteus/internal/domain"
	"proteus/internal/infra/anchor"
)

type Provider struct {
	name        string
	bundleID    string
	enabled     bool
	implemented bool
}

func NewProvider(bundleID string) *Provider {
	return &Provider{
		name:     "blockchain",
		bundleID: bundleID,
	}
}

func (p *Provider) Enable() {
	p.enabled = true
}

func (p *Provider) ProviderName() string {
	if p.name == "" {
		return "blockchain"
	}
	return p.name
}

func (p *Provider) BundleID() string {
	if p.bundleID == "" {
		return "blockchain"
	}
	return p.bundleID
}

func (p *Provider) Anchor(ctx context.Context, payload anchor.Payload) domain.AnchorReceipt {
	receipt := domain.AnchorReceipt{
		Provider:    p.ProviderName(),
		BundleID:    p.BundleID(),
		PayloadHash: payload.HashHex,
		Status:      domain.AnchorStatusSkipped,
	}
	if !p.enabled {
		return receipt
	}
	if !p.implemented {
		receipt.Status = domain.AnchorStatusFailed
		receipt.ErrorCode = domain.AnchorErrorNotImplemented
		return receipt
	}
	return receipt
}
