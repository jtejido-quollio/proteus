package domain

import (
	"context"
	"encoding/json"
	"time"
)

type AnchorService interface {
	// AnchorSTH submits a commitment to an external anchor provider.
	// Implementations must not fail core flows on network/provider errors.
	AnchorSTH(ctx context.Context, tenantID string, sth STH) ([]AnchorReceipt, error)
}

type AnchorAttempt struct {
	TenantID    string
	Provider    string
	BundleID    string
	Status      string
	ErrorCode   string
	PayloadHash string
	TreeSize    int64

	ProviderReceiptJSON      json.RawMessage
	ProviderReceiptTruncated bool
	ProviderReceiptSizeBytes int

	CreatedAt time.Time
}

type AnchorReceipt struct {
	TenantID    string
	Provider    string
	BundleID    string
	Status      string
	ErrorCode   string
	PayloadHash string
	TreeSize    int64

	EntryUUID      string
	LogIndex       int64
	IntegratedTime int64
	EntryURL       string

	TxID        string
	ChainID     string
	ExplorerURL string

	ProviderReceiptJSON      json.RawMessage
	ProviderReceiptTruncated bool
	ProviderReceiptSizeBytes int
	ProviderReceiptSHA256    string
}

const (
	AnchorStatusAnchored = "anchored"
	AnchorStatusFailed   = "failed"
	AnchorStatusSkipped  = "skipped"
)

const (
	AnchorErrorNetwork        = "NETWORK"
	AnchorErrorRateLimit      = "RATE_LIMIT"
	AnchorErrorBadConfig      = "BAD_CONFIG"
	AnchorErrorProviderError  = "PROVIDER_ERROR"
	AnchorErrorProvider5xx    = "PROVIDER_5XX"
	AnchorErrorPersistence    = "PERSISTENCE"
	AnchorErrorTimeout        = "TIMEOUT"
	AnchorErrorNotImplemented = "NOT_IMPLEMENTED"
)

type AnchorAttemptRepository interface {
	Append(ctx context.Context, attempt AnchorAttempt) error
	ListByPayloadHash(ctx context.Context, tenantID, payloadHash string) ([]AnchorAttempt, error)
}

type AnchorReceiptRepository interface {
	AppendAnchored(ctx context.Context, receipt AnchorReceipt) error
	ListByPayloadHash(ctx context.Context, tenantID, payloadHash string) ([]AnchorReceipt, error)
}
