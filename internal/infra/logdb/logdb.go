package logdb

import (
	"context"
	"errors"
	"time"

	"proteus/internal/domain"
	"proteus/internal/infra/db"
	"proteus/internal/infra/merkle"

	"gorm.io/gorm"
)

type Log struct {
	repo    *db.TransparencyLogRepository
	clock   func() time.Time
	signSTH func(domain.STH) ([]byte, error)
}

func New(repo *db.TransparencyLogRepository) *Log {
	return &Log{
		repo:  repo,
		clock: time.Now,
	}
}

func NewWithSigner(repo *db.TransparencyLogRepository, signSTH func(domain.STH) ([]byte, error)) *Log {
	return NewWithSignerAndClock(repo, signSTH, time.Now)
}

func NewWithSignerAndClock(repo *db.TransparencyLogRepository, signSTH func(domain.STH) ([]byte, error), clock func() time.Time) *Log {
	if clock == nil {
		clock = time.Now
	}
	return &Log{
		repo:    repo,
		clock:   clock,
		signSTH: signSTH,
	}
}

func (l *Log) AppendLeaf(ctx context.Context, tenantID string, signedManifestID string, leafHash []byte) (int64, domain.STH, domain.InclusionProof, error) {
	if err := ctx.Err(); err != nil {
		return 0, domain.STH{}, domain.InclusionProof{}, err
	}
	if len(leafHash) != merkle.HashSize {
		return 0, domain.STH{}, domain.InclusionProof{}, merkle.ErrInvalidHashLen
	}
	if l.repo == nil {
		return 0, domain.STH{}, domain.InclusionProof{}, errors.New("log repository required")
	}

	index, err := l.repo.GetLeafIndex(ctx, tenantID, leafHash)
	if err == nil {
		return l.receiptForSize(ctx, tenantID, leafHash, index, index+1)
	}
	if !errors.Is(err, domain.ErrNotFound) {
		return 0, domain.STH{}, domain.InclusionProof{}, err
	}

	index, err = l.repo.AppendLeaf(ctx, tenantID, signedManifestID, leafHash)
	if err != nil {
		return 0, domain.STH{}, domain.InclusionProof{}, err
	}
	return l.receiptForSize(ctx, tenantID, leafHash, index, index+1)
}

func (l *Log) GetInclusionProof(ctx context.Context, tenantID string, leafHash []byte) (int64, domain.STH, domain.InclusionProof, error) {
	if err := ctx.Err(); err != nil {
		return 0, domain.STH{}, domain.InclusionProof{}, err
	}
	if l.repo == nil {
		return 0, domain.STH{}, domain.InclusionProof{}, errors.New("log repository required")
	}

	index, err := l.repo.GetLeafIndex(ctx, tenantID, leafHash)
	if err != nil {
		return 0, domain.STH{}, domain.InclusionProof{}, err
	}
	sth, err := l.repo.GetLatestSTH(ctx, tenantID)
	if err != nil {
		return 0, domain.STH{}, domain.InclusionProof{}, err
	}

	inclusion, err := l.inclusionForSize(ctx, tenantID, leafHash, index, sth.TreeSize)
	if err != nil {
		return 0, domain.STH{}, domain.InclusionProof{}, err
	}
	return index, *sth, inclusion, nil
}

func (l *Log) GetConsistencyProof(ctx context.Context, tenantID string, fromSize, toSize int64) (domain.ConsistencyProof, error) {
	if err := ctx.Err(); err != nil {
		return domain.ConsistencyProof{}, err
	}
	if fromSize <= 0 || toSize <= 0 || fromSize > toSize {
		return domain.ConsistencyProof{}, merkle.ErrInvalidSize
	}
	if l.repo == nil {
		return domain.ConsistencyProof{}, errors.New("log repository required")
	}

	leaves, err := l.repo.ListLeafHashes(ctx, tenantID, toSize)
	if err != nil {
		return domain.ConsistencyProof{}, err
	}
	if int64(len(leaves)) != toSize {
		return domain.ConsistencyProof{}, merkle.ErrInvalidSize
	}
	path, err := merkle.ConsistencyProof(leaves, int(fromSize), int(toSize))
	if err != nil {
		return domain.ConsistencyProof{}, err
	}
	return domain.ConsistencyProof{
		TenantID: tenantID,
		FromSize: fromSize,
		ToSize:   toSize,
		Path:     path,
	}, nil
}

func (l *Log) GetLatestSTH(ctx context.Context, tenantID string) (domain.STH, error) {
	if err := ctx.Err(); err != nil {
		return domain.STH{}, err
	}
	if l.repo == nil {
		return domain.STH{}, errors.New("log repository required")
	}
	sth, err := l.repo.GetLatestSTH(ctx, tenantID)
	if err != nil {
		return domain.STH{}, err
	}
	return *sth, nil
}

func (l *Log) receiptForSize(ctx context.Context, tenantID string, leafHash []byte, leafIndex int64, treeSize int64) (int64, domain.STH, domain.InclusionProof, error) {
	sth, err := l.repo.GetSTHBySize(ctx, tenantID, treeSize)
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		return 0, domain.STH{}, domain.InclusionProof{}, err
	}

	if sth == nil || errors.Is(err, domain.ErrNotFound) {
		sth, err = l.buildSTH(ctx, tenantID, treeSize)
		if err != nil {
			return 0, domain.STH{}, domain.InclusionProof{}, err
		}
	}

	inclusion, err := l.inclusionForSize(ctx, tenantID, leafHash, leafIndex, treeSize)
	if err != nil {
		return 0, domain.STH{}, domain.InclusionProof{}, err
	}
	return leafIndex, *sth, inclusion, nil
}

func (l *Log) inclusionForSize(ctx context.Context, tenantID string, leafHash []byte, leafIndex int64, treeSize int64) (domain.InclusionProof, error) {
	leaves, err := l.repo.ListLeafHashes(ctx, tenantID, treeSize)
	if err != nil {
		return domain.InclusionProof{}, err
	}
	if int64(len(leaves)) != treeSize {
		return domain.InclusionProof{}, merkle.ErrInvalidSize
	}
	path, err := merkle.InclusionProof(leaves, int(leafIndex))
	if err != nil {
		return domain.InclusionProof{}, err
	}
	root, err := merkle.Root(leaves)
	if err != nil {
		return domain.InclusionProof{}, err
	}
	return domain.InclusionProof{
		TenantID:    tenantID,
		LeafIndex:   leafIndex,
		Path:        path,
		STHTreeSize: treeSize,
		STHRootHash: root,
	}, nil
}

func (l *Log) buildSTH(ctx context.Context, tenantID string, treeSize int64) (*domain.STH, error) {
	leaves, err := l.repo.ListLeafHashes(ctx, tenantID, treeSize)
	if err != nil {
		return nil, err
	}
	if int64(len(leaves)) != treeSize {
		return nil, merkle.ErrInvalidSize
	}
	root, err := merkle.Root(leaves)
	if err != nil {
		return nil, err
	}
	sth := domain.STH{
		TenantID:  tenantID,
		TreeSize:  treeSize,
		RootHash:  root,
		IssuedAt:  l.clock().UTC(),
		Signature: nil,
	}
	if l.signSTH != nil {
		sig, err := l.signSTH(sth)
		if err != nil {
			return nil, err
		}
		sth.Signature = sig
	}
	if sth.Signature == nil {
		sth.Signature = []byte{}
	}
	if err := l.repo.StoreSTH(ctx, sth); err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return l.repo.GetSTHBySize(ctx, tenantID, treeSize)
		}
		return nil, err
	}
	return &sth, nil
}
