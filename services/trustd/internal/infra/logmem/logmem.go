package logmem

import (
	"context"
	"encoding/hex"
	"sync"
	"time"

	"proteus/internal/domain"
	"proteus/internal/infra/merkle"
)

type Log struct {
	mu            sync.RWMutex
	tenants       map[string]*tenantState
	clock         func() time.Time
	signSTH       func(domain.STH) ([]byte, error)
	anchor        domain.AnchorService
	anchorTimeout time.Duration
}

type tenantState struct {
	leaves      [][]byte
	indexByHash map[string]int64
	sth         domain.STH
	receipts    map[string]logReceipt
}

type logReceipt struct {
	leafIndex int64
	sth       domain.STH
	inclusion domain.InclusionProof
}

func New() *Log {
	return &Log{
		tenants: make(map[string]*tenantState),
		clock:   time.Now,
	}
}

func NewWithSigner(signSTH func(domain.STH) ([]byte, error)) *Log {
	return &Log{
		tenants: make(map[string]*tenantState),
		clock:   time.Now,
		signSTH: signSTH,
	}
}

func NewWithSignerAndClock(signSTH func(domain.STH) ([]byte, error), clock func() time.Time) *Log {
	return NewWithSignerClockAndAnchor(signSTH, clock, nil, 0)
}

func NewWithSignerClockAndAnchor(signSTH func(domain.STH) ([]byte, error), clock func() time.Time, anchorSvc domain.AnchorService, timeout time.Duration) *Log {
	if clock == nil {
		clock = time.Now
	}
	return &Log{
		tenants:       make(map[string]*tenantState),
		clock:         clock,
		signSTH:       signSTH,
		anchor:        anchorSvc,
		anchorTimeout: timeout,
	}
}

func (l *Log) AppendLeaf(ctx context.Context, tenantID string, signedManifestID string, leafHash []byte) (int64, domain.STH, domain.InclusionProof, error) {
	if err := ctx.Err(); err != nil {
		return 0, domain.STH{}, domain.InclusionProof{}, err
	}
	if len(leafHash) != merkle.HashSize {
		return 0, domain.STH{}, domain.InclusionProof{}, merkle.ErrInvalidHashLen
	}

	l.mu.Lock()

	state := l.ensureTenant(tenantID)
	key := hex.EncodeToString(leafHash)
	if receipt, ok := state.receipts[key]; ok {
		l.mu.Unlock()
		return receipt.leafIndex, cloneSTH(receipt.sth), cloneInclusion(receipt.inclusion), nil
	}
	index := int64(len(state.leaves))
	state.leaves = append(state.leaves, cloneHash(leafHash))
	state.indexByHash[key] = index

	root, err := merkle.Root(state.leaves)
	if err != nil {
		state.leaves = state.leaves[:len(state.leaves)-1]
		l.mu.Unlock()
		return 0, domain.STH{}, domain.InclusionProof{}, err
	}
	path, err := merkle.InclusionProof(state.leaves, int(index))
	if err != nil {
		state.leaves = state.leaves[:len(state.leaves)-1]
		l.mu.Unlock()
		return 0, domain.STH{}, domain.InclusionProof{}, err
	}

	sth := domain.STH{
		TenantID: tenantID,
		TreeSize: int64(len(state.leaves)),
		RootHash: cloneHash(root),
		IssuedAt: l.clock().UTC(),
	}
	if l.signSTH != nil {
		sig, err := l.signSTH(sth)
		if err != nil {
			state.leaves = state.leaves[:len(state.leaves)-1]
			l.mu.Unlock()
			return 0, domain.STH{}, domain.InclusionProof{}, err
		}
		sth.Signature = sig
	}
	state.sth = sth

	inclusion := domain.InclusionProof{
		TenantID:    tenantID,
		LeafIndex:   index,
		Path:        path,
		STHTreeSize: sth.TreeSize,
		STHRootHash: cloneHash(root),
	}

	state.receipts[key] = logReceipt{
		leafIndex: index,
		sth:       sth,
		inclusion: inclusion,
	}
	l.mu.Unlock()

	l.anchorBestEffort(ctx, tenantID, sth)
	return index, sth, inclusion, nil
}

func (l *Log) GetInclusionProof(ctx context.Context, tenantID string, leafHash []byte) (int64, domain.STH, domain.InclusionProof, error) {
	if err := ctx.Err(); err != nil {
		return 0, domain.STH{}, domain.InclusionProof{}, err
	}

	l.mu.RLock()
	state := l.tenants[tenantID]
	if state == nil {
		l.mu.RUnlock()
		return 0, domain.STH{}, domain.InclusionProof{}, domain.ErrNotFound
	}
	index, ok := state.indexByHash[hex.EncodeToString(leafHash)]
	if !ok {
		l.mu.RUnlock()
		return 0, domain.STH{}, domain.InclusionProof{}, domain.ErrNotFound
	}
	leaves := state.leaves
	sth := state.sth
	l.mu.RUnlock()

	path, err := merkle.InclusionProof(leaves, int(index))
	if err != nil {
		return 0, domain.STH{}, domain.InclusionProof{}, err
	}
	if sth.TreeSize == 0 {
		root, err := merkle.Root(leaves)
		if err != nil {
			return 0, domain.STH{}, domain.InclusionProof{}, err
		}
		sth = domain.STH{
			TenantID: tenantID,
			TreeSize: int64(len(leaves)),
			RootHash: cloneHash(root),
			IssuedAt: l.clock().UTC(),
		}
	}

	inclusion := domain.InclusionProof{
		TenantID:    tenantID,
		LeafIndex:   index,
		Path:        path,
		STHTreeSize: sth.TreeSize,
		STHRootHash: cloneHash(sth.RootHash),
	}
	return index, sth, inclusion, nil
}

func (l *Log) GetLatestSTH(ctx context.Context, tenantID string) (domain.STH, error) {
	if err := ctx.Err(); err != nil {
		return domain.STH{}, err
	}

	l.mu.RLock()
	state := l.tenants[tenantID]
	if state == nil || state.sth.TreeSize == 0 {
		l.mu.RUnlock()
		return domain.STH{}, domain.ErrNotFound
	}
	sth := state.sth
	l.mu.RUnlock()
	return cloneSTH(sth), nil
}

func (l *Log) anchorBestEffort(ctx context.Context, tenantID string, sth domain.STH) {
	if l.anchor == nil {
		return
	}
	timeout := l.anchorTimeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	anchorCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	_, _ = l.anchor.AnchorSTH(anchorCtx, tenantID, sth)
}

func (l *Log) GetConsistencyProof(ctx context.Context, tenantID string, fromSize, toSize int64) (domain.ConsistencyProof, error) {
	if err := ctx.Err(); err != nil {
		return domain.ConsistencyProof{}, err
	}
	if fromSize <= 0 || toSize <= 0 || fromSize > toSize {
		return domain.ConsistencyProof{}, merkle.ErrInvalidSize
	}

	l.mu.RLock()
	state := l.tenants[tenantID]
	if state == nil {
		l.mu.RUnlock()
		return domain.ConsistencyProof{}, domain.ErrNotFound
	}
	if toSize > int64(len(state.leaves)) {
		l.mu.RUnlock()
		return domain.ConsistencyProof{}, merkle.ErrInvalidSize
	}
	leaves := state.leaves[:toSize]
	l.mu.RUnlock()

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

func (l *Log) ensureTenant(tenantID string) *tenantState {
	state := l.tenants[tenantID]
	if state == nil {
		state = &tenantState{
			indexByHash: make(map[string]int64),
			receipts:    make(map[string]logReceipt),
		}
		l.tenants[tenantID] = state
	}
	return state
}

func cloneHash(hash []byte) []byte {
	if hash == nil {
		return nil
	}
	out := make([]byte, len(hash))
	copy(out, hash)
	return out
}

func cloneSTH(sth domain.STH) domain.STH {
	return domain.STH{
		TenantID:  sth.TenantID,
		TreeSize:  sth.TreeSize,
		RootHash:  cloneHash(sth.RootHash),
		IssuedAt:  sth.IssuedAt,
		Signature: cloneHash(sth.Signature),
	}
}

func cloneInclusion(inclusion domain.InclusionProof) domain.InclusionProof {
	path := make([][]byte, 0, len(inclusion.Path))
	for _, p := range inclusion.Path {
		path = append(path, cloneHash(p))
	}
	return domain.InclusionProof{
		TenantID:    inclusion.TenantID,
		LeafIndex:   inclusion.LeafIndex,
		Path:        path,
		STHTreeSize: inclusion.STHTreeSize,
		STHRootHash: cloneHash(inclusion.STHRootHash),
	}
}
