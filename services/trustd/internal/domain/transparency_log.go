package domain

import "time"

type TreeHead struct {
	TenantID   string
	TreeSize   int64
	RootHash   []byte
	IssuedAt   time.Time
	Signature  []byte
}

type STH = TreeHead

type InclusionProof struct {
	TenantID     string
	LeafIndex    int64
	Path         [][]byte
	STHTreeSize  int64
	STHRootHash  []byte
}

type ConsistencyProof struct {
	TenantID   string
	FromSize   int64
	ToSize     int64
	Path       [][]byte
}
