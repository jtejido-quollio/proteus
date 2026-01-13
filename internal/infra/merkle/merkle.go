package merkle

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
)

const HashSize = 32

var (
	ErrEmptyTree      = errors.New("empty merkle tree")
	ErrInvalidHashLen = errors.New("invalid hash length")
	ErrInvalidIndex   = errors.New("invalid leaf index")
	ErrInvalidSize    = errors.New("invalid tree size")
)

func NodeHash(left, right []byte) []byte {
	hasher := sha256.New()
	hasher.Write([]byte{0x01})
	hasher.Write(left)
	hasher.Write(right)
	return hasher.Sum(nil)
}

func Root(leaves [][]byte) ([]byte, error) {
	level, err := cloneAndValidateLeaves(leaves)
	if err != nil {
		return nil, err
	}
	return merkleTreeHash(level)
}

func InclusionProof(leaves [][]byte, leafIndex int) ([][]byte, error) {
	level, err := cloneAndValidateLeaves(leaves)
	if err != nil {
		return nil, err
	}
	if len(level) == 0 {
		return nil, ErrEmptyTree
	}
	if leafIndex < 0 || leafIndex >= len(level) {
		return nil, ErrInvalidIndex
	}

	path := make([][]byte, 0)
	if err := inclusionProof(level, leafIndex, &path); err != nil {
		return nil, err
	}
	return path, nil
}

func VerifyInclusionProof(leafHash []byte, leafIndex int, treeSize int, path [][]byte, expectedRoot []byte) (bool, error) {
	if treeSize <= 0 {
		return false, ErrInvalidSize
	}
	if leafIndex < 0 || leafIndex >= treeSize {
		return false, ErrInvalidIndex
	}
	if err := validateHash(leafHash); err != nil {
		return false, err
	}
	if err := validateHash(expectedRoot); err != nil {
		return false, err
	}
	for _, p := range path {
		if err := validateHash(p); err != nil {
			return false, err
		}
	}

	hash, used, err := inclusionRootFromPath(leafHash, leafIndex, treeSize, path)
	if err != nil {
		return false, err
	}
	if used != len(path) {
		return false, ErrInvalidSize
	}
	return bytes.Equal(hash, expectedRoot), nil
}

func ConsistencyProof(leaves [][]byte, fromSize int, toSize int) ([][]byte, error) {
	if fromSize <= 0 || toSize <= 0 || fromSize > toSize {
		return nil, ErrInvalidSize
	}
	if toSize > len(leaves) {
		return nil, ErrInvalidSize
	}
	level, err := cloneAndValidateLeaves(leaves[:toSize])
	if err != nil {
		return nil, err
	}
	if fromSize == toSize {
		return [][]byte{}, nil
	}
	return consistencyProofCT(level, fromSize, toSize, true)
}

func VerifyConsistencyProof(oldRoot []byte, newRoot []byte, fromSize int, toSize int, path [][]byte) (bool, error) {
	if fromSize <= 0 || toSize <= 0 || fromSize > toSize {
		return false, ErrInvalidSize
	}
	if fromSize == toSize {
		if len(path) != 0 {
			return false, nil
		}
		return bytes.Equal(oldRoot, newRoot), nil
	}
	if err := validateHash(oldRoot); err != nil {
		return false, err
	}
	if err := validateHash(newRoot); err != nil {
		return false, err
	}
	for _, p := range path {
		if err := validateHash(p); err != nil {
			return false, err
		}
	}
	if len(path) == 0 {
		return false, ErrInvalidSize
	}

	oldCandidate, newCandidate, used, err := consistencyVerify(fromSize, toSize, path, true, oldRoot)
	if err != nil {
		return false, err
	}
	if used != len(path) {
		return false, ErrInvalidSize
	}
	return bytes.Equal(oldCandidate, oldRoot) && bytes.Equal(newCandidate, newRoot), nil
}

func merkleTreeHash(leaves [][]byte) ([]byte, error) {
	if len(leaves) == 0 {
		return nil, ErrEmptyTree
	}
	if len(leaves) == 1 {
		return cloneHash(leaves[0]), nil
	}
	k := largestPowerOfTwoLessThan(len(leaves))
	left, err := merkleTreeHash(leaves[:k])
	if err != nil {
		return nil, err
	}
	right, err := merkleTreeHash(leaves[k:])
	if err != nil {
		return nil, err
	}
	return NodeHash(left, right), nil
}

func cloneAndValidateLeaves(leaves [][]byte) ([][]byte, error) {
	if len(leaves) == 0 {
		return nil, ErrEmptyTree
	}
	out := make([][]byte, len(leaves))
	for i, leaf := range leaves {
		if err := validateHash(leaf); err != nil {
			return nil, fmt.Errorf("leaf %d: %w", i, err)
		}
		out[i] = cloneHash(leaf)
	}
	return out, nil
}

func validateHash(hash []byte) error {
	if len(hash) != HashSize {
		return ErrInvalidHashLen
	}
	return nil
}

func inclusionProof(leaves [][]byte, leafIndex int, path *[][]byte) error {
	if len(leaves) == 1 {
		return nil
	}
	k := largestPowerOfTwoLessThan(len(leaves))
	if leafIndex < k {
		if err := inclusionProof(leaves[:k], leafIndex, path); err != nil {
			return err
		}
		rightRoot, err := merkleTreeHash(leaves[k:])
		if err != nil {
			return err
		}
		*path = append(*path, rightRoot)
		return nil
	}
	if err := inclusionProof(leaves[k:], leafIndex-k, path); err != nil {
		return err
	}
	leftRoot, err := merkleTreeHash(leaves[:k])
	if err != nil {
		return err
	}
	*path = append(*path, leftRoot)
	return nil
}

func cloneHash(hash []byte) []byte {
	if hash == nil {
		return nil
	}
	out := make([]byte, len(hash))
	copy(out, hash)
	return out
}

func isPowerOfTwo(value int) bool {
	return value > 0 && (value&(value-1)) == 0
}

func largestPowerOfTwoLessThan(value int) int {
	power := 1
	for power<<1 < value {
		power <<= 1
	}
	return power
}

func inclusionRootFromPath(leafHash []byte, leafIndex int, treeSize int, path [][]byte) ([]byte, int, error) {
	if treeSize <= 0 {
		return nil, 0, ErrInvalidSize
	}
	if treeSize == 1 {
		if leafIndex != 0 {
			return nil, 0, ErrInvalidIndex
		}
		return cloneHash(leafHash), 0, nil
	}
	k := largestPowerOfTwoLessThan(treeSize)
	if leafIndex < k {
		leftRoot, used, err := inclusionRootFromPath(leafHash, leafIndex, k, path)
		if err != nil {
			return nil, 0, err
		}
		if used >= len(path) {
			return nil, 0, ErrInvalidSize
		}
		return NodeHash(leftRoot, path[used]), used + 1, nil
	}
	rightRoot, used, err := inclusionRootFromPath(leafHash, leafIndex-k, treeSize-k, path)
	if err != nil {
		return nil, 0, err
	}
	if used >= len(path) {
		return nil, 0, ErrInvalidSize
	}
	return NodeHash(path[used], rightRoot), used + 1, nil
}

func consistencyProofCT(leaves [][]byte, fromSize int, toSize int, isFirst bool) ([][]byte, error) {
	if fromSize == toSize {
		if isFirst {
			return [][]byte{}, nil
		}
		root, err := merkleTreeHash(leaves[:fromSize])
		if err != nil {
			return nil, err
		}
		return [][]byte{root}, nil
	}
	if toSize <= 1 {
		return nil, ErrInvalidSize
	}
	k := largestPowerOfTwoLessThan(toSize)
	if fromSize <= k {
		proof, err := consistencyProofCT(leaves[:k], fromSize, k, isFirst)
		if err != nil {
			return nil, err
		}
		rightRoot, err := merkleTreeHash(leaves[k:toSize])
		if err != nil {
			return nil, err
		}
		return append(proof, rightRoot), nil
	}
	proof, err := consistencyProofCT(leaves[k:toSize], fromSize-k, toSize-k, false)
	if err != nil {
		return nil, err
	}
	leftRoot, err := merkleTreeHash(leaves[:k])
	if err != nil {
		return nil, err
	}
	return append(proof, leftRoot), nil
}

func consistencyVerify(fromSize int, toSize int, path [][]byte, isFirst bool, oldRoot []byte) ([]byte, []byte, int, error) {
	if fromSize == toSize {
		if isFirst {
			return cloneHash(oldRoot), cloneHash(oldRoot), 0, nil
		}
		if len(path) == 0 {
			return nil, nil, 0, ErrInvalidSize
		}
		return cloneHash(path[0]), cloneHash(path[0]), 1, nil
	}
	if toSize <= 1 {
		return nil, nil, 0, ErrInvalidSize
	}

	k := largestPowerOfTwoLessThan(toSize)
	if fromSize <= k {
		leftOld, leftNew, used, err := consistencyVerify(fromSize, k, path, isFirst, oldRoot)
		if err != nil {
			return nil, nil, 0, err
		}
		if used >= len(path) {
			return nil, nil, 0, ErrInvalidSize
		}
		rightRoot := path[used]
		used++
		return leftOld, NodeHash(leftNew, rightRoot), used, nil
	}

	rightOld, rightNew, used, err := consistencyVerify(fromSize-k, toSize-k, path, false, oldRoot)
	if err != nil {
		return nil, nil, 0, err
	}
	if used >= len(path) {
		return nil, nil, 0, ErrInvalidSize
	}
	leftRoot := path[used]
	used++
	return NodeHash(leftRoot, rightOld), NodeHash(leftRoot, rightNew), used, nil
}
