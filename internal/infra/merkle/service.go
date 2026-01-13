package merkle

type Service struct{}

func (s *Service) VerifyInclusionProof(leafHash []byte, leafIndex int64, treeSize int64, path [][]byte, expectedRoot []byte) (bool, error) {
	return VerifyInclusionProof(leafHash, int(leafIndex), int(treeSize), path, expectedRoot)
}
