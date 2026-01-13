package replay

import (
	"crypto/sha256"
	"encoding/hex"
)

func sha256Hex(input []byte) string {
	sum := sha256.Sum256(input)
	return hex.EncodeToString(sum[:])
}
