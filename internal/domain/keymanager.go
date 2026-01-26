package domain

import "context"

type KeyPurpose string

const (
	KeyPurposeSigning KeyPurpose = "signing"
	KeyPurposeLog     KeyPurpose = "log"
)

type KeyRef struct {
	TenantID string
	Purpose  KeyPurpose
	KID      string
}

// KeyManager performs cryptographic operations using keys resolved by KeyRef.
// Verify accepts a public key to keep offline verification independent of key stores.
type KeyManager interface {
	Sign(ctx context.Context, ref KeyRef, payload []byte) ([]byte, error)
	Verify(ctx context.Context, ref KeyRef, payload []byte, sig []byte, pubKey []byte) error
}
