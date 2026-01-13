package domain

import "time"

type KeyStatus string

const (
	KeyStatusActive  KeyStatus = "active"
	KeyStatusRetired KeyStatus = "retired"
	KeyStatusRevoked KeyStatus = "revoked"
)

type SigningKey struct {
	ID        string
	TenantID  string
	KID       string
	Alg       string
	PublicKey []byte
	Status    KeyStatus
	NotBefore *time.Time
	NotAfter  *time.Time
	CreatedAt time.Time
}

type Revocation struct {
	ID        string
	TenantID  string
	KID       string
	RevokedAt time.Time
	Reason    string
	CreatedAt time.Time
}
