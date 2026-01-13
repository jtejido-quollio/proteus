package db

import "time"

type TenantModel struct {
	ID        string    `gorm:"type:uuid;primaryKey"`
	Name      string    `gorm:"uniqueIndex;not null"`
	CreatedAt time.Time `gorm:"not null"`
}

type SigningKeyModel struct {
	ID        string `gorm:"type:uuid;primaryKey"`
	TenantID  string `gorm:"type:uuid;index;not null"`
	KID       string `gorm:"index;not null"`
	Alg       string `gorm:"not null"`
	PublicKey []byte `gorm:"type:bytea;not null"`
	Status    string `gorm:"not null"`
	NotBefore *time.Time
	NotAfter  *time.Time
	CreatedAt time.Time `gorm:"not null"`
}

type RevocationModel struct {
	ID        string    `gorm:"type:uuid;primaryKey"`
	TenantID  string    `gorm:"type:uuid;index;not null"`
	KID       string    `gorm:"index;not null"`
	RevokedAt time.Time `gorm:"not null"`
	Reason    string
	CreatedAt time.Time `gorm:"not null"`
}

type ManifestModel struct {
	ID               string    `gorm:"type:uuid;primaryKey"`
	TenantID         string    `gorm:"type:uuid;index;not null"`
	SubjectHashAlg   string    `gorm:"not null"`
	SubjectHashValue string    `gorm:"index;not null"`
	SubjectMediaType string    `gorm:"not null"`
	ManifestJSON     []byte    `gorm:"type:jsonb;not null"`
	CreatedAt        time.Time `gorm:"not null"`
}

type SignedManifestModel struct {
	ID         string    `gorm:"type:uuid;primaryKey"`
	TenantID   string    `gorm:"type:uuid;index;not null"`
	ManifestID string    `gorm:"type:uuid;index;not null"`
	KID        string    `gorm:"not null"`
	SigAlg     string    `gorm:"not null"`
	Signature  []byte    `gorm:"type:bytea;not null"`
	ReceivedAt time.Time `gorm:"not null"`
}

type TransparencyLeafModel struct {
	ID               int64     `gorm:"primaryKey"`
	TenantID         string    `gorm:"type:uuid;index;not null"`
	LeafIndex        int64     `gorm:"index;not null"`
	LeafHash         []byte    `gorm:"type:bytea;not null"`
	SignedManifestID string    `gorm:"type:uuid;index;not null"`
	CreatedAt        time.Time `gorm:"not null"`
}

type TreeHeadModel struct {
	ID        int64     `gorm:"primaryKey"`
	TenantID  string    `gorm:"type:uuid;index;not null"`
	TreeSize  int64     `gorm:"index;not null"`
	RootHash  []byte    `gorm:"type:bytea;not null"`
	IssuedAt  time.Time `gorm:"not null"`
	Signature []byte    `gorm:"column:sth_signature;type:bytea;not null"`
}

type ArtifactModel struct {
	ID        string    `gorm:"type:uuid;primaryKey"`
	TenantID  string    `gorm:"type:uuid;index;not null"`
	HashAlg   string    `gorm:"not null"`
	HashValue string    `gorm:"index;not null"`
	MediaType string    `gorm:"not null"`
	URI       *string
	CreatedAt time.Time `gorm:"not null"`
}

type ProvenanceEdgeModel struct {
	ID         int64     `gorm:"primaryKey"`
	TenantID   string    `gorm:"type:uuid;index;not null"`
	ManifestID string    `gorm:"type:uuid;index;not null"`
	EdgeType   string    `gorm:"index;not null"`
	ArtifactID *string   `gorm:"type:uuid;index"`
	KID        *string   `gorm:"index"`
	CreatedAt  time.Time `gorm:"not null"`
}
