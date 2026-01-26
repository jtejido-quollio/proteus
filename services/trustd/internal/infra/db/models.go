package db

import "time"

type TenantModel struct {
	ID        string    `gorm:"type:uuid;primaryKey"`
	Name      string    `gorm:"uniqueIndex;not null"`
	CreatedAt time.Time `gorm:"not null"`
}

func (TenantModel) TableName() string {
	return "tenants"
}

type SigningKeyModel struct {
	ID        string `gorm:"type:uuid;primaryKey"`
	TenantID  string `gorm:"type:uuid;index;not null"`
	KID       string `gorm:"column:kid;index;not null"`
	Purpose   string `gorm:"not null"`
	Alg       string `gorm:"not null"`
	PublicKey []byte `gorm:"type:bytea;not null"`
	Status    string `gorm:"not null"`
	NotBefore *time.Time
	NotAfter  *time.Time
	CreatedAt time.Time `gorm:"not null"`
}

func (SigningKeyModel) TableName() string {
	return "signing_keys"
}

type RevocationModel struct {
	ID        string    `gorm:"type:uuid;primaryKey"`
	TenantID  string    `gorm:"type:uuid;index;not null"`
	KID       string    `gorm:"column:kid;index;not null"`
	RevokedAt time.Time `gorm:"not null"`
	Reason    string
	CreatedAt time.Time `gorm:"not null"`
}

func (RevocationModel) TableName() string {
	return "revocations"
}

type RevocationEpochModel struct {
	TenantID  string    `gorm:"primaryKey"`
	Epoch     int64     `gorm:"not null"`
	UpdatedAt time.Time `gorm:"not null"`
}

func (RevocationEpochModel) TableName() string {
	return "tenant_revocation_epoch"
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

func (ManifestModel) TableName() string {
	return "manifests"
}

type SignedManifestModel struct {
	ID         string    `gorm:"type:uuid;primaryKey"`
	TenantID   string    `gorm:"type:uuid;index;not null"`
	ManifestID string    `gorm:"type:uuid;index;not null"`
	KID        string    `gorm:"column:kid;not null"`
	SigAlg     string    `gorm:"not null"`
	Signature  []byte    `gorm:"type:bytea;not null"`
	ReceivedAt time.Time `gorm:"not null"`
}

func (SignedManifestModel) TableName() string {
	return "signed_manifests"
}

type TransparencyLeafModel struct {
	ID               int64     `gorm:"primaryKey"`
	TenantID         string    `gorm:"type:uuid;index;not null"`
	LeafIndex        int64     `gorm:"index;not null"`
	LeafHash         []byte    `gorm:"type:bytea;not null"`
	SignedManifestID string    `gorm:"type:uuid;index;not null"`
	CreatedAt        time.Time `gorm:"not null"`
}

func (TransparencyLeafModel) TableName() string {
	return "transparency_log_leaves"
}

type TreeHeadModel struct {
	ID        int64     `gorm:"primaryKey"`
	TenantID  string    `gorm:"type:uuid;index;not null"`
	TreeSize  int64     `gorm:"index;not null"`
	RootHash  []byte    `gorm:"type:bytea;not null"`
	IssuedAt  time.Time `gorm:"not null"`
	Signature []byte    `gorm:"column:sth_signature;type:bytea;not null"`
}

func (TreeHeadModel) TableName() string {
	return "tree_heads"
}

type ArtifactModel struct {
	ID        string `gorm:"type:uuid;primaryKey"`
	TenantID  string `gorm:"type:uuid;index;not null"`
	HashAlg   string `gorm:"not null"`
	HashValue string `gorm:"index;not null"`
	MediaType string `gorm:"not null"`
	URI       *string
	CreatedAt time.Time `gorm:"not null"`
}

func (ArtifactModel) TableName() string {
	return "artifacts"
}

type ProvenanceEdgeModel struct {
	ID         int64     `gorm:"primaryKey"`
	TenantID   string    `gorm:"type:uuid;index;not null"`
	ManifestID string    `gorm:"type:uuid;index;not null"`
	EdgeType   string    `gorm:"index;not null"`
	ArtifactID *string   `gorm:"type:uuid;index"`
	KID        *string   `gorm:"column:kid;index"`
	CreatedAt  time.Time `gorm:"not null"`
}

func (ProvenanceEdgeModel) TableName() string {
	return "provenance_edges"
}

type AnchorReceiptModel struct {
	ID                       int64  `gorm:"primaryKey"`
	TenantID                 string `gorm:"not null"`
	Provider                 string `gorm:"not null"`
	BundleID                 string `gorm:"not null"`
	Status                   string `gorm:"not null"`
	ErrorCode                *string
	PayloadHash              string `gorm:"not null"`
	TreeSize                 int64  `gorm:"not null"`
	EntryUUID                *string
	LogIndex                 *int64
	IntegratedTime           *int64
	EntryURL                 *string
	TxID                     *string
	ChainID                  *string
	ExplorerURL              *string
	ProviderReceiptJSON      []byte    `gorm:"type:jsonb"`
	ProviderReceiptTruncated bool      `gorm:"not null"`
	ProviderReceiptSizeBytes int       `gorm:"not null"`
	ProviderReceiptSHA256    string    `gorm:"not null"`
	CreatedAt                time.Time `gorm:"not null"`
}

func (AnchorReceiptModel) TableName() string {
	return "anchor_receipts"
}

type AnchorAttemptModel struct {
	ID                       int64  `gorm:"primaryKey"`
	TenantID                 string `gorm:"not null"`
	TreeSize                 int64  `gorm:"not null"`
	Provider                 string `gorm:"not null"`
	BundleID                 string `gorm:"not null"`
	Status                   string `gorm:"not null"`
	ErrorCode                *string
	PayloadHash              string    `gorm:"not null"`
	ProviderReceiptJSON      []byte    `gorm:"type:jsonb"`
	ProviderReceiptTruncated bool      `gorm:"not null"`
	ProviderReceiptSizeBytes int       `gorm:"not null"`
	CreatedAt                time.Time `gorm:"not null"`
}

func (AnchorAttemptModel) TableName() string {
	return "anchor_attempts"
}

type AuditEventModel struct {
	ID            string `gorm:"type:uuid;primaryKey"`
	TenantID      string `gorm:"type:text;index;not null"`
	Seq           int64  `gorm:"not null"`
	EventType     string `gorm:"column:event_type;not null"`
	PayloadJSON   []byte `gorm:"type:jsonb;not null"`
	PayloadHash   string `gorm:"not null"`
	ActorType     string `gorm:"not null"`
	ActorIDHash   *string
	TargetType    string `gorm:"not null"`
	TargetID      *string
	Result        string `gorm:"not null"`
	ErrorCode     *string
	PrevEventHash string    `gorm:"not null"`
	EventHash     string    `gorm:"not null"`
	CreatedAt     time.Time `gorm:"column:created_at;not null"`
}

func (AuditEventModel) TableName() string {
	return "audit_events"
}
