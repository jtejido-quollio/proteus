package domain

import "time"

type AuditActorType string

const (
	// AuditSystemTenantID is the reserved tenant identifier for global/system audit events.
	AuditSystemTenantID = "__system__"
	AuditChainVersion   = "audit_chain_v0"

	AuditActorSystem      AuditActorType = "system"
	AuditActorAdminAPIKey AuditActorType = "admin_api_key"
	AuditActorService     AuditActorType = "service"
	AuditActorUser        AuditActorType = "user"
)

type AuditEventType string

const (
	AuditEventKeyRegistered         AuditEventType = "key_registered"
	AuditEventKeyRotated            AuditEventType = "key_rotated"
	AuditEventKeyRevoked            AuditEventType = "key_revoked"
	AuditEventPolicyBundleUpserted  AuditEventType = "policy_bundle_upserted"
	AuditEventPolicyBundleActivated AuditEventType = "policy_activated"
	AuditEventBundleExported        AuditEventType = "bundle_exported"
)

type AuditTargetType string

const (
	AuditTargetTenant       AuditTargetType = "tenant"
	AuditTargetKey          AuditTargetType = "key"
	AuditTargetPolicyBundle AuditTargetType = "policy_bundle"
	AuditTargetReceipt      AuditTargetType = "receipt"
	AuditTargetBundle       AuditTargetType = "bundle"
)

type AuditResult string

const (
	AuditResultSuccess AuditResult = "success"
	AuditResultFailure AuditResult = "failure"
)

type AuditEvent struct {
	ID            string
	TenantID      string
	Seq           int64
	EventType     AuditEventType
	Payload       any
	PayloadHash   string
	ActorType     AuditActorType
	ActorIDHash   string
	TargetType    AuditTargetType
	TargetID      string
	Result        AuditResult
	ErrorCode     string
	PrevEventHash string
	EventHash     string
	CreatedAt     time.Time
}
