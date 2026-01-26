package usecase

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"proteus/internal/domain"
)

func VerifyTenantAuditChain(ctx context.Context, repo AuditEventRepository, tenantID string) error {
	if repo == nil {
		return errors.New("audit repository required")
	}
	if tenantID == "" {
		tenantID = domain.AuditSystemTenantID
	}
	events, err := repo.ListByTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return nil
	}

	expectedSeq := int64(1)
	prevHash := zeroAuditHash()
	for _, event := range events {
		if event.TenantID != tenantID {
			return fmt.Errorf("audit chain tenant mismatch at seq %d", event.Seq)
		}
		if event.Seq != expectedSeq {
			return fmt.Errorf("audit chain seq mismatch: expected %d got %d", expectedSeq, event.Seq)
		}
		if event.PrevEventHash != prevHash {
			return fmt.Errorf("audit chain prev hash mismatch at seq %d", event.Seq)
		}
		payloadJSON, err := payloadBytes(event.Payload)
		if err != nil {
			return fmt.Errorf("audit chain payload decode failed at seq %d: %w", event.Seq, err)
		}
		payloadHash := sha256Hex(payloadJSON)
		if payloadHash != event.PayloadHash {
			return fmt.Errorf("audit chain payload hash mismatch at seq %d", event.Seq)
		}
		if event.CreatedAt.IsZero() {
			return fmt.Errorf("audit chain missing created_at at seq %d", event.Seq)
		}
		expectedHash, err := computeChainHash(event)
		if err != nil {
			return fmt.Errorf("audit chain hash compute failed at seq %d: %w", event.Seq, err)
		}
		if expectedHash != event.EventHash {
			return fmt.Errorf("audit chain hash mismatch at seq %d", event.Seq)
		}
		prevHash = event.EventHash
		expectedSeq++
	}
	return nil
}

func payloadBytes(payload any) ([]byte, error) {
	switch v := payload.(type) {
	case []byte:
		return v, nil
	case string:
		return []byte(v), nil
	default:
		return nil, errors.New("payload_json must be []byte")
	}
}

func computeChainHash(event domain.AuditEvent) (string, error) {
	if event.TenantID == "" || event.EventType == "" {
		return "", errors.New("audit event missing tenant_id or event_type")
	}
	if event.PayloadHash == "" || event.PrevEventHash == "" {
		return "", errors.New("audit event missing payload_hash or prev_event_hash")
	}
	payload := chainPayload{
		Version:       domain.AuditChainVersion,
		TenantID:      event.TenantID,
		Seq:           event.Seq,
		EventType:     string(event.EventType),
		PayloadHash:   event.PayloadHash,
		PrevEventHash: event.PrevEventHash,
		CreatedAt:     event.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
	canonical := payload.CanonicalJSON()
	return sha256Hex(canonical), nil
}

func sha256Hex(input []byte) string {
	sum := sha256.Sum256(input)
	return hex.EncodeToString(sum[:])
}

func zeroAuditHash() string {
	return "0000000000000000000000000000000000000000000000000000000000000000"
}

type chainPayload struct {
	Version       string
	TenantID      string
	Seq           int64
	EventType     string
	PayloadHash   string
	PrevEventHash string
	CreatedAt     string
}

func (c chainPayload) CanonicalJSON() []byte {
	buf := &bytes.Buffer{}
	buf.WriteByte('{')
	writeKV(buf, "created_at", c.CreatedAt, false)
	writeKV(buf, "event_type", c.EventType, false)
	writeKV(buf, "payload_hash", c.PayloadHash, false)
	writeKV(buf, "prev_event_hash", c.PrevEventHash, false)
	writeKVNumber(buf, "seq", c.Seq, false)
	writeKV(buf, "tenant_id", c.TenantID, false)
	writeKV(buf, "v", c.Version, true)
	buf.WriteByte('}')
	return buf.Bytes()
}

func writeKV(buf *bytes.Buffer, key, value string, last bool) {
	writeJSONString(buf, key)
	buf.WriteByte(':')
	writeJSONString(buf, value)
	if !last {
		buf.WriteByte(',')
	}
}

func writeKVNumber(buf *bytes.Buffer, key string, value int64, last bool) {
	writeJSONString(buf, key)
	buf.WriteByte(':')
	buf.WriteString(strconv.FormatInt(value, 10))
	if !last {
		buf.WriteByte(',')
	}
}

func writeJSONString(buf *bytes.Buffer, value string) {
	buf.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"', '\\':
			buf.WriteByte('\\')
			buf.WriteRune(r)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				buf.WriteString(`\u00`)
				buf.WriteByte(hexLower[r>>4])
				buf.WriteByte(hexLower[r&0x0f])
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

var hexLower = []byte("0123456789abcdef")
